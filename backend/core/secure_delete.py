# -*- coding: utf-8 -*-
"""
Secure Delete - Secure File Deletion and Memory Protection

Provides:
- SecureFileDeleter for overwriting and deleting files
- MemoryGuard context manager for automatic key zeroing

Author: Nikita (BE1)
Version: 2.0
"""

import os
import secrets
import logging
from typing import Optional, BinaryIO, Any, Literal

from .crypto_core import zero_memory


logger = logging.getLogger(__name__)


# =============================================================================
# Secure File Deletion
# =============================================================================


class SecureFileDeleter:
    """
    Secure file deletion with multiple overwrite passes.

    Implements DoD 5220.22-M style secure deletion:
    1. Overwrite with random data
    2. Overwrite with complement
    3. Overwrite with random data again
    4. Delete file

    Example:
        >>> deleter = SecureFileDeleter(passes=3)
        >>> deleter.delete_file("sensitive_data.txt")
    """

    # Default buffer size for reading/writing (64 KB)
    BUFFER_SIZE = 65536

    def __init__(self, passes: int = 3):
        """
        Initialize SecureFileDeleter.

        Args:
            passes: Number of overwrite passes (1-7)

        Raises:
            ValueError: If passes is out of range
        """
        if not 1 <= passes <= 7:
            raise ValueError("passes must be between 1 and 7")

        self._passes = passes

    def delete_file(self, filepath: str) -> bool:
        """
        Securely delete a file.

        Args:
            filepath: Path to file to delete

        Returns:
            True if file was deleted successfully

        Raises:
            FileNotFoundError: If file doesn't exist
            PermissionError: If file cannot be modified
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        try:
            # Get file size
            file_size = os.path.getsize(filepath)

            if file_size == 0:
                # Empty file - just delete
                os.remove(filepath)
                return True

            # Open file for binary write
            with open(filepath, "r+b") as f:
                # Multiple overwrite passes
                for pass_num in range(self._passes):
                    self._overwrite_pass(f, file_size, pass_num)
                    f.flush()
                    os.fsync(f.fileno())

            # Delete the file
            os.remove(filepath)
            return True

        except Exception as e:
            raise type(e)(f"Failed to securely delete file: {e}")

    def _overwrite_pass(
        self,
        f: BinaryIO,
        file_size: int,
        pass_num: int,
    ) -> None:
        """
        Perform single overwrite pass.

        Args:
            f: Open file handle
            file_size: Size of file in bytes
            pass_num: Current pass number (0-indexed)
        """
        # Go to beginning of file
        f.seek(0)

        # Generate pattern for this pass
        pattern = self._generate_pattern(pass_num, file_size)

        # Write pattern to file
        bytes_written = 0
        while bytes_written < file_size:
            chunk_size = min(self.BUFFER_SIZE, file_size - bytes_written)
            chunk = pattern[
                bytes_written % len(pattern) : bytes_written % len(pattern) + chunk_size
            ]
            f.write(chunk)
            bytes_written += len(chunk)

    def _generate_pattern(self, pass_num: int, file_size: int) -> bytes:
        """
        Generate overwrite pattern for pass.

        Args:
            pass_num: Pass number (0-indexed)
            file_size: Size of file

        Returns:
            Pattern bytes
        """
        if pass_num == 0:
            # First pass: random data
            return secrets.token_bytes(min(1024, file_size))

        elif pass_num == 1:
            # Second pass: all zeros
            return b"\x00" * min(1024, file_size)

        elif pass_num == 2:
            # Third pass: all ones
            return b"\xff" * min(1024, file_size)

        else:
            # Additional passes: random data
            return secrets.token_bytes(min(1024, file_size))

    def delete_directory(
        self,
        dirpath: str,
        recursive: bool = True,
    ) -> int:
        """
        Securely delete all files in directory.

        Args:
            dirpath: Path to directory
            recursive: Whether to delete recursively

        Returns:
            Number of files deleted

        Raises:
            NotADirectoryError: If path is not a directory
        """
        if not os.path.isdir(dirpath):
            raise NotADirectoryError(f"Not a directory: {dirpath}")

        deleted_count = 0

        if recursive:
            # Walk directory tree
            for root, dirs, files in os.walk(dirpath, topdown=False):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    try:
                        self.delete_file(filepath)
                        deleted_count += 1
                    except Exception as e:
                        # Secure logging: record failure without leaking filename
                        logger.error(
                            "File wipe failure: %s: %s",
                            type(e).__name__,
                            e,
                        )

            # Remove empty directories
            for root, dirs, _ in os.walk(dirpath, topdown=False):
                for dirname in dirs:
                    dir_fullpath = os.path.join(root, dirname)
                    try:
                        os.rmdir(dir_fullpath)
                    except OSError as e:
                        logger.warning(
                            "Directory removal failure: %s: %s",
                            type(e).__name__,
                            e,
                        )
        else:
            # Only top-level files
            for filename in os.listdir(dirpath):
                filepath = os.path.join(dirpath, filename)
                if os.path.isfile(filepath):
                    try:
                        self.delete_file(filepath)
                        deleted_count += 1
                    except Exception as e:
                        logger.error(
                            "File wipe failure: %s: %s",
                            type(e).__name__,
                            e,
                        )

        return deleted_count


# =============================================================================
# Memory Guard
# =============================================================================


class MemoryGuard:
    """
    Context manager for automatic memory zeroing.

    Ensures sensitive data (keys, passwords) are zeroed
    from memory after use, even if an exception occurs.

    Uses bytearray for mutable storage and ctypes.memset
    for secure zeroing.

    Example:
        >>> with MemoryGuard(secret_key) as key:
        ...     # Use the key
        ...     encrypted = crypto.encrypt(data, key)
        # key is automatically zeroed here
    """

    def __init__(self, data: bytearray, label: Optional[str] = None):
        """
        Initialize MemoryGuard.

        Args:
            data: bytearray containing sensitive data
            label: Optional label for debugging

        Raises:
            TypeError: If data is not a bytearray
        """
        if not isinstance(data, bytearray):
            raise TypeError("data must be bytearray, not bytes")

        self._data = data
        self._label = label or "unnamed"
        self._zeroed = False

    def __enter__(self) -> bytearray:
        """Return the protected data."""
        return self._data

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Literal[False]:
        """Zero the data on exit."""
        self.zero()
        return False  # Don't suppress exceptions

    def zero(self) -> None:
        """
        Zero the protected memory using ctypes.memset.

        Can be called manually before context exit.
        Subsequent calls are no-ops.
        """
        if self._zeroed:
            return

        zero_memory(self._data)
        self._zeroed = True

    @property
    def is_zeroed(self) -> bool:
        """Check if data has been zeroed."""
        return self._zeroed

    def __repr__(self) -> str:
        status = "zeroed" if self._zeroed else "active"
        return f"<MemoryGuard label={self._label} size={len(self._data)} {status}>"


# =============================================================================
# SecureString - String with automatic zeroing
# =============================================================================


class SecureString:
    """
    Secure string that can be zeroed from memory.

    Unlike regular strings, SecureString stores data
    in a mutable bytearray that can be zeroed.

    Example:
        >>> secret = SecureString("my_password")
        >>> # Use the password
        >>> key = crypto.derive_master_key(str(secret), salt)
        >>> # Zero the password
        >>> secret.zero()
    """

    def __init__(self, value: str):
        """
        Initialize SecureString.

        Args:
            value: String value to protect
        """
        self._data = bytearray(value.encode("utf-8"))
        self._zeroed = False

    def __str__(self) -> str:
        """
        Get string value.

        Warning: The returned string is a Python str object and
        may be interned or retained by the GC. Callers must treat
        the result as sensitive and avoid storing it.
        """
        if self._zeroed:
            raise ValueError("SecureString has been zeroed")
        return self._data.decode("utf-8")

    def __bytes__(self) -> bytes:
        """Get bytes value."""
        if self._zeroed:
            raise ValueError("SecureString has been zeroed")
        return bytes(self._data)

    def zero(self) -> None:
        """Zero the string from memory."""
        if self._zeroed:
            return

        zero_memory(self._data)
        self._zeroed = True

    @property
    def is_zeroed(self) -> bool:
        """Check if string has been zeroed."""
        return self._zeroed

    def __len__(self) -> int:
        """Get string length."""
        if self._zeroed:
            raise ValueError("SecureString has been zeroed")
        return len(self._data)

    def __enter__(self) -> "SecureString":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Literal[False]:
        """Context manager exit - zero the string."""
        self.zero()
        return False

    def __repr__(self) -> str:
        if self._zeroed:
            return "<SecureString zeroed>"
        return f"<SecureString length={len(self._data)}>"


# =============================================================================
# Convenience Functions
# =============================================================================


def secure_delete_file(filepath: str, passes: int = 3) -> bool:
    """
    Securely delete a file.

    Convenience function for one-off deletions.

    Args:
        filepath: Path to file
        passes: Number of overwrite passes

    Returns:
        True if file was deleted

    Example:
        >>> secure_delete_file("sensitive.txt")
    """
    deleter = SecureFileDeleter(passes=passes)
    return deleter.delete_file(filepath)


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Classes
    "SecureFileDeleter",
    "MemoryGuard",
    "SecureString",
    # Functions
    "secure_delete_file",
]
