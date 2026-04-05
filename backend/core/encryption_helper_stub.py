# STUB — replace with real EncryptionHelper before production
# -*- coding: utf-8 -*-
"""
Encryption Helper Stub — placeholder for CRUD development.

Provides the same public API as the real EncryptionHelper but performs
NO real cryptography. All methods return input data unchanged.

This stub unblocks database-layer development (Alex / BE2) from Week 1
without requiring the cryptographic core to be production-ready.

Security warning: DO NOT use this stub in any production or staging
environment. All data is stored in PLAINTEXT.
"""

from typing import Dict, Any, Optional, Callable


# =============================================================================
# Data Classes
# =============================================================================


class EntryFieldsRaw:
    """
    Raw (unencrypted) entry fields.

    Attributes:
        title: Entry title (e.g. "Google Account")
        username: Username or email
        password: Plaintext password
        url: Optional associated URL
        notes: Optional free-text notes
        custom_fields: Optional dict of user-defined fields
    """

    def __init__(
        self,
        title: str,
        username: str,
        password: str,
        url: Optional[str] = None,
        notes: Optional[str] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialise raw entry fields.

        Args:
            title: Entry title
            username: Username or email
            password: Plaintext password
            url: Optional associated URL
            notes: Optional free-text notes
            custom_fields: Optional dict of user-defined fields
        """
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.notes = notes
        self.custom_fields = custom_fields or {}


class EntryFieldsEncrypted:
    """
    Encrypted entry fields (stub — data is NOT actually encrypted).

    In production this will hold ciphertext, nonce, and auth tag.

    Attributes:
        title: Encrypted title (stub: plaintext)
        username: Encrypted username (stub: plaintext)
        password: Encrypted password (stub: plaintext)
        url: Encrypted URL (stub: plaintext)
        notes: Encrypted notes (stub: plaintext)
        custom_fields: Encrypted custom fields as JSON string
        auth_tag: Authentication tag (stub: placeholder string)
    """

    def __init__(
        self,
        title: str,
        username: str,
        password: str,
        url: Optional[str],
        notes: Optional[str],
        custom_fields: str,
        auth_tag: str,
    ) -> None:
        """
        Initialise encrypted entry fields (stub).

        Args:
            title: Title (stub: plaintext)
            username: Username (stub: plaintext)
            password: Password (stub: plaintext)
            url: URL (stub: plaintext)
            notes: Notes (stub: plaintext)
            custom_fields: Custom fields as JSON string
            auth_tag: Authentication tag (stub placeholder)
        """
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.notes = notes
        self.custom_fields = custom_fields
        self.auth_tag = auth_tag


# =============================================================================
# EncryptionHelper (Stub)
# =============================================================================


class EncryptionHelper:
    """
    Stub encryption helper — mirrors the real API with NO cryptography.

    All encrypt/decrypt methods return data unchanged.  This allows
    the database and API layers to be developed and tested in parallel
    with the cryptographic core.

    Usage:
        >>> helper = EncryptionHelper(key_provider)
        >>> encrypted = helper.encrypt_entry_fields(raw_fields)
        >>> decrypted = helper.decrypt_entry_fields(encrypted)
        # encrypted.title == raw_fields.title  (stub — no encryption!)

    Args:
        key_provider: Callable returning 32-byte master key material.
            The stub validates the signature but never uses the key.

    Raises:
        TypeError: If key_provider is not callable.
        ValueError: If key_provider does not return exactly 32 bytes.
    """

    def __init__(self, key_provider: Callable[[], bytes]) -> None:
        """
        Initialise the stub encryption helper.

        Validates that key_provider is callable and returns 32 bytes,
        then discards the key material.  No key is stored.

        Args:
            key_provider: Callable returning 32-byte master key.
        """
        if not callable(key_provider):
            raise TypeError("key_provider must be callable")
        key_material = key_provider()
        if len(key_material) != 32:
            raise ValueError("key_provider must return exactly 32 bytes")
        # Stub: key material is intentionally discarded.
        self._is_stub = True

    def encrypt_entry_fields(self, raw: EntryFieldsRaw) -> EntryFieldsEncrypted:
        """
        Encrypt all entry fields (stub — returns plaintext).

        Args:
            raw: Raw entry fields to encrypt.

        Returns:
            EntryFieldsEncrypted with data unchanged (stub).
        """
        import json

        return EntryFieldsEncrypted(
            title=raw.title,
            username=raw.username,
            password=raw.password,
            url=raw.url,
            notes=raw.notes,
            custom_fields=json.dumps(raw.custom_fields or {}),
            auth_tag="stub_auth_tag",
        )

    def decrypt_entry_fields(self, encrypted: EntryFieldsEncrypted) -> EntryFieldsRaw:
        """
        Decrypt all entry fields (stub — returns plaintext).

        Args:
            encrypted: Encrypted entry fields (stub: plaintext).

        Returns:
            EntryFieldsRaw with data unchanged (stub).
        """
        import json

        return EntryFieldsRaw(
            title=encrypted.title,
            username=encrypted.username,
            password=encrypted.password,
            url=encrypted.url,
            notes=encrypted.notes,
            custom_fields=json.loads(encrypted.custom_fields)
            if encrypted.custom_fields
            else None,
        )

    def encrypt_custom_fields(self, custom_data: Dict[str, Any]) -> str:
        """
        Encrypt custom fields dict to JSON string (stub — no encryption).

        Args:
            custom_data: Dict of custom field key-value pairs.

        Returns:
            JSON string of the input dict (stub: unencrypted).
        """
        import json

        return json.dumps(custom_data)

    def decrypt_custom_fields(self, encrypted_json: str) -> Dict[str, Any]:
        """
        Decrypt custom fields JSON string to dict (stub — no decryption).

        Args:
            encrypted_json: JSON string (stub: unencrypted).

        Returns:
            Dict of custom field key-value pairs.
        """
        import json

        return json.loads(encrypted_json) if encrypted_json else {}

    def encrypt_bytes(self, data: bytes) -> bytes:
        """
        Encrypt arbitrary bytes (stub — returns input unchanged).

        Args:
            data: Bytes to encrypt.

        Returns:
            The same bytes (stub: no encryption).
        """
        return data

    def decrypt_bytes(self, data: bytes) -> bytes:
        """
        Decrypt arbitrary bytes (stub — returns input unchanged).

        Args:
            data: Bytes to decrypt.

        Returns:
            The same bytes (stub: no decryption).
        """
        return data

    def is_stub(self) -> bool:
        """
        Check whether this is a stub instance.

        Returns:
            True — this is always a stub.
        """
        return self._is_stub


# =============================================================================
# Factory Function
# =============================================================================


def create_encryption_helper(
    key_provider: Callable[[], bytes],
) -> EncryptionHelper:
    """
    Factory function to create an EncryptionHelper instance.

    Args:
        key_provider: Callable returning 32-byte master key.

    Returns:
        EncryptionHelper (stub) instance.
    """
    return EncryptionHelper(key_provider)
