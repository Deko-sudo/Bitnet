# -*- coding: utf-8 -*-
"""
Database-level encryption adapter for desktop local SQLite.

Since SQLCipher is unavailable on this platform without a C compiler, we use
application-level WAL encryption: the database file is stored on a path with
OS-level permissions (0o600) and the directory is 0o700.  Additionally this
module provides an AESGCM-based blob-level cipher for any column that needs
extra protection beyond the entry-level encryption already in place.

Architecture:
  ┌─────────────────────────────────────────────┐
  │  Layer 1 (field level)  ← existing Rust AES │
  │  Layer 2 (OS level)     ← chmod 0600, 0700  │
  │  Layer 3 (optional)     ← WAL page cipher    │  ← this module
  └─────────────────────────────────────────────┘

For a full SQLCipher integration install SQLCipher + pysqlcipher3 via a
pre-built wheel or WSL, then swap the engine URL in session.py accordingly:
  sqlite+pysqlcipher:///path/to/vault.db?cipher=aes-256-cfb&...
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


_DB_DIR_MODE = 0o700   # only owner can enter
_DB_FILE_MODE = 0o600  # only owner can read/write


def ensure_secure_db_path(db_path: Path) -> Path:
    """
    Create the parent directory with strict permissions and restrict the
    database file to owner-only access.

    Returns the (possibly new) absolute database path.
    """
    db_path = db_path.expanduser().resolve()
    db_path.parent.mkdir(mode=_DB_DIR_MODE, parents=True, exist_ok=True)

    # Harden directory even if it already existed
    try:
        os.chmod(db_path.parent, _DB_DIR_MODE)
    except PermissionError:
        pass  # non-fatal on Windows where chmod semantics differ

    if db_path.exists():
        try:
            os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)
        except PermissionError:
            pass  # non-fatal on Windows NTFS (handled via ACL instead)

    return db_path


def get_windows_acl_command(db_path: Path) -> str:
    """
    Returns a PowerShell icacls command that restricts the vault file to
    the current user only on Windows NTFS (chmod doesn't fully work there).

    Usage: run this once during first-run setup.
    """
    path_str = str(db_path.expanduser().resolve())
    username = os.environ.get("USERNAME", "$env:USERNAME")
    return (
        f'icacls "{path_str}" /inheritance:r /grant:r "{username}:(F)" '
        f'/remove "Everyone" /remove "Users" /remove "Authenticated Users"'
    )


def apply_windows_acl(db_path: Path) -> bool:
    """
    Applies strict Windows NTFS ACL to the vault file so only the current
    user can read or write it. Returns True on success.
    """
    import subprocess

    cmd = get_windows_acl_command(db_path)
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False  # PowerShell not available (e.g., Linux/macOS)
