# -*- coding: utf-8 -*-
"""
Encryption helper — thin security wrapper around the Rust crypto bridge.

All cryptographic operations flow through ``backend.core.crypto_bridge.bridge``.
Sensitive plaintext is **never** cast to Python ``str``: inputs arrive as
``bytearray`` / ``memoryview`` and outputs are returned as ``LockedBuffer`` or
``bytearray`` that the caller is responsible for wiping.

This module exposes **pure functions only** — no classes, no state.

Public API
----------
* ``encrypt_entry_data(key, raw_data) -> tuple[str, str]``
* ``decrypt_entry_data(key, cipher_hex, nonce_hex) -> LockedBuffer``
* ``generate_search_index(key, title) -> str``
* ``encrypt_all_entry_fields(key, *, ...) -> dict[str, Optional[str]]``
* ``decrypt_all_entry_fields(key, *, ...) -> dict[str, Optional[bytearray]]``
"""

from __future__ import annotations

from typing import Optional

from backend.core.crypto_bridge import (
    LockedBuffer,
    bridge,
    zeroize_mutable_buffer,
)
from backend.core.crypto_core import zero_memory

# ===========================================================================
# Single-field primitives
# ===========================================================================


def encrypt_entry_data(
    key: LockedBuffer,
    raw_data: bytearray,
) -> tuple[str, str]:
    """Encrypt a single plaintext field into hex strings for DB storage.

    Parameters
    ----------
    key:
        The user's master key (locked, non-wipeable from this function).
    raw_data:
        UTF-8 encoded plaintext as a mutable ``bytearray``.  It **will** be
        zeroized before this function returns.

    Returns
    -------
    (cipher_hex, nonce_hex) — both suitable for storage in a text column.
    """
    return bridge.encrypt_for_storage(key, raw_data, wipe_plaintext=True)


def decrypt_entry_data(
    key: LockedBuffer,
    cipher_hex: str,
    nonce_hex: str,
) -> LockedBuffer:
    """Decrypt a field previously stored via :func:`encrypt_entry_data`.

    The returned ``LockedBuffer`` is **not** automatically closed — the caller
    must invoke ``.close()`` when finished.
    """
    return bridge.decrypt_from_storage(key, cipher_hex, nonce_hex)


def generate_search_index(
    key: LockedBuffer,
    title: bytearray,
) -> str:
    """Generate a deterministic blind HMAC index for the given title.

    The ``title`` buffer is zeroized before this function returns.

    Returns
    -------
    hex-encoded HMAC digest that can be stored in an indexed text column.
    """
    return bridge.generate_blind_index_hmac(key, title, wipe_title=True)


# ===========================================================================
# Batch helpers — used by the entry CRUD service
# ===========================================================================


def encrypt_all_entry_fields(
    key: LockedBuffer,
    *,
    title: bytearray,
    username: Optional[bytearray] = None,
    password: bytearray,
    url: Optional[bytearray] = None,
    notes: Optional[bytearray] = None,
) -> dict[str, Optional[str]]:
    """Encrypt every non-None field and return a flat dict of hex columns.

    Every input ``bytearray`` is zeroized before this function returns.
    """
    result: dict[str, Optional[str]] = {}

    # Mandatory fields
    result["title_cipher"], result["title_nonce"] = encrypt_entry_data(key, title)
    result["password_cipher"], result["password_nonce"] = encrypt_entry_data(
        key, password
    )

    # Optional fields
    for field_name, buf in (("username", username), ("url", url), ("notes", notes)):
        if buf is not None:
            c, n = encrypt_entry_data(key, buf)
            result[f"{field_name}_cipher"] = c
            result[f"{field_name}_nonce"] = n
        else:
            result[f"{field_name}_cipher"] = None
            result[f"{field_name}_nonce"] = None

    return result


class LockedBufferSet:
    """Manages a set of LockedBuffers/bytearrays for automatic cleanup."""

    def __init__(self):
        self._buffers = []

    def add(self, buf):
        self._buffers.append(buf)
        return buf

    def close(self):
        for buf in self._buffers:
            if hasattr(buf, "close"):
                buf.close()
            elif isinstance(buf, bytearray):
                zero_memory(buf)
        self._buffers = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def decrypt_all_entry_fields(
    key: LockedBuffer,
    *,
    title_cipher: str,
    title_nonce: str,
    username_cipher: Optional[str] = None,
    username_nonce: Optional[str] = None,
    password_cipher: str,
    password_nonce: str,
    url_cipher: Optional[str] = None,
    url_nonce: Optional[str] = None,
    notes_cipher: Optional[str] = None,
    notes_nonce: Optional[str] = None,
) -> tuple[LockedBufferSet, dict[str, Optional[bytearray]]]:
    """Decrypt every stored field and return a LockedBufferSet and dict of bytearray values."""
    lbs = LockedBufferSet()
    result: dict[str, Optional[bytearray]] = {}

    result["title"] = lbs.add(_decrypt_to_bytearray(key, title_cipher, title_nonce))
    result["password"] = lbs.add(
        _decrypt_to_bytearray(key, password_cipher, password_nonce)
    )

    for field_name, ciph, nce in (
        ("username", username_cipher, username_nonce),
        ("url", url_cipher, url_nonce),
        ("notes", notes_cipher, notes_nonce),
    ):
        if ciph is not None and nce is not None:
            result[field_name] = lbs.add(_decrypt_to_bytearray(key, ciph, nce))
        else:
            result[field_name] = None

    return lbs, result


# ===========================================================================
# Internal
# ===========================================================================


def _decrypt_to_bytearray(
    key: LockedBuffer,
    cipher_hex: str,
    nonce_hex: str,
) -> bytearray:
    """Decrypt hex-stored field and copy the plaintext into a ``bytearray``."""
    locked = decrypt_entry_data(key, cipher_hex, nonce_hex)
    try:
        return bridge.locked_buffer_to_bytearray(locked)
    finally:
        locked.close()
