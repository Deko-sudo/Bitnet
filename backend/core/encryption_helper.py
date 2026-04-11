# -*- coding: utf-8 -*-
"""
Encryption helper backed by the Rust + PyO3 crypto core.

The bridge only accepts mutable Python buffers or Rust-managed LockedBuffer
instances for sensitive inputs. Plaintext is encoded into bytearray buffers,
passed to Rust without creating intermediate Python `bytes`, and zeroized in
`finally` blocks immediately after the FFI call returns.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterator, Optional
import json

from pydantic import BaseModel, SecretStr

from backend.core.crypto_bridge import LockedBuffer, bridge, zeroize_mutable_buffer
from backend.core.crypto_core import DecryptionError


class EntryFieldsRaw(BaseModel):
    """Raw (unencrypted) entry fields."""

    title: SecretStr
    username: Optional[SecretStr] = None
    password: SecretStr
    url: Optional[SecretStr] = None
    notes: Optional[SecretStr] = None


class EntryFieldsEncrypted(BaseModel):
    """Encrypted entry fields stored as hex strings in the database."""

    title_cipher: str
    title_nonce: str
    username_cipher: Optional[str] = None
    username_nonce: Optional[str] = None
    password_cipher: str
    password_nonce: str
    url_cipher: Optional[str] = None
    url_nonce: Optional[str] = None
    notes_cipher: Optional[str] = None
    notes_nonce: Optional[str] = None


class EncryptionHelper:
    """Helper for securely encrypting database entry fields."""

    def __init__(self, key_provider: Callable[[], LockedBuffer]):
        if not callable(key_provider):
            raise TypeError("key_provider must be callable and return LockedBuffer")

        self._key_provider = key_provider

    def _materialize_operation_key(self) -> LockedBuffer:
        key = self._key_provider()
        if not isinstance(key, LockedBuffer):
            raise TypeError("key_provider must return LockedBuffer")
        return key.duplicate()

    @contextmanager
    def _operation_key(self) -> Iterator[LockedBuffer]:
        key = self._materialize_operation_key()
        try:
            yield key
        finally:
            key.close()

    @staticmethod
    def _secret_to_mutable_buffer(plaintext: str | SecretStr) -> bytearray:
        text = plaintext.get_secret_value() if isinstance(plaintext, SecretStr) else plaintext
        return bytearray(text.encode("utf-8"))

    def _encrypt_text_field(
        self,
        plaintext: str | SecretStr,
        key: LockedBuffer,
    ) -> tuple[str, str]:
        plaintext_buf = self._secret_to_mutable_buffer(plaintext)
        try:
            return bridge.encrypt_for_storage(key, plaintext_buf, wipe_plaintext=True)
        finally:
            zeroize_mutable_buffer(plaintext_buf)

    def _decrypt_text_field(self, cipher_hex: str, nonce_hex: str, key: LockedBuffer) -> bytearray:
        locked_plaintext = bridge.decrypt_from_storage(key, cipher_hex, nonce_hex)
        try:
            return bridge.locked_buffer_to_bytearray(locked_plaintext)
        finally:
            locked_plaintext.close()

    def generate_blind_index(self, plaintext: str | SecretStr, key: LockedBuffer) -> str:
        plaintext_buf = self._secret_to_mutable_buffer(plaintext)
        try:
            return bridge.generate_blind_index_hmac(key, plaintext_buf, wipe_title=True)
        finally:
            zeroize_mutable_buffer(plaintext_buf)

    def encrypt_entry_fields(self, raw: EntryFieldsRaw) -> EntryFieldsEncrypted:
        with self._operation_key() as key:
            title_enc, title_nonce = self._encrypt_text_field(raw.title, key)
            pass_enc, pass_nonce = self._encrypt_text_field(raw.password, key)

            user_enc, user_nonce = (
                self._encrypt_text_field(raw.username, key) if raw.username else (None, None)
            )
            url_enc, url_nonce = (
                self._encrypt_text_field(raw.url, key) if raw.url else (None, None)
            )
            notes_enc, notes_nonce = (
                self._encrypt_text_field(raw.notes, key) if raw.notes else (None, None)
            )

            return EntryFieldsEncrypted(
                title_cipher=title_enc,
                title_nonce=title_nonce,
                username_cipher=user_enc,
                username_nonce=user_nonce,
                password_cipher=pass_enc,
                password_nonce=pass_nonce,
                url_cipher=url_enc,
                url_nonce=url_nonce,
                notes_cipher=notes_enc,
                notes_nonce=notes_nonce,
            )

    def decrypt_entry_fields(self, encrypted: EntryFieldsEncrypted) -> Dict[str, Optional[bytearray]]:
        with self._operation_key() as key:
            try:
                return {
                    "title": self._decrypt_text_field(
                        encrypted.title_cipher,
                        encrypted.title_nonce,
                        key,
                    ),
                    "username": (
                        self._decrypt_text_field(
                            encrypted.username_cipher,
                            encrypted.username_nonce,
                            key,
                        )
                        if encrypted.username_cipher and encrypted.username_nonce
                        else None
                    ),
                    "password": self._decrypt_text_field(
                        encrypted.password_cipher,
                        encrypted.password_nonce,
                        key,
                    ),
                    "url": (
                        self._decrypt_text_field(encrypted.url_cipher, encrypted.url_nonce, key)
                        if encrypted.url_cipher and encrypted.url_nonce
                        else None
                    ),
                    "notes": (
                        self._decrypt_text_field(
                            encrypted.notes_cipher,
                            encrypted.notes_nonce,
                            key,
                        )
                        if encrypted.notes_cipher and encrypted.notes_nonce
                        else None
                    ),
                }
            except Exception as exc:  # pragma: no cover - PyO3 exceptions are runtime specific
                raise DecryptionError(f"Failed to decrypt entry fields: {exc}") from exc

    def encrypt_custom_fields(self, custom_data: Dict[str, Any]) -> str:
        with self._operation_key() as key:
            json_buf = bytearray(
                json.dumps(custom_data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            )
            try:
                envelope = bridge.aes_gcm_encrypt(key, json_buf, wipe_plaintext=True)
                return (envelope.nonce + envelope.ciphertext + envelope.tag).hex()
            finally:
                zeroize_mutable_buffer(json_buf)

    def decrypt_custom_fields(self, encrypted_hex: str) -> Dict[str, Any]:
        if not encrypted_hex:
            return {}

        packed = bytes.fromhex(encrypted_hex)
        if len(packed) < 12 + 16:
            raise DecryptionError("Encrypted custom payload is malformed")

        nonce = packed[:12]
        ciphertext = packed[12:-16]
        tag = packed[-16:]

        with self._operation_key() as key:
            locked_plaintext = bridge.aes_gcm_decrypt(key, ciphertext, nonce, tag)
            try:
                json_buf = bridge.locked_buffer_to_bytearray(locked_plaintext)
                try:
                    return json.loads(json_buf.decode("utf-8"))
                finally:
                    zeroize_mutable_buffer(json_buf)
            except Exception as exc:  # pragma: no cover
                raise DecryptionError(f"Failed to decrypt custom fields: {exc}") from exc
            finally:
                locked_plaintext.close()

    def decrypt_title_cipher(self, title_cipher: str, title_nonce: str) -> bytearray:
        with self._operation_key() as key:
            try:
                return self._decrypt_text_field(title_cipher, title_nonce, key)
            except Exception as exc:  # pragma: no cover
                raise DecryptionError(f"Failed to decrypt title field: {exc}") from exc
