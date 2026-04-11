# -*- coding: utf-8 -*-
"""
Encryption Helper - Bridge between CRUD and Crypto modules.
Provides easy-to-use methods for encrypting and decrypting PasswordEntry records.
"""

from contextlib import contextmanager
from typing import Dict, Any, Optional, Callable, Iterator
import json
from pydantic import BaseModel, SecretStr

from backend.core.crypto_core import CryptoCore, MemoryGuard, DecryptionError, zero_memory


class EntryFieldsRaw(BaseModel):
    """Raw (unencrypted) entry fields."""
    title: SecretStr
    username: Optional[str] = None
    password: SecretStr
    url: Optional[str] = None
    notes: Optional[SecretStr] = None


class EntryFieldsEncrypted(BaseModel):
    """Encrypted entry fields, typically stored as hex strings in DB."""
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

    def __init__(self, key_provider: Callable[[], bytearray | bytes]):
        """
        Initialize EncryptionHelper with on-demand key provider.
        
        Args:
            key_provider: Callable that returns current master key material.
                Returned data is copied and zeroed after each operation.
        """
        if not callable(key_provider):
            raise TypeError("key_provider must be callable and return bytes/bytearray")

        self._key_provider = key_provider
        self._crypto = CryptoCore()

    def _materialize_operation_key(self) -> bytearray:
        """Get key from provider and copy it into zeroizable buffer."""
        source_key = self._key_provider()
        if not isinstance(source_key, (bytes, bytearray)):
            raise TypeError("key_provider must return bytes or bytearray")
        key = bytearray(source_key)
        if isinstance(source_key, bytearray):
            zero_memory(source_key)
        if len(key) != self._crypto.config.key_size:
            zero_memory(key)
            raise ValueError(f"Key must be {self._crypto.config.key_size} bytes")
        return key

    @contextmanager
    def _operation_key(self) -> Iterator[bytearray]:
        """Yield temporary key buffer that is always zeroed after use."""
        key = self._materialize_operation_key()
        with MemoryGuard(key) as guarded_key:
            yield guarded_key

    def _encrypt_text_field(self, plaintext: str | SecretStr, key: bytearray) -> tuple[str, str]:
        """Encrypt text, returning (cipher_hex, nonce_hex) and zeroizing intermediate buffers."""
        text_str = plaintext.get_secret_value() if isinstance(plaintext, SecretStr) else plaintext
        plaintext_buf = bytearray(text_str.encode("utf-8"))
        try:
            encrypted_data = self._crypto.encrypt(plaintext_buf, key)
            nonce_size = self._crypto.config.nonce_size
            nonce = encrypted_data[:nonce_size]
            cipher = encrypted_data[nonce_size:]
            return cipher.hex(), nonce.hex()
        finally:
            zero_memory(plaintext_buf)
            
    def _decrypt_text_field(self, cipher_hex: str, nonce_hex: str, key: bytearray) -> bytearray:
        """Decrypt text, returns bytearray buffer which caller MUST zero after use."""
        encrypted_data = bytearray.fromhex(nonce_hex) + bytearray.fromhex(cipher_hex)
        try:
            return self._crypto.decrypt(encrypted_data, key)
        finally:
            zero_memory(encrypted_data)

    def encrypt_entry_fields(self, raw: EntryFieldsRaw) -> EntryFieldsEncrypted:
        """Encrypt all sensitive fields in an entry."""
        with self._operation_key() as key:
            title_enc, title_nonce = self._encrypt_text_field(raw.title, key)
            pass_enc, pass_nonce = self._encrypt_text_field(raw.password, key)
            
            user_enc, user_nonce = self._encrypt_text_field(raw.username, key) if raw.username else (None, None)
            url_enc, url_nonce = self._encrypt_text_field(raw.url, key) if raw.url else (None, None)
            notes_enc, notes_nonce = self._encrypt_text_field(raw.notes, key) if raw.notes else (None, None)
            
            return EntryFieldsEncrypted(
                title_cipher=title_enc, title_nonce=title_nonce,
                username_cipher=user_enc, username_nonce=user_nonce,
                password_cipher=pass_enc, password_nonce=pass_nonce,
                url_cipher=url_enc, url_nonce=url_nonce,
                notes_cipher=notes_enc, notes_nonce=notes_nonce
            )

    def decrypt_entry_fields(self, encrypted: EntryFieldsEncrypted) -> Dict[str, Optional[bytearray]]:
        """Decrypt all sensitive fields in an entry. Returns dict of bytearrays to avoid immutable string leaks."""
        with self._operation_key() as key:
            try:
                title_dec = self._decrypt_text_field(encrypted.title_cipher, encrypted.title_nonce, key)
                pass_dec = self._decrypt_text_field(encrypted.password_cipher, encrypted.password_nonce, key)
                
                user_dec = self._decrypt_text_field(encrypted.username_cipher, encrypted.username_nonce, key) if encrypted.username_cipher else None
                url_dec = self._decrypt_text_field(encrypted.url_cipher, encrypted.url_nonce, key) if encrypted.url_cipher else None
                notes_dec = self._decrypt_text_field(encrypted.notes_cipher, encrypted.notes_nonce, key) if encrypted.notes_cipher else None
                
                return {
                    "title": title_dec,
                    "username": user_dec,
                    "password": pass_dec,
                    "url": url_dec,
                    "notes": notes_dec
                }
            except Exception as e:
                raise DecryptionError(f"Failed to decrypt entry fields: {e}")

    def encrypt_custom_fields(self, custom_data: Dict[str, Any]) -> str:
        """Encrypt custom JSON schema."""
        with self._operation_key() as key:
            json_buf = bytearray(json.dumps(custom_data).encode("utf-8"))
            try:
                return self._crypto.encrypt(json_buf, key).hex()
            finally:
                zero_memory(json_buf)

    def decrypt_custom_fields(self, encrypted_hex: str) -> Dict[str, Any]:
        """Decrypt custom JSON schema."""
        if not encrypted_hex:
            return {}
        with self._operation_key() as key:
            try:
                json_data = self._crypto.decrypt(bytearray.fromhex(encrypted_hex), key)
                res = json.loads(json_data.decode('utf-8'))
                zero_memory(json_data)
                return res
            except Exception as e:
                raise DecryptionError(f"Failed to decrypt custom fields: {e}")

    def decrypt_title_cipher(self, title_cipher: str, title_nonce: str) -> bytearray:
        """Decrypt only title field to minimize plaintext exposure during search."""
        with self._operation_key() as key:
            try:
                return self._decrypt_text_field(title_cipher, title_nonce, key)
            except Exception as e:
                raise DecryptionError(f"Failed to decrypt title field: {e}")
