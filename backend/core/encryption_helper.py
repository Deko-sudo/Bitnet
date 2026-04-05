# -*- coding: utf-8 -*-
"""
Encryption Helper - Bridge between CRUD and Crypto modules.
Provides easy-to-use methods for encrypting and decrypting PasswordEntry records.
"""

from contextlib import contextmanager
from typing import Dict, Any, Optional, Callable, Iterator
import json
from pydantic import BaseModel

from backend.core.crypto_core import CryptoCore, MemoryGuard, DecryptionError, zero_memory


class EntryFieldsRaw(BaseModel):
    """Raw (unencrypted) entry fields."""
    title: str
    username: Optional[str] = None
    password: str
    url: Optional[str] = None
    notes: Optional[str] = None


class EntryFieldsEncrypted(BaseModel):
    """Encrypted entry fields, typically stored as hex strings in DB."""
    title_cipher: str
    username_cipher: Optional[str] = None
    password_cipher: str
    url_cipher: Optional[str] = None
    notes_cipher: Optional[str] = None


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

    def _encrypt_text_field(self, plaintext: str, key: bytearray) -> str:
        """Encrypt text while keeping mutable plaintext buffer zeroizable."""
        plaintext_buf = bytearray(plaintext.encode("utf-8"))
        try:
            return self._crypto.encrypt(plaintext_buf, key).hex()
        finally:
            zero_memory(plaintext_buf)

    def encrypt_entry_fields(self, raw: EntryFieldsRaw) -> EntryFieldsEncrypted:
        """Encrypt all sensitive fields in an entry."""
        with self._operation_key() as key:
            # encrypt() returns nonce + ciphertext + auth_tag
            title_enc = self._encrypt_text_field(raw.title, key)
            pass_enc = self._encrypt_text_field(raw.password, key)
            
            user_enc = self._encrypt_text_field(raw.username, key) if raw.username else None
            url_enc = self._encrypt_text_field(raw.url, key) if raw.url else None
            notes_enc = self._encrypt_text_field(raw.notes, key) if raw.notes else None
            
            return EntryFieldsEncrypted(
                title_cipher=title_enc,
                username_cipher=user_enc,
                password_cipher=pass_enc,
                url_cipher=url_enc,
                notes_cipher=notes_enc
            )

    def decrypt_entry_fields(self, encrypted: EntryFieldsEncrypted) -> EntryFieldsRaw:
        """Decrypt all sensitive fields in an entry."""
        with self._operation_key() as key:
            try:
                title_dec = self._crypto.decrypt(bytes.fromhex(encrypted.title_cipher), key).decode('utf-8')
                pass_dec = self._crypto.decrypt(bytes.fromhex(encrypted.password_cipher), key).decode('utf-8')
                
                user_dec = self._crypto.decrypt(bytes.fromhex(encrypted.username_cipher), key).decode('utf-8') if encrypted.username_cipher else None
                url_dec = self._crypto.decrypt(bytes.fromhex(encrypted.url_cipher), key).decode('utf-8') if encrypted.url_cipher else None
                notes_dec = self._crypto.decrypt(bytes.fromhex(encrypted.notes_cipher), key).decode('utf-8') if encrypted.notes_cipher else None
                
                return EntryFieldsRaw(
                    title=title_dec,
                    username=user_dec,
                    password=pass_dec,
                    url=url_dec,
                    notes=notes_dec
                )
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
                json_data = self._crypto.decrypt(bytes.fromhex(encrypted_hex), key)
                return json.loads(json_data.decode('utf-8'))
            except Exception as e:
                raise DecryptionError(f"Failed to decrypt custom fields: {e}")

    def decrypt_title_cipher(self, title_cipher: str) -> str:
        """Decrypt only title field to minimize plaintext exposure during search."""
        with self._operation_key() as key:
            try:
                return self._crypto.decrypt(bytes.fromhex(title_cipher), key).decode("utf-8")
            except Exception as e:
                raise DecryptionError(f"Failed to decrypt title field: {e}")
