# -*- coding: utf-8 -*-
"""Safe Python bridge for the Rust-backed BitNet crypto core."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import TypeAlias

try:
    from backend.core import bitnet_crypto_rs as _rust_crypto
except ImportError:  # pragma: no cover - allows direct local development builds
    import bitnet_crypto_rs as _rust_crypto  # type: ignore[no-redef]


LockedBuffer = _rust_crypto.LockedBuffer
MutableBuffer: TypeAlias = bytearray | memoryview
ReadableBuffer: TypeAlias = bytes | bytearray | memoryview | LockedBuffer

TAG_BYTES = 16


def _as_writable_view(value: MutableBuffer, *, field_name: str) -> memoryview:
    if isinstance(value, bytearray):
        return memoryview(value)

    if isinstance(value, memoryview):
        if value.readonly:
            raise TypeError(f"{field_name} must be writable")
        if not value.contiguous:
            raise ValueError(f"{field_name} must be contiguous")
        return value.cast("B")

    raise TypeError(
        f"{field_name} must be a bytearray or writable memoryview, not {type(value).__name__}"
    )


def _as_readable_buffer(value: ReadableBuffer, *, field_name: str) -> ReadableBuffer:
    if isinstance(value, LockedBuffer):
        return value
    if isinstance(value, bytes):
        return memoryview(value)
    if isinstance(value, bytearray):
        return memoryview(value)
    if isinstance(value, memoryview):
        if not value.contiguous:
            raise ValueError(f"{field_name} must be contiguous")
        return value.cast("B")
    raise TypeError(
        f"{field_name} must be bytes-like or LockedBuffer, not {type(value).__name__}"
    )


def zeroize_mutable_buffer(value: MutableBuffer) -> None:
    view = _as_writable_view(value, field_name="value")
    if not view:
        return

    c_buffer = (ctypes.c_ubyte * len(view)).from_buffer(view)
    ctypes.memset(ctypes.addressof(c_buffer), 0, len(view))


@dataclass(frozen=True)
class AesGcmEnvelope:
    ciphertext: bytes
    nonce: bytes
    tag: bytes


class RustCryptoBridge:
    """High-level Python facade over the PyO3 extension module."""

    def lock_bytes(self, data: MutableBuffer, *, wipe_input: bool = True) -> LockedBuffer:
        view = _as_writable_view(data, field_name="data")
        try:
            return _rust_crypto.lock_bytes(view)
        finally:
            if wipe_input:
                zeroize_mutable_buffer(view)

    def generate_random_locked(self, length: int = 32) -> LockedBuffer:
        return _rust_crypto.generate_locked_random(length)

    def argon2_derive_key(
        self,
        master_pwd: MutableBuffer,
        salt: ReadableBuffer,
        *,
        wipe_password: bool = True,
    ) -> LockedBuffer:
        password_view = _as_writable_view(master_pwd, field_name="master_pwd")
        salt_buffer = _as_readable_buffer(salt, field_name="salt")
        try:
            return _rust_crypto.argon2_derive_key(password_view, salt_buffer)
        finally:
            if wipe_password:
                zeroize_mutable_buffer(password_view)

    def aes_gcm_encrypt(
        self,
        key: LockedBuffer,
        plaintext: MutableBuffer | LockedBuffer,
        *,
        wipe_plaintext: bool = True,
    ) -> AesGcmEnvelope:
        if isinstance(plaintext, LockedBuffer):
            ciphertext, nonce, tag = _rust_crypto.aes_gcm_encrypt(key, plaintext)
            return AesGcmEnvelope(ciphertext=bytes(ciphertext), nonce=bytes(nonce), tag=bytes(tag))

        plaintext_view = _as_writable_view(plaintext, field_name="plaintext")
        try:
            ciphertext, nonce, tag = _rust_crypto.aes_gcm_encrypt(key, plaintext_view)
            return AesGcmEnvelope(
                ciphertext=bytes(ciphertext),
                nonce=bytes(nonce),
                tag=bytes(tag),
            )
        finally:
            if wipe_plaintext:
                zeroize_mutable_buffer(plaintext_view)

    def aes_gcm_decrypt(
        self,
        key: LockedBuffer,
        ciphertext: ReadableBuffer,
        nonce: ReadableBuffer,
        tag: ReadableBuffer,
    ) -> LockedBuffer:
        return _rust_crypto.aes_gcm_decrypt(
            key,
            _as_readable_buffer(ciphertext, field_name="ciphertext"),
            _as_readable_buffer(nonce, field_name="nonce"),
            _as_readable_buffer(tag, field_name="tag"),
        )

    def encrypt_for_storage(
        self,
        key: LockedBuffer,
        plaintext: MutableBuffer | LockedBuffer,
        *,
        wipe_plaintext: bool = True,
    ) -> tuple[str, str]:
        envelope = self.aes_gcm_encrypt(
            key,
            plaintext,
            wipe_plaintext=wipe_plaintext,
        )
        cipher_and_tag = envelope.ciphertext + envelope.tag
        return cipher_and_tag.hex(), envelope.nonce.hex()

    def decrypt_from_storage(
        self,
        key: LockedBuffer,
        cipher_hex: str,
        nonce_hex: str,
    ) -> LockedBuffer:
        packed = bytes.fromhex(cipher_hex)
        if len(packed) < TAG_BYTES:
            raise ValueError("cipher_hex does not contain an AES-GCM tag")

        ciphertext = packed[:-TAG_BYTES]
        tag = packed[-TAG_BYTES:]
        nonce = bytes.fromhex(nonce_hex)
        return self.aes_gcm_decrypt(key, ciphertext, nonce, tag)

    def generate_blind_index_hmac(
        self,
        key: LockedBuffer,
        title: MutableBuffer,
        *,
        wipe_title: bool = True,
    ) -> str:
        title_view = _as_writable_view(title, field_name="title")
        try:
            return _rust_crypto.generate_blind_index_hmac(key, title_view)
        finally:
            if wipe_title:
                zeroize_mutable_buffer(title_view)

    @staticmethod
    def locked_buffer_to_bytearray(buffer: LockedBuffer) -> bytearray:
        out = bytearray(len(buffer))
        buffer.copy_into(out)
        return out


bridge = RustCryptoBridge()

