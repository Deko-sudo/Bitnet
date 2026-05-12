# -*- coding: utf-8 -*-
"""
TOTP Authenticator API — Zero-Trust, Rust-backed encryption.

Every TOTP secret is AES-256-GCM encrypted with the user's master key.
Secrets are only decrypted in LockedBuffer memory and zeroized after use.
"""

from __future__ import annotations

import base64
import io
import os
import time
from typing import Optional

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, SecretStr, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.v1.endpoints.auth import CryptoContext, get_current_user
from backend.core.crypto_bridge import LockedBuffer, zeroize_mutable_buffer
from backend.core.encryption_helper import encrypt_entry_data, decrypt_entry_data
from backend.core.security_utils import RateLimiter
from backend.database.models import TotpEntry, PasswordEntry
from backend.database.session import get_db

router = APIRouter()

_totp_rate_limiter = RateLimiter(max_attempts=5, window_seconds=60, block_duration_seconds=300)
_totp_setup_rate_limiter = RateLimiter(max_attempts=10, window_seconds=300, block_duration_seconds=900)


class TotpSetupRequest(BaseModel):
    issuer: Optional[str] = None
    account_name: str = ""
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA256"
    vault_entry_id: Optional[int] = None
    secret: Optional[str] = None

    @field_validator("digits")
    @classmethod
    def validate_digits(cls, v: int) -> int:
        if v < 6 or v > 8:
            raise ValueError("digits must be between 6 and 8")
        return v

    @field_validator("period")
    @classmethod
    def validate_period(cls, v: int) -> int:
        if v < 10 or v > 120:
            raise ValueError("period must be between 10 and 120 seconds")
        return v

    @staticmethod
    def _validate_algorithm(v: str) -> str:
        allowed = {"SHA1", "SHA256", "SHA512"}
        if v.upper() not in allowed:
            raise ValueError(f"Algorithm must be one of {allowed}")
        return v.upper()

    @staticmethod
    def _validate_secret(v: Optional[str]) -> Optional[str]:
        if v is not None and v.strip():
            import re
            clean = re.sub(r'\s', '', v.strip())
            if len(clean) < 16:
                raise ValueError("Secret must be at least 16 base32 characters")
            if not re.match(r'^[A-Z2-7]+=*$', clean, re.IGNORECASE):
                raise ValueError("Secret must be valid base32")
        return v


class TotpVerifyRequest(BaseModel):
    code: str


class TotpEntryResponse(BaseModel):
    id: int
    issuer: Optional[str]
    account_name: str
    digits: int
    period: int
    algorithm: str
    verified: bool
    vault_entry_id: Optional[int]
    created_at: str


class TotpCodeResponse(BaseModel):
    id: int
    issuer: Optional[str]
    account_name: str
    digits: int
    period: int
    current_code: str
    seconds_remaining: int
    vault_entry_id: Optional[int]
    verified: bool


class TotpSetupResponse(BaseModel):
    id: int
    otpauth_uri: str
    qr_code_base64: str


def _secret_to_bytearray(value: SecretStr) -> bytearray:
    return bytearray(value.get_secret_value().encode("utf-8"))


def _locked_to_str(locked: LockedBuffer) -> str:
    buf = bytearray(len(locked))
    locked.copy_into(buf)
    try:
        return buf.decode("utf-8")
    finally:
        zeroize_mutable_buffer(buf)


def _encrypt_secret(key: LockedBuffer, secret: str) -> tuple[bytes, bytes]:
    secret_buf = bytearray(secret.encode("utf-8"))
    try:
        cipher_hex, nonce_hex = encrypt_entry_data(key, secret_buf)
    finally:
        zeroize_mutable_buffer(secret_buf)
    return bytes.fromhex(cipher_hex), bytes.fromhex(nonce_hex)


def _decrypt_secret(key: LockedBuffer, cipher: bytes, nonce: bytes) -> str:
    locked: LockedBuffer | None = None
    try:
        locked = decrypt_entry_data(key, cipher.hex(), nonce.hex())
        return _locked_to_str(locked)
    finally:
        if locked is not None:
            locked.close()


_trust_proxy = os.getenv("BITNET_TRUST_PROXY", "").lower() in ("1", "true", "yes")


def _get_client_ip(request: Request) -> str:
    if _trust_proxy:
        return (
            request.headers.get("X-Real-IP", "").strip()
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )
    return request.client.host if request.client else "unknown"


@router.post("/setup", response_model=TotpSetupResponse, status_code=status.HTTP_201_CREATED)
async def setup_totp(
    request: Request,
    data: TotpSetupRequest,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> TotpSetupResponse:
    client_ip = _get_client_ip(request)
    if not _totp_setup_rate_limiter.can_attempt(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many TOTP setup attempts. Please try again later.",
        )
    if data.algorithm.upper() not in ("SHA1", "SHA256", "SHA512"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Algorithm must be SHA1, SHA256, or SHA512")
    if data.secret is not None and data.secret.strip():
        import re as _re
        clean = _re.sub(r'\s', '', data.secret.strip())
        if len(clean) < 16:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Secret must be at least 16 base32 characters")

    if data.vault_entry_id is not None:
        stmt = select(PasswordEntry).where(
            PasswordEntry.id == data.vault_entry_id,
            PasswordEntry.user_id == ctx.user_id,
            PasswordEntry.is_deleted == False,
        )
        result = await db.execute(stmt)
        entry = result.scalar_one_or_none()
        if entry is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vault entry not found")

    secret = data.secret if data.secret else pyotp.random_base32(length=32)
    if not data.secret and not data.account_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="account_name is required when secret is not provided")
    totp = pyotp.TOTP(
        secret,
        digits=data.digits,
        interval=data.period,
    )

    otpauth_uri = pyotp.TOTP(
        secret,
        digits=data.digits,
        interval=data.period,
        name=data.account_name,
        issuer=data.issuer,
    ).provisioning_uri()

    cipher_bytes, nonce_bytes = _encrypt_secret(ctx.master_key, secret)

    db_entry = TotpEntry(
        user_id=ctx.user_id,
        vault_entry_id=data.vault_entry_id,
        secret_cipher=cipher_bytes,
        secret_nonce=nonce_bytes,
        issuer=data.issuer,
        account_name=data.account_name,
        digits=data.digits,
        period=data.period,
        algorithm=data.algorithm,
        verified=False,
    )
    db.add(db_entry)
    await db.commit()
    await db.refresh(db_entry)

    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(otpauth_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return TotpSetupResponse(
        id=db_entry.id,
        otpauth_uri=otpauth_uri,
        qr_code_base64=qr_base64,
    )


@router.post("/{totp_id}/verify", response_model=TotpEntryResponse)
async def verify_totp(
    totp_id: int,
    data: TotpVerifyRequest,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> TotpEntryResponse:
    rate_key = f"totp:{ctx.user_id}:{totp_id}"
    if not _totp_rate_limiter.can_attempt(rate_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many verification attempts. Please try again later.",
        )

    stmt = select(TotpEntry).where(
        TotpEntry.id == totp_id,
        TotpEntry.user_id == ctx.user_id,
    )
    result = await db.execute(stmt)
    db_entry = result.scalar_one_or_none()
    if db_entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="TOTP entry not found")

    secret = _decrypt_secret(ctx.master_key, db_entry.secret_cipher, db_entry.secret_nonce)
    try:
        totp = pyotp.TOTP(secret, digits=db_entry.digits, interval=db_entry.period)
        if not totp.verify(data.code, valid_window=1):
            _totp_rate_limiter.register_failed(rate_key)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid TOTP code",
            )
    finally:
        del secret

    db_entry.verified = True
    await db.commit()
    await db.refresh(db_entry)

    return TotpEntryResponse(
        id=db_entry.id,
        issuer=db_entry.issuer,
        account_name=db_entry.account_name,
        digits=db_entry.digits,
        period=db_entry.period,
        algorithm=db_entry.algorithm,
        verified=db_entry.verified,
        vault_entry_id=db_entry.vault_entry_id,
        created_at=db_entry.created_at.isoformat(),
    )


@router.get("/", response_model=list[TotpCodeResponse])
async def list_totp(
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> list[TotpCodeResponse]:
    stmt = select(TotpEntry).where(TotpEntry.user_id == ctx.user_id)
    result = await db.execute(stmt)
    entries = list(result.scalars().all())

    results: list[TotpCodeResponse] = []
    for entry in entries:
        secret = _decrypt_secret(ctx.master_key, entry.secret_cipher, entry.secret_nonce)
        try:
            if not entry.verified:
                continue
            totp = pyotp.TOTP(secret, digits=entry.digits, interval=entry.period)
            current_code = totp.now()
            remaining = entry.period - int(time.time() % entry.period)
            results.append(
                TotpCodeResponse(
                    id=entry.id,
                    issuer=entry.issuer,
                    account_name=entry.account_name,
                    digits=entry.digits,
                    period=entry.period,
                    current_code=current_code,
                    seconds_remaining=remaining,
                    vault_entry_id=entry.vault_entry_id,
                    verified=entry.verified,
                )
            )
        finally:
            del secret

    return results


@router.get("/{totp_id}", response_model=TotpCodeResponse)
async def get_totp(
    totp_id: int,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> TotpCodeResponse:
    stmt = select(TotpEntry).where(
        TotpEntry.id == totp_id,
        TotpEntry.user_id == ctx.user_id,
    )
    result = await db.execute(stmt)
    entry = result.scalar_one_or_none()
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="TOTP entry not found")
    if not entry.verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="TOTP entry not verified yet")

    secret = _decrypt_secret(ctx.master_key, entry.secret_cipher, entry.secret_nonce)
    try:
        totp = pyotp.TOTP(secret, digits=entry.digits, interval=entry.period)
        current_code = totp.now()
        remaining = entry.period - int(time.time() % entry.period)

        return TotpCodeResponse(
            id=entry.id,
            issuer=entry.issuer,
            account_name=entry.account_name,
            digits=entry.digits,
            period=entry.period,
            current_code=current_code,
            seconds_remaining=remaining,
            vault_entry_id=entry.vault_entry_id,
            verified=entry.verified,
        )
    finally:
        del secret


@router.delete("/{totp_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_totp(
    totp_id: int,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> None:
    stmt = select(TotpEntry).where(
        TotpEntry.id == totp_id,
        TotpEntry.user_id == ctx.user_id,
    )
    result = await db.execute(stmt)
    entry = result.scalar_one_or_none()
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="TOTP entry not found")
    await db.delete(entry)
    await db.commit()