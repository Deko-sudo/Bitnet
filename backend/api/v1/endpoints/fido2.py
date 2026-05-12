# -*- coding: utf-8 -*-
"""
FIDO2/WebAuthn endpoints — hardware security key authentication (YubiKey, TouchID).

Implements the **double-wrap** strategy for master key protection:

    Layer 1 (device):  master_key  ──AES-GCM(device_protector)──► wrapped_master_key_fido
    Layer 2 (server):  device_protector  ──AES-GCM(server_wrap_key)──► device_protector_blob

During FIDO2 login:
    1. Verify WebAuthn assertion against stored public_key
    2. Decrypt device_protector with server wrap key
    3. Decrypt wrapped_master_key_fido with device_protector → LockedBuffer
    4. Issue session token (identical to password login)

Registration flow (requires existing authentication):
    POST /register/options  → WebAuthn registration options
    POST /register/verify   → Verify attestation + store credential + double-wrapped keys

Login flow (no authentication required):
    POST /login/options     → WebAuthn authentication options
    POST /login/verify      → Verify assertion + unwrap master_key + issue session

Dependencies:
    pip install webauthn>=2.0.0
"""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.crypto_bridge import LockedBuffer, bridge, zeroize_mutable_buffer
from backend.core.security_utils import RateLimiter
from backend.database.models import Fido2Challenge, User, WebAuthnCredential
from backend.database.session import get_db

try:
    from webauthn import (
        generate_authentication_options,
        generate_registration_options,
        verify_authentication_response,
        verify_registration_response,
    )
    from webauthn.helpers import (
        base64url_to_bytes,
        bytes_to_base64url,
    )
    from webauthn.helpers.structs import (
        AuthenticatorAttachment,
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialRequestOptions,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )
except ImportError:  # pragma: no cover — webauthn is optional
    raise RuntimeError(
        "webauthn>=2.0.0 is required for FIDO2 support. "
        "Install with: pip install webauthn>=2.0.0"
    )

# ---------------------------------------------------------------------------
# Import auth helpers (CryptoContext, get_current_user, session issue logic)
# ---------------------------------------------------------------------------
from backend.api.v1.endpoints.auth import (
    CryptoContext,
    LoginResponse,
    _load_server_wrap_key,
    get_current_user,
)

router = APIRouter()

_fido2_register_rate_limiter = RateLimiter(max_attempts=5, window_seconds=300, block_duration_seconds=900)
_fido2_login_rate_limiter = RateLimiter(max_attempts=10, window_seconds=60, block_duration_seconds=300)


# ===========================================================================
# Configuration
# ===========================================================================

_FIDO2_RP_ID = os.getenv("BITNET_FIDO2_RP_ID", "localhost")
_FIDO2_RP_NAME = os.getenv("BITNET_FIDO2_RP_NAME", "BitNet Vault")
_FIDO2_ORIGIN = os.getenv("BITNET_FIDO2_ORIGIN", "http://localhost:3000")
_FIDO2_CHALLENGE_TTL = int(os.getenv("BITNET_FIDO2_CHALLENGE_TTL", "300"))  # 5 min


# ===========================================================================
# Request / response schemas
# ===========================================================================


class RegistrationOptionsRequest(BaseModel):
    """Request to generate FIDO2 registration options.

    The user must already be authenticated (session token in Authorization header).
    """

    label: Optional[str] = None  # Human-readable device name
    authenticator_type: Literal["cross-platform", "platform"] = "cross-platform"


class RegistrationVerifyRequest(BaseModel):
    """Client response after WebAuthn registration ceremony."""

    credential: dict[str, Any]  # PublicKeyCredential serialized by client
    authenticator_type: Literal["cross-platform", "platform"] = "cross-platform"


class LoginOptionsRequest(BaseModel):
    """Request to generate FIDO2 login options (no auth required)."""

    username: str


class LoginVerifyRequest(BaseModel):
    """Client response after WebAuthn authentication ceremony."""

    credential: dict[str, Any]  # PublicKeyCredential serialized by client
    challenge_id: str  # Returned from /login/options


class WebAuthnOptionsResponse(BaseModel):
    """WebAuthn options serialized as a dict for the client."""

    challenge_id: str
    options: dict[str, Any]


# ===========================================================================
# Internal helpers
# ===========================================================================


def _serialize_credential_options(
    options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions,
) -> dict[str, Any]:
    """Convert WebAuthn options to a JSON-serializable dict for the client."""
    result: dict[str, Any] = {}

    # RP
    if hasattr(options, "rp"):
        result["rp"] = {"id": options.rp.id, "name": options.rp.name}

    # User (registration only)
    if hasattr(options, "user"):
        result["user"] = {
            "id": bytes_to_base64url(options.user.id),
            "name": options.user.name,
            "displayName": options.user.display_name,
        }

    # Challenge
    result["challenge"] = bytes_to_base64url(options.challenge)

    # PubKeyCredParams (registration)
    if hasattr(options, "pub_key_cred_params"):
        result["pubKeyCredParams"] = [
            {"alg": p.alg, "type": p.type} for p in options.pub_key_cred_params
        ]

    # Timeout
    if options.timeout:
        result["timeout"] = options.timeout

    # Authenticator selection (registration)
    if hasattr(options, "authenticator_selection") and options.authenticator_selection:
        sel = options.authenticator_selection
        result["authenticatorSelection"] = {}
        if sel.authenticator_attachment:
            result["authenticatorSelection"][
                "authenticatorAttachment"
            ] = sel.authenticator_attachment
        if sel.resident_key:
            result["authenticatorSelection"]["residentKey"] = sel.resident_key
        if sel.user_verification:
            result["authenticatorSelection"]["userVerification"] = sel.user_verification

    # Attestation (registration)
    if hasattr(options, "attestation"):
        result["attestation"] = options.attestation

    # Allow credentials (login)
    if hasattr(options, "allow_credentials") and options.allow_credentials:
        result["allowCredentials"] = [
            {
                "type": c.type,
                "id": bytes_to_base64url(c.id),
            }
            for c in options.allow_credentials
        ]

    # User verification (login)
    if hasattr(options, "user_verification"):
        result["userVerification"] = options.user_verification

    return result


async def _store_device_credential(
    db: AsyncSession,
    user_id: int,
    credential_id: bytes,
    public_key: bytes,
    sign_count: int,
    master_key: LockedBuffer,
    label: Optional[str] = None,
    authenticator_type: str = "cross-platform",
    is_biometric: bool = False,
) -> WebAuthnCredential:
    """Execute the **double-wrap** and persist the credential.

    1. Generate random ``device_protector`` (32 bytes).
    2. Wrap ``master_key`` with ``device_protector`` (AES-GCM).
    3. Wrap ``device_protector`` with server wrap key (AES-GCM).
    4. Store everything in the DB.
    5. Zeroize all intermediate buffers.
    """
    device_protector_buf: bytearray | None = None
    device_protector_locked: LockedBuffer | None = None
    server_key: LockedBuffer | None = None

    try:
        # Step 1: Generate per-device protector and lock it immediately
        device_protector_buf = bytearray(secrets.token_bytes(32))
        device_protector_locked = bridge.lock_bytes(device_protector_buf, wipe_input=True)
        # ↑ device_protector_buf is now ZERO — do NOT use it again

        # Step 2: Wrap master_key with device_protector
        mk_envelope = bridge.aes_gcm_encrypt(
            device_protector_locked,
            master_key,
            wipe_plaintext=False,
        )

        # Step 3: Wrap device_protector with server wrap key
        # Use the LockedBuffer directly — the bridge accepts LockedBuffer as plaintext
        server_key = _load_server_wrap_key()
        protector_envelope = bridge.aes_gcm_encrypt(
            server_key,
            device_protector_locked,
            wipe_plaintext=False,
        )

        # Step 4: Persist
        credential = WebAuthnCredential(
            user_id=user_id,
            credential_id=credential_id,
            public_key=public_key,
            sign_count=sign_count,
            wrapped_master_key_fido_cipher=mk_envelope.ciphertext,
            wrapped_master_key_fido_nonce=mk_envelope.nonce,
            wrapped_master_key_fido_tag=mk_envelope.tag,
            device_protector_cipher=protector_envelope.ciphertext,
            device_protector_nonce=protector_envelope.nonce,
            device_protector_tag=protector_envelope.tag,
            label=label,
            authenticator_type=authenticator_type,
            is_biometric=is_biometric,
        )
        db.add(credential)
        await db.commit()
        await db.refresh(credential)

        return credential

    finally:
        # Step 5: Zeroize everything
        mk_envelope.zeroize()
        protector_envelope.zeroize()
        if device_protector_buf is not None:
            zeroize_mutable_buffer(device_protector_buf)
        if device_protector_locked is not None:
            device_protector_locked.close()
        # NOTE: server_key is the global cached _server_wrap_key — must NOT be closed


def _unwrap_master_key_from_fido_credential(
    credential: WebAuthnCredential,
) -> LockedBuffer:
    """Reverse the double-wrap to recover the user's master key.

    1. Decrypt ``device_protector`` with server wrap key.
    2. Decrypt ``wrapped_master_key_fido`` with ``device_protector``.
    3. Return master key as ``LockedBuffer``.
    4. Zeroize all intermediate buffers.
    """
    device_protector_locked: LockedBuffer | None = None
    server_key: LockedBuffer | None = None

    try:
        # Step 1: Unwrap device_protector
        server_key = _load_server_wrap_key()
        device_protector_locked = bridge.aes_gcm_decrypt(
            server_key,
            credential.device_protector_cipher,
            credential.device_protector_nonce,
            credential.device_protector_tag,
        )

        # Step 2: Unwrap master_key
        master_key = bridge.aes_gcm_decrypt(
            device_protector_locked,
            credential.wrapped_master_key_fido_cipher,
            credential.wrapped_master_key_fido_nonce,
            credential.wrapped_master_key_fido_tag,
        )

        return master_key

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unable to recover master key from FIDO2 credential",
        )
    finally:
        if device_protector_locked is not None:
            device_protector_locked.close()
        # NOTE: server_key is the global cached _server_wrap_key — must NOT be closed


async def _issue_session_token(
    db: AsyncSession,
    user: User,
) -> str:
    """Generate a session token and store its hash on the user record."""
    token = secrets.token_urlsafe(32)
    user.session_token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    user.session_expires_at = datetime.now(timezone.utc) + timedelta(days=30)
    await db.commit()
    return token


async def _delete_expired_challenges(db: AsyncSession) -> None:
    stmt = delete(Fido2Challenge).where(Fido2Challenge.expires_at <= datetime.now(timezone.utc))
    await db.execute(stmt)


async def _persist_challenge(
    db: AsyncSession,
    *,
    challenge_id: str,
    challenge: bytes,
    purpose: str,
    user_id: Optional[int] = None,
) -> None:
    await _delete_expired_challenges(db)

    existing = await db.get(Fido2Challenge, challenge_id)
    if existing is not None:
        await db.delete(existing)
        await db.flush()

    db.add(
        Fido2Challenge(
            id=challenge_id,
            purpose=purpose,
            user_id=user_id,
            challenge=challenge,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=_FIDO2_CHALLENGE_TTL),
        )
    )
    await db.commit()


async def _consume_challenge(
    db: AsyncSession,
    *,
    challenge_id: str,
    purpose: str,
    user_id: Optional[int] = None,
) -> tuple[bytes, Optional[int]]:
    await _delete_expired_challenges(db)

    stmt = select(Fido2Challenge).where(
        Fido2Challenge.id == challenge_id,
        Fido2Challenge.purpose == purpose,
    )
    if user_id is not None:
        stmt = stmt.where(Fido2Challenge.user_id == user_id)

    result = await db.execute(stmt)
    challenge_row = result.scalar_one_or_none()
    if challenge_row is None:
        await db.commit()
        raise KeyError(challenge_id)

    now = datetime.now(timezone.utc)
    expires_at = challenge_row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= now:
        await db.delete(challenge_row)
        await db.commit()
        raise KeyError(challenge_id)

    challenge = bytes(challenge_row.challenge)
    challenge_user_id = challenge_row.user_id
    await db.delete(challenge_row)
    await db.commit()
    return challenge, challenge_user_id


# ===========================================================================
# Registration endpoints (require existing authentication)
# ===========================================================================


_trust_proxy = os.getenv("BITNET_TRUST_PROXY", "").lower() in ("1", "true", "yes")


def _get_client_ip(request: Request) -> str:
    if _trust_proxy:
        return (
            request.headers.get("X-Real-IP", "").strip()
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )
    return request.client.host if request.client else "unknown"


@router.post("/register/options", response_model=WebAuthnOptionsResponse)
async def registration_options(
    request: Request,
    req: RegistrationOptionsRequest,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> WebAuthnOptionsResponse:
    """Generate WebAuthn registration options for an authenticated user.

    The client uses these options to call ``navigator.credentials.create()``.
    """
    client_ip = _get_client_ip(request)
    if not _fido2_register_rate_limiter.can_attempt(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many FIDO2 registration attempts. Please try again later.",
            headers={"Retry-After": str(_fido2_register_rate_limiter.get_delay(client_ip))},
        )

    user_id_bytes = ctx.user_id.to_bytes(8, byteorder="big")

    if req.authenticator_type == "platform":
        auth_selection = AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
    else:
        auth_selection = AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

    options = generate_registration_options(
        rp_id=_FIDO2_RP_ID,
        rp_name=_FIDO2_RP_NAME,
        user_id=user_id_bytes,
        user_name=ctx.username,
        user_display_name=ctx.username,
        authenticator_selection=auth_selection,
    )

    challenge_id = f"reg:{ctx.user_id}"
    await _persist_challenge(
        db,
        challenge_id=challenge_id,
        challenge=options.challenge,
        purpose="registration",
        user_id=ctx.user_id,
    )

    return WebAuthnOptionsResponse(
        challenge_id=challenge_id,
        options=_serialize_credential_options(options),
    )


@router.post("/register/verify", status_code=status.HTTP_201_CREATED)
async def registration_verify(
    request: Request,
    req: RegistrationVerifyRequest,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> dict[str, str]:
    """Verify the WebAuthn registration response and store the credential.

    The user must be authenticated — we use their ``master_key`` from
    ``CryptoContext`` for the double-wrap.

    Returns the credential ID (base64url) for the client to reference.
    """
    client_ip = _get_client_ip(request)
    if not _fido2_register_rate_limiter.can_attempt(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many FIDO2 registration attempts. Please try again later.",
            headers={"Retry-After": str(_fido2_register_rate_limiter.get_delay(client_ip))},
        )

    challenge_id = f"reg:{ctx.user_id}"

    try:
        stored_challenge, _ = await _consume_challenge(
            db,
            challenge_id=challenge_id,
            purpose="registration",
            user_id=ctx.user_id,
        )
    except KeyError:
        _fido2_register_rate_limiter.register_failed(client_ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration challenge expired or not found",
        )

    try:
        verification = verify_registration_response(
            credential=req.credential,
            expected_challenge=stored_challenge,
            expected_rp_id=_FIDO2_RP_ID,
            expected_origin=_FIDO2_ORIGIN,
        )
    except Exception:
        _fido2_register_rate_limiter.register_failed(client_ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="WebAuthn registration verification failed",
        )

    # Check for duplicate credential_id
    stmt = select(WebAuthnCredential).where(
        WebAuthnCredential.credential_id == verification.credential_id
    )
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()
    if existing is not None:
        _fido2_register_rate_limiter.register_failed(client_ip)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This security key is already registered",
        )

    # Double-wrap and persist
    credential = await _store_device_credential(
        db=db,
        user_id=ctx.user_id,
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        master_key=ctx.master_key,
        label=None,
        authenticator_type=req.authenticator_type,
        is_biometric=(req.authenticator_type == "platform"),
    )

    _fido2_register_rate_limiter.register_success(client_ip)

    return {
        "credential_id": bytes_to_base64url(credential.credential_id),
        "message": "FIDO2 credential registered successfully",
    }


# ===========================================================================
# Login endpoints (no authentication required)
# ===========================================================================


@router.post("/login/options", response_model=WebAuthnOptionsResponse)
async def login_options(
    request: Request,
    req: LoginOptionsRequest,
    db: AsyncSession = Depends(get_db),
) -> WebAuthnOptionsResponse:
    """Generate WebAuthn login options for a given username.

    Returns all registered credential IDs for this user so the client
    can present them to the authenticator.
    """
    client_ip = _get_client_ip(request)
    if not _fido2_login_rate_limiter.can_attempt(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many FIDO2 login attempts. Please try again later.",
            headers={"Retry-After": str(_fido2_login_rate_limiter.get_delay(client_ip))},
        )

    stmt_user = select(User).where(User.username == req.username)
    result_user = await db.execute(stmt_user)
    user = result_user.scalar_one_or_none()
    if user is None:
        # Fail silently to avoid user enumeration
        # Return empty options with a persisted, verifiable fake challenge.
        challenge_id = secrets.token_urlsafe(16)
        fake_challenge = secrets.token_bytes(32)
        await _persist_challenge(
            db,
            challenge_id=f"login:{challenge_id}",
            challenge=fake_challenge,
            purpose="login",
        )
        return WebAuthnOptionsResponse(
            challenge_id=challenge_id,
            options={"challenge": bytes_to_base64url(fake_challenge)},
        )

    stmt_creds = select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id)
    result_creds = await db.execute(stmt_creds)
    credentials = list(result_creds.scalars().all())

    allow_credentials = [
        {
            "type": "public-key",
            "id": bytes_to_base64url(c.credential_id),
        }
        for c in credentials
    ]

    options = generate_authentication_options(
        rp_id=_FIDO2_RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    challenge_id = secrets.token_urlsafe(16)
    await _persist_challenge(
        db,
        challenge_id=f"login:{challenge_id}",
        challenge=options.challenge,
        purpose="login",
        user_id=user.id,
    )

    return WebAuthnOptionsResponse(
        challenge_id=challenge_id,
        options=_serialize_credential_options(options),
    )


@router.post("/login/verify", response_model=LoginResponse)
async def login_verify(
    request: Request,
    req: LoginVerifyRequest,
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    """Verify the WebAuthn login response and issue a session token.

    Flow
    ----
    1. Retrieve challenge by ``challenge_id``.
    2. Verify the assertion against stored public_key.
    3. Look up the credential and update sign_count.
    4. **Double-unwrap**: server_key → device_protector → master_key.
    5. Verify master_key decryptability (fail-closed).
    6. Issue session token.
    7. Close master_key.
    """
    client_ip = _get_client_ip(request)
    if not _fido2_login_rate_limiter.can_attempt(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many FIDO2 login attempts. Please try again later.",
            headers={"Retry-After": str(_fido2_login_rate_limiter.get_delay(client_ip))},
        )

    challenge_id = f"login:{req.challenge_id}"

    try:
        stored_challenge, challenge_user_id = await _consume_challenge(
            db,
            challenge_id=challenge_id,
            purpose="login",
        )
    except KeyError:
        _fido2_login_rate_limiter.register_failed(client_ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Login challenge expired or not found",
        )

    # Extract credential_id from the assertion to look up the stored public key
    raw_id = req.credential.get("rawId") or req.credential.get("id")
    if not raw_id:
        _fido2_login_rate_limiter.register_failed(client_ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing credential ID in assertion",
        )

    try:
        credential_id = base64url_to_bytes(raw_id)
    except Exception:
        _fido2_login_rate_limiter.register_failed(client_ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid credential ID format",
        )

    stmt_cred = select(WebAuthnCredential).where(WebAuthnCredential.credential_id == credential_id)
    result_cred = await db.execute(stmt_cred)
    stored_cred = result_cred.scalar_one_or_none()
    if stored_cred is None:
        _fido2_login_rate_limiter.register_failed(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown security key",
        )

    if challenge_user_id != stored_cred.user_id:
        _fido2_login_rate_limiter.register_failed(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown security key",
        )

    # Verify the assertion
    try:
        verification = verify_authentication_response(
            credential=req.credential,
            expected_challenge=stored_challenge,
            expected_rp_id=_FIDO2_RP_ID,
            expected_origin=_FIDO2_ORIGIN,
            credential_public_key=stored_cred.public_key,
            credential_current_sign_count=stored_cred.sign_count,
        )
    except Exception:
        _fido2_login_rate_limiter.register_failed(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="WebAuthn assertion verification failed",
        )

    # Update sign count
    stored_cred.sign_count = verification.new_sign_count
    stored_cred.last_used_at = datetime.now(timezone.utc)
    await db.commit()

    # Load user
    stmt_user = select(User).where(User.id == stored_cred.user_id)
    result_user = await db.execute(stmt_user)
    user = result_user.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    # Double-unwrap: recover master_key (fail-closed if decryption fails)
    master_key = _unwrap_master_key_from_fido_credential(stored_cred)
    try:
        # Issue session token
        token = await _issue_session_token(db, user)
    finally:
        # Always close the master key — even if token issuance fails
        master_key.close()

    _fido2_login_rate_limiter.register_success(client_ip)

    return LoginResponse(
        access_token=token,
        user_id=user.id,
        username=user.username,
    )


# ===========================================================================
# Credential management (authenticated)
# ===========================================================================


@router.get("/credentials")
async def list_credentials(
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """List all registered FIDO2 credentials for the authenticated user."""
    stmt = select(WebAuthnCredential).where(WebAuthnCredential.user_id == ctx.user_id)
    result = await db.execute(stmt)
    credentials = list(result.scalars().all())

    return [
        {
            "id": bytes_to_base64url(c.credential_id),
            "label": c.label,
            "sign_count": c.sign_count,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
        }
        for c in credentials
    ]


@router.delete("/credentials/{credential_id_b64}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_credential(
    credential_id_b64: str,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> None:
    """Remove a FIDO2 credential. Does NOT affect the user's primary master key."""
    credential_id = base64url_to_bytes(credential_id_b64)

    stmt = select(WebAuthnCredential).where(
        WebAuthnCredential.credential_id == credential_id,
        WebAuthnCredential.user_id == ctx.user_id,
    )
    result = await db.execute(stmt)
    credential = result.scalar_one_or_none()
    if credential is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential not found",
        )

    await db.delete(credential)
    await db.commit()


@router.get("/biometric/status")
async def biometric_status(
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
):
    """Check if the user has enrolled platform biometric credentials."""
    stmt = select(WebAuthnCredential).where(
        WebAuthnCredential.user_id == ctx.user_id,
        WebAuthnCredential.is_biometric == True,
    )
    result = await db.execute(stmt)
    credentials = result.scalars().all()
    return {
        "enrolled": len(credentials) > 0,
        "credentials": [
            {
                "id": bytes_to_base64url(c.credential_id),
                "label": c.label,
                "authenticator_type": c.authenticator_type,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in credentials
        ],
    }


@router.delete("/biometric/unregister/{credential_id_b64}", status_code=status.HTTP_204_NO_CONTENT)
async def unregister_biometric(
    credential_id_b64: str,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> None:
    """Unregister a biometric credential. Only removes platform-type credentials."""
    credential_id = base64url_to_bytes(credential_id_b64)

    stmt = select(WebAuthnCredential).where(
        WebAuthnCredential.credential_id == credential_id,
        WebAuthnCredential.user_id == ctx.user_id,
    )
    result = await db.execute(stmt)
    credential = result.scalar_one_or_none()
    if credential is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")
    if not credential.is_biometric:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credential is not a biometric (platform) credential",
        )

    await db.delete(credential)
    await db.commit()
