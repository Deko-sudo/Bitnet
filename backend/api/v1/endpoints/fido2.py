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
import time
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.crypto_bridge import LockedBuffer, bridge, zeroize_mutable_buffer
from backend.database.models import User, WebAuthnCredential
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
except ImportError:
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


# ===========================================================================
# Configuration
# ===========================================================================

_FIDO2_RP_ID = os.getenv("BITNET_FIDO2_RP_ID", "localhost")
_FIDO2_RP_NAME = os.getenv("BITNET_FIDO2_RP_NAME", "BitNet Vault")
_FIDO2_ORIGIN = os.getenv("BITNET_FIDO2_ORIGIN", "http://localhost:3000")
_FIDO2_CHALLENGE_TTL = int(os.getenv("BITNET_FIDO2_CHALLENGE_TTL", "300"))  # 5 min


# ===========================================================================
# In-memory challenge store (production: use Redis / Memcached)
# ===========================================================================


class _ChallengeStore:
    """Thread-safe TTL-bounded challenge cache.

    In production, replace with Redis with automatic expiry.
    """

    def __init__(self, ttl: int = 300):
        self._store: dict[str, tuple[bytes, float]] = {}
        self._ttl = ttl

    def put(self, key: str, challenge: bytes) -> None:
        self._cleanup()
        self._store[key] = (challenge, time.monotonic())

    def get(self, key: str) -> bytes:
        entry = self._store.pop(key, None)
        if entry is None:
            raise KeyError(key)
        challenge, timestamp = entry
        if time.monotonic() - timestamp > self._ttl:
            raise KeyError(f"Challenge expired: {key}")
        return challenge

    def _cleanup(self) -> None:
        now = time.monotonic()
        expired = [k for k, (_, ts) in self._store.items() if now - ts > self._ttl]
        for k in expired:
            del self._store[k]


_challenge_store = _ChallengeStore(ttl=_FIDO2_CHALLENGE_TTL)


# ===========================================================================
# Request / response schemas
# ===========================================================================


class RegistrationOptionsRequest(BaseModel):
    """Request to generate FIDO2 registration options.

    The user must already be authenticated (session token in Authorization header).
    """

    label: Optional[str] = None  # Human-readable device name


class RegistrationVerifyRequest(BaseModel):
    """Client response after WebAuthn registration ceremony."""

    credential: dict[str, Any]  # PublicKeyCredential serialized by client


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
        )
        db.add(credential)
        await db.commit()
        await db.refresh(credential)

        return credential

    finally:
        # Step 5: Zeroize everything
        if device_protector_buf is not None:
            zeroize_mutable_buffer(device_protector_buf)
        if device_protector_locked is not None:
            device_protector_locked.close()
        if server_key is not None:
            server_key.close()


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
        if server_key is not None:
            server_key.close()


async def _issue_session_token(
    db: AsyncSession,
    user: User,
) -> str:
    """Generate a session token and store its hash on the user record."""
    token = secrets.token_urlsafe(32)
    user.session_token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    await db.commit()
    return token


# ===========================================================================
# Registration endpoints (require existing authentication)
# ===========================================================================


@router.post("/register/options", response_model=WebAuthnOptionsResponse)
def registration_options(
    req: RegistrationOptionsRequest,
    ctx: CryptoContext = Depends(get_current_user),
) -> WebAuthnOptionsResponse:
    """Generate WebAuthn registration options for an authenticated user.

    The client uses these options to call ``navigator.credentials.create()``.
    """
    user_id_bytes = ctx.user_id.to_bytes(8, byteorder="big")

    options = generate_registration_options(
        rp_id=_FIDO2_RP_ID,
        rp_name=_FIDO2_RP_NAME,
        user_id=user_id_bytes,
        user_name=ctx.username,
        user_display_name=ctx.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

    # Store challenge for later verification
    challenge_id = f"reg:{ctx.user_id}"
    _challenge_store.put(challenge_id, options.challenge)

    return WebAuthnOptionsResponse(
        challenge_id=challenge_id,
        options=_serialize_credential_options(options),
    )


@router.post("/register/verify", status_code=status.HTTP_201_CREATED)
async def registration_verify(
    req: RegistrationVerifyRequest,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> dict[str, str]:
    """Verify the WebAuthn registration response and store the credential.

    The user must be authenticated — we use their ``master_key`` from
    ``CryptoContext`` for the double-wrap.

    Returns the credential ID (base64url) for the client to reference.
    """
    challenge_id = f"reg:{ctx.user_id}"

    try:
        stored_challenge = _challenge_store.get(challenge_id)
    except KeyError:
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
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"WebAuthn registration verification failed: {exc}",
        )

    # Check for duplicate credential_id
    stmt = select(WebAuthnCredential).where(
        WebAuthnCredential.credential_id == verification.credential_id
    )
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()
    if existing is not None:
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
    )

    return {
        "credential_id": bytes_to_base64url(credential.credential_id),
        "message": "FIDO2 credential registered successfully",
    }


# ===========================================================================
# Login endpoints (no authentication required)
# ===========================================================================


@router.post("/login/options", response_model=WebAuthnOptionsResponse)
async def login_options(
    req: LoginOptionsRequest,
    db: AsyncSession = Depends(get_db),
) -> WebAuthnOptionsResponse:
    """Generate WebAuthn login options for a given username.

    Returns all registered credential IDs for this user so the client
    can present them to the authenticator.
    """
    stmt_user = select(User).where(User.username == req.username)
    result_user = await db.execute(stmt_user)
    user = result_user.scalar_one_or_none()
    if user is None:
        # Fail silently to avoid user enumeration
        # Return empty options
        challenge_id = secrets.token_urlsafe(16)
        _challenge_store.put(f"login:{challenge_id}", secrets.token_bytes(32))
        return WebAuthnOptionsResponse(
            challenge_id=challenge_id,
            options={"challenge": bytes_to_base64url(secrets.token_bytes(32))},
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
    _challenge_store.put(f"login:{challenge_id}", options.challenge)

    return WebAuthnOptionsResponse(
        challenge_id=challenge_id,
        options=_serialize_credential_options(options),
    )


@router.post("/login/verify", response_model=LoginResponse)
async def login_verify(
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
    challenge_id = f"login:{req.challenge_id}"

    try:
        stored_challenge = _challenge_store.get(challenge_id)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Login challenge expired or not found",
        )

    # Extract credential_id from the assertion to look up the stored public key
    raw_id = req.credential.get("rawId") or req.credential.get("id")
    if not raw_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing credential ID in assertion",
        )

    credential_id = base64url_to_bytes(raw_id)

    stmt_cred = select(WebAuthnCredential).where(WebAuthnCredential.credential_id == credential_id)
    result_cred = await db.execute(stmt_cred)
    stored_cred = result_cred.scalar_one_or_none()
    if stored_cred is None:
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
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"WebAuthn assertion verification failed: {exc}",
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
