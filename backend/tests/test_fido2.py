# -*- coding: utf-8 -*-
"""
FIDO2 / WebAuthn Double-Wrap Tests.

Verifies that the **double-wrap** strategy works correctly:
    master_key ──AES-GCM(device_protector)──► wrapped_master_key_fido
    device_protector ──AES-GCM(server_wrap_key)──► device_protector_blob

and that the reverse unwrap recovers the **exact** original master key.

**The Rust crypto bridge is NEVER mocked.**  Only the external
``webauthn`` library's signature-verification functions are replaced
with deterministic fakes.
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from backend.api.v1.endpoints.fido2 import (
    _challenge_store,
    _store_device_credential,
    _unwrap_master_key_from_fido_credential,
)
from backend.core.crypto_bridge import bridge, zeroize_mutable_buffer
from backend.database.models import User, WebAuthnCredential

# =============================================================================
# Mock WebAuthn verification objects
# =============================================================================


@dataclass
class FakeRegistration:
    """Mimics ``webauthn.helpers.structs.RegistrationVerification``."""

    credential_id: bytes
    credential_public_key: bytes
    sign_count: int


@dataclass
class FakeAuthentication:
    """Mimics ``webauthn.helpers.structs.AuthenticationVerification``."""

    credential_id: bytes
    new_sign_count: int


def _make_fake_credential() -> tuple[bytes, bytes]:
    """Return a (credential_id, fake_cose_public_key) pair."""
    credential_id = secrets.token_bytes(32)
    # Minimal COSE key (EC P-256) structure
    fake_cose = (
        b"\xa5"  # map(5)
        + b"\x01\x02"  # kty: 2 (EC2)
        + b"\x03\x26"  # alg: -7 (ES256)
        + b"\x20\x01"  # crv: 1 (P-256)
        + b"\x21\x58\x20"
        + b"\x11" * 32  # x: 32 bytes
        + b"\x22\x58\x20"
        + b"\x22" * 32  # y: 32 bytes
    )
    return credential_id, fake_cose


# =============================================================================
# Test: Double-Wrap → Unwrap Round-Trip (Direct Crypto)
# =============================================================================


class TestDoubleWrapUnwrap:
    """Test the core double-wrap / double-unwrap logic with real Rust bridge."""

    def _create_test_user(self, db_session: Session, user_id: int) -> User:
        """Helper to create a minimal User for FK satisfaction."""
        import hashlib
        import secrets as _secrets

        salt = _secrets.token_bytes(16)
        user = User(
            username=f"fido_user_{user_id}",
            email=f"fido_{user_id}@example.com",
            password_hash=hashlib.sha256(b"dummy").hexdigest(),
            salt=salt,
            wrapped_master_key_cipher=b"\x00" * 32,
            wrapped_master_key_nonce=b"\x00" * 12,
            wrapped_master_key_tag=b"\x00" * 16,
        )
        db_session.add(user)
        db_session.flush()
        return user

    def test_wrap_unwrap_roundtrip(self, db_session: Session):
        """Encrypt master_key with device_protector, then unwrap — must match."""
        user = self._create_test_user(db_session, user_id=42)
        master_key = bridge.generate_random_locked(32)
        credential_id, cose_key = _make_fake_credential()

        try:
            # Store (double-wrap)
            cred = _store_device_credential(
                db=db_session,
                user_id=user.id,
                credential_id=credential_id,
                public_key=cose_key,
                sign_count=0,
                master_key=master_key,
                label="Test YubiKey",
            )

            # Verify DB persistence
            assert cred.credential_id == credential_id
            assert cred.public_key == cose_key
            assert cred.label == "Test YubiKey"
            assert len(cred.wrapped_master_key_fido_cipher) > 0
            assert len(cred.device_protector_cipher) > 0

            # Unwrap (double-unwrap)
            recovered_key = _unwrap_master_key_from_fido_credential(cred)
            try:
                # Compare contents
                original_bytes = bytearray(len(master_key))
                recovered_bytes = bytearray(len(recovered_key))
                master_key.copy_into(original_bytes)
                recovered_key.copy_into(recovered_bytes)

                assert original_bytes == recovered_bytes, (
                    "Recovered master key does not match original — double-wrap is broken!"
                )
            finally:
                recovered_key.close()
        finally:
            master_key.close()

    def test_different_devices_different_wraps(self, db_session: Session):
        """Two devices wrapping the same master key must produce different blobs."""
        user = self._create_test_user(db_session, user_id=1)
        master_key = bridge.generate_random_locked(32)
        cred_id_1, cose_1 = _make_fake_credential()
        cred_id_2, cose_2 = _make_fake_credential()

        try:
            cred1 = _store_device_credential(
                db_session, user.id, cred_id_1, cose_1, 0, master_key
            )
            cred2 = _store_device_credential(
                db_session, user.id, cred_id_2, cose_2, 0, master_key
            )

            # Both device_protector_blobs must differ (different random protectors)
            assert cred1.device_protector_cipher != cred2.device_protector_cipher
            assert (
                cred1.wrapped_master_key_fido_cipher
                != cred2.wrapped_master_key_fido_cipher
            )

            # But both must unwrap to the same master key
            rk1 = _unwrap_master_key_from_fido_credential(cred1)
            rk2 = _unwrap_master_key_from_fido_credential(cred2)
            try:
                b1 = bytearray(len(rk1))
                b2 = bytearray(len(rk2))
                rk1.copy_into(b1)
                rk2.copy_into(b2)
                assert b1 == b2
            finally:
                rk1.close()
                rk2.close()
        finally:
            master_key.close()

    def test_unwrap_fail_closed_on_corrupt_data(self, db_session: Session):
        """Tampered credential must raise HTTPException(401), not crash."""
        from fastapi import HTTPException

        user = self._create_test_user(db_session, user_id=2)
        master_key = bridge.generate_random_locked(32)
        cred_id, cose_key = _make_fake_credential()

        try:
            cred = _store_device_credential(
                db_session, user.id, cred_id, cose_key, 0, master_key
            )
        finally:
            master_key.close()

        # Corrupt the device_protector_cipher
        cred.device_protector_cipher = b"\xff" * len(cred.device_protector_cipher)

        with pytest.raises(HTTPException) as exc_info:
            _unwrap_master_key_from_fido_credential(cred)

        assert exc_info.value.status_code == 401
        assert "Unable to recover" in exc_info.value.detail


# =============================================================================
# Test: FIDO2 Registration via API (Mocked WebAuthn, Real Crypto)
# =============================================================================


class TestFido2Registration:
    """Test FIDO2 registration endpoint with mocked webauthn verification."""

    def test_register_verify_stores_credential(
        self, client, registered_user: dict, auth_headers: dict, db_session: Session
    ):
        """Full FIDO2 registration: options → verify → credential stored."""
        credential_id, cose_key = _make_fake_credential()
        challenge = secrets.token_bytes(32)

        # Inject challenge
        challenge_id = f"reg:{registered_user['user_id']}"
        _challenge_store.put(challenge_id, challenge)

        # Build mock credential dict (what the browser would send)
        mock_credential = {
            "id": base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode(),
            "rawId": base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode(),
            "type": "public-key",
            "response": {
                "attestationObject": base64.urlsafe_b64encode(
                    b"fake_attestation"
                ).decode(),
                "clientDataJSON": base64.urlsafe_b64encode(
                    b'{"type":"webauthn.create","challenge":"","origin":"http://localhost:3000"}'
                ).decode(),
            },
        }

        # Mock the webauthn verification — crypto bridge is NOT mocked
        with patch(
            "backend.api.v1.endpoints.fido2.verify_registration_response",
            return_value=FakeRegistration(
                credential_id=credential_id,
                credential_public_key=cose_key,
                sign_count=0,
            ),
        ):
            resp = client.post(
                "/api/v1/fido2/register/verify",
                json={"credential": mock_credential},
                headers=auth_headers,
            )

        assert resp.status_code == 201, f"FIDO2 registration failed: {resp.text}"
        data = resp.json()
        assert "credential_id" in data
        assert (
            data["credential_id"]
            == base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode()
        )

        # Verify credential is in DB
        stored_cred = (
            db_session.query(WebAuthnCredential)
            .filter(WebAuthnCredential.credential_id == credential_id)
            .first()
        )
        assert stored_cred is not None
        assert stored_cred.user_id == registered_user["user_id"]
        assert stored_cred.sign_count == 0

        # Verify double-wrap can be unwrapped
        recovered = _unwrap_master_key_from_fido_credential(stored_cred)
        try:
            assert len(recovered) == 32
            assert not recovered.is_closed
        finally:
            recovered.close()


# =============================================================================
# Test: FIDO2 Login via API (Mocked WebAuthn, Real Crypto)
# =============================================================================


class TestFido2Login:
    """Test FIDO2 login endpoint with mocked webauthn verification."""

    def test_fido2_login_recovers_master_key(
        self, client, registered_user: dict, auth_headers: dict, db_session: Session
    ):
        """Register a FIDO2 credential, then login with it."""
        credential_id, cose_key = _make_fake_credential()
        challenge = secrets.token_bytes(32)

        # --- Step 1: Register the credential ---
        reg_challenge_id = f"reg:{registered_user['user_id']}"
        _challenge_store.put(reg_challenge_id, challenge)

        mock_credential = {
            "id": base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode(),
            "rawId": base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode(),
            "type": "public-key",
            "response": {
                "attestationObject": base64.urlsafe_b64encode(
                    b"fake_attestation"
                ).decode(),
                "clientDataJSON": base64.urlsafe_b64encode(
                    b'{"type":"webauthn.create","challenge":"","origin":"http://localhost:3000"}'
                ).decode(),
            },
        }

        with patch(
            "backend.api.v1.endpoints.fido2.verify_registration_response",
            return_value=FakeRegistration(
                credential_id=credential_id,
                credential_public_key=cose_key,
                sign_count=0,
            ),
        ):
            resp = client.post(
                "/api/v1/fido2/register/verify",
                json={"credential": mock_credential},
                headers=auth_headers,
            )
        assert resp.status_code == 201

        # --- Step 2: FIDO2 Login ---
        login_challenge = secrets.token_bytes(32)
        login_challenge_id = secrets.token_urlsafe(16)
        _challenge_store.put(f"login:{login_challenge_id}", login_challenge)

        login_credential = {
            "id": base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode(),
            "rawId": base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode(),
            "type": "public-key",
            "response": {
                "authenticatorData": base64.urlsafe_b64encode(
                    b"\x00" * 37  # fake authenticator data
                ).decode(),
                "clientDataJSON": base64.urlsafe_b64encode(
                    b'{"type":"webauthn.get","challenge":"","origin":"http://localhost:3000"}'
                ).decode(),
                "signature": base64.urlsafe_b64encode(b"fake_signature").decode(),
            },
        }

        with patch(
            "backend.api.v1.endpoints.fido2.verify_authentication_response",
            return_value=FakeAuthentication(
                credential_id=credential_id,
                new_sign_count=1,
            ),
        ):
            resp = client.post(
                "/api/v1/fido2/login/verify",
                json={
                    "credential": login_credential,
                    "challenge_id": login_challenge_id,
                },
            )

        assert resp.status_code == 200, f"FIDO2 login failed: {resp.text}"
        login_data = resp.json()

        assert "access_token" in login_data
        assert login_data["user_id"] == registered_user["user_id"]
        assert login_data["username"] == registered_user["username"]
        assert login_data["token_type"] == "bearer"

        # --- Step 3: Verify the token works for encrypted operations ---
        fido_headers = {"Authorization": f"Bearer {login_data['access_token']}"}

        # Create an encrypted entry with the FIDO2-issued token
        resp = client.post(
            "/api/v1/entries/",
            json={
                "title": "FIDO2 Secured Entry",
                "username": "fido_user",
                "password": "fido_secret_pass",
                "url": None,
                "notes": None,
            },
            headers=fido_headers,
        )
        assert resp.status_code == 201, (
            f"Create entry with FIDO2 token failed: {resp.text}"
        )
        created = resp.json()
        assert created["title"] == "FIDO2 Secured Entry"
        assert created["password"] == "fido_secret_pass"

        # Read it back
        entry_id = created["id"]
        resp = client.get(f"/api/v1/entries/{entry_id}", headers=fido_headers)
        assert resp.status_code == 200
        fetched = resp.json()
        assert fetched["title"] == "FIDO2 Secured Entry"
        assert fetched["password"] == "fido_secret_pass"


# =============================================================================
# Test: Credential Management
# =============================================================================


class TestCredentialManagement:
    """List and delete FIDO2 credentials."""

    def test_list_credentials(self, client, registered_user: dict, auth_headers: dict):
        """List returns credentials for the authenticated user."""
        # Register a credential first
        credential_id, cose_key = _make_fake_credential()
        challenge = secrets.token_bytes(32)
        challenge_id = f"reg:{registered_user['user_id']}"
        _challenge_store.put(challenge_id, challenge)

        mock_credential = {
            "id": base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode(),
            "rawId": base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode(),
            "type": "public-key",
            "response": {
                "attestationObject": base64.urlsafe_b64encode(b"x").decode(),
                "clientDataJSON": base64.urlsafe_b64encode(b"{}").decode(),
            },
        }

        with patch(
            "backend.api.v1.endpoints.fido2.verify_registration_response",
            return_value=FakeRegistration(credential_id, cose_key, 0),
        ):
            resp = client.post(
                "/api/v1/fido2/register/verify",
                json={"credential": mock_credential},
                headers=auth_headers,
            )
        assert resp.status_code == 201

        # List
        resp = client.get("/api/v1/fido2/credentials", headers=auth_headers)
        assert resp.status_code == 200
        creds = resp.json()
        assert len(creds) >= 1
        assert (
            creds[0]["id"]
            == base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode()
        )

    def test_delete_credential(self, client, registered_user: dict, auth_headers: dict):
        """Delete a credential and verify it's gone."""
        credential_id, cose_key = _make_fake_credential()
        challenge = secrets.token_bytes(32)
        challenge_id = f"reg:{registered_user['user_id']}"
        _challenge_store.put(challenge_id, challenge)

        mock_credential = {
            "id": base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode(),
            "rawId": base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode(),
            "type": "public-key",
            "response": {
                "attestationObject": base64.urlsafe_b64encode(b"x").decode(),
                "clientDataJSON": base64.urlsafe_b64encode(b"{}").decode(),
            },
        }

        with patch(
            "backend.api.v1.endpoints.fido2.verify_registration_response",
            return_value=FakeRegistration(credential_id, cose_key, 0),
        ):
            resp = client.post(
                "/api/v1/fido2/register/verify",
                json={"credential": mock_credential},
                headers=auth_headers,
            )
        assert resp.status_code == 201

        # Delete
        cred_b64 = base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode()
        resp = client.delete(
            f"/api/v1/fido2/credentials/{cred_b64}",
            headers=auth_headers,
        )
        assert resp.status_code == 204

        # Verify gone
        resp = client.get("/api/v1/fido2/credentials", headers=auth_headers)
        assert resp.status_code == 200
        assert len(resp.json()) == 0
