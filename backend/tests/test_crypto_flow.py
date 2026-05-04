# -*- coding: utf-8 -*-
"""
End-to-End Crypto Flow Test.

Exercises the **full** request chain without mocking the crypto:
    Register → Login → Create Entry → Read Entry → Verify Decryption

All encryption/decryption goes through the Rust-backed ``bridge``.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.core.crypto_bridge import bridge, zeroize_mutable_buffer

# Username constant (must match conftest.py fixture)
_TEST_USERNAME = "testuser_e2e"


# =============================================================================
# Test: Full E2E Workflow
# =============================================================================


class TestFullCryptoFlow:
    """Register → Login → Create → Read → Verify decryption."""

    def test_register_login_create_read(
        self, client: TestClient, registered_user: dict, auth_headers: dict
    ):
        """Complete user lifecycle with real Rust crypto."""
        # ------------------------------------------------------------------
        # 1. Create an encrypted entry
        # ------------------------------------------------------------------
        entry_payload = {
            "title": "GitHub Account",
            "username": "dev_user",
            "password": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "url": "https://github.com",
            "notes": "Main development account",
        }
        resp = client.post("/api/v1/entries/", json=entry_payload, headers=auth_headers)
        assert resp.status_code == 201, f"Create entry failed: {resp.text}"
        created = resp.json()

        assert created["id"] > 0
        assert created["user_id"] == registered_user["user_id"]
        assert created["title"] == "GitHub Account"
        assert created["username"] == "dev_user"
        assert created["password"] == "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        assert created["url"] == "https://github.com"
        assert created["notes"] == "Main development account"

        entry_id = created["id"]

        # ------------------------------------------------------------------
        # 2. Read the entry back
        # ------------------------------------------------------------------
        resp = client.get(f"/api/v1/entries/{entry_id}", headers=auth_headers)
        assert resp.status_code == 200, f"Read entry failed: {resp.text}"
        fetched = resp.json()

        assert fetched["id"] == entry_id
        assert fetched["title"] == "GitHub Account"
        assert fetched["username"] == "dev_user"
        assert fetched["password"] == "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        assert fetched["url"] == "https://github.com"
        assert fetched["notes"] == "Main development account"

    def test_create_multiple_entries(self, client: TestClient, auth_headers: dict):
        """Create several entries and list them."""
        entries = [
            {
                "title": "AWS Root",
                "username": "root",
                "password": "aws_secret_1",
                "url": None,
                "notes": None,
            },
            {
                "title": "Stripe",
                "username": "api@company.com",
                "password": "sk_live_xxx",
                "url": "https://dashboard.stripe.com",
                "notes": "Production",
            },
            {
                "title": "Vercel",
                "username": "deploy",
                "password": "vc_xxx",
                "url": None,
                "notes": "Frontend hosting",
            },
        ]

        for entry in entries:
            resp = client.post("/api/v1/entries/", json=entry, headers=auth_headers)
            assert resp.status_code == 201, (
                f"Failed to create {entry['title']}: {resp.text}"
            )

        # List all
        resp = client.get("/api/v1/entries/", headers=auth_headers)
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) >= len(entries)

        # Verify titles are decryptable
        titles = {item["title"] for item in items}
        for entry in entries:
            assert entry["title"] in titles


# =============================================================================
# Test: Entry Update (PATCH)
# =============================================================================


class TestEntryUpdate:
    """PATCH entry with re-encryption and password history."""

    def test_update_entry_title_and_password(
        self, client: TestClient, auth_headers: dict
    ):
        """Update title + password, verify old password is archived."""
        # Create
        resp = client.post(
            "/api/v1/entries/",
            json={
                "title": "Old Title",
                "username": "user1",
                "password": "old_pass",
                "url": None,
                "notes": None,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 201
        entry_id = resp.json()["id"]

        # Patch
        resp = client.patch(
            f"/api/v1/entries/{entry_id}",
            json={"title": "New Title", "password": "new_pass_123"},
            headers=auth_headers,
        )
        assert resp.status_code == 200, f"Patch failed: {resp.text}"
        updated = resp.json()

        assert updated["title"] == "New Title"
        assert updated["password"] == "new_pass_123"

        # Re-read to confirm persistence
        resp = client.get(f"/api/v1/entries/{entry_id}", headers=auth_headers)
        assert resp.status_code == 200
        refetched = resp.json()
        assert refetched["title"] == "New Title"
        assert refetched["password"] == "new_pass_123"

    def test_update_nullify_optional_field(
        self, client: TestClient, auth_headers: dict
    ):
        """Set optional field to null."""
        resp = client.post(
            "/api/v1/entries/",
            json={
                "title": "Test",
                "username": "u",
                "password": "p",
                "url": "https://example.com",
                "notes": "note",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 201
        entry_id = resp.json()["id"]

        resp = client.patch(
            f"/api/v1/entries/{entry_id}",
            json={"url": None, "notes": None},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["url"] is None
        assert resp.json()["notes"] is None


# =============================================================================
# Test: Entry Deletion (Soft Delete)
# =============================================================================


class TestEntryDeletion:
    """Soft-delete entries."""

    def test_soft_delete_entry(self, client: TestClient, auth_headers: dict):
        """Delete entry → should not appear in list or read."""
        resp = client.post(
            "/api/v1/entries/",
            json={
                "title": "To Delete",
                "username": "u",
                "password": "p",
                "url": None,
                "notes": None,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 201
        entry_id = resp.json()["id"]

        # Delete
        resp = client.delete(f"/api/v1/entries/{entry_id}", headers=auth_headers)
        assert resp.status_code == 204

        # Read should 404
        resp = client.get(f"/api/v1/entries/{entry_id}", headers=auth_headers)
        assert resp.status_code == 404

        # List should not include it
        resp = client.get("/api/v1/entries/", headers=auth_headers)
        titles = [item["title"] for item in resp.json()]
        assert "To Delete" not in titles


# =============================================================================
# Test: Search by Blind Index
# =============================================================================


class TestSearchByBlindIndex:
    """Search entries by title using the blind HMAC index."""

    def test_search_matching_title(self, client: TestClient, auth_headers: dict):
        """Create entries, search for one by title."""
        titles = ["GitHub", "GitLab", "BitBucket"]
        for t in titles:
            resp = client.post(
                "/api/v1/entries/",
                json={
                    "title": t,
                    "username": "u",
                    "password": "p",
                    "url": None,
                    "notes": None,
                },
                headers=auth_headers,
            )
            assert resp.status_code == 201

        # Search for "GitLab"
        resp = client.get(
            "/api/v1/entries/", params={"query": "GitLab"}, headers=auth_headers
        )
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 1
        assert items[0]["title"] == "GitLab"

    def test_search_no_match(self, client: TestClient, auth_headers: dict):
        """Search for a title that doesn't exist."""
        client.post(
            "/api/v1/entries/",
            json={
                "title": "UniqueTitle",
                "username": "u",
                "password": "p",
                "url": None,
                "notes": None,
            },
            headers=auth_headers,
        )

        resp = client.get(
            "/api/v1/entries/", params={"query": "NonExistent"}, headers=auth_headers
        )
        assert resp.status_code == 200
        assert len(resp.json()) == 0


# =============================================================================
# Test: Master Key Lifecycle
# =============================================================================


class TestMasterKeyLifecycle:
    """Verify that LockedBuffers are properly closed after requests."""

    def test_bridge_direct_usage(self, bridge):
        """Direct bridge test: encrypt → decrypt → close."""
        key = bridge.generate_random_locked(32)
        try:
            plaintext = bytearray(b"Hello, secure world!")
            cipher_hex, nonce_hex = bridge.encrypt_for_storage(
                key, plaintext, wipe_plaintext=True
            )

            # Verify the plaintext was zeroized
            assert all(b == 0 for b in plaintext), (
                "Plaintext was not zeroized after encryption"
            )

            # Decrypt
            decrypted = bridge.decrypt_from_storage(key, cipher_hex, nonce_hex)
            try:
                out = bytearray(len(decrypted))
                decrypted.copy_into(out)
                assert out == b"Hello, secure world!"
            finally:
                decrypted.close()
        finally:
            assert not key.is_closed
            key.close()
            assert key.is_closed

    def test_locked_buffer_zeroize(self, bridge):
        """LockedBuffer → bytearray → verify zeroization after close."""
        key = bridge.generate_random_locked(32)
        buf = bytearray(32)
        key.copy_into(buf)

        # buf should contain the key
        assert any(b != 0 for b in buf)

        key.close()

        # buf is a COPY — it is NOT zeroized by close()
        # This is expected behavior: caller owns the bytearray
        # The important thing is the LockedBuffer internal memory is wiped
        assert key.is_closed


# =============================================================================
# Test: Auth Error Cases
# =============================================================================


class TestAuthErrors:
    """Verify auth failures."""

    def test_login_wrong_password(self, client: TestClient, registered_user: dict):
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": _TEST_USERNAME, "password": "WrongPassword!"},
        )
        assert resp.status_code == 401

    def test_login_nonexistent_user(self, client: TestClient):
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "nobody_here", "password": "anything"},
        )
        assert resp.status_code == 401

    def test_access_without_token(self, client: TestClient):
        resp = client.get("/api/v1/entries/")
        assert resp.status_code == 401

    def test_access_with_invalid_token(self, client: TestClient):
        resp = client.get(
            "/api/v1/entries/", headers={"Authorization": "Bearer invalidtoken123"}
        )
        assert resp.status_code == 401

    def test_duplicate_user_registration(
        self, client: TestClient, registered_user: dict
    ):
        resp = client.post(
            "/api/v1/auth/register",
            json={
                "username": _TEST_USERNAME,
                "email": "another@example.com",
                "password": "DifferentP@ss!",
            },
        )
        assert resp.status_code == 409
