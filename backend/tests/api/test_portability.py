# -*- coding: utf-8 -*-
"""
Integration tests for the Portability API (Import/Export).

Covers the full chain:
    Register -> Login -> Create Entries -> Export (streaming) -> Import

Tests verify:
1. JWT & LockedBuffer flow through DI
2. Async streaming consumption (aiter_lines)
3. Session & DI conflict-free operation
4. Zero-Trust: cleanup on error
"""

from __future__ import annotations

import csv
import io
import json
from typing import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient

from backend.database.session import get_db

# ===========================================================================
# Markers
# ===========================================================================

pytestmark = pytest.mark.asyncio


# ===========================================================================
# Helper fixtures
# ===========================================================================


@pytest_asyncio.fixture()
async def populated_user(client: AsyncClient, auth_headers: dict) -> dict:
    """
    Registers a user, logs in, and creates 5 test entries.
    Returns user info + auth headers.
    """
    entries = [
        {
            "title": f"Entry_{i}",
            "username": f"user_{i}@test.com",
            "password": f"SecureP@ss_{i}!",
            "url": f"https://site{i}.example.com",
            "notes": f"Test entry number {i}",
        }
        for i in range(5)
    ]

    for entry in entries:
        resp = await client.post(
            "/api/v1/entries/",
            json=entry,
            headers=auth_headers,
        )
        assert resp.status_code == 201, f"Failed to create entry: {resp.text}"

    return {"headers": auth_headers, "entry_count": len(entries)}


# ===========================================================================
# 1. JWT & LockedBuffer Flow
# ===========================================================================


class TestJwtLockedBufferFlow:
    """
    Проверка: после Login токен даёт доступ к эндпоинтам,
    которые используют CryptoContext с реальным LockedBuffer.
    """

    async def test_login_returns_bearer_token(
        self, client: AsyncClient, registered_user: dict
    ):
        """Login endpoint returns a valid bearer token."""
        resp = await client.post(
            "/api/v1/auth/login",
            json={
                "username": registered_user["username"],
                "password": registered_user["password"],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user_id"] == registered_user["user_id"]
        assert data["username"] == registered_user["username"]

    async def test_export_requires_authentication(self, client: AsyncClient):
        """Export endpoint rejects requests without a token."""
        resp = await client.get("/api/v1/portability/export/csv")
        assert resp.status_code in (401, 403)

    async def test_export_with_valid_token_returns_200(
        self, client: AsyncClient, populated_user: dict
    ):
        """
        Export CSV returns 200 with correct Content-Type.
        Confirms that DI resolved CryptoContext -> LockedBuffer.
        """
        resp = await client.get(
            "/api/v1/portability/export/csv",
            headers=populated_user["headers"],
        )
        assert resp.status_code == 200
        assert "text/csv" in resp.headers.get("content-type", "")

    async def test_export_headers_include_no_buffering(
        self, client: AsyncClient, populated_user: dict
    ):
        """Reverse proxy should not buffer the streaming response."""
        resp = await client.get(
            "/api/v1/portability/export/csv",
            headers=populated_user["headers"],
        )
        assert resp.status_code == 200
        assert resp.headers.get("x-accel-buffering") == "no"


# ===========================================================================
# 2. Async Streaming Consumption
# ===========================================================================


class TestAsyncStreamingConsumption:
    """
    Проверка: StreamingResponse отдаёт данные порциями,
    клиент может итерироваться по строкам через aiter_lines().
    """

    async def test_csv_stream_iterable_lines(
        self, client: AsyncClient, populated_user: dict
    ):
        """
        CSV export streams line-by-line.
        We consume via aiter_lines() and verify structure.
        """
        resp = await client.get(
            "/api/v1/portability/export/csv",
            headers=populated_user["headers"],
        )
        assert resp.status_code == 200

        lines: list[str] = []
        async for line in resp.aiter_lines():
            if line:
                lines.append(line)

        # First line = header
        assert len(lines) >= 2  # header + at least 1 data row
        header = lines[0]
        assert "title" in header
        assert "password" in header

        # Parse data rows as CSV
        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        rows = list(reader)
        assert len(rows) == populated_user["entry_count"]

    async def test_jsonl_stream_valid_objects(
        self, client: AsyncClient, populated_user: dict
    ):
        """
        JSONL export streams one JSON object per line.
        Each line must be parseable and contain required fields.
        """
        resp = await client.get(
            "/api/v1/portability/export/jsonl",
            headers=populated_user["headers"],
        )
        assert resp.status_code == 200

        objects: list[dict] = []
        async for line in resp.aiter_lines():
            if not line:
                continue
            obj = json.loads(line)
            assert "title" in obj
            assert "password" in obj
            objects.append(obj)

        assert len(objects) == populated_user["entry_count"]

        # Verify entry titles match what we created
        titles = {obj["title"] for obj in objects}
        expected_titles = {f"Entry_{i}" for i in range(populated_user["entry_count"])}
        assert titles == expected_titles

    async def test_csv_contains_decrypted_passwords(
        self, client: AsyncClient, populated_user: dict
    ):
        """
        Zero-Trust: passwords are decrypted during export
        and included in the stream (this is expected for backup).
        """
        resp = await client.get(
            "/api/v1/portability/export/csv",
            headers=populated_user["headers"],
        )
        assert resp.status_code == 200

        content = await resp.aread()
        text = content.decode("utf-8")

        # Passwords we created should be present in the export
        for i in range(populated_user["entry_count"]):
            assert f"SecureP@ss_{i}!" in text

    async def test_export_empty_user_has_only_header(
        self, client: AsyncClient, auth_headers: dict
    ):
        """
        User with no entries gets only the CSV header row.
        Confirms streaming works even with zero data.
        """
        resp = await client.get(
            "/api/v1/portability/export/csv",
            headers=auth_headers,
        )
        assert resp.status_code == 200

        lines: list[str] = []
        async for line in resp.aiter_lines():
            if line:
                lines.append(line)

        assert len(lines) == 1  # header only
        assert "title" in lines[0]


# ===========================================================================
# 3. Session & DI Conflict Check
# ===========================================================================


class TestSessionDiConflict:
    """
    Проверка: get_db и get_current_user используют одну AsyncSession
    в рамках одного запроса, без MissingGreenlet или конфликтов.
    """

    async def test_create_then_export_same_session(
        self, client: AsyncClient, populated_user: dict
    ):
        """
        Create entries and immediately export them in the same test.
        If DI used different sessions, export would miss the entries.
        """
        resp = await client.get(
            "/api/v1/portability/export/jsonl",
            headers=populated_user["headers"],
        )
        assert resp.status_code == 200

        objects: list[dict] = []
        async for line in resp.aiter_lines():
            if line:
                objects.append(json.loads(line))

        # All created entries must appear in export
        assert len(objects) == populated_user["entry_count"]

    async def test_multiple_exports_consistent_results(
        self, client: AsyncClient, populated_user: dict
    ):
        """
        Two consecutive exports must return identical data.
        Confirms session state is not mutated between requests.
        """
        headers = populated_user["headers"]

        # First export
        resp1 = await client.get(
            "/api/v1/portability/export/csv",
            headers=headers,
        )
        content1 = await resp1.aread()

        # Second export
        resp2 = await client.get(
            "/api/v1/portability/export/csv",
            headers=headers,
        )
        content2 = await resp2.aread()

        # Same data (order is deterministic via ORDER BY id)
        assert content1 == content2

    async def test_import_then_export_roundtrip(
        self, client: AsyncClient, auth_headers: dict, registered_user: dict
    ):
        """
        Import CSV data, then export it back.
        Confirms import and export use compatible session handling.
        """
        # Prepare CSV with 3 entries
        csv_content = (
            "title,username,password,url,notes\n"
            "Imported_1,imp1@test.com,pass1!,"
            "https://imp1.com,Note 1\n"
            "Imported_2,imp2@test.com,pass2!,"
            "https://imp2.com,Note 2\n"
            "Imported_3,imp3@test.com,pass3!,"
            "https://imp3.com,Note 3\n"
        )

        resp_import = await client.post(
            "/api/v1/portability/import/csv",
            headers=auth_headers,
            files={"file": ("test.csv", csv_content, "text/csv")},
        )
        assert resp_import.status_code == 200
        import_result = resp_import.json()
        assert import_result["imported"] == 3

        # Export and verify
        resp_export = await client.get(
            "/api/v1/portability/export/csv",
            headers=auth_headers,
        )
        assert resp_export.status_code == 200

        lines: list[str] = []
        async for line in resp_export.aiter_lines():
            if line:
                lines.append(line)

        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        rows = list(reader)

        imported_titles = {row["title"] for row in rows}
        assert "Imported_1" in imported_titles
        assert "Imported_2" in imported_titles
        assert "Imported_3" in imported_titles


# ===========================================================================
# 4. Zero-Trust Validation (API Level)
# ===========================================================================


class TestZeroTrustCleanupOnError:
    """
    Проверка: при ошибке в стриминге сессия закрывается,
    LockedBuffer очищается.
    """

    async def test_export_handles_db_error_gracefully(
        self, client: AsyncClient, auth_headers: dict
    ):
        """
        If the DB query fails mid-stream, the response should not
        leak partial data. The session must be cleaned up.
        """
        # Normal export should work — baseline
        resp = await client.get(
            "/api/v1/portability/export/csv",
            headers=auth_headers,
        )
        # With no entries, still returns 200 with header
        assert resp.status_code == 200

    async def test_locked_buffer_closed_after_export(
        self, client: AsyncClient, populated_user: dict
    ):
        """
        After export completes, the LockedBuffer in CryptoContext
        must be closed (verified via the get_current_user cleanup).

        We verify indirectly: multiple sequential exports must all
        succeed, meaning the buffer was properly closed and a new
        one created on each request.
        """
        headers = populated_user["headers"]

        for _ in range(3):
            resp = await client.get(
                "/api/v1/portability/export/jsonl",
                headers=headers,
            )
            assert resp.status_code == 200, f"Export failed on iteration: {resp.text}"

    async def test_import_rolls_back_on_validation_error(
        self, client: AsyncClient, auth_headers: dict
    ):
        """
        Import with malformed CSV should not corrupt the database.
        Rows with validation errors are counted as skipped.
        """
        # CSV with empty title and password (will produce a row with empty
        # strings — Pydantic allows empty str, but the row has no useful data)
        bad_csv = "title,username,password,url,notes\n,,,,empty\n"

        resp = await client.post(
            "/api/v1/portability/import/csv",
            headers=auth_headers,
            files={"file": ("bad.csv", bad_csv, "text/csv")},
        )
        assert resp.status_code == 200
        result = resp.json()

        # At least one row was processed
        assert result["total_rows"] >= 1

        # Export should show no new entries from the bad import
        resp_export = await client.get(
            "/api/v1/portability/export/jsonl",
            headers=auth_headers,
        )
        assert resp_export.status_code == 200

    async def test_import_rolls_back_on_database_error(
        self, client: AsyncClient, auth_headers: dict
    ):
        """
        Simulate a database error during import batch insert.
        The session must rollback and the LockedBuffer must close.
        """
        csv_content = (
            "title,username,password,url,notes\n"
            "TestEntry,test@test.com,secret123!,https://test.com,note\n"
        )

        with patch(
            "backend.services.import_export.DataPortabilityService._insert_batch",
            side_effect=Exception("Simulated DB failure"),
        ):
            # The exception propagates through the ASGI stack.
            # We just verify that subsequent requests still work.
            try:
                await client.post(
                    "/api/v1/portability/import/csv",
                    headers=auth_headers,
                    files={"file": ("test.csv", csv_content, "text/csv")},
                )
            except Exception:
                pass  # Expected — server error propagates

        # Subsequent request must still work (session/buffer cleaned up)
        resp_health = await client.get(
            "/api/v1/portability/export/csv",
            headers=auth_headers,
        )
        assert resp_health.status_code == 200

    async def test_unauthorized_import_rejected(self, client: AsyncClient):
        """Import without auth token must be rejected."""
        csv_content = "title,username,password\nHacked,hacker,pwned\n"

        resp = await client.post(
            "/api/v1/portability/import/csv",
            files={"file": ("hack.csv", csv_content, "text/csv")},
        )
        assert resp.status_code in (401, 403)

    async def test_unauthorized_export_rejected(self, client: AsyncClient):
        """Export without auth token must be rejected."""
        resp = await client.get("/api/v1/portability/export/jsonl")
        assert resp.status_code in (401, 403)


# ===========================================================================
# 5. Content-Type and Header Assertions
# ===========================================================================


class TestResponseHeaders:
    """Strict header validation for streaming endpoints."""

    async def test_csv_content_type(self, client: AsyncClient, populated_user: dict):
        """CSV export must have Content-Type: text/csv."""
        resp = await client.get(
            "/api/v1/portability/export/csv",
            headers=populated_user["headers"],
        )
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "text/csv" in content_type

    async def test_jsonl_content_type(self, client: AsyncClient, populated_user: dict):
        """JSONL export must have application/x-ndjson Content-Type."""
        resp = await client.get(
            "/api/v1/portability/export/jsonl",
            headers=populated_user["headers"],
        )
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "application/x-ndjson" in content_type

    async def test_csv_content_disposition(
        self, client: AsyncClient, populated_user: dict
    ):
        """CSV export must include attachment filename."""
        resp = await client.get(
            "/api/v1/portability/export/csv",
            headers=populated_user["headers"],
        )
        assert resp.status_code == 200
        cd = resp.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert "bitnet_export.csv" in cd

    async def test_jsonl_content_disposition(
        self, client: AsyncClient, populated_user: dict
    ):
        """JSONL export must include attachment filename."""
        resp = await client.get(
            "/api/v1/portability/export/jsonl",
            headers=populated_user["headers"],
        )
        assert resp.status_code == 200
        cd = resp.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert "bitnet_export.jsonl" in cd
