# -*- coding: utf-8 -*-
"""
Error-path tests for the Import/Export Portability API endpoints.

Covers the three exception branches (ImportValidationError, ImportDatabaseError,
SQLAlchemyError) for both /import/csv and /import/jsonl, plus content-type guard.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from backend.services.import_export import (
    ImportDatabaseError,
    ImportValidationError,
)

pytestmark = pytest.mark.asyncio


async def _register_and_login(client: AsyncClient) -> dict:
    username = f"port_{id(client)}_{__name__}"
    email = f"{username}@example.com"
    password = "PortTestP@ss1!"

    resp = await client.post(
        "/api/v1/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    assert resp.status_code == 201, f"Register failed: {resp.text}"

    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


_SERVICE_PATH = "backend.api.v1.endpoints.portability.DataPortabilityService"


class TestImportCsvErrors:
    async def test_wrong_content_type(self, client: AsyncClient):
        headers = await _register_and_login(client)
        resp = await client.post(
            "/api/v1/portability/import/csv",
            headers=headers,
            files={"file": ("data.json", b"{}", "application/json")},
        )
        assert resp.status_code == 400
        assert "error_id" in resp.json()

    async def test_import_validation_error(self, client: AsyncClient):
        headers = await _register_and_login(client)
        with patch(
            f"{_SERVICE_PATH}.import_from_csv",
            new_callable=AsyncMock,
            side_effect=ImportValidationError("bad row"),
        ):
            resp = await client.post(
                "/api/v1/portability/import/csv",
                headers=headers,
                files={"file": ("data.csv", b"title,password\nA,B", "text/csv")},
            )
        assert resp.status_code == 400

    async def test_import_database_error(self, client: AsyncClient):
        headers = await _register_and_login(client)
        with patch(
            f"{_SERVICE_PATH}.import_from_csv",
            new_callable=AsyncMock,
            side_effect=ImportDatabaseError("insert failed"),
        ):
            resp = await client.post(
                "/api/v1/portability/import/csv",
                headers=headers,
                files={"file": ("data.csv", b"title,password\nA,B", "text/csv")},
            )
        assert resp.status_code == 503

    async def test_import_sqlalchemy_error(self, client: AsyncClient):
        from sqlalchemy.exc import SQLAlchemyError

        headers = await _register_and_login(client)
        with patch(
            f"{_SERVICE_PATH}.import_from_csv",
            new_callable=AsyncMock,
            side_effect=SQLAlchemyError("connection lost"),
        ):
            resp = await client.post(
                "/api/v1/portability/import/csv",
                headers=headers,
                files={"file": ("data.csv", b"title,password\nA,B", "text/csv")},
            )
        assert resp.status_code == 500


class TestImportJsonlErrors:
    async def test_import_validation_error(self, client: AsyncClient):
        headers = await _register_and_login(client)
        with patch(
            f"{_SERVICE_PATH}.import_from_jsonl",
            new_callable=AsyncMock,
            side_effect=ImportValidationError("bad jsonl"),
        ):
            resp = await client.post(
                "/api/v1/portability/import/jsonl",
                headers=headers,
                files={"file": ("data.jsonl", b'{"title":"A","password":"B"}', "application/x-ndjson")},
            )
        assert resp.status_code == 400

    async def test_import_database_error(self, client: AsyncClient):
        headers = await _register_and_login(client)
        with patch(
            f"{_SERVICE_PATH}.import_from_jsonl",
            new_callable=AsyncMock,
            side_effect=ImportDatabaseError("db down"),
        ):
            resp = await client.post(
                "/api/v1/portability/import/jsonl",
                headers=headers,
                files={"file": ("data.jsonl", b'{"title":"A","password":"B"}', "application/x-ndjson")},
            )
        assert resp.status_code == 503

    async def test_import_sqlalchemy_error(self, client: AsyncClient):
        from sqlalchemy.exc import SQLAlchemyError

        headers = await _register_and_login(client)
        with patch(
            f"{_SERVICE_PATH}.import_from_jsonl",
            new_callable=AsyncMock,
            side_effect=SQLAlchemyError("conn error"),
        ):
            resp = await client.post(
                "/api/v1/portability/import/jsonl",
                headers=headers,
                files={"file": ("data.jsonl", b'{"title":"A","password":"B"}', "application/x-ndjson")},
            )
        assert resp.status_code == 500