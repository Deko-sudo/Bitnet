# -*- coding: utf-8 -*-
"""
Async tests for the Breach Monitor API endpoints.

Uses the shared ``client`` + ``auth_headers`` fixtures from conftest.py
and patches the AsyncBreachMonitorService where needed.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient

from backend.main import app
from backend.features.breach_monitor_async import AsyncBreachMonitorService

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Helper: register + login + set up breach monitor on app.state
# ---------------------------------------------------------------------------


async def _register_and_login(client: AsyncClient) -> dict:
    username = f"breach_test_{id(client)}"
    email = f"{username}@example.com"
    password = "BreachTestP@ss1!"

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


def _setup_monitor(engine) -> AsyncBreachMonitorService:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    monitor = AsyncBreachMonitorService(
        db_session_factory=session_factory,
        hibp_api_key=None,
        check_interval_hours=9999,
    )
    app.state.breach_monitor = monitor
    return monitor


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBreachStatus:
    async def test_status_returns_defaults(self, client: AsyncClient, engine):
        headers = await _register_and_login(client)
        monitor = _setup_monitor(engine)
        try:
            resp = await client.get("/api/v1/breach/status", headers=headers)
            assert resp.status_code == 200
            data = resp.json()
            assert "monitored_items" in data
            assert "unacknowledged_alerts" in data
            assert "running" in data
        finally:
            if hasattr(app.state, "breach_monitor"):
                delattr(app.state, "breach_monitor")


class TestMonitorPassword:
    async def test_add_password_returns_item_id(self, client: AsyncClient, engine):
        headers = await _register_and_login(client)
        monitor = _setup_monitor(engine)
        try:
            resp = await client.post(
                "/api/v1/breach/monitor/password",
                json={"password": "test_password_123"},
                headers=headers,
            )
            assert resp.status_code == 201
            data = resp.json()
            assert "item_id" in data
            assert data["status"] == "monitoring"
        finally:
            if hasattr(app.state, "breach_monitor"):
                delattr(app.state, "breach_monitor")


class TestMonitorEmail:
    async def test_add_email_returns_item_id(self, client: AsyncClient, engine):
        headers = await _register_and_login(client)
        monitor = _setup_monitor(engine)
        try:
            resp = await client.post(
                "/api/v1/breach/monitor/email",
                json={"email": "test@example.com"},
                headers=headers,
            )
            assert resp.status_code == 201
            data = resp.json()
            assert "item_id" in data
            assert data["status"] == "monitoring"
        finally:
            if hasattr(app.state, "breach_monitor"):
                delattr(app.state, "breach_monitor")


class TestRemoveItem:
    async def test_remove_monitored_item(self, client: AsyncClient, engine):
        headers = await _register_and_login(client)
        monitor = _setup_monitor(engine)
        try:
            resp = await client.post(
                "/api/v1/breach/monitor/password",
                json={"password": "removeme"},
                headers=headers,
            )
            assert resp.status_code == 201
            item_id = resp.json()["item_id"]

            resp = await client.delete(
                f"/api/v1/breach/monitor/{item_id}",
                headers=headers,
            )
            assert resp.status_code == 204
        finally:
            if hasattr(app.state, "breach_monitor"):
                delattr(app.state, "breach_monitor")

    async def test_remove_nonexistent_item_returns_404(self, client: AsyncClient, engine):
        headers = await _register_and_login(client)
        monitor = _setup_monitor(engine)
        try:
            resp = await client.delete(
                "/api/v1/breach/monitor/nonexistent_id",
                headers=headers,
            )
            assert resp.status_code == 404
        finally:
            if hasattr(app.state, "breach_monitor"):
                delattr(app.state, "breach_monitor")


class TestListAlerts:
    async def test_list_alerts_empty(self, client: AsyncClient, engine):
        headers = await _register_and_login(client)
        monitor = _setup_monitor(engine)
        try:
            resp = await client.get("/api/v1/breach/alerts", headers=headers)
            assert resp.status_code == 200
            assert resp.json() == []
        finally:
            if hasattr(app.state, "breach_monitor"):
                delattr(app.state, "breach_monitor")


class TestAcknowledgeAndResolve:
    async def test_acknowledge_nonexistent_alert(self, client: AsyncClient, engine):
        headers = await _register_and_login(client)
        monitor = _setup_monitor(engine)
        try:
            resp = await client.patch(
                "/api/v1/breach/alerts/nonexistent/acknowledge",
                headers=headers,
            )
            assert resp.status_code == 404
        finally:
            if hasattr(app.state, "breach_monitor"):
                delattr(app.state, "breach_monitor")

    async def test_resolve_nonexistent_alert(self, client: AsyncClient, engine):
        headers = await _register_and_login(client)
        monitor = _setup_monitor(engine)
        try:
            resp = await client.patch(
                "/api/v1/breach/alerts/nonexistent/resolve",
                headers=headers,
            )
            assert resp.status_code == 404
        finally:
            if hasattr(app.state, "breach_monitor"):
                delattr(app.state, "breach_monitor")


class TestCheckNow:
    async def test_check_password_endpoint(self, client: AsyncClient, engine):
        headers = await _register_and_login(client)
        _setup_monitor(engine)
        try:
            with patch(
                "backend.api.v1.endpoints.breach.HaveIBeenPwnedChecker"
            ) as MockChecker:
                mock_instance = AsyncMock()
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=False)
                mock_instance.check_password = AsyncMock(return_value=(False, 0))
                mock_instance.close = AsyncMock()
                MockChecker.return_value = mock_instance

                resp = await client.post(
                    "/api/v1/breach/check/password",
                    json={"password": "safe_password"},
                    headers=headers,
                )
                assert resp.status_code == 200
                data = resp.json()
                assert "is_pwned" in data
                assert "breach_count" in data
        finally:
            if hasattr(app.state, "breach_monitor"):
                delattr(app.state, "breach_monitor")

    async def test_check_email_endpoint_no_api_key(self, client: AsyncClient, engine):
        headers = await _register_and_login(client)
        _setup_monitor(engine)
        try:
            with patch(
                "backend.api.v1.endpoints.breach.HaveIBeenPwnedChecker"
            ) as MockChecker:
                mock_instance = AsyncMock()
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=False)
                mock_instance.check_email = AsyncMock(
                    side_effect=PermissionError("HIBP API key required")
                )
                mock_instance.close = AsyncMock()
                MockChecker.return_value = mock_instance

                resp = await client.post(
                    "/api/v1/breach/check/email",
                    json={"email": "test@example.com"},
                    headers=headers,
                )
                assert resp.status_code == 403
        finally:
            if hasattr(app.state, "breach_monitor"):
                delattr(app.state, "breach_monitor")


class TestCheckNowTrigger:
    async def test_trigger_check_now(self, client: AsyncClient, engine):
        headers = await _register_and_login(client)
        monitor = _setup_monitor(engine)
        try:
            with patch.object(monitor, "check_now", new_callable=AsyncMock) as mock_check:
                mock_check.return_value = 3
                resp = await client.post(
                    "/api/v1/breach/check/now",
                    headers=headers,
                )
                assert resp.status_code == 200
                data = resp.json()
                assert data["checked_items"] == 3
                assert data["status"] == "completed"
        finally:
            if hasattr(app.state, "breach_monitor"):
                delattr(app.state, "breach_monitor")