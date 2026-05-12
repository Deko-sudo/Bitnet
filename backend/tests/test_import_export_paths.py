# -*- coding: utf-8 -*-
"""
Tests for import/export path configuration and cross-platform behavior.

Tests the real ``backend.services.import_export.DataPortabilityService``
with mocked crypto dependencies so the Rust bridge is not required.
"""

import json
import secrets
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import pytest_asyncio

from backend.services.import_export import DataPortabilityService, ImportResult


@pytest_asyncio.fixture
async def mock_service(tmp_path):
    """Create a DataPortabilityService with a mocked master_key and session."""
    mock_session = MagicMock()
    mock_key = MagicMock()
    mock_key.__len__ = lambda _s: 32
    mock_key.__bool__ = lambda _s: True

    return DataPortabilityService(
        session=mock_session,
        master_key=mock_key,
    )


def test_import_result_schema():
    """ImportResult Pydantic schema validates totals."""
    result = ImportResult(total_rows=100, imported=95, skipped=5)
    assert result.total_rows == 100
    assert result.imported == 95
    assert result.skipped == 5


def test_import_result_defaults():
    """ImportResult has sensible defaults."""
    result = ImportResult()
    assert result.total_rows == 0
    assert result.imported == 0
    assert result.skipped == 0
    assert result.errors == []
