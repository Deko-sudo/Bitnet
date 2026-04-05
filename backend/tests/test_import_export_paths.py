# -*- coding: utf-8 -*-
"""Tests for import/export path configuration and cross-platform behavior."""

import json
import secrets

import pytest

from backend.features.import_export import ImportExportService


@pytest.fixture
def import_export_service(tmp_path):
    export_dir = tmp_path / "exports"
    import_dir = tmp_path / "imports"
    temp_dir = tmp_path / "temp"
    return ImportExportService(
        db_session=None,
        crypto_key=secrets.token_bytes(32),
        export_dir=export_dir,
        import_dir=import_dir,
        temp_dir=temp_dir,
    )


def test_export_uses_configured_base_dir_for_relative_paths(import_export_service, tmp_path):
    entries = [
        {
            "id": 1,
            "title": "Mail",
            "username": "user@example.com",
            "password": "S3cret!",
            "url": "https://example.com",
            "notes": "test",
        }
    ]
    ok = import_export_service.export_to_json(
        user_id=1,
        entries=entries,
        filepath="vault.json",
        master_password="MasterPass123!",
    )
    assert ok is True
    assert (tmp_path / "exports" / "vault.json").exists()


def test_import_allows_absolute_path(import_export_service, tmp_path):
    import_file = tmp_path / "outside_import.json"
    data = {
        "version": "1.0",
        "entries": [
            {
                "title": "Service",
                "username": "user",
                "password": "pwd123",
                "url": "https://example.com",
                "notes": "ok",
            }
        ],
    }
    import_file.write_text(json.dumps(data), encoding="utf-8")

    entries = import_export_service.import_from_json(
        user_id=1,
        filepath=str(import_file),
        master_password="MasterPass123!",
    )
    assert len(entries) == 1
    assert entries[0].title == "Service"


def test_cleanup_temp_files_rejects_paths_outside_temp_base(import_export_service, tmp_path):
    temp_file = tmp_path / "temp" / "file.tmp"
    temp_file.parent.mkdir(parents=True, exist_ok=True)
    temp_file.write_text("x", encoding="utf-8")

    deleted = import_export_service.cleanup_temp_files(str(tmp_path / "temp"))
    assert deleted == 1
    assert not temp_file.exists()

    outside_dir = tmp_path / "outside"
    outside_dir.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError, match="Invalid temp directory"):
        import_export_service.cleanup_temp_files(str(outside_dir))
