"""Tests for manifest module."""

from __future__ import annotations

from pathlib import Path

import pytest

from taptuna.manifest import create_manifest, load_manifest, validate_manifest, SCHEMA_VERSION
from taptuna.errors import ProjectAlreadyExistsError


def test_create_manifest(tmp_path: Path):
    """init создаёт manifest.json с правильными полями."""
    project_dir = tmp_path / "test_proj"
    project_dir.mkdir()

    manifest = create_manifest(project_dir)

    assert manifest["schema_version"] == SCHEMA_VERSION
    assert "app_version" in manifest
    assert manifest["user_version"] == 1
    assert "tshark_version" in manifest
    assert "python_version" in manifest
    assert "pip_freeze" in manifest
    assert "platform" in manifest
    assert "policies" in manifest
    assert manifest["policies"]["checksum"] == "verify"
    assert manifest["policies"]["overlap"] == "first_wins"
    assert manifest["policies"]["max_output_bytes"] == 10_485_760
    assert manifest["policies"]["blob_inline_threshold"] == 4096

    # Файл создан
    manifest_file = project_dir / "manifest.json"
    assert manifest_file.exists()


def test_duplicate_init_fails(tmp_path: Path):
    """Повторный init падает с ошибкой, не перезаписывает."""
    project_dir = tmp_path / "test_proj"
    project_dir.mkdir()

    create_manifest(project_dir)

    with pytest.raises(ProjectAlreadyExistsError) as exc_info:
        create_manifest(project_dir)

    assert exc_info.value.code == "PROJECT_EXISTS"


def test_load_manifest(tmp_path: Path):
    """load_manifest читает и валидирует манифест."""
    project_dir = tmp_path / "test_proj"
    project_dir.mkdir()

    original = create_manifest(project_dir)
    loaded = load_manifest(project_dir)

    assert loaded["schema_version"] == original["schema_version"]
    assert loaded["user_version"] == original["user_version"]
    assert loaded["tshark_version"] == original["tshark_version"]


def test_load_manifest_validates_schema(tmp_path: Path):
    """load_manifest валидирует schema_version и обязательные поля."""
    project_dir = tmp_path / "test_proj"
    project_dir.mkdir()

    # Создаём невалидный манифест вручную
    import json
    bad_manifest = {
        "schema_version": 999,
        "app_version": "0.1.0",
        "user_version": 1,
        "tshark_version": "test",
        "python_version": "3.11",
        "pip_freeze": "",
        "platform": "test",
        "policies": {},
    }
    (project_dir / "manifest.json").write_text(json.dumps(bad_manifest))

    with pytest.raises(ValueError) as exc_info:
        load_manifest(project_dir)

    assert "Invalid manifest" in str(exc_info.value)
    assert "schema_version" in str(exc_info.value)


def test_validate_manifest():
    """validate_manifest проверяет обязательные поля и версию схемы."""
    valid = {
        "schema_version": SCHEMA_VERSION,
        "app_version": "0.1.0",
        "user_version": 1,
        "tshark_version": "test",
        "python_version": "3.11",
        "pip_freeze": "",
        "platform": "test",
        "policies": {},
    }
    ok, errors = validate_manifest(valid)
    assert ok
    assert errors == []

    # Missing field
    invalid = valid.copy()
    del invalid["tshark_version"]
    ok, errors = validate_manifest(invalid)
    assert not ok
    assert any("tshark_version" in e for e in errors)

    # Wrong schema_version
    invalid = valid.copy()
    invalid["schema_version"] = 999
    ok, errors = validate_manifest(invalid)
    assert not ok
    assert any("schema_version" in e for e in errors)