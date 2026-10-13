"""Манифест проекта taptuna: чтение/запись manifest.json.

Схема v1:
{
  "schema_version": 1,
  "app_version": "0.1.0",
  "user_version": 1,
  "tshark_version": "TShark 4.2.0 ...",
  "python_version": "3.11.9",
  "pip_freeze": "Flask==3.0.3\npytest==8.3.2\n...",
  "platform": "Linux-6.8.0...",
  "policies": {
    "checksum": "verify",
    "overlap": "first_wins",
    "max_output_bytes": 10485760,
    "blob_inline_threshold": 4096
  }
}
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

import config

from .errors import ProjectAlreadyExistsError


MANIFEST_FILENAME = "manifest.json"
SCHEMA_VERSION = 1
DEFAULT_POLICIES = {
    "checksum": "verify",
    "overlap": "first_wins",
    "max_output_bytes": 10_485_760,   # 10 MiB
    "blob_inline_threshold": 4096,    # 4 KiB
}


def _get_pip_freeze() -> str:
    try:
        out = subprocess.run(
            [sys.executable, "-m", "pip", "freeze"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return out.stdout.strip()
    except Exception:
        return ""


def _get_tshark_version() -> str:
    from .tshark_check import get_tshark_version_raw
    ok, ver = get_tshark_version_raw()
    return ver if ok else "unknown"


def create_manifest(project_dir: Path) -> dict[str, Any]:
    """Создаёт новый manifest.json. Если файл уже есть — поднимает ProjectAlreadyExistsError."""
    manifest_path = project_dir / MANIFEST_FILENAME
    if manifest_path.exists():
        raise ProjectAlreadyExistsError(
            code="PROJECT_EXISTS",
            message=f"Project already exists at {project_dir}",
            details={"path": str(project_dir)}
        )

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "app_version": config.PROJECT_VERSION if hasattr(config, "PROJECT_VERSION") else "0.1.0",
        "user_version": 1,  # PRAGMA user_version схемы БД
        "tshark_version": _get_tshark_version(),
        "python_version": sys.version.split()[0],
        "pip_freeze": _get_pip_freeze(),
        "platform": platform.platform(),
        "policies": DEFAULT_POLICIES.copy(),
    }

    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest


def load_manifest(project_dir: Path) -> dict[str, Any]:
    """Читает manifest.json. Если нет файла — поднимает FileNotFoundError.
    Валидирует схему при загрузке."""
    manifest_path = project_dir / MANIFEST_FILENAME
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    ok, errors = validate_manifest(manifest)
    if not ok:
        raise ValueError(f"Invalid manifest: {'; '.join(errors)}")
    return manifest


def update_manifest(project_dir: Path, updates: dict[str, Any]) -> dict[str, Any]:
    """Частичное обновление манифеста (например, policies)."""
    manifest = load_manifest(project_dir)
    manifest.update(updates)
    manifest_path = project_dir / MANIFEST_FILENAME
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest


def validate_manifest(manifest: dict[str, Any]) -> tuple[bool, list[str]]:
    """Проверяет обязательные поля и совместимость версий."""
    errors = []
    required = [
        "schema_version", "app_version", "user_version",
        "tshark_version", "python_version", "pip_freeze", "platform", "policies"
    ]
    for field in required:
        if field not in manifest:
            errors.append(f"Missing field: {field}")

    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"Unsupported schema_version: {manifest.get('schema_version')}, expected {SCHEMA_VERSION}")

    return len(errors) == 0, errors


def sync_user_version(project_dir: Path, db_user_version: int) -> dict[str, Any]:
    """Синхронизирует user_version в манифесте с PRAGMA user_version БД."""
    manifest = load_manifest(project_dir)
    if manifest.get("user_version") != db_user_version:
        manifest["user_version"] = db_user_version
        manifest_path = project_dir / MANIFEST_FILENAME
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest