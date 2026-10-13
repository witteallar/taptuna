"""Pytest fixtures for taptuna tests."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Generator

import pytest


@pytest.fixture
def tmp_project_dir() -> Generator[Path, None, None]:
    """Создаёт временную директорию для проекта."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp) / "test_project"


@pytest.fixture
def project_dir(tmp_project_dir: Path) -> Path:
    """Создаёт инициализированный проект (manifest + sqlite)."""
    from taptuna.manifest import create_manifest
    from taptuna.store import init_db

    tmp_project_dir.mkdir(parents=True)
    (tmp_project_dir / "captures").mkdir(exist_ok=True)
    (tmp_project_dir / "blobs").mkdir(exist_ok=True)
    (tmp_project_dir / "interpretations").mkdir(exist_ok=True)
    (tmp_project_dir / "corpora").mkdir(exist_ok=True)
    (tmp_project_dir / "action_log").mkdir(exist_ok=True)
    (tmp_project_dir / "reports").mkdir(exist_ok=True)
    (tmp_project_dir / "logs").mkdir(exist_ok=True)

    create_manifest(tmp_project_dir)
    init_db(tmp_project_dir)

    return tmp_project_dir