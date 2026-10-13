"""Tests for store module (SQLite schema, migrations, indexes)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from taptuna.store import (
    init_db,
    open_db,
    migrate,
    get_user_version,
    SCHEMA_VERSION,
    DDL_TABLES,
    DDL_INDEXES,
)


def test_init_db_creates_tables(tmp_path: Path):
    """init_db создаёт все 14 таблиц и индексы."""
    project_dir = tmp_path / "test_proj"
    conn = init_db(project_dir)

    # Проверяем user_version
    assert get_user_version(conn) == SCHEMA_VERSION

    # Проверяем наличие всех 14 таблиц
    tables = [row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()]

    expected_tables = [
        "captures",
        "sessions",
        "directions",
        "stream_segments",
        "packets",
        "interpretations",
        "corpora",
        "verification_runs",
        "verification_results",
        "observations",
        "hypotheses",
        "hypothesis_observations",
        "action_log",
        "meta",
    ]

    for t in expected_tables:
        assert t in tables, f"Missing table: {t}"

    # Проверяем JSON-столбцы в directions
    cols = [row[1] for row in conn.execute("PRAGMA table_info(directions)").fetchall()]
    assert "gaps_json" in cols
    assert "ambiguities_json" in cols

    conn.close()


def test_all_indexes_created(tmp_path: Path):
    """Все индексы из ТЗ §14 созданы."""
    project_dir = tmp_path / "test_proj"
    conn = init_db(project_dir)

    indexes = [row[1] for row in conn.execute(
        "SELECT * FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()]

    expected_indexes = [
        "idx_vres_run_status",
        "idx_vres_run_id",
        "idx_sessions_capture_stream",
        "idx_interp_name_version",
        "idx_seg_dir_offset",
        "idx_obs_target",
        "idx_directions_session",
        "idx_packets_direction",
        "idx_verification_runs_corpus",
        "idx_verification_runs_interp",
    ]

    for idx in expected_indexes:
        assert idx in indexes, f"Missing index: {idx}"

    conn.close()


def test_migrate_idempotent(tmp_path: Path):
    """Мигратор идемпотентен: повторный вызов не меняет версию."""
    project_dir = tmp_path / "test_proj"
    project_dir.mkdir()
    db_path = project_dir / "project.sqlite"

    # Первый запуск
    v1 = migrate(db_path)
    assert v1 == 1

    # Второй запуск
    v2 = migrate(db_path)
    assert v2 == 1

    # Третий запуск
    v3 = migrate(db_path)
    assert v3 == 1


def test_meta_table_initialized(tmp_path: Path):
    """meta таблица инициализируется с schema_version."""
    project_dir = tmp_path / "test_proj"
    conn = init_db(project_dir)

    row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    assert row is not None
    assert row[0] == str(SCHEMA_VERSION)

    conn.close()


def test_foreign_keys_enabled(tmp_path: Path):
    """Foreign keys включены."""
    project_dir = tmp_path / "test_proj"
    conn = init_db(project_dir)

    row = conn.execute("PRAGMA foreign_keys").fetchone()
    assert row[0] == 1

    conn.close()


def test_open_db_existing(tmp_path: Path):
    """open_db открывает существующую БД."""
    project_dir = tmp_path / "test_proj"
    init_db(project_dir)

    conn = open_db(project_dir)
    assert get_user_version(conn) == SCHEMA_VERSION
    conn.close()


def test_open_db_missing_raises(tmp_path: Path):
    """open_db поднимает FileNotFoundError для несуществующей БД."""
    project_dir = tmp_path / "nonexistent"
    with pytest.raises(FileNotFoundError):
        open_db(project_dir)