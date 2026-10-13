"""Проверка tshark: версия, доступность, сравнение с манифестом.

Использует только subprocess.Popen(shell=False).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Tuple


def get_tshark_path() -> str | None:
    """Возвращает путь к tshark из TAPTUNA_TSHARK или PATH."""
    import os
    env_path = os.environ.get("TAPTUNA_TSHARK")
    if env_path and Path(env_path).is_file():
        return env_path
    return shutil.which("tshark")


def get_tshark_version_raw() -> Tuple[bool, str]:
    """Вызывает tshark -v, возвращает (ok, version_string)."""
    path = get_tshark_path()
    if not path:
        return False, "tshark not found in PATH or PROTOLAB_TSHARK"

    try:
        proc = subprocess.Popen(
            [path, "-v"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
        )
        stdout, _ = proc.communicate(timeout=10)
        if proc.returncode != 0:
            return False, f"tshark exited with code {proc.returncode}"
        text = stdout.decode("utf-8", "replace").strip()
        first_line = text.splitlines()[0] if text else "unknown"
        return True, first_line
    except subprocess.TimeoutExpired:
        return False, "tshark -v timed out"
    except Exception as e:
        return False, f"tshark failed: {e}"


def check_tshark_compatibility(project_dir: Path) -> Tuple[bool, str]:
    """Сравнивает версию tshark в манифесте с текущей.
    Возвращает (ok, message). ok=False — предупреждение, не ошибка.
    """
    from .manifest import load_manifest

    try:
        manifest = load_manifest(project_dir)
        recorded = manifest.get("tshark_version", "unknown")
    except FileNotFoundError:
        return True, "No manifest to compare"

    ok, current = get_tshark_version_raw()
    if not ok:
        return False, f"Cannot get current tshark version: {current}"

    if recorded != current:
        return False, f"tshark version mismatch: manifest={recorded}, current={current}"

    return True, f"tshark version matches: {current}"