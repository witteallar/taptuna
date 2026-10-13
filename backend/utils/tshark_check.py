import shutil
import subprocess

import config
from .errors import TsharkNotFoundError


def check_tshark() -> str:
    path = shutil.which("tshark")
    if not path:
        raise TsharkNotFoundError(
            "tshark_not_found",
            "tshark не найден в PATH. Установите Wireshark/tshark >= 4.0.",
        )
    try:
        out = subprocess.check_output(
            [path, "-v"],
            stderr=subprocess.STDOUT,
            timeout=config.TSHARK_TIMEOUT,
        )
    except Exception as e:
        raise TsharkNotFoundError("tshark_failed", f"Не удалось выполнить tshark: {e}")
    text = out.decode("utf-8", "replace")
    first_line = text.splitlines()[0].strip() if text else "tshark (unknown version)"
    return first_line


def get_tshark_status() -> tuple[bool, str]:
    try:
        return True, check_tshark()
    except TsharkNotFoundError as e:
        return False, e.message