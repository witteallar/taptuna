"""Список TCP-сессий через tshark -T fields.

Ключевые моменты:
- НЕ используем pyshark: он медленный (парсит структурированный вывод tshark
  в Python). Нам нужны 6 колонок — берём их напрямую из tshark.
- НЕ используем -E quote=d: кавычки вокруг значений ломают int()/float().
  Без quote-флага tshark отдаёт значения как есть.
- Разделитель задан явно (таб), и код это проверяет по первой строке.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import uuid

import config
from ..models.session import Session
from ..utils.errors import ProtocolLabError, TsharkNotFoundError

_CAPTURES: dict[str, dict] = {}

_FIELDS = (
    "tcp.stream",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "frame.time_epoch",
    "frame.number",
)

# --- публичные функции ---

def list_local_captures() -> list[dict]:
    if not os.path.isdir(config.CAPTURES_DIR):
        return []
    out = []
    for name in sorted(os.listdir(config.CAPTURES_DIR)):
        if name.lower().endswith((".pcap", ".pcapng")):
            full = os.path.join(config.CAPTURES_DIR, name)
            out.append({"name": name, "path": full, "size": os.path.getsize(full)})
    return out


def open_capture(path: str) -> tuple[str, list[Session]]:
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise ProtocolLabError("file_not_found", f"Файл не найден: {path}")
    if not os.path.isfile(path):
        raise ProtocolLabError("not_a_file", f"Это не файл: {path}")
    size = os.path.getsize(path)
    if size > config.MAX_FILE_SIZE:
        raise ProtocolLabError(
            "file_too_large",
            f"Размер {size} байт превышает лимит {config.MAX_FILE_SIZE}.",
        )

    sessions = _collect_sessions(path)
    capture_id = uuid.uuid4().hex[:12]
    _CAPTURES[capture_id] = {"path": path, "sessions": sessions}
    return capture_id, sessions


def get_sessions(capture_id: str) -> list[Session]:
    entry = _CAPTURES.get(capture_id)
    if not entry:
        raise ProtocolLabError("capture_not_found", f"Неизвестный capture_id: {capture_id}")
    return entry["sessions"]


def get_capture_path(capture_id: str) -> str:
    entry = _CAPTURES.get(capture_id)
    if not entry:
        raise ProtocolLabError("capture_not_found", f"Неизвестный capture_id: {capture_id}")
    return entry["path"]


# --- внутреннее ---

def _collect_sessions(path: str) -> list[Session]:
    tshark = shutil.which("tshark")
    if not tshark:
        raise TsharkNotFoundError(
            "tshark_not_found",
            "tshark не найден в PATH. Установите Wireshark/tshark >= 4.0.",
        )

    # Явно: разделитель — таб, никаких кавычек, только первое вхождение поля.
    cmd = [
        tshark, "-r", path, "-n", "-Y", "tcp", "-T", "fields",
        "-E", "separator=/t",
        "-E", "occurrence=f",
        "-E", "quote=n",
    ]
    for f in _FIELDS:
        cmd += ["-e", f]

    print("[pcap_service] cmd:", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=config.TSHARK_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise ProtocolLabError(
            "tshark_timeout",
            f"tshark не уложился в {config.TSHARK_TIMEOUT} с.",
        )
    except Exception as e:
        raise ProtocolLabError("tshark_failed", f"Ошибка запуска tshark: {e}")

    if proc.stderr.strip():
        print("[pcap_service] stderr:", proc.stderr.strip()[:800])

    if proc.returncode != 0:
        raise ProtocolLabError(
            "tshark_failed",
            f"tshark rc={proc.returncode}. stderr: {proc.stderr.strip()[:400]}",
        )

    lines = proc.stdout.splitlines()
    print(f"[pcap_service] строк от tshark: {len(lines)}")
    if lines:
        print("[pcap_service] первая строка repr:", repr(lines[0][:200]))

    buckets: dict[int, dict] = {}
    bad = 0
    no_stream = 0

    for raw in lines:
        if not raw:
            continue
        parts = raw.split("\t")
        if len(parts) < len(_FIELDS):
            bad += 1
            if bad <= 3:
                print("[pcap_service] bad line:", repr(raw[:200]))
            continue

        stream_s, src_ip, sport_s, dst_ip, dport_s, ts_s, _num = parts[:len(_FIELDS)]
        if not stream_s:
            no_stream += 1
            continue

        try:
            stream = int(stream_s)
            sport = int(sport_s)
            dport = int(dport_s)
            ts = float(ts_s)
        except ValueError as e:
            bad += 1
            if bad <= 3:
                print("[pcap_service] parse err:", repr(raw[:200]), "→", e)
            continue

        e = buckets.get(stream)
        if e is None:
            buckets[stream] = {
                "stream": stream,
                "src_ip": src_ip, "src_port": sport,
                "dst_ip": dst_ip, "dst_port": dport,
                "packets": 1, "start_ts": ts, "end_ts": ts,
            }
        else:
            e["packets"] += 1
            if ts < e["start_ts"]:
                e["start_ts"] = ts
            if ts > e["end_ts"]:
                e["end_ts"] = ts

    print(f"[pcap_service] итог: строк={len(lines)} bad={bad} "
          f"no_stream={no_stream} sessions={len(buckets)}")

    return _build_sessions(buckets)


def _build_sessions(buckets: dict[int, dict]) -> list[Session]:
    ordered = sorted(buckets.values(), key=lambda x: (x["start_ts"], x["stream"]))
    result = []
    for e in ordered:
        result.append(Session(
            session_id=f"s{e['stream']}",
            stream_index=e["stream"],
            src_ip=e["src_ip"],
            src_port=e["src_port"],
            dst_ip=e["dst_ip"],
            dst_port=e["dst_port"],
            packets=e["packets"],
            start_ts=e["start_ts"],
            end_ts=e["end_ts"],
        ))
    return result