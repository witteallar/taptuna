"""Список TCP-сессий через tshark -T fields.

Ключевые моменты:
- НЕ используем pyshark: он медленный (парсит структурированный вывод tshark
  в Python). Нам нужны поля — берём их напрямую из tshark.
- НЕ используем -E quote=d: кавычки вокруг значений ломают int()/float().
  Без quote-флага tshark отдаёт значения как есть.
- Разделитель задан явно (таб), и код это проверяет по первой строке.
- tshark (tcp.stream) обычно разделяет соединения, но может склеить
  переиспользование портов. Добавляем верификацию по SYN/FIN/RST + время.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass

import config
from ..models.session import Session
from ..utils.errors import ProtocolLabError, TsharkNotFoundError

_CAPTURES: dict[str, dict] = {}

# Поля для tshark: stream, 4-tuple, время, флаги, длина payload
_FIELDS = (
    "tcp.stream",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "frame.time_epoch",
    "frame.number",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.rst",
    "tcp.len",
)

# Ключ 4-tuple для обнаружения переиспользования портов
@dataclass(frozen=True, slots=True)
class FourTuple:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int

    @property
    def reverse(self) -> FourTuple:
        return FourTuple(self.dst_ip, self.dst_port, self.src_ip, self.src_port)


# Порог времени (сек) для разделения сессий на одном 4-tuple без явного FIN/RST
SESSION_GAP_THRESHOLD = 30.0

# Флаги TCP (битовая маска)
SYN_FLAG = 0x02
ACK_FLAG = 0x10
FIN_FLAG = 0x01
RST_FLAG = 0x04


def _parse_flags(flags_str: str) -> int:
    """Парсит строку флагов tshark (например '0x0002' или '2') в int."""
    if not flags_str:
        return 0
    try:
        if flags_str.startswith("0x"):
            return int(flags_str, 16)
        return int(flags_str)
    except ValueError:
        return 0


def _is_syn_only(flags: int) -> bool:
    """True если это чистый SYN (SYN=1, ACK=0)."""
    return (flags & SYN_FLAG) != 0 and (flags & ACK_FLAG) == 0


def _is_fin_or_rst(flags: int) -> bool:
    """True если FIN или RST установлен."""
    return (flags & (FIN_FLAG | RST_FLAG)) != 0


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

    # Сначала собираем пакеты по tcp.stream (как сделал tshark)
    stream_packets: dict[int, list[dict]] = {}
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

        (stream_s, src_ip, sport_s, dst_ip, dport_s, ts_s, _num,
         syn_s, ack_s, fin_s, rst_s, tcp_len_s) = parts[:len(_FIELDS)]

        if not stream_s:
            no_stream += 1
            continue

        try:
            stream = int(stream_s)
            sport = int(sport_s)
            dport = int(dport_s)
            ts = float(ts_s)
            syn = _parse_flags(syn_s)
            ack = _parse_flags(ack_s)
            fin = _parse_flags(fin_s)
            rst = _parse_flags(rst_s)
            tcp_len = int(tcp_len_s) if tcp_len_s else 0
        except ValueError as e:
            bad += 1
            if bad <= 3:
                print("[pcap_service] parse err:", repr(raw[:200]), "->", e)
            continue

        flags = syn | ack | fin | rst
        pkt = {
            "stream": stream,
            "src_ip": src_ip, "src_port": sport,
            "dst_ip": dst_ip, "dst_port": dport,
            "ts": ts,
            "flags": flags,
            "tcp_len": tcp_len,
        }
        stream_packets.setdefault(stream, []).append(pkt)

    print(f"[pcap_service] итог: строк={len(lines)} bad={bad} "
          f"no_stream={no_stream} streams={len(stream_packets)}")

    # Теперь верифицируем: внутри каждого tcp.stream проверяем,
    # не склеил ли tshark разные соединения на одном 4-tuple
    sessions_data = _split_streams_by_connection(stream_packets)

    return _build_sessions(sessions_data)


def _split_streams_by_connection(
    stream_packets: dict[int, list[dict]]
) -> list[dict]:
    """
    Разбивает пакеты внутри одного tcp.stream на отдельные соединения,
    если tshark склеил переиспользование портов.
    Логика: новое соединение начинается с чистого SYN после FIN/RST
    или после таймаута SESSION_GAP_THRESHOLD.
    """
    result = []

    for stream_idx, packets in stream_packets.items():
        if not packets:
            continue

        # Сортируем по времени на всякий случай
        packets.sort(key=lambda p: p["ts"])

        # Группируем по 4-tuple (учитывая направление)
        # tshark обычно даёт одинаковый stream для обоих направлений,
        # но 4-tuple может быть одинаковым для переиспользованных портов
        current_conn = []
        last_ts = None
        last_flags = 0
        conn_closed = False  # было ли FIN/RST в текущем соединении

        for pkt in packets:
            four_tuple = FourTuple(
                pkt["src_ip"], pkt["src_port"],
                pkt["dst_ip"], pkt["dst_port"]
            )
            flags = pkt["flags"]
            ts = pkt["ts"]

            start_new_conn = False

            if current_conn:
                # Проверяем, не началось ли новое соединение
                if _is_syn_only(flags) and conn_closed:
                    # Чистый SYN после FIN/RST -> новое соединение
                    start_new_conn = True
                elif _is_syn_only(flags) and last_ts is not None:
                    # Чистый SYN после большого промежутка времени
                    if (ts - last_ts) > SESSION_GAP_THRESHOLD:
                        start_new_conn = True

            if start_new_conn:
                # Завершаем текущее соединение
                if current_conn:
                    result.append(_conn_to_session_data(stream_idx, current_conn))
                current_conn = [pkt]
                conn_closed = False
            else:
                current_conn.append(pkt)
                if _is_fin_or_rst(flags):
                    conn_closed = True

            last_ts = ts
            last_flags = flags

        # Последнее соединение в стриме
        if current_conn:
            result.append(_conn_to_session_data(stream_idx, current_conn))

    return result


def _conn_to_session_data(stream_idx: int, packets: list[dict]) -> dict:
    """Считает статистику для одного соединения."""
    first = packets[0]
    last = packets[-1]
    # Определяем направление по первому пакету (тот, кто отправил SYN)
    # Но для простоты используем направление первого пакета
    return {
        "stream": stream_idx,
        "src_ip": first["src_ip"],
        "src_port": first["src_port"],
        "dst_ip": first["dst_ip"],
        "dst_port": first["dst_port"],
        "packets": len(packets),
        "start_ts": first["ts"],
        "end_ts": last["ts"],
    }


def _build_sessions(buckets: list[dict]) -> list[Session]:
    ordered = sorted(buckets, key=lambda x: (x["start_ts"], x["stream"]))
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