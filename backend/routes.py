from flask import Blueprint, jsonify, request

import config
from .services import pcap_service
from .utils.errors import ProtocolLabError
from .utils.tshark_check import get_tshark_status

api = Blueprint("api", __name__, url_prefix="/api")


@api.get("/health")
def health():
    ok, info = get_tshark_status()
    return jsonify({
        "status": "ok" if ok else "degraded",
        "tshark_available": ok,
        "tshark_version": info,
        "project_version": config.PROJECT_VERSION,
    })


@api.get("/capture/list")
def capture_list():
    return jsonify({"files": pcap_service.list_local_captures()})

@api.get("/capture/<capture_id>/debug")
def capture_debug(capture_id: str):
    import pyshark
    from .services import pcap_service

    path = pcap_service.get_capture_path(capture_id)

    cap = pyshark.FileCapture(path, keep_packets=True, include_raw=False)
    samples = []
    total = 0
    try:
        for i, pkt in enumerate(cap):
            total += 1
            if i >= 5:
                break
            entry = {
                "index": i,
                "layer_names": [getattr(l, "layer_name", "?") for l in pkt.layers],
            }
            probes = [
                ("ip", "src"), ("ip", "dst"),
                ("tcp", "stream"), ("tcp", "srcport"), ("tcp", "dstport"),
                ("frame_info", "time_epoch"),
                ("frame", "time_epoch"),
            ]
            for a, b in probes:
                key = f"{a}.{b}"
                try:
                    obj = getattr(pkt, a)
                    val = getattr(obj, b)
                    entry[key] = f"{type(val).__name__}: {val!r}"
                except Exception as e:
                    entry[key] = f"ERR {type(e).__name__}: {e}"
            samples.append(entry)
    finally:
        cap.close()

    return jsonify({"packets_read_at_least": total, "samples": samples})

@api.post("/capture/open")
def capture_open():
    data = request.get_json(silent=True) or {}
    path = (data.get("path") or "").strip()
    if not path:
        raise ProtocolLabError("bad_request", "Поле 'path' обязательно.")
    capture_id, sessions = pcap_service.open_capture(path)
    return jsonify({
        "capture_id": capture_id,
        "path": path,
        "sessions": [s.to_dict() for s in sessions],
    })


@api.get("/capture/<capture_id>/sessions")
def capture_sessions(capture_id: str):
    sessions = pcap_service.get_sessions(capture_id)
    return jsonify([s.to_dict() for s in sessions])