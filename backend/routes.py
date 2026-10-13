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