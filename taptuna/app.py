"""Flask application factory."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify

from .errors import ProtocolLabError
from .routes import bp as api_bp


def create_app(project_dir: Path) -> Flask:
    """Создаёт и конфигурирует Flask-приложение для проекта."""
    app = Flask(__name__)
    app.config["PROJECT_DIR"] = project_dir

    # Register API blueprint
    app.register_blueprint(api_bp, url_prefix="/api")

    # Error handlers
    @app.errorhandler(ProtocolLabError)
    def handle_taptuna_error(e: ProtocolLabError):
        return jsonify(e.to_dict()), e.http_status

    @app.errorhandler(404)
    def handle_404(e):
        return jsonify({"error": {"code": "NOT_FOUND", "message": "Not found", "details": {}}}), 404

    @app.errorhandler(500)
    def handle_500(e):
        return jsonify({"error": {"code": "INTERNAL_ERROR", "message": "Internal server error", "details": {}}}), 500

    return app