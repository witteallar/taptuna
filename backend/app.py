import os

from flask import Flask, jsonify, render_template
from werkzeug.exceptions import HTTPException

from .routes import api
from .utils.errors import ProtocolLabError

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=os.path.join(_ROOT, "frontend", "templates"),
        static_folder=os.path.join(_ROOT, "frontend", "static"),
    )
    app.config["JSON_AS_ASCII"] = False
    app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False

    app.register_blueprint(api)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.errorhandler(ProtocolLabError)
    def _lab_error(e: ProtocolLabError):
        return jsonify(e.to_dict()), e.http_status

    @app.errorhandler(HTTPException)
    def _http_error(e: HTTPException):
        return jsonify({
            "error": {
                "code": (e.name or "http_error").lower().replace(" ", "_"),
                "message": e.description,
                "details": {},
            }
        }), e.code

    return app