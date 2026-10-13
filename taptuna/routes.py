"""API routes: только POST /api/projects и GET /api/projects/<id> на этом этапе."""

from __future__ import annotations

from pathlib import Path

from flask import Blueprint, current_app, jsonify, request

from .errors import ProjectNotFoundError, ValidationError
from .manifest import create_manifest, load_manifest, validate_manifest
from .store import init_db, get_user_version


bp = Blueprint("api", __name__)


def _get_project_dir() -> Path:
    return current_app.config["PROJECT_DIR"]


@bp.route("/projects", methods=["POST"])
def create_project():
    """POST /api/projects
    Создаёт новый проект: каталог + manifest.json + project.sqlite.
    Body (JSON): {"path": "/abs/or/rel/path", "name": "optional"}
    """
    data = request.get_json(silent=True) or {}
    path_str = data.get("path")
    if not path_str:
        raise ValidationError(
            code="MISSING_FIELD",
            message="Field 'path' is required",
            details={"field": "path"}
        )

    project_dir = Path(path_str).resolve()

    # Check if parent exists
    if not project_dir.parent.exists():
        raise ValidationError(
            code="INVALID_PATH",
            message=f"Parent directory does not exist: {project_dir.parent}",
            details={"path": str(path_str)}
        )

    # Create project structure
    try:
        project_dir.mkdir(parents=True, exist_ok=False)
        (project_dir / "captures").mkdir(exist_ok=True)
        (project_dir / "blobs").mkdir(exist_ok=True)
        (project_dir / "interpretations").mkdir(exist_ok=True)
        (project_dir / "corpora").mkdir(exist_ok=True)
        (project_dir / "action_log").mkdir(exist_ok=True)
        (project_dir / "reports").mkdir(exist_ok=True)
        (project_dir / "logs").mkdir(exist_ok=True)

        manifest = create_manifest(project_dir)
        init_db(project_dir)
        db_version = get_user_version(init_db(project_dir))  # re-open to get version

        return jsonify({
            "id": project_dir.name,
            "path": str(project_dir),
            "manifest": manifest,
            "db_user_version": db_version,
        }), 201
    except FileExistsError:
        raise ValidationError(
            code="PROJECT_EXISTS",
            message=f"Project already exists at {project_dir}",
            details={"path": str(project_dir)}
        )
    except Exception as e:
        raise ValidationError(
            code="CREATE_FAILED",
            message=f"Failed to create project: {e}",
            details={"path": str(project_dir)}
        )


@bp.route("/projects/<project_id>", methods=["GET"])
def get_project(project_id: str):
    """GET /api/projects/<id>
    Возвращает манифест и метаданные проекта.
    """
    project_dir = _get_project_dir()
    # For now, project_id must match the project directory name
    if project_dir.name != project_id:
        raise ProjectNotFoundError(
            code="PROJECT_NOT_FOUND",
            message=f"Project '{project_id}' not found",
            details={"project_id": project_id}
        )

    try:
        manifest = load_manifest(project_dir)
        from .store import open_db
        conn = open_db(project_dir)
        db_version = get_user_version(conn)
        conn.close()

        return jsonify({
            "id": project_id,
            "path": str(project_dir),
            "manifest": manifest,
            "db_user_version": db_version,
        })
    except FileNotFoundError:
        raise ProjectNotFoundError(
            code="PROJECT_NOT_FOUND",
            message=f"Project '{project_id}' not found",
            details={"project_id": project_id}
        )
    except ValueError as e:
        raise ValidationError(
            code="INVALID_MANIFEST",
            message=str(e),
            details={"project_id": project_id}
        )