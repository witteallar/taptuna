"""CLI entry point: taptuna command."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def cmd_init(args: argparse.Namespace) -> int:
    """taptuna init --project <dir>"""
    from .manifest import create_manifest
    from .store import init_db
    from .errors import ProjectAlreadyExistsError

    project_dir = Path(args.project).resolve()
    try:
        # Create project directory structure
        project_dir.mkdir(parents=True, exist_ok=True)
        (project_dir / "captures").mkdir(exist_ok=True)
        (project_dir / "blobs").mkdir(exist_ok=True)
        (project_dir / "interpretations").mkdir(exist_ok=True)
        (project_dir / "corpora").mkdir(exist_ok=True)
        (project_dir / "action_log").mkdir(exist_ok=True)
        (project_dir / "reports").mkdir(exist_ok=True)
        (project_dir / "logs").mkdir(exist_ok=True)

        # Create manifest
        manifest = create_manifest(project_dir)
        # Initialize database
        init_db(project_dir)

        print(f"Project created at {project_dir}")
        print(f"  manifest.json: schema_version={manifest['schema_version']}, user_version={manifest['user_version']}")
        print(f"  tshark_version: {manifest['tshark_version']}")
        return 0
    except ProjectAlreadyExistsError as e:
        print(f"Error: {e.message}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_serve(args: argparse.Namespace) -> int:
    """taptuna serve --project <dir> [--port 5000]"""
    from .app import create_app

    project_dir = Path(args.project).resolve()
    if not (project_dir / "manifest.json").exists():
        print(f"Error: Project not found at {project_dir}", file=sys.stderr)
        return 1

    app = create_app(project_dir)
    print(f"Starting taptuna server on http://127.0.0.1:{args.port}")
    print(f"Project: {project_dir}")
    app.run(host="127.0.0.1", port=args.port, debug=False)
    return 0


def cmd_not_implemented(args: argparse.Namespace) -> int:
    """Stub for not-yet-implemented commands."""
    print("not implemented", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="taptuna", description="Protocol Laboratory")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = subparsers.add_parser("init", help="Create new project")
    p_init.add_argument("--project", required=True, help="Project directory")
    p_init.set_defaults(func=cmd_init)

    # serve
    p_serve = subparsers.add_parser("serve", help="Start web server")
    p_serve.add_argument("--project", required=True, help="Project directory")
    p_serve.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    p_serve.set_defaults(func=cmd_serve)

    # Stubs for remaining commands (ТЗ §11.3)
    stubs = [
        ("ingest", ["--project", "--input", "--no-copy"]),
        ("interp-add", ["--project", "--file"]),
        ("interp-apply", ["--project", "--session", "--direction", "--name", "--id", "--out"]),
        ("corpus-add", ["--project", "--name", "--file"]),
        ("corpus-list", ["--project"]),
        ("verify", ["--project", "--corpus", "--interpretation", "--interpretation-id", "--seed", "--out"]),
        ("runs", ["--project"]),
        ("results", ["--project", "--run", "--status", "--offset", "--limit", "--out"]),
        ("report", ["--project", "--run", "--format", "--out"]),
        ("action-add", ["--project", "--name", "--file"]),
        ("action-list", ["--project"]),
    ]

    for name, opts in stubs:
        p = subparsers.add_parser(name, help=f"{name} (not implemented)")
        for opt in opts:
            p.add_argument(opt)
        p.set_defaults(func=cmd_not_implemented)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())