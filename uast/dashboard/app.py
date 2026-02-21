"""
Lightweight Flask dashboard for viewing UAST session reports.

Reads JSON session files from ~/.uast/sessions/ (configurable).
No database — pure file-based. Server-rendered with Jinja2.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

from flask import Flask, abort, jsonify, redirect, render_template, url_for

logger = logging.getLogger("uast.dashboard")

# ---------------------------------------------------------------------------
# Filename validation — prevent path traversal
# ---------------------------------------------------------------------------

_SAFE_FILENAME = re.compile(r"^[a-zA-Z0-9_\-]+\.json$")


def _is_safe_filename(name: str) -> bool:
    """Reject filenames with path traversal or non-JSON extensions."""
    return bool(_SAFE_FILENAME.match(name)) and ".." not in name


# ---------------------------------------------------------------------------
# Session data helpers
# ---------------------------------------------------------------------------

def _load_session(sessions_dir: Path, filename: str) -> Optional[dict[str, Any]]:
    """Load a single session JSON file safely."""
    if not _is_safe_filename(filename):
        return None

    filepath = sessions_dir / filename
    if not filepath.is_file():
        return None

    # Resolve to ensure no symlink escapes
    resolved = filepath.resolve()
    if not str(resolved).startswith(str(sessions_dir.resolve())):
        return None

    try:
        with open(resolved) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        logger.warning("Failed to load session file: %s", filename)
        return None


def _list_sessions(sessions_dir: Path) -> list[dict[str, Any]]:
    """List all session files with summary metadata."""
    sessions = []
    if not sessions_dir.is_dir():
        return sessions

    for path in sorted(sessions_dir.glob("*.json"), reverse=True):
        if not _is_safe_filename(path.name):
            continue
        try:
            with open(path) as f:
                data = json.load(f)
            summary = data.get("summary", {})
            sessions.append({
                "filename": path.name,
                "agent": data.get("agent", "unknown"),
                "project": data.get("project", "unknown"),
                "started_at": data.get("started_at", ""),
                "total_packages": summary.get("total_packages", 0),
                "alerts": summary.get("alerts", 0),
                "critical": summary.get("critical", 0),
                "suspicious": summary.get("suspicious", 0),
                "max_ars_score": summary.get("max_ars_score", 0.0),
            })
        except (json.JSONDecodeError, OSError):
            continue

    return sessions


# ---------------------------------------------------------------------------
# Flask app factory
# ---------------------------------------------------------------------------

def create_app(sessions_dir: Optional[Path] = None) -> Flask:
    """Create and configure the Flask dashboard app."""
    template_dir = Path(__file__).parent / "templates"
    static_dir = Path(__file__).parent / "static"

    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir),
    )

    if sessions_dir is None:
        sessions_dir = Path.home() / ".uast" / "sessions"

    app.config["SESSIONS_DIR"] = sessions_dir

    # Security headers
    @app.after_request
    def _security_headers(response):  # noqa: ANN001, ANN202
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response

    # -----------------------------------------------------------------------
    # Routes
    # -----------------------------------------------------------------------

    @app.route("/")
    def index():  # noqa: ANN202
        return redirect(url_for("sessions_list"))

    @app.route("/sessions")
    def sessions_list():  # noqa: ANN202
        items = _list_sessions(app.config["SESSIONS_DIR"])
        return render_template("sessions.html", sessions=items)

    @app.route("/sessions/<filename>")
    def session_detail(filename: str):  # noqa: ANN202
        data = _load_session(app.config["SESSIONS_DIR"], filename)
        if data is None:
            abort(404)
        results = data.get("results", [])
        summary = data.get("summary", {})
        return render_template(
            "session_detail.html",
            filename=filename,
            data=data,
            results=results,
            summary=summary,
        )

    @app.route("/sessions/<filename>/pkg/<int:index>")
    def package_detail(filename: str, index: int):  # noqa: ANN202
        data = _load_session(app.config["SESSIONS_DIR"], filename)
        if data is None:
            abort(404)
        results = data.get("results", [])
        if index < 0 or index >= len(results):
            abort(404)
        pkg = results[index]
        return render_template(
            "package_detail.html",
            filename=filename,
            pkg=pkg,
            index=index,
        )

    # -----------------------------------------------------------------------
    # API routes (JSON)
    # -----------------------------------------------------------------------

    @app.route("/api/sessions")
    def api_sessions():  # noqa: ANN202
        items = _list_sessions(app.config["SESSIONS_DIR"])
        return jsonify(items)

    @app.route("/api/sessions/<filename>")
    def api_session_detail(filename: str):  # noqa: ANN202
        data = _load_session(app.config["SESSIONS_DIR"], filename)
        if data is None:
            abort(404)
        return jsonify(data)

    return app
