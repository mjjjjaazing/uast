"""
Tests for the UAST web dashboard.

Covers:
  - App factory and configuration
  - Session listing endpoint
  - Session detail endpoint
  - Package detail endpoint
  - API endpoints (JSON)
  - Security: path traversal prevention, headers
  - Edge cases: empty dir, missing files, malformed JSON
"""

import json
from pathlib import Path

import pytest

from uast.dashboard.app import _is_safe_filename, _list_sessions, _load_session, create_app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def sessions_dir(tmp_path):
    """Create a temp directory with sample session files."""
    d = tmp_path / "sessions"
    d.mkdir()

    session1 = {
        "agent": "cursor",
        "project": "/home/user/app",
        "started_at": "2025-01-15T10:00:00",
        "schema_version": "4",
        "summary": {
            "total_packages": 5,
            "alerts": 2,
            "critical": 1,
            "suspicious": 1,
            "max_ars_score": 8.5,
        },
        "results": [
            {
                "package_name": "evil-pkg",
                "ecosystem": "pypi",
                "version": "1.0.0",
                "ars_score": 8.5,
                "cvss_base": 7.0,
                "verdict": "critical",
                "recommendation": "Do not install.",
                "signals": [
                    {
                        "signal_id": "AGE-001",
                        "severity": "high",
                        "title": "Very new package",
                        "detail": "Package is 2 days old.",
                        "score_contribution": 0.85,
                    }
                ],
                "arsm": {"ars": 8.5, "aal": 0.7, "cis": 1.0, "arsm": 8.9},
                "threat_intel": None,
                "provenance": None,
            },
            {
                "package_name": "safe-pkg",
                "ecosystem": "pypi",
                "version": "2.0.0",
                "ars_score": 1.0,
                "cvss_base": 0.0,
                "verdict": "clean",
                "recommendation": "No issues found.",
                "signals": [],
                "arsm": None,
                "threat_intel": None,
                "provenance": None,
            },
        ],
    }

    session2 = {
        "agent": "claude-code",
        "project": "/home/user/other",
        "started_at": "2025-01-16T14:30:00",
        "schema_version": "4",
        "summary": {
            "total_packages": 3,
            "alerts": 0,
            "critical": 0,
            "suspicious": 0,
            "max_ars_score": 2.0,
        },
        "results": [],
    }

    (d / "session_20250115_100000.json").write_text(json.dumps(session1))
    (d / "session_20250116_143000.json").write_text(json.dumps(session2))

    return d


@pytest.fixture()
def app(sessions_dir):
    """Create Flask test app."""
    application = create_app(sessions_dir=sessions_dir)
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    """Flask test client."""
    return app.test_client()


# ---------------------------------------------------------------------------
# Filename validation
# ---------------------------------------------------------------------------

class TestFilenameValidation:

    def test_safe_filenames(self):
        assert _is_safe_filename("session_20250115_100000.json") is True
        assert _is_safe_filename("test-file.json") is True
        assert _is_safe_filename("abc123.json") is True

    def test_reject_path_traversal(self):
        assert _is_safe_filename("../etc/passwd") is False
        assert _is_safe_filename("../../secret.json") is False
        assert _is_safe_filename("..%2F..%2Fetc%2Fpasswd") is False

    def test_reject_non_json(self):
        assert _is_safe_filename("file.txt") is False
        assert _is_safe_filename("file.py") is False
        assert _is_safe_filename("file") is False

    def test_reject_absolute_paths(self):
        assert _is_safe_filename("/etc/passwd") is False
        assert _is_safe_filename("/tmp/session.json") is False

    def test_reject_empty(self):
        assert _is_safe_filename("") is False

    def test_reject_spaces_and_special(self):
        assert _is_safe_filename("file name.json") is False
        assert _is_safe_filename("file;rm.json") is False


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

class TestDataHelpers:

    def test_list_sessions(self, sessions_dir):
        items = _list_sessions(sessions_dir)
        assert len(items) == 2
        # Sorted reverse by name, so session2 first
        assert items[0]["filename"] == "session_20250116_143000.json"
        assert items[1]["filename"] == "session_20250115_100000.json"
        assert items[1]["alerts"] == 2
        assert items[1]["critical"] == 1

    def test_list_sessions_empty_dir(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        items = _list_sessions(empty)
        assert items == []

    def test_list_sessions_nonexistent_dir(self, tmp_path):
        items = _list_sessions(tmp_path / "nope")
        assert items == []

    def test_load_session(self, sessions_dir):
        data = _load_session(sessions_dir, "session_20250115_100000.json")
        assert data is not None
        assert data["agent"] == "cursor"
        assert len(data["results"]) == 2

    def test_load_session_not_found(self, sessions_dir):
        data = _load_session(sessions_dir, "nonexistent.json")
        assert data is None

    def test_load_session_unsafe_name(self, sessions_dir):
        data = _load_session(sessions_dir, "../etc/passwd")
        assert data is None

    def test_load_session_malformed_json(self, sessions_dir):
        (sessions_dir / "bad.json").write_text("{invalid json")
        data = _load_session(sessions_dir, "bad.json")
        assert data is None


# ---------------------------------------------------------------------------
# HTML routes
# ---------------------------------------------------------------------------

class TestHTMLRoutes:

    def test_index_redirects_to_sessions(self, client):
        resp = client.get("/")
        assert resp.status_code == 302
        assert "/sessions" in resp.headers["Location"]

    def test_sessions_list(self, client):
        resp = client.get("/sessions")
        assert resp.status_code == 200
        assert b"Session History" in resp.data
        assert b"session_20250115_100000.json" in resp.data
        assert b"cursor" in resp.data

    def test_sessions_list_empty(self, tmp_path):
        empty = tmp_path / "empty_sessions"
        empty.mkdir()
        application = create_app(sessions_dir=empty)
        application.config["TESTING"] = True
        c = application.test_client()
        resp = c.get("/sessions")
        assert resp.status_code == 200
        assert b"No sessions found" in resp.data

    def test_session_detail(self, client):
        resp = client.get("/sessions/session_20250115_100000.json")
        assert resp.status_code == 200
        assert b"evil-pkg" in resp.data
        assert b"safe-pkg" in resp.data
        assert b"critical" in resp.data

    def test_session_detail_not_found(self, client):
        resp = client.get("/sessions/nonexistent.json")
        assert resp.status_code == 404

    def test_session_detail_path_traversal(self, client):
        resp = client.get("/sessions/..%2F..%2Fetc%2Fpasswd")
        assert resp.status_code == 404

    def test_package_detail(self, client):
        resp = client.get("/sessions/session_20250115_100000.json/pkg/0")
        assert resp.status_code == 200
        assert b"evil-pkg" in resp.data
        assert b"AGE-001" in resp.data
        assert b"Very new package" in resp.data

    def test_package_detail_second_package(self, client):
        resp = client.get("/sessions/session_20250115_100000.json/pkg/1")
        assert resp.status_code == 200
        assert b"safe-pkg" in resp.data

    def test_package_detail_index_out_of_range(self, client):
        resp = client.get("/sessions/session_20250115_100000.json/pkg/99")
        assert resp.status_code == 404

    def test_package_detail_negative_index(self, client):
        resp = client.get("/sessions/session_20250115_100000.json/pkg/-1")
        assert resp.status_code == 404

    def test_package_detail_session_not_found(self, client):
        resp = client.get("/sessions/nonexistent.json/pkg/0")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

class TestAPIRoutes:

    def test_api_sessions_list(self, client):
        resp = client.get("/api/sessions")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 2
        assert data[0]["filename"] == "session_20250116_143000.json"

    def test_api_session_detail(self, client):
        resp = client.get("/api/sessions/session_20250115_100000.json")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["agent"] == "cursor"
        assert len(data["results"]) == 2

    def test_api_session_not_found(self, client):
        resp = client.get("/api/sessions/nonexistent.json")
        assert resp.status_code == 404

    def test_api_session_path_traversal(self, client):
        resp = client.get("/api/sessions/../../../etc/passwd")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

class TestSecurityHeaders:

    def test_nosniff_header(self, client):
        resp = client.get("/sessions")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_frame_deny_header(self, client):
        resp = client.get("/sessions")
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_xss_protection_header(self, client):
        resp = client.get("/sessions")
        assert resp.headers.get("X-XSS-Protection") == "1; mode=block"

    def test_headers_on_api_routes(self, client):
        resp = client.get("/api/sessions")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_headers_on_404(self, client):
        resp = client.get("/sessions/nonexistent.json")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

class TestAppFactory:

    def test_create_app_default_sessions_dir(self):
        application = create_app()
        assert application.config["SESSIONS_DIR"] == Path.home() / ".uast" / "sessions"

    def test_create_app_custom_sessions_dir(self, tmp_path):
        application = create_app(sessions_dir=tmp_path)
        assert application.config["SESSIONS_DIR"] == tmp_path

    def test_app_serves_static_css(self, client):
        resp = client.get("/static/style.css")
        assert resp.status_code == 200
        assert b"--bg-primary" in resp.data
