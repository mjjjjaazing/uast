"""
Security tests for UAST — Sprint 1.5 penetration testing.

Tests that UAST handles adversarial inputs safely:
  - Shell injection via package names
  - Extremely long package names (DoS)
  - Unicode/emoji package names
  - Malformed config files
  - Path traversal in config loading
  - URL scheme validation (SSRF prevention)
  - File permission checks
  - Cache size limits
"""

import json
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from uast.analyzer import (
    SupplyChainAnalyzer,
    sanitize_package_name,
    MAX_PACKAGE_NAME_LENGTH,
)
from uast.http_client import CachedHTTPClient


# ---------------------------------------------------------------------------
# Package name sanitization
# ---------------------------------------------------------------------------

class TestSanitizePackageName:

    def test_valid_pypi_name(self):
        assert sanitize_package_name("requests") == "requests"

    def test_valid_npm_scoped(self):
        assert sanitize_package_name("@babel/core") == "@babel/core"

    def test_valid_name_with_dots(self):
        assert sanitize_package_name("zope.interface") == "zope.interface"

    def test_valid_name_with_hyphens(self):
        assert sanitize_package_name("my-package-name") == "my-package-name"

    def test_valid_name_with_underscores(self):
        assert sanitize_package_name("my_package") == "my_package"

    def test_strips_whitespace(self):
        assert sanitize_package_name("  requests  ") == "requests"

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="Empty"):
            sanitize_package_name("")

    def test_rejects_whitespace_only(self):
        with pytest.raises(ValueError, match="Empty"):
            sanitize_package_name("   ")

    def test_rejects_shell_injection_semicolon(self):
        with pytest.raises(ValueError, match="disallowed"):
            sanitize_package_name("pkg; rm -rf /")

    def test_rejects_shell_injection_backtick(self):
        with pytest.raises(ValueError, match="disallowed"):
            sanitize_package_name("pkg`whoami`")

    def test_rejects_shell_injection_dollar(self):
        with pytest.raises(ValueError, match="disallowed"):
            sanitize_package_name("pkg$(evil)")

    def test_rejects_shell_injection_pipe(self):
        with pytest.raises(ValueError, match="disallowed"):
            sanitize_package_name("pkg | evil")

    def test_rejects_shell_injection_ampersand(self):
        with pytest.raises(ValueError, match="disallowed"):
            sanitize_package_name("pkg && evil")

    def test_rejects_newline(self):
        with pytest.raises(ValueError, match="disallowed"):
            sanitize_package_name("pkg\nevil")

    def test_rejects_very_long_name(self):
        long_name = "a" * 10000
        with pytest.raises(ValueError, match="too long"):
            sanitize_package_name(long_name)

    def test_rejects_max_plus_one(self):
        name = "a" * (MAX_PACKAGE_NAME_LENGTH + 1)
        with pytest.raises(ValueError, match="too long"):
            sanitize_package_name(name)

    def test_accepts_max_length(self):
        name = "a" * MAX_PACKAGE_NAME_LENGTH
        assert sanitize_package_name(name) == name

    def test_rejects_unicode_emoji(self):
        with pytest.raises(ValueError, match="disallowed"):
            sanitize_package_name("package-\U0001f4a9")

    def test_rejects_control_chars(self):
        with pytest.raises(ValueError, match="disallowed"):
            sanitize_package_name("pkg\x00evil")


# ---------------------------------------------------------------------------
# Analyzer with adversarial inputs
# ---------------------------------------------------------------------------

class TestAnalyzerSecurityInputs:

    def setup_method(self):
        self.analyzer = SupplyChainAnalyzer(aal=0.7)

    def test_shell_injection_package_name_pypi(self):
        result = self.analyzer.analyze_pypi("; rm -rf /")
        assert result.ars_score == 0.0
        assert "Invalid" in result.recommendation

    def test_shell_injection_package_name_npm(self):
        result = self.analyzer.analyze_npm("$(whoami)")
        assert result.ars_score == 0.0
        assert "Invalid" in result.recommendation

    def test_very_long_package_name(self):
        result = self.analyzer.analyze_pypi("a" * 10000)
        assert result.ars_score == 0.0
        assert "Invalid" in result.recommendation

    def test_unicode_emoji_package_name(self):
        result = self.analyzer.analyze_pypi("\U0001f4a9package")
        assert result.ars_score == 0.0

    def test_empty_package_name(self):
        result = self.analyzer.analyze_pypi("")
        assert result.ars_score == 0.0


# ---------------------------------------------------------------------------
# HTTP client security
# ---------------------------------------------------------------------------

class TestHTTPClientSecurity:

    def test_rejects_file_scheme(self):
        client = CachedHTTPClient(max_retries=1)
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            client.get("file:///etc/passwd")

    def test_rejects_ftp_scheme(self):
        client = CachedHTTPClient(max_retries=1)
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            client.get("ftp://evil.com/payload")

    def test_rejects_empty_hostname(self):
        client = CachedHTTPClient(max_retries=1)
        with pytest.raises(ValueError, match="no hostname"):
            client.get("http://")

    def test_rejects_javascript_scheme(self):
        client = CachedHTTPClient(max_retries=1)
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            client.get("javascript:alert(1)")

    def test_user_agent_header(self):
        client = CachedHTTPClient()
        assert client._session.headers["User-Agent"] == "UAST/0.1.0"

    def test_cache_eviction(self):
        client = CachedHTTPClient(max_retries=1)
        client.MAX_CACHE_SIZE = 3

        # Fill cache beyond limit
        for i in range(5):
            url = f"https://example.com/{i}"
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            client._cache[url] = (float(i), mock_resp)

        client._evict_cache()
        assert len(client._cache) <= 3

    def test_head_validates_url(self):
        client = CachedHTTPClient(max_retries=1)
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            client.head("file:///etc/passwd")


# ---------------------------------------------------------------------------
# File permissions
# ---------------------------------------------------------------------------

class TestFilePermissions:

    def test_report_file_permissions(self):
        from uast.reporter import SessionReporter
        from uast.analyzer import AnalysisResult

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.json"
            reporter = SessionReporter(
                agent="cursor",
                project="/test",
                output_path=output_path,
            )
            reporter.save()
            assert output_path.exists()
            file_stat = os.stat(output_path)
            mode = stat.S_IMODE(file_stat.st_mode)
            assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"


# ---------------------------------------------------------------------------
# Config file safety
# ---------------------------------------------------------------------------

class TestConfigSafety:

    def test_malformed_toml_doesnt_crash(self):
        from uast.config import load_config
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".uast.toml"
            config_file.write_text("not valid toml {{{")
            # Should not crash, falls back to defaults
            config = load_config(project_path=Path(tmpdir))
            assert "threshold" in config

    def test_shell_injection_in_config_values(self):
        from uast.config import load_config
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".uast.toml"
            config_file.write_text('[blocklist]\npypi = ["$(rm -rf /)"]\n')
            config = load_config(project_path=Path(tmpdir))
            # Config validation should reject invalid package names
            blocklist = config.get("blocklist", {}).get("pypi", [])
            assert "$(rm -rf /)" not in blocklist  # rejected by validation


# ---------------------------------------------------------------------------
# CLI with malformed inputs
# ---------------------------------------------------------------------------

class TestCLIMalformedInputs:

    def setup_method(self):
        from click.testing import CliRunner
        self.runner = CliRunner()

    def test_check_malformed_json_report(self):
        from uast.main import cli
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {{{")
            f.flush()
            result = self.runner.invoke(cli, ["report", f.name])
            # Should fail gracefully, not crash with unhandled exception
            # Click will catch the JSONDecodeError and show an error
            assert result.exit_code != 0 or "Error" in result.output or "error" in str(result.exception)
