"""
Tests for threat intelligence integration (OSV.dev).

Covers:
  - ThreatIntelChecker query, parsing, severity mapping
  - VULN-001 / VULN-002 signal generation
  - Ecosystem mapping
  - Error handling and disabled state
  - Analyzer integration with threat_intel weight
"""

from unittest.mock import MagicMock, patch

import pytest

from uast.threat_intel import ThreatIntelChecker, ECOSYSTEM_MAP


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_checker(enabled=True, cache_ttl=300):
    config = {"threat_intel": {"enabled": enabled, "cache_ttl": cache_ttl}}
    return ThreatIntelChecker(config)


def _mock_osv_response(vulns):
    """Create a mock HTTP response with given vulnerabilities."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"vulns": vulns}
    return resp


def _make_vuln(
    vuln_id="GHSA-1234",
    summary="Test vulnerability",
    severity_type="CVSS_V3",
    severity_score="9.8",
    fixed_in=None,
    db_severity=None,
):
    vuln = {
        "id": vuln_id,
        "summary": summary,
        "severity": [],
        "affected": [],
    }
    if severity_type and severity_score:
        vuln["severity"] = [{"type": severity_type, "score": severity_score}]
    if fixed_in:
        vuln["affected"] = [{
            "ranges": [{
                "events": [{"introduced": "0"}, {"fixed": fixed_in}]
            }]
        }]
    if db_severity:
        vuln["database_specific"] = {"severity": db_severity}
    return vuln


# ---------------------------------------------------------------------------
# ThreatIntelChecker unit tests
# ---------------------------------------------------------------------------

class TestThreatIntelChecker:

    def test_disabled_returns_empty(self):
        checker = _make_checker(enabled=False)
        signals, score, vulns = checker.check("requests", "pypi", "2.31.0")
        assert signals == []
        assert score == 0.0
        assert vulns == []

    def test_unsupported_ecosystem(self):
        checker = _make_checker()
        signals, score, vulns = checker.check("somepkg", "cargo", "1.0")
        assert signals == []

    def test_ecosystem_mapping(self):
        assert ECOSYSTEM_MAP["pypi"] == "PyPI"
        assert ECOSYSTEM_MAP["npm"] == "npm"

    def test_no_vulns_returns_empty(self):
        checker = _make_checker()
        with patch.object(checker._http, "post", return_value=_mock_osv_response([])):
            signals, score, vulns = checker.check("requests", "pypi", "2.31.0")
        assert signals == []
        assert score == 0.0
        assert vulns == []

    def test_single_critical_vuln(self):
        checker = _make_checker()
        vuln = _make_vuln(
            vuln_id="CVE-2023-1234",
            summary="Critical RCE vulnerability",
            severity_score="9.8",
            fixed_in="2.32.0",
        )
        with patch.object(checker._http, "post", return_value=_mock_osv_response([vuln])):
            signals, score, vulns = checker.check("requests", "pypi", "2.31.0")

        assert len(signals) == 1
        assert signals[0].signal_id == "VULN-001"
        assert signals[0].severity == "critical"
        assert score >= 0.9
        assert len(vulns) == 1
        assert vulns[0]["id"] == "CVE-2023-1234"
        assert vulns[0]["fixed_in"] == "2.32.0"

    def test_single_medium_vuln(self):
        checker = _make_checker()
        vuln = _make_vuln(
            vuln_id="CVE-2023-5678",
            summary="Medium severity issue",
            severity_score="5.0",
        )
        with patch.object(checker._http, "post", return_value=_mock_osv_response([vuln])):
            signals, score, vulns = checker.check("flask", "pypi", "3.0.0")

        assert len(signals) == 1
        assert signals[0].signal_id == "VULN-001"
        assert signals[0].severity == "medium"

    def test_multiple_vulns_triggers_vuln_002(self):
        checker = _make_checker()
        vulns_data = [
            _make_vuln(vuln_id=f"CVE-2023-{i}", severity_score="7.5")
            for i in range(4)
        ]
        with patch.object(checker._http, "post", return_value=_mock_osv_response(vulns_data)):
            signals, score, vulns = checker.check("old-lib", "pypi", "1.0.0")

        signal_ids = [s.signal_id for s in signals]
        assert "VULN-001" in signal_ids
        assert "VULN-002" in signal_ids
        assert score >= 0.95
        assert len(vulns) == 4

    def test_exactly_3_vulns_triggers_vuln_002(self):
        checker = _make_checker()
        vulns_data = [
            _make_vuln(vuln_id=f"GHSA-{i}", severity_score="4.0")
            for i in range(3)
        ]
        with patch.object(checker._http, "post", return_value=_mock_osv_response(vulns_data)):
            signals, score, vulns = checker.check("pkg", "npm", "1.0")

        signal_ids = [s.signal_id for s in signals]
        assert "VULN-002" in signal_ids

    def test_two_vulns_no_vuln_002(self):
        checker = _make_checker()
        vulns_data = [
            _make_vuln(vuln_id=f"CVE-2023-{i}", severity_score="8.0")
            for i in range(2)
        ]
        with patch.object(checker._http, "post", return_value=_mock_osv_response(vulns_data)):
            signals, score, vulns = checker.check("pkg", "pypi", "1.0")

        signal_ids = [s.signal_id for s in signals]
        assert "VULN-001" in signal_ids
        assert "VULN-002" not in signal_ids

    def test_api_error_returns_empty(self):
        checker = _make_checker()
        resp = MagicMock()
        resp.status_code = 500
        with patch.object(checker._http, "post", return_value=resp):
            signals, score, vulns = checker.check("pkg", "pypi", "1.0")
        assert signals == []

    def test_network_error_returns_empty(self):
        checker = _make_checker()
        with patch.object(checker._http, "post", side_effect=Exception("timeout")):
            signals, score, vulns = checker.check("pkg", "npm", "1.0")
        assert signals == []
        assert score == 0.0

    def test_npm_ecosystem_query(self):
        checker = _make_checker()
        vuln = _make_vuln(vuln_id="GHSA-npm-1", severity_score="7.0")
        mock_resp = _mock_osv_response([vuln])
        with patch.object(checker._http, "post", return_value=mock_resp) as mock_post:
            signals, score, vulns = checker.check("lodash", "npm", "4.17.20")

        # Verify correct ecosystem sent
        call_args = mock_post.call_args
        payload = call_args[1]["json"]
        assert payload["package"]["ecosystem"] == "npm"
        assert payload["package"]["name"] == "lodash"
        assert payload["version"] == "4.17.20"

    def test_pypi_ecosystem_query(self):
        checker = _make_checker()
        vuln = _make_vuln(vuln_id="PYSEC-1", severity_score="6.0")
        mock_resp = _mock_osv_response([vuln])
        with patch.object(checker._http, "post", return_value=mock_resp) as mock_post:
            signals, score, vulns = checker.check("flask", "pypi", "2.3.0")

        call_args = mock_post.call_args
        payload = call_args[1]["json"]
        assert payload["package"]["ecosystem"] == "PyPI"

    def test_no_version_query(self):
        checker = _make_checker()
        mock_resp = _mock_osv_response([])
        with patch.object(checker._http, "post", return_value=mock_resp) as mock_post:
            checker.check("pkg", "pypi")

        call_args = mock_post.call_args
        payload = call_args[1]["json"]
        assert "version" not in payload

    def test_fixed_version_extraction(self):
        checker = _make_checker()
        vuln = _make_vuln(
            vuln_id="CVE-FIX",
            severity_score="8.0",
            fixed_in="3.0.1",
        )
        with patch.object(checker._http, "post", return_value=_mock_osv_response([vuln])):
            signals, score, vulns = checker.check("pkg", "pypi", "3.0.0")
        assert vulns[0]["fixed_in"] == "3.0.1"

    def test_no_fixed_version(self):
        checker = _make_checker()
        vuln = _make_vuln(vuln_id="CVE-NOFIX", severity_score="7.0")
        with patch.object(checker._http, "post", return_value=_mock_osv_response([vuln])):
            signals, score, vulns = checker.check("pkg", "pypi", "1.0")
        assert vulns[0]["fixed_in"] is None


class TestSeverityMapping:

    def test_critical_cvss(self):
        checker = _make_checker()
        vuln = _make_vuln(severity_score="9.5")
        parsed = checker._parse_vuln(vuln)
        assert parsed["severity"] == "critical"

    def test_high_cvss(self):
        checker = _make_checker()
        vuln = _make_vuln(severity_score="7.5")
        parsed = checker._parse_vuln(vuln)
        assert parsed["severity"] == "high"

    def test_medium_cvss(self):
        checker = _make_checker()
        vuln = _make_vuln(severity_score="5.0")
        parsed = checker._parse_vuln(vuln)
        assert parsed["severity"] == "medium"

    def test_low_cvss(self):
        checker = _make_checker()
        vuln = _make_vuln(severity_score="2.0")
        parsed = checker._parse_vuln(vuln)
        assert parsed["severity"] == "low"

    def test_cvss_vector_string_high_impact(self):
        checker = _make_checker()
        vuln = _make_vuln(
            severity_score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        parsed = checker._parse_vuln(vuln)
        assert parsed["severity"] == "critical"

    def test_cvss_vector_string_low_impact(self):
        checker = _make_checker()
        vuln = _make_vuln(
            severity_score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        )
        parsed = checker._parse_vuln(vuln)
        assert parsed["severity"] == "medium"

    def test_database_specific_severity(self):
        checker = _make_checker()
        vuln = _make_vuln(severity_type=None, severity_score=None, db_severity="HIGH")
        parsed = checker._parse_vuln(vuln)
        assert parsed["severity"] == "high"

    def test_unknown_severity(self):
        checker = _make_checker()
        vuln = _make_vuln(severity_type=None, severity_score=None)
        parsed = checker._parse_vuln(vuln)
        assert parsed["severity"] == "unknown"

    def test_max_severity_across_vulns(self):
        checker = _make_checker()
        assert checker._max_severity([
            {"severity": "low"},
            {"severity": "critical"},
            {"severity": "medium"},
        ]) == "critical"

    def test_max_severity_empty(self):
        checker = _make_checker()
        assert checker._max_severity([]) == "unknown"

    def test_severity_to_score_critical(self):
        checker = _make_checker()
        assert checker._severity_to_score("critical") == 0.95

    def test_severity_to_score_high(self):
        checker = _make_checker()
        assert checker._severity_to_score("high") == 0.75

    def test_severity_to_score_medium(self):
        checker = _make_checker()
        assert checker._severity_to_score("medium") == 0.55

    def test_severity_to_score_low(self):
        checker = _make_checker()
        assert checker._severity_to_score("low") == 0.35


class TestAnalyzerThreatIntelIntegration:
    """Test that threat_intel integrates properly with SupplyChainAnalyzer."""

    def test_weight_exists(self):
        from uast.analyzer import SupplyChainAnalyzer
        assert "threat_intel" in SupplyChainAnalyzer.WEIGHTS
        assert SupplyChainAnalyzer.WEIGHTS["threat_intel"] == 0.08

    def test_weights_sum_to_one(self):
        from uast.analyzer import SupplyChainAnalyzer
        total = sum(SupplyChainAnalyzer.WEIGHTS.values())
        assert abs(total - 1.0) < 0.001

    def test_analysis_result_has_threat_intel_field(self):
        from uast.analyzer import AnalysisResult
        result = AnalysisResult(
            package_name="test",
            ecosystem="pypi",
            version="1.0",
            ars_score=0.0,
            cvss_base=0.0,
        )
        assert result.threat_intel is None

    @patch("uast.analyzer.http_client")
    def test_pypi_analysis_calls_threat_intel(self, mock_http):
        from uast.analyzer import SupplyChainAnalyzer

        # Mock PyPI response
        pypi_resp = MagicMock()
        pypi_resp.status_code = 200
        pypi_resp.json.return_value = {
            "info": {
                "version": "1.0.0",
                "author": "test",
                "author_email": "a@b.com",
                "summary": "A test package description here",
                "license": "MIT",
                "home_page": "https://github.com/test/test",
                "project_urls": {"Source": "https://github.com/test/test"},
                "requires_dist": [],
                "classifiers": ["License :: OSI Approved :: MIT License"],
            },
            "releases": {"1.0.0": [{"upload_time": "2020-01-01T00:00:00"}]},
        }
        # Mock download stats
        stats_resp = MagicMock()
        stats_resp.status_code = 200
        stats_resp.json.return_value = {"data": {"last_week": 50000}}

        mock_http.get.return_value = pypi_resp
        mock_http.head.return_value = MagicMock(status_code=200)

        analyzer = SupplyChainAnalyzer(
            config={"threat_intel": {"enabled": False}},
        )
        result = analyzer.analyze_pypi("some-test-package-xyz")

        # With threat_intel disabled, no VULN signals
        vuln_signals = [s for s in result.signals if s.signal_id.startswith("VULN")]
        assert len(vuln_signals) == 0

    @patch("uast.analyzer.http_client")
    def test_npm_analysis_calls_threat_intel(self, mock_http):
        from uast.analyzer import SupplyChainAnalyzer

        npm_resp = MagicMock()
        npm_resp.status_code = 200
        npm_resp.json.return_value = {
            "name": "test-pkg-xyz",
            "description": "A test npm package for testing",
            "dist-tags": {"latest": "1.0.0"},
            "versions": {
                "1.0.0": {
                    "license": "MIT",
                    "dependencies": {},
                }
            },
            "time": {"created": "2020-01-01T00:00:00Z"},
            "author": {"name": "tester"},
            "maintainers": [{"name": "tester", "email": "t@t.com"}],
            "repository": {"url": "https://github.com/test/test"},
        }
        stats_resp = MagicMock()
        stats_resp.status_code = 200
        stats_resp.json.return_value = {"downloads": 50000}

        mock_http.get.return_value = npm_resp
        mock_http.head.return_value = MagicMock(status_code=200)

        analyzer = SupplyChainAnalyzer(
            config={"threat_intel": {"enabled": False}},
        )
        result = analyzer.analyze_npm("test-pkg-xyz")
        vuln_signals = [s for s in result.signals if s.signal_id.startswith("VULN")]
        assert len(vuln_signals) == 0


class TestReporterThreatIntel:
    """Test that reporter includes threat_intel field."""

    def test_reporter_includes_threat_intel(self, tmp_path):
        import json
        from uast.reporter import SessionReporter
        from uast.analyzer import AnalysisResult

        reporter = SessionReporter(
            agent="test",
            project="/test",
            output_path=tmp_path / "report.json",
        )
        result = AnalysisResult(
            package_name="vuln-pkg",
            ecosystem="pypi",
            version="1.0",
            ars_score=8.0,
            cvss_base=7.0,
            threat_intel={
                "vulnerabilities": [
                    {"id": "CVE-2023-1", "summary": "Test", "severity": "high", "fixed_in": "2.0"}
                ],
                "source": "osv.dev",
            },
        )
        reporter.add_result(result, "test")
        path = reporter.save()
        with open(path) as f:
            data = json.load(f)
        assert data["version"] == "4"
        ti = data["results"][0]["threat_intel"]
        assert ti["source"] == "osv.dev"
        assert len(ti["vulnerabilities"]) == 1
        assert ti["vulnerabilities"][0]["id"] == "CVE-2023-1"
