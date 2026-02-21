"""
Tests for the uast supply chain analyzer.

Run with: pytest
"""

import pytest
from unittest.mock import patch, MagicMock
from uast.analyzer import (
    SupplyChainAnalyzer,
    AnalysisResult,
    ARSMContext,
    PackageSignal,
    PYPI_SAFE,
    NPM_SAFE,
    AGENT_AAL,
)


class TestSupplyChainAnalyzer:

    def setup_method(self):
        self.analyzer = SupplyChainAnalyzer()

    # -- Allowlist tests ------------------------------------------------------

    def test_known_safe_pypi_package(self):
        result = self.analyzer.analyze_pypi("requests")
        assert result.verdict == "clean"
        assert result.ars_score == 0.0
        assert any(s.signal_id == "ALLOW-001" for s in result.signals)

    def test_known_safe_npm_package(self):
        result = self.analyzer.analyze_npm("lodash")
        assert result.verdict == "clean"
        assert result.ars_score == 0.0

    # -- Name squatting detection ---------------------------------------------

    def test_detects_high_similarity_typosquatting(self):
        signal, contribution = self.analyzer._check_name_squatting("requestss", list(PYPI_SAFE))
        assert signal is not None
        assert "SQUAT" in signal.signal_id
        assert contribution >= 0.6

    def test_no_squatting_on_exact_match(self):
        signal, contribution = self.analyzer._check_name_squatting("requests", ["requests"])
        assert signal is None
        assert contribution == 0.0

    def test_no_squatting_on_dissimilar_name(self):
        signal, contribution = self.analyzer._check_name_squatting("zxcvbn", ["requests"])
        assert signal is None

    # -- Pattern matching -----------------------------------------------------

    def test_detects_suspicious_utils_pattern(self):
        signal, contribution = self.analyzer._check_name_patterns("request-utils-async")
        assert signal is not None
        assert signal.signal_id == "PATTERN-001"
        assert contribution > 0.0

    def test_detects_official_suffix_pattern(self):
        signal, contribution = self.analyzer._check_name_patterns("numpy-official")
        assert signal is not None

    def test_clean_name_passes_pattern(self):
        signal, contribution = self.analyzer._check_name_patterns("requests")
        assert signal is None

    # -- Metadata quality -----------------------------------------------------

    def test_sparse_metadata_flagged(self):
        sparse = {"summary": "", "author": "", "author_email": "", "home_page": "", "license": ""}
        signal, contribution = self.analyzer._check_metadata_quality(sparse)
        assert signal is not None
        assert contribution > 0.0

    @patch.object(SupplyChainAnalyzer, "_verify_repository_url", return_value=True)
    def test_complete_metadata_passes(self, mock_verify):
        complete = {
            "summary": "A well documented package for doing useful things",
            "author": "Jane Smith",
            "author_email": "jane@example.com",
            "home_page": "https://github.com/jane/pkg",
            "license": "MIT",
            "project_urls": None,
        }
        signal, contribution = self.analyzer._check_metadata_quality(complete)
        assert signal is None

    # -- Dependency depth (legacy method) -------------------------------------

    def test_high_dep_count_flagged(self):
        deps = [f"dep{i}" for i in range(30)]
        signal, contribution = self.analyzer._check_dependency_depth(deps)
        assert signal is not None
        assert signal.signal_id == "DEPTH-001"

    def test_normal_dep_count_passes(self):
        deps = ["requests", "click", "pydantic"]
        signal, contribution = self.analyzer._check_dependency_depth(deps)
        assert signal is None

    # -- Verdict computation --------------------------------------------------

    def test_critical_verdict_on_high_score(self):
        verdict, avt, rec = self.analyzer._compute_verdict(8.5, [])
        assert verdict == "critical"

    def test_suspicious_verdict_on_medium_score(self):
        verdict, avt, rec = self.analyzer._compute_verdict(6.0, [])
        assert verdict == "suspicious"

    def test_clean_verdict_on_low_score(self):
        verdict, avt, rec = self.analyzer._compute_verdict(2.0, [])
        assert verdict == "clean"

    def test_critical_verdict_on_critical_signal(self):
        signals = [PackageSignal("SQUAT-001", "critical", "test", "test", 0.95)]
        verdict, avt, rec = self.analyzer._compute_verdict(3.0, signals)
        assert verdict == "critical"

    # -- AVT classification ---------------------------------------------------

    def test_avt_d3_01_on_squatting(self):
        signals = [PackageSignal("SQUAT-001", "critical", "test", "test", 0.95)]
        _, avt, _ = self.analyzer._compute_verdict(8.0, signals)
        assert "AVT-D3-01" in avt

    def test_avt_d1_03_on_hallucination(self):
        signals = [PackageSignal("HALLUC-001", "critical", "test", "test", 0.9)]
        _, avt, _ = self.analyzer._compute_verdict(9.0, signals)
        assert "AVT-D1-03" in avt

    def test_avt_d3_02_on_payload(self):
        signals = [PackageSignal("PAYLOAD-001", "high", "test", "test", 0.7)]
        _, avt, _ = self.analyzer._compute_verdict(7.0, signals)
        assert "AVT-D3-02" in avt

    def test_avt_d3_04_on_depth_suspicious(self):
        signals = [PackageSignal("DEPTH-SUSP", "critical", "test", "test", 0.9)]
        _, avt, _ = self.analyzer._compute_verdict(8.0, signals)
        assert "AVT-D3-04" in avt

    # -- ARSM -----------------------------------------------------------------

    def test_arsm_zero_base_returns_zero(self):
        ctx = ARSMContext(aal=0.8, cis=1.0, pc=1.0, srf=0.0)
        assert self.analyzer._compute_arsm(0.0, ctx) == 0.0

    def test_arsm_increases_with_aal(self):
        ctx_low = ARSMContext(aal=0.3, cis=1.0, pc=1.0, srf=0.0)
        ctx_high = ARSMContext(aal=0.9, cis=1.0, pc=1.0, srf=0.0)
        base = 5.0
        assert self.analyzer._compute_arsm(base, ctx_high) > self.analyzer._compute_arsm(base, ctx_low)

    def test_arsm_increases_with_low_provenance(self):
        ctx_high_pc = ARSMContext(aal=0.5, cis=1.0, pc=0.9, srf=0.0)
        ctx_low_pc = ARSMContext(aal=0.5, cis=1.0, pc=0.2, srf=0.0)
        base = 5.0
        assert self.analyzer._compute_arsm(base, ctx_low_pc) > self.analyzer._compute_arsm(base, ctx_high_pc)

    def test_arsm_capped_at_10(self):
        ctx = ARSMContext(aal=1.0, cis=0.0, pc=0.0, srf=100.0)
        assert self.analyzer._compute_arsm(10.0, ctx) == 10.0

    # -- Agent AAL mapping ----------------------------------------------------

    def test_agent_aal_mapping(self):
        assert AGENT_AAL["cursor"] == 0.7
        assert AGENT_AAL["claude-code"] == 0.8
        assert AGENT_AAL["copilot"] == 0.5

    def test_analyzer_uses_aal(self):
        analyzer = SupplyChainAnalyzer(aal=0.8)
        assert analyzer.aal == 0.8

    # -- Hallucinated package detection ---------------------------------------

    def test_find_closest_package_pypi(self):
        result = self.analyzer._find_closest_package("reqeusts", "pypi")
        assert result == "requests"

    def test_find_closest_package_no_match(self):
        result = self.analyzer._find_closest_package("zzzzzzzzzzzzzzz", "pypi")
        assert result is None

    def test_handle_hallucinated_package(self):
        result = AnalysisResult("nonexistent-pkg", "pypi", "unknown", 0.0, 0.0)
        result = self.analyzer._handle_hallucinated_package(result, "nonexistent-pkg", "pypi")
        assert result.verdict == "critical"
        assert result.ars_score == 9.0
        assert any(s.signal_id == "HALLUC-001" for s in result.signals)
        assert "AVT-D1-03" in result.avt_classes

    def test_handle_hallucinated_package_with_suggestion(self):
        result = AnalysisResult("reqeusts", "pypi", "unknown", 0.0, 0.0)
        result = self.analyzer._handle_hallucinated_package(result, "reqeusts", "pypi")
        assert result.did_you_mean == "requests"

    # -- Provenance confidence ------------------------------------------------

    def test_provenance_full_metadata(self):
        info = {
            "home_page": "https://github.com/test/pkg",
            "author_email": "test@example.com",
            "classifiers": ["Development Status :: 5"],
            "license": "MIT",
        }
        pc = self.analyzer._estimate_provenance_confidence(info)
        assert pc > 0.7

    def test_provenance_empty_metadata(self):
        info = {}
        pc = self.analyzer._estimate_provenance_confidence(info)
        assert pc < 0.5

    # -- Repository URL verification ------------------------------------------

    def test_extract_repo_url_from_home_page(self):
        info = {"home_page": "https://github.com/test/pkg", "project_urls": None}
        url = self.analyzer._extract_repo_url(info)
        assert url == "https://github.com/test/pkg"

    def test_extract_repo_url_from_project_urls(self):
        info = {"home_page": "", "project_urls": {"Source": "https://github.com/test/pkg"}}
        url = self.analyzer._extract_repo_url(info)
        assert url == "https://github.com/test/pkg"

    def test_extract_repo_url_none(self):
        info = {"home_page": "", "project_urls": None}
        url = self.analyzer._extract_repo_url(info)
        assert url is None

    # -- Download velocity (mocked) -------------------------------------------

    @patch("uast.analyzer.http_client")
    def test_fetch_download_stats_pypi(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"last_week": 50000}}
        mock_client.get.return_value = mock_resp

        result = self.analyzer._fetch_download_stats("requests", "pypi")
        assert result == 50000

    @patch("uast.analyzer.http_client")
    def test_fetch_download_stats_failure(self, mock_client):
        import requests as req_lib
        mock_client.get.side_effect = req_lib.ConnectionError("timeout")
        result = self.analyzer._fetch_download_stats("requests", "pypi")
        assert result is None

    # -- Analysis result properties -------------------------------------------

    def test_is_flagged_property(self):
        result = AnalysisResult("pkg", "pypi", "1.0", 8.0, 7.0, verdict="critical")
        assert result.is_flagged is True

        result2 = AnalysisResult("pkg", "pypi", "1.0", 1.0, 0.5, verdict="clean")
        assert result2.is_flagged is False

    def test_analysis_result_has_arsm_field(self):
        result = AnalysisResult("pkg", "pypi", "1.0", 5.0, 4.0)
        assert result.arsm is None

    def test_analysis_result_has_did_you_mean_field(self):
        result = AnalysisResult("pkg", "pypi", "1.0", 5.0, 4.0)
        assert result.did_you_mean is None

    # -- Metadata quality with repo URL verification --------------------------

    @patch.object(SupplyChainAnalyzer, "_verify_repository_url", return_value=False)
    def test_metadata_flags_dead_repo_url(self, mock_verify):
        info = {
            "summary": "A well documented package for doing useful things",
            "author": "Jane Smith",
            "author_email": "jane@example.com",
            "home_page": "https://github.com/jane/nonexistent-repo",
            "license": "MIT",
            "project_urls": None,
        }
        signal, contribution = self.analyzer._check_metadata_quality(info)
        assert signal is not None
        assert "404" in signal.detail
        assert contribution >= 0.35

    # -- NPM metadata quality with repo verification --------------------------

    @patch.object(SupplyChainAnalyzer, "_verify_repository_url", return_value=False)
    def test_npm_metadata_flags_dead_repo_url(self, mock_verify):
        data = {
            "description": "A well documented package for useful stuff",
            "author": {"name": "Test Author"},
            "maintainers": [{"name": "test"}],
            "repository": {"url": "git+https://github.com/test/nonexistent.git"},
        }
        signal, contribution = self.analyzer._check_metadata_quality_npm(data)
        assert signal is not None
        assert "404" in signal.detail
