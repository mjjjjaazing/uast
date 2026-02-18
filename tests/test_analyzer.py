"""
Tests for the uast supply chain analyzer.

Run with: pytest
"""

import pytest
from uast.analyzer import SupplyChainAnalyzer, PYPI_SAFE, NPM_SAFE


class TestSupplyChainAnalyzer:

    def setup_method(self):
        self.analyzer = SupplyChainAnalyzer()

    # ── Allowlist tests ──────────────────────────────────────────────────────

    def test_known_safe_pypi_package(self):
        result = self.analyzer.analyze_pypi("requests")
        assert result.verdict == "clean"
        assert result.ars_score == 0.0
        assert any(s.signal_id == "ALLOW-001" for s in result.signals)

    def test_known_safe_npm_package(self):
        result = self.analyzer.analyze_npm("lodash")
        assert result.verdict == "clean"
        assert result.ars_score == 0.0

    # ── Name squatting detection ─────────────────────────────────────────────

    def test_detects_high_similarity_typosquatting(self):
        # "requestss" is highly similar to "requests"
        result_signals = self.analyzer._check_name_squatting("requestss", list(PYPI_SAFE))
        signal, contribution = result_signals
        assert signal is not None
        assert "SQUAT" in signal.signal_id
        assert contribution >= 0.6

    def test_no_squatting_on_exact_match(self):
        # Exact match should NOT be flagged as squatting
        signal, contribution = self.analyzer._check_name_squatting("requests", ["requests"])
        assert signal is None
        assert contribution == 0.0

    def test_no_squatting_on_dissimilar_name(self):
        signal, contribution = self.analyzer._check_name_squatting("zxcvbn", ["requests"])
        assert signal is None

    # ── Pattern matching ─────────────────────────────────────────────────────

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

    # ── Metadata quality ─────────────────────────────────────────────────────

    def test_sparse_metadata_flagged(self):
        sparse = {"summary": "", "author": "", "author_email": "", "home_page": "", "license": ""}
        signal, contribution = self.analyzer._check_metadata_quality(sparse)
        assert signal is not None
        assert contribution > 0.0

    def test_complete_metadata_passes(self):
        complete = {
            "summary": "A well documented package for doing useful things",
            "author": "Jane Smith",
            "author_email": "jane@example.com",
            "home_page": "https://github.com/jane/pkg",
            "license": "MIT",
        }
        signal, contribution = self.analyzer._check_metadata_quality(complete)
        assert signal is None

    # ── Dependency depth ─────────────────────────────────────────────────────

    def test_high_dep_count_flagged(self):
        deps = [f"dep{i}" for i in range(30)]
        signal, contribution = self.analyzer._check_dependency_depth(deps)
        assert signal is not None
        assert signal.signal_id == "DEPTH-001"

    def test_normal_dep_count_passes(self):
        deps = ["requests", "click", "pydantic"]
        signal, contribution = self.analyzer._check_dependency_depth(deps)
        assert signal is None

    # ── Verdict computation ──────────────────────────────────────────────────

    def test_critical_verdict_on_high_score(self):
        verdict, avt, rec = self.analyzer._compute_verdict(8.5, [])
        assert verdict == "critical"

    def test_suspicious_verdict_on_medium_score(self):
        verdict, avt, rec = self.analyzer._compute_verdict(6.0, [])
        assert verdict == "suspicious"

    def test_clean_verdict_on_low_score(self):
        verdict, avt, rec = self.analyzer._compute_verdict(2.0, [])
        assert verdict == "clean"

    # ── Analysis result properties ───────────────────────────────────────────

    def test_is_flagged_property(self):
        from uast.analyzer import AnalysisResult
        result = AnalysisResult("pkg", "pypi", "1.0", 8.0, 7.0, verdict="critical")
        assert result.is_flagged is True

        result2 = AnalysisResult("pkg", "pypi", "1.0", 1.0, 0.5, verdict="clean")
        assert result2.is_flagged is False
