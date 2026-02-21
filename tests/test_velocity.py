"""
Tests for release pattern analysis and velocity improvements.

Covers:
  - RELEASE-001: Single version packages
  - RELEASE-002: Rapid-fire releases
"""

from uast.analyzer import SupplyChainAnalyzer


class TestReleasePattern:

    def setup_method(self):
        self.analyzer = SupplyChainAnalyzer(aal=0.7)

    def test_single_version_flagged(self):
        releases = {
            "1.0.0": [{"upload_time": "2024-06-01T00:00:00"}],
        }
        signal, score = self.analyzer._check_release_pattern(releases, "test-pkg")
        assert signal is not None
        assert signal.signal_id == "RELEASE-001"
        assert "1 published version" in signal.detail

    def test_multiple_versions_not_flagged(self):
        releases = {
            "1.0.0": [{"upload_time": "2024-01-01T00:00:00"}],
            "1.1.0": [{"upload_time": "2024-03-01T00:00:00"}],
            "1.2.0": [{"upload_time": "2024-06-01T00:00:00"}],
        }
        signal, score = self.analyzer._check_release_pattern(releases, "test-pkg")
        assert signal is None

    def test_empty_releases_not_flagged(self):
        signal, score = self.analyzer._check_release_pattern({}, "test-pkg")
        assert signal is None

    def test_rapid_fire_releases_flagged(self):
        """Many versions published in a very short window."""
        releases = {
            "0.0.1": [{"upload_time": "2025-01-01T00:00:00"}],
            "0.0.2": [{"upload_time": "2025-01-01T06:00:00"}],
            "0.0.3": [{"upload_time": "2025-01-01T12:00:00"}],
            "0.0.4": [{"upload_time": "2025-01-02T00:00:00"}],
            "0.0.5": [{"upload_time": "2025-01-02T06:00:00"}],
            "0.0.6": [{"upload_time": "2025-01-02T12:00:00"}],
            "0.0.7": [{"upload_time": "2025-01-03T00:00:00"}],
        }
        signal, score = self.analyzer._check_release_pattern(releases, "spam-pkg")
        assert signal is not None
        assert signal.signal_id == "RELEASE-002"
        assert "rapid" in signal.title.lower() or "releases" in signal.title.lower()

    def test_normal_cadence_not_rapid(self):
        """Releases spread over weeks — normal cadence."""
        releases = {
            "1.0.0": [{"upload_time": "2024-01-01T00:00:00"}],
            "1.0.1": [{"upload_time": "2024-01-15T00:00:00"}],
            "1.1.0": [{"upload_time": "2024-02-01T00:00:00"}],
            "1.2.0": [{"upload_time": "2024-03-01T00:00:00"}],
        }
        signal, score = self.analyzer._check_release_pattern(releases, "normal-pkg")
        assert signal is None

    def test_two_versions_not_flagged(self):
        """Two versions is normal, not single-version or rapid."""
        releases = {
            "1.0.0": [{"upload_time": "2024-01-01T00:00:00"}],
            "1.0.1": [{"upload_time": "2024-02-01T00:00:00"}],
        }
        signal, score = self.analyzer._check_release_pattern(releases, "test-pkg")
        assert signal is None

    def test_missing_upload_times_handled(self):
        """Releases without upload_time should not crash."""
        releases = {
            "1.0.0": [{}],
            "1.1.0": [{}],
            "1.2.0": [{}],
        }
        signal, score = self.analyzer._check_release_pattern(releases, "test-pkg")
        # No timestamps to analyze, should not flag rapid-fire
        assert signal is None or signal.signal_id == "RELEASE-001"
