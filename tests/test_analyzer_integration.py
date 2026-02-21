"""
Integration tests for the full analyze_pypi() and analyze_npm() pipelines.

Uses mocked HTTP responses to test the complete analysis flow including
ARSM scoring, signal generation, and verdict computation.
"""

import datetime
import json
from unittest.mock import patch, MagicMock, PropertyMock

import pytest
import requests

from uast.analyzer import SupplyChainAnalyzer, AnalysisResult, PYPI_SAFE, NPM_SAFE


def _mock_pypi_response(
    name="test-pkg",
    version="1.0.0",
    summary="A test package",
    author="Test Author",
    author_email="test@example.com",
    home_page="https://github.com/test/test-pkg",
    license_str="MIT",
    classifiers=None,
    requires_dist=None,
    first_upload_days_ago=365,
):
    """Build a mock PyPI JSON response."""
    upload_time = (
        datetime.datetime.utcnow() - datetime.timedelta(days=first_upload_days_ago)
    ).strftime("%Y-%m-%dT%H:%M:%S")

    data = {
        "info": {
            "name": name,
            "version": version,
            "summary": summary,
            "author": author,
            "author_email": author_email,
            "home_page": home_page,
            "license": license_str,
            "classifiers": classifiers or ["License :: OSI Approved :: MIT License"],
            "project_urls": {"Source": home_page} if home_page else {},
            "requires_dist": requires_dist or [],
        },
        "releases": {
            version: [{"upload_time": upload_time}],
        },
    }

    resp = MagicMock(spec=requests.Response)
    resp.status_code = 200
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    return resp


def _mock_npm_response(
    name="test-pkg",
    version="1.0.0",
    description="A test npm package",
    author=None,
    repository=None,
    maintainers=None,
    dependencies=None,
    created_days_ago=365,
):
    """Build a mock npm registry JSON response."""
    created = (
        datetime.datetime.utcnow() - datetime.timedelta(days=created_days_ago)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    data = {
        "name": name,
        "description": description,
        "dist-tags": {"latest": version},
        "versions": {
            version: {
                "license": "MIT",
                "dependencies": dependencies or {},
            }
        },
        "time": {"created": created},
        "author": author or {"name": "Test Author"},
        "maintainers": maintainers or [{"name": "testuser"}],
        "repository": repository or {"url": "git+https://github.com/test/test-pkg.git"},
    }

    resp = MagicMock(spec=requests.Response)
    resp.status_code = 200
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    return resp


def _mock_404_response():
    resp = MagicMock(spec=requests.Response)
    resp.status_code = 404
    return resp


def _mock_download_stats_response(downloads=100000):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = 200
    resp.json.return_value = {"data": {"last_week": downloads}, "downloads": downloads}
    return resp


class TestAnalyzePyPI:

    def setup_method(self):
        self.analyzer = SupplyChainAnalyzer(aal=0.7)

    @patch("uast.analyzer.http_client")
    def test_full_analysis_clean_old_package(self, mock_client):
        """A well-established package with good metadata should be clean."""
        mock_client.get.return_value = _mock_pypi_response(
            name="my-good-pkg",
            first_upload_days_ago=365,
        )
        mock_client.head.return_value = MagicMock(status_code=200)

        result = self.analyzer.analyze_pypi("my-good-pkg")
        assert result.package_name == "my-good-pkg"
        assert result.ecosystem == "pypi"
        assert result.version == "1.0.0"
        assert result.verdict in ("clean", "suspicious")
        assert result.arsm is not None
        assert result.arsm["aal"] == 0.7

    @patch("uast.analyzer.http_client")
    def test_full_analysis_new_package_flagged(self, mock_client):
        """A brand-new package (3 days old) should be flagged."""
        mock_client.get.side_effect = [
            # Main PyPI API call
            _mock_pypi_response(name="brand-new-pkg", first_upload_days_ago=3),
            # Download stats call
            _mock_download_stats_response(downloads=50),
            # Dependency resolver (not found)
            _mock_404_response(),
            # SRF download stats
            _mock_download_stats_response(downloads=50),
        ]
        mock_client.head.return_value = MagicMock(status_code=200)

        result = self.analyzer.analyze_pypi("brand-new-pkg")
        assert result.ars_score > 0
        assert any(s.signal_id.startswith("AGE") for s in result.signals)

    @patch("uast.analyzer.http_client")
    def test_hallucinated_package_404(self, mock_client):
        """A package that returns 404 should be detected as hallucinated."""
        mock_client.get.return_value = _mock_404_response()

        result = self.analyzer.analyze_pypi("totally-fake-package-xyz")
        assert result.verdict == "critical"
        assert result.ars_score == 9.0
        assert any(s.signal_id == "HALLUC-001" for s in result.signals)
        assert "AVT-D1-03" in result.avt_classes

    @patch("uast.analyzer.http_client")
    def test_network_error_handled(self, mock_client):
        """Network errors should be handled gracefully."""
        mock_client.get.side_effect = requests.ConnectionError("timeout")

        result = self.analyzer.analyze_pypi("unreachable-pkg")
        assert any(s.signal_id == "NET-001" for s in result.signals)

    @patch("uast.analyzer.http_client")
    def test_sparse_metadata_flagged(self, mock_client):
        """Package with missing metadata should get META-001 signal."""
        mock_client.get.return_value = _mock_pypi_response(
            name="sparse-pkg",
            summary="",
            author="",
            author_email="",
            home_page="",
            license_str="",
            first_upload_days_ago=365,
        )
        mock_client.head.return_value = MagicMock(status_code=200)

        result = self.analyzer.analyze_pypi("sparse-pkg")
        assert any(s.signal_id == "META-001" for s in result.signals)

    @patch("uast.analyzer.http_client")
    def test_arsm_fields_populated(self, mock_client):
        """The arsm field should contain all ARSM dimensions."""
        mock_client.get.return_value = _mock_pypi_response(
            name="scored-pkg", first_upload_days_ago=365
        )
        mock_client.head.return_value = MagicMock(status_code=200)

        result = self.analyzer.analyze_pypi("scored-pkg")
        assert result.arsm is not None
        assert "aal" in result.arsm
        assert "cis" in result.arsm
        assert "pc" in result.arsm
        assert "srf" in result.arsm
        assert "alpha" in result.arsm

    @patch("uast.analyzer.http_client")
    def test_deep_mode_triggers_payload_analysis(self, mock_client):
        """With deep=True, payload analysis should run."""
        analyzer = SupplyChainAnalyzer(aal=0.5, deep=True)
        mock_client.get.return_value = _mock_pypi_response(
            name="deep-pkg", first_upload_days_ago=365
        )
        mock_client.head.return_value = MagicMock(status_code=200)

        with patch.object(analyzer, "_check_payload", return_value=[]) as mock_payload:
            result = analyzer.analyze_pypi("deep-pkg")
            mock_payload.assert_called_once()


class TestAnalyzeNpm:

    def setup_method(self):
        self.analyzer = SupplyChainAnalyzer(aal=0.7)

    @patch("uast.analyzer.http_client")
    def test_full_npm_analysis_clean(self, mock_client):
        """An established npm package should be clean."""
        mock_client.get.return_value = _mock_npm_response(
            name="my-good-npm-pkg", created_days_ago=365
        )
        mock_client.head.return_value = MagicMock(status_code=200)

        result = self.analyzer.analyze_npm("my-good-npm-pkg")
        assert result.ecosystem == "npm"
        assert result.version == "1.0.0"
        assert result.arsm is not None

    @patch("uast.analyzer.http_client")
    def test_npm_404_hallucinated(self, mock_client):
        """npm 404 should be detected as hallucinated."""
        mock_client.get.return_value = _mock_404_response()

        result = self.analyzer.analyze_npm("fake-npm-pkg")
        assert result.verdict == "critical"
        assert any(s.signal_id == "HALLUC-001" for s in result.signals)

    @patch("uast.analyzer.http_client")
    def test_npm_new_package_flagged(self, mock_client):
        """A very new npm package should get AGE signal."""
        mock_client.get.side_effect = [
            _mock_npm_response(name="new-npm-pkg", created_days_ago=2),
            _mock_download_stats_response(50),
            _mock_404_response(),  # dependency resolution fallback
            _mock_download_stats_response(50),
        ]
        mock_client.head.return_value = MagicMock(status_code=200)

        result = self.analyzer.analyze_npm("new-npm-pkg")
        assert any(s.signal_id.startswith("AGE") for s in result.signals)

    @patch("uast.analyzer.http_client")
    def test_npm_sparse_metadata(self, mock_client):
        """npm package with sparse metadata should get flagged."""
        mock_client.get.return_value = _mock_npm_response(
            name="sparse-npm",
            description="",
            author=None,
            repository=None,
            maintainers=[],
            created_days_ago=365,
        )
        mock_client.head.return_value = MagicMock(status_code=200)

        result = self.analyzer.analyze_npm("sparse-npm")
        assert any(s.signal_id == "META-001" for s in result.signals)

    @patch("uast.analyzer.http_client")
    def test_npm_network_error(self, mock_client):
        """npm network errors should be handled gracefully."""
        mock_client.get.side_effect = requests.Timeout("timeout")

        result = self.analyzer.analyze_npm("timeout-npm-pkg")
        assert any(s.signal_id == "NET-001" for s in result.signals)


class TestProvenanceEstimation:

    def setup_method(self):
        self.analyzer = SupplyChainAnalyzer()

    def test_pypi_full_provenance(self):
        info = {
            "home_page": "https://github.com/test/test",
            "project_urls": {"Source": "https://github.com/test/test"},
            "author_email": "test@example.com",
            "classifiers": ["License :: MIT"],
            "license": "MIT",
        }
        pc = self.analyzer._estimate_provenance_confidence(info)
        assert pc > 0.7

    def test_pypi_empty_provenance(self):
        info = {}
        pc = self.analyzer._estimate_provenance_confidence(info)
        assert pc < 0.5

    def test_npm_full_provenance(self):
        data = {
            "repository": {"url": "https://github.com/test/test"},
            "author": {"name": "test"},
            "maintainers": [{"name": "test"}],
            "dist-tags": {"latest": "1.0.0"},
            "versions": {
                "1.0.0": {"license": "MIT"},
                "0.9.0": {},
            },
        }
        pc = self.analyzer._estimate_provenance_confidence_npm(data)
        assert pc == 1.0

    def test_npm_empty_provenance(self):
        data = {"dist-tags": {}, "versions": {}}
        pc = self.analyzer._estimate_provenance_confidence_npm(data)
        assert pc < 0.5


class TestAgeVelocity:

    def setup_method(self):
        self.analyzer = SupplyChainAnalyzer()

    @patch("uast.analyzer.http_client")
    def test_npm_age_velocity_no_created(self, mock_client):
        data = {"time": {}, "name": "pkg"}
        signal, contrib = self.analyzer._check_age_velocity_npm(data)
        assert signal is None
        assert contrib == 0.0

    @patch("uast.analyzer.http_client")
    def test_npm_age_velocity_invalid_date(self, mock_client):
        data = {"time": {"created": "not-a-date"}, "name": "pkg"}
        signal, contrib = self.analyzer._check_age_velocity_npm(data)
        assert signal is None
        assert contrib == 0.0
