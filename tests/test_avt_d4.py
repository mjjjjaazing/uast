"""
Tests for AVT D4: Trust & Identity detectors.

Covers:
  - MAINTAINER-001: Maintainer trust signals (disposable email, no identity)
  - SPOOF-001: Metadata spoofing (description references different package)
"""

from unittest.mock import patch, MagicMock

import requests

from uast.analyzer import SupplyChainAnalyzer


class TestMaintainerTrust:

    def setup_method(self):
        self.analyzer = SupplyChainAnalyzer(aal=0.7)

    def test_disposable_email_pypi(self):
        info = {
            "author": "attacker",
            "author_email": "user@mailinator.com",
        }
        signal, score = self.analyzer._check_maintainer_trust(info, "pypi")
        assert signal is not None
        assert signal.signal_id == "MAINTAINER-001"
        assert "disposable" in signal.detail.lower()

    def test_no_author_identity_pypi(self):
        info = {"author": "", "author_email": ""}
        signal, score = self.analyzer._check_maintainer_trust(info, "pypi")
        assert signal is not None
        assert signal.signal_id == "MAINTAINER-001"

    def test_valid_author_pypi(self):
        info = {"author": "Good Author", "author_email": "good@example.com"}
        signal, score = self.analyzer._check_maintainer_trust(info, "pypi")
        assert signal is None

    def test_disposable_email_npm(self):
        data = {
            "maintainers": [{"name": "attacker", "email": "x@yopmail.com"}],
            "author": {"name": "attacker"},
        }
        signal, score = self.analyzer._check_maintainer_trust(data, "npm")
        assert signal is not None
        assert signal.signal_id == "MAINTAINER-001"
        assert "disposable" in signal.detail.lower()

    def test_no_maintainer_npm(self):
        data = {"maintainers": [], "author": {}}
        signal, score = self.analyzer._check_maintainer_trust(data, "npm")
        assert signal is not None
        assert signal.signal_id == "MAINTAINER-001"

    def test_valid_maintainer_npm(self):
        data = {
            "maintainers": [
                {"name": "gooddev", "email": "dev@company.com"},
                {"name": "codev", "email": "codev@company.com"},
            ],
            "author": {"name": "gooddev"},
        }
        signal, score = self.analyzer._check_maintainer_trust(data, "npm")
        assert signal is None

    def test_none_email_pypi(self):
        """None email should not crash."""
        info = {"author": "author", "author_email": None}
        signal, score = self.analyzer._check_maintainer_trust(info, "pypi")
        assert signal is None  # has author name, no issues


class TestMetadataSpoofing:

    def setup_method(self):
        self.analyzer = SupplyChainAnalyzer(aal=0.7)

    def test_description_references_different_package_pypi(self):
        info = {
            "summary": "A fast replacement for requests with better performance",
            "description": "",
            "author": "someone",
            "home_page": "",
            "project_urls": {},
        }
        signal, score = self.analyzer._check_metadata_spoofing(
            info, "not-requests", "pypi"
        )
        assert signal is not None
        assert signal.signal_id == "SPOOF-001"
        assert "requests" in signal.detail.lower()

    def test_description_matches_own_name_pypi(self):
        """If description mentions the package's own popular name, no spoofing."""
        info = {
            "summary": "requests is an HTTP library",
            "description": "",
            "author": "Kenneth Reitz",
            "home_page": "https://github.com/psf/requests",
            "project_urls": {},
        }
        signal, score = self.analyzer._check_metadata_spoofing(
            info, "requests", "pypi"
        )
        assert signal is None

    def test_clean_description_pypi(self):
        info = {
            "summary": "A utility for processing data files",
            "description": "",
            "author": "gooddev",
            "home_page": "",
            "project_urls": {},
        }
        signal, score = self.analyzer._check_metadata_spoofing(
            info, "dataproc-utils", "pypi"
        )
        assert signal is None

    def test_description_references_different_package_npm(self):
        data = {
            "description": "A better lodash with improved tree shaking",
        }
        signal, score = self.analyzer._check_metadata_spoofing(
            data, "lodash-better", "npm"
        )
        assert signal is not None
        assert signal.signal_id == "SPOOF-001"

    def test_clean_description_npm(self):
        data = {
            "description": "Utility functions for array manipulation",
        }
        signal, score = self.analyzer._check_metadata_spoofing(
            data, "array-tools", "npm"
        )
        assert signal is None


class TestTrustIntegration:

    def setup_method(self):
        self.analyzer = SupplyChainAnalyzer(aal=0.7)

    @patch("uast.analyzer.http_client")
    def test_pypi_disposable_email_flagged(self, mock_client):
        """Package with disposable email author should get MAINTAINER-001."""
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.json.return_value = {
            "info": {
                "name": "sketchy-pkg",
                "version": "0.1.0",
                "summary": "A helpful utility package",
                "author": "nobody",
                "author_email": "throwaway@guerrillamail.com",
                "home_page": "",
                "license": "",
                "classifiers": [],
                "project_urls": {},
                "requires_dist": [],
            },
            "releases": {"0.1.0": [{"upload_time": "2025-06-01T00:00:00"}]},
        }
        resp.raise_for_status = MagicMock()
        mock_client.get.return_value = resp
        mock_client.head.return_value = MagicMock(status_code=200)

        result = self.analyzer.analyze_pypi("sketchy-pkg")
        assert any(s.signal_id == "MAINTAINER-001" for s in result.signals)

    @patch("uast.analyzer.http_client")
    def test_pypi_spoof_description_flagged(self, mock_client):
        """Package whose description references a different popular package."""
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.json.return_value = {
            "info": {
                "name": "requestz",
                "version": "1.0.0",
                "summary": "Drop-in replacement for requests with extra features",
                "author": "faker",
                "author_email": "faker@example.com",
                "home_page": "",
                "license": "",
                "classifiers": [],
                "project_urls": {},
                "requires_dist": [],
            },
            "releases": {"1.0.0": [{"upload_time": "2025-01-01T00:00:00"}]},
        }
        resp.raise_for_status = MagicMock()
        mock_client.get.return_value = resp
        mock_client.head.return_value = MagicMock(status_code=200)

        result = self.analyzer.analyze_pypi("requestz")
        # Should have both SPOOF-001 (description mentions "requests") and
        # likely SQUAT-001/002 (name similar to "requests")
        assert any(s.signal_id == "SPOOF-001" for s in result.signals)

    @patch("uast.analyzer.http_client")
    def test_npm_spoof_flagged(self, mock_client):
        """npm package description referencing a different popular package."""
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.json.return_value = {
            "name": "expresss",
            "description": "A faster version of express for Node.js",
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"license": "MIT", "dependencies": {}}},
            "time": {"created": "2025-01-01T00:00:00Z"},
            "author": {"name": "attacker"},
            "maintainers": [{"name": "attacker"}, {"name": "codev"}],
            "repository": {},
        }
        resp.raise_for_status = MagicMock()
        mock_client.get.return_value = resp
        mock_client.head.return_value = MagicMock(status_code=200)

        result = self.analyzer.analyze_npm("expresss")
        assert any(s.signal_id == "SPOOF-001" for s in result.signals)
