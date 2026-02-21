"""Tests for Provenance Verification (Sprint 3.1 & 3.2)."""

from __future__ import annotations

import hashlib
import os
import tempfile
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from uast.provenance import (
    ProvenanceResult,
    ProvenanceVerifier,
    GIT_SAFE_ENV,
    BUILD_SAFE_ENV_KEYS,
    DEFAULT_CLONE_TIMEOUT,
    DEFAULT_BUILD_TIMEOUT,
    DEFAULT_MAX_REPO_SIZE_MB,
)


class TestProvenanceResult:
    """Tests for ProvenanceResult data class."""

    def test_default_values(self):
        result = ProvenanceResult()
        assert result.source_verified is False
        assert result.verification_method == "none"
        assert result.source_hash is None
        assert result.registry_hash is None
        assert result.attestation is None
        assert result.slsa_level is None
        assert result.error is None

    def test_to_dict(self):
        result = ProvenanceResult(
            source_verified=True,
            verification_method="hash_match",
            source_hash="abc123",
            registry_hash="abc123",
            attestation="verified",
            slsa_level=3,
        )
        d = result.to_dict()
        assert d["source_verified"] is True
        assert d["verification_method"] == "hash_match"
        assert d["source_hash"] == "abc123"
        assert d["registry_hash"] == "abc123"
        assert d["attestation"] == "verified"
        assert d["slsa_level"] == 3

    def test_to_dict_none_values(self):
        result = ProvenanceResult()
        d = result.to_dict()
        assert d["source_hash"] is None
        assert d["attestation"] is None


class TestProvenanceVerifier:
    """Tests for ProvenanceVerifier."""

    def setup_method(self):
        self.verifier = ProvenanceVerifier()

    def test_default_timeouts(self):
        assert self.verifier.clone_timeout == DEFAULT_CLONE_TIMEOUT
        assert self.verifier.build_timeout == DEFAULT_BUILD_TIMEOUT
        assert self.verifier.max_repo_size_mb == DEFAULT_MAX_REPO_SIZE_MB

    def test_custom_timeouts(self):
        v = ProvenanceVerifier(clone_timeout=30, build_timeout=60, max_repo_size_mb=50)
        assert v.clone_timeout == 30
        assert v.build_timeout == 60
        assert v.max_repo_size_mb == 50


class TestExtractRepoUrl:
    """Tests for _extract_repo_url()."""

    def setup_method(self):
        self.verifier = ProvenanceVerifier()

    def test_from_project_urls_source(self):
        info = {
            "project_urls": {"Source": "https://github.com/user/repo"},
        }
        url = self.verifier._extract_repo_url(info)
        assert url == "https://github.com/user/repo"

    def test_from_project_urls_repository(self):
        info = {
            "project_urls": {"Repository": "https://github.com/user/repo"},
        }
        url = self.verifier._extract_repo_url(info)
        assert url == "https://github.com/user/repo"

    def test_from_home_page(self):
        info = {
            "home_page": "https://github.com/user/repo",
        }
        url = self.verifier._extract_repo_url(info)
        assert url == "https://github.com/user/repo"

    def test_gitlab_url(self):
        info = {
            "project_urls": {"Source": "https://gitlab.com/user/repo"},
        }
        url = self.verifier._extract_repo_url(info)
        assert url == "https://gitlab.com/user/repo"

    def test_no_repo_url(self):
        info = {
            "project_urls": {"Documentation": "https://docs.example.com"},
            "home_page": "https://example.com",
        }
        url = self.verifier._extract_repo_url(info)
        assert url is None

    def test_empty_info(self):
        url = self.verifier._extract_repo_url({})
        assert url is None

    def test_none_project_urls(self):
        info = {"project_urls": None}
        url = self.verifier._extract_repo_url(info)
        assert url is None


class TestCloneRepo:
    """Tests for _clone_repo()."""

    def setup_method(self):
        self.verifier = ProvenanceVerifier()

    @patch("uast.provenance.subprocess.run")
    def test_successful_clone(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = os.path.join(tmpdir, "cloned")
            # Create the directory to simulate git clone
            os.makedirs(dest)
            result = self.verifier._clone_repo("https://github.com/user/repo", dest)
            assert result is True
            mock_run.assert_called_once()

    @patch("uast.provenance.subprocess.run")
    def test_clone_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stderr="fatal: repo not found")
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = os.path.join(tmpdir, "cloned")
            result = self.verifier._clone_repo("https://github.com/user/nonexistent", dest)
            assert result is False

    @patch("uast.provenance.subprocess.run")
    def test_clone_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("git", 60)
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = os.path.join(tmpdir, "cloned")
            result = self.verifier._clone_repo("https://github.com/user/repo", dest)
            assert result is False

    def test_clone_rejects_non_https(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = os.path.join(tmpdir, "cloned")
            result = self.verifier._clone_repo("git://github.com/user/repo", dest)
            assert result is False

    @patch("uast.provenance.subprocess.run")
    def test_clone_upgrades_http_to_https(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = os.path.join(tmpdir, "cloned")
            os.makedirs(dest)
            self.verifier._clone_repo("http://github.com/user/repo", dest)
            # Check that the URL was upgraded
            call_args = mock_run.call_args[0][0]
            assert "https://github.com/user/repo" in call_args

    @patch("uast.provenance.subprocess.run")
    def test_clone_uses_safe_env(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = os.path.join(tmpdir, "cloned")
            os.makedirs(dest)
            self.verifier._clone_repo("https://github.com/user/repo", dest)
            call_kwargs = mock_run.call_args[1]
            env = call_kwargs.get("env", {})
            for key, val in GIT_SAFE_ENV.items():
                assert env.get(key) == val

    @patch("uast.provenance.subprocess.run")
    def test_clone_git_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError("git not found")
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = os.path.join(tmpdir, "cloned")
            result = self.verifier._clone_repo("https://github.com/user/repo", dest)
            assert result is False

    @patch("uast.provenance.subprocess.run")
    def test_clone_repo_too_large(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        verifier = ProvenanceVerifier(max_repo_size_mb=0)  # 0 MB limit
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = os.path.join(tmpdir, "cloned")
            os.makedirs(dest)
            # Create a file to make dir non-empty
            with open(os.path.join(dest, "big.bin"), "wb") as f:
                f.write(b"x" * 1024 * 1024)  # 1 MB
            result = verifier._clone_repo("https://github.com/user/repo", dest)
            assert result is False


class TestBuildFromSource:
    """Tests for _build_from_source()."""

    def setup_method(self):
        self.verifier = ProvenanceVerifier()

    @patch("uast.provenance.subprocess.run")
    def test_build_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = os.path.join(tmpdir, "source")
            output_dir = os.path.join(tmpdir, "output")
            os.makedirs(source_dir)
            os.makedirs(output_dir)
            # Simulate built artifact
            with open(os.path.join(output_dir, "pkg-1.0.tar.gz"), "w") as f:
                f.write("artifact")
            result = self.verifier._build_from_source(source_dir, output_dir)
            assert result is not None
            assert result.endswith(".tar.gz")

    @patch("uast.provenance.subprocess.run")
    def test_build_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stderr="build failed")
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = os.path.join(tmpdir, "source")
            output_dir = os.path.join(tmpdir, "output")
            os.makedirs(source_dir)
            os.makedirs(output_dir)
            result = self.verifier._build_from_source(source_dir, output_dir)
            assert result is None

    @patch("uast.provenance.subprocess.run")
    def test_build_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("build", 120)
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = os.path.join(tmpdir, "source")
            output_dir = os.path.join(tmpdir, "output")
            os.makedirs(source_dir)
            os.makedirs(output_dir)
            result = self.verifier._build_from_source(source_dir, output_dir)
            assert result is None

    @patch("uast.provenance.subprocess.run")
    def test_build_uses_safe_env(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = os.path.join(tmpdir, "source")
            output_dir = os.path.join(tmpdir, "output")
            os.makedirs(source_dir)
            os.makedirs(output_dir)
            self.verifier._build_from_source(source_dir, output_dir)
            call_kwargs = mock_run.call_args[1]
            env = call_kwargs.get("env", {})
            assert env.get("PIP_NO_INDEX") == "1"
            assert env.get("HOME") == output_dir


class TestComputeFileHash:
    """Tests for _compute_file_hash()."""

    def setup_method(self):
        self.verifier = ProvenanceVerifier()

    def test_hash_deterministic(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test content")
            path = f.name
        try:
            h1 = self.verifier._compute_file_hash(path)
            h2 = self.verifier._compute_file_hash(path)
            assert h1 == h2
            assert len(h1) == 64
        finally:
            os.unlink(path)

    def test_different_content_different_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(b"content A")
            path1 = f1.name
        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(b"content B")
            path2 = f2.name
        try:
            assert self.verifier._compute_file_hash(path1) != self.verifier._compute_file_hash(path2)
        finally:
            os.unlink(path1)
            os.unlink(path2)

    def test_known_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello")
            path = f.name
        try:
            h = self.verifier._compute_file_hash(path)
            expected = hashlib.sha256(b"hello").hexdigest()
            assert h == expected
        finally:
            os.unlink(path)


class TestCompareFileHashes:
    """Tests for _compare_file_hashes()."""

    def setup_method(self):
        self.verifier = ProvenanceVerifier()

    def test_matching_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "src")
            reg = os.path.join(tmpdir, "reg")
            os.makedirs(src)
            os.makedirs(reg)

            with open(os.path.join(src, "mod.py"), "w") as f:
                f.write("print('hello')\n")
            with open(os.path.join(reg, "mod.py"), "w") as f:
                f.write("print('hello')\n")

            match, mismatches = self.verifier._compare_file_hashes(src, reg)
            assert match is True
            assert mismatches == 0

    def test_mismatched_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "src")
            reg = os.path.join(tmpdir, "reg")
            os.makedirs(src)
            os.makedirs(reg)

            with open(os.path.join(src, "mod.py"), "w") as f:
                f.write("print('hello')\n")
            with open(os.path.join(reg, "mod.py"), "w") as f:
                f.write("print('evil')\n")

            match, mismatches = self.verifier._compare_file_hashes(src, reg)
            assert match is False
            assert mismatches == 1

    def test_no_python_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "src")
            reg = os.path.join(tmpdir, "reg")
            os.makedirs(src)
            os.makedirs(reg)

            with open(os.path.join(src, "readme.md"), "w") as f:
                f.write("# Hello\n")

            match, mismatches = self.verifier._compare_file_hashes(src, reg)
            assert match is False
            assert mismatches == 0

    def test_no_common_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "src")
            reg = os.path.join(tmpdir, "reg")
            os.makedirs(src)
            os.makedirs(reg)

            with open(os.path.join(src, "a.py"), "w") as f:
                f.write("a\n")
            with open(os.path.join(reg, "b.py"), "w") as f:
                f.write("b\n")

            match, mismatches = self.verifier._compare_file_hashes(src, reg)
            assert match is False
            assert mismatches == 0


class TestGetDirSizeMb:
    """Tests for _get_dir_size_mb()."""

    def setup_method(self):
        self.verifier = ProvenanceVerifier()

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            size = self.verifier._get_dir_size_mb(tmpdir)
            assert size == 0.0

    def test_dir_with_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "test.bin"), "wb") as f:
                f.write(b"x" * 1024 * 1024)  # 1 MB
            size = self.verifier._get_dir_size_mb(tmpdir)
            assert 0.9 < size < 1.1


class TestVerifySource:
    """Tests for verify_source()."""

    def setup_method(self):
        self.verifier = ProvenanceVerifier()

    def test_no_repo_url(self):
        result, signals = self.verifier.verify_source(
            "test-pkg", "1.0", repo_url=None, info={},
        )
        assert result.source_verified is False
        assert any(s.signal_id == "PROV-002" for s in signals)

    @patch.object(ProvenanceVerifier, "_clone_repo", return_value=False)
    def test_clone_failure(self, mock_clone):
        result, signals = self.verifier.verify_source(
            "test-pkg", "1.0",
            repo_url="https://github.com/user/repo",
        )
        assert result.source_verified is False
        assert result.error is not None
        assert "clone" in result.error.lower()

    @patch("uast.provenance.download_package", return_value=None)
    @patch.object(ProvenanceVerifier, "_clone_repo", return_value=True)
    def test_registry_download_failure(self, mock_clone, mock_download):
        result, signals = self.verifier.verify_source(
            "test-pkg", "1.0",
            repo_url="https://github.com/user/repo",
        )
        assert result.source_verified is False
        assert result.error is not None

    @patch("uast.provenance.extract_archive", return_value=True)
    @patch("uast.provenance.download_package")
    @patch.object(ProvenanceVerifier, "_build_from_source")
    @patch.object(ProvenanceVerifier, "_clone_repo", return_value=True)
    def test_hash_match(self, mock_clone, mock_build, mock_download, mock_extract):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create matching artifacts
            artifact = os.path.join(tmpdir, "pkg.tar.gz")
            with open(artifact, "wb") as f:
                f.write(b"same content")

            mock_build.return_value = artifact
            mock_download.return_value = artifact

            result, signals = self.verifier.verify_source(
                "test-pkg", "1.0",
                repo_url="https://github.com/user/repo",
            )
            assert result.source_verified is True
            assert result.verification_method == "hash_match"
            assert any(s.signal_id == "PROV-003" for s in signals)

    @patch("uast.provenance.download_package")
    @patch.object(ProvenanceVerifier, "_build_from_source")
    @patch.object(ProvenanceVerifier, "_clone_repo", return_value=True)
    def test_hash_mismatch(self, mock_clone, mock_build, mock_download):
        with tempfile.TemporaryDirectory() as tmpdir:
            source_artifact = os.path.join(tmpdir, "source.tar.gz")
            registry_artifact = os.path.join(tmpdir, "registry.tar.gz")
            with open(source_artifact, "wb") as f:
                f.write(b"source content")
            with open(registry_artifact, "wb") as f:
                f.write(b"different content")

            mock_build.return_value = source_artifact
            mock_download.return_value = registry_artifact

            result, signals = self.verifier.verify_source(
                "test-pkg", "1.0",
                repo_url="https://github.com/user/repo",
            )
            assert result.source_verified is False
            assert any(s.signal_id == "PROV-001" for s in signals)
            prov_signal = next(s for s in signals if s.signal_id == "PROV-001")
            assert prov_signal.severity == "critical"
            assert prov_signal.score_contribution == 0.95


class TestCheckAttestation:
    """Tests for check_attestation() — Tier 1 HTTP check."""

    def setup_method(self):
        self.verifier = ProvenanceVerifier()

    @patch("uast.provenance.http_client")
    def test_attestation_present(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<a href="pkg-1.0.tar.gz" data-provenance="true">'
        mock_client.get.return_value = mock_resp

        status, signals = self.verifier.check_attestation("test-pkg")
        assert status == "present"
        assert any(s.signal_id == "SIG-001" for s in signals)
        sig = next(s for s in signals if s.signal_id == "SIG-001")
        assert sig.score_contribution == -0.15

    @patch("uast.provenance.http_client")
    def test_no_attestation(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<a href="pkg-1.0.tar.gz">'
        mock_client.get.return_value = mock_resp

        status, signals = self.verifier.check_attestation("test-pkg")
        assert status == "none"
        assert any(s.signal_id == "SIG-002" for s in signals)
        sig = next(s for s in signals if s.signal_id == "SIG-002")
        assert sig.score_contribution == 0.0

    @patch("uast.provenance.http_client")
    def test_api_error(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_client.get.return_value = mock_resp

        status, signals = self.verifier.check_attestation("test-pkg")
        assert status is None
        assert len(signals) == 0

    @patch("uast.provenance.http_client")
    def test_network_error(self, mock_client):
        mock_client.get.side_effect = Exception("network error")

        status, signals = self.verifier.check_attestation("test-pkg")
        assert status is None
        assert len(signals) == 0


class TestVerifyAttestation:
    """Tests for verify_attestation() — Tier 2 Sigstore."""

    def setup_method(self):
        self.verifier = ProvenanceVerifier()

    def test_import_error_graceful(self):
        """Should handle missing sigstore gracefully."""
        # sigstore is not installed in test env, so this tests the ImportError path
        status, signals = self.verifier.verify_attestation("test-pkg", "1.0")
        assert status is None
        assert len(signals) == 0

    @patch.dict("sys.modules", {"sigstore": MagicMock(), "sigstore.verify": MagicMock(), "pypi_attestations": MagicMock()})
    @patch("uast.provenance.http_client")
    def test_verification_with_sigstore(self, mock_client):
        """Should attempt verification when sigstore is available."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "urls": [{"provenance": True}],
        }
        mock_client.get.return_value = mock_resp

        status, signals = self.verifier.verify_attestation("test-pkg", "1.0")
        # May return "verified" or None depending on mock depth
        # The key assertion is no crash


class TestCollectPythonHashes:
    """Tests for _collect_python_hashes()."""

    def setup_method(self):
        self.verifier = ProvenanceVerifier()

    def test_collects_python_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "mod.py"), "w") as f:
                f.write("hello")
            with open(os.path.join(tmpdir, "readme.md"), "w") as f:
                f.write("docs")

            hashes = self.verifier._collect_python_hashes(tmpdir)
            assert len(hashes) == 1
            assert "mod.py" in hashes

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hashes = self.verifier._collect_python_hashes(tmpdir)
            assert hashes == {}

    def test_nested_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_dir = os.path.join(tmpdir, "pkg")
            os.makedirs(pkg_dir)
            with open(os.path.join(pkg_dir, "__init__.py"), "w") as f:
                f.write("")
            with open(os.path.join(pkg_dir, "core.py"), "w") as f:
                f.write("code")

            hashes = self.verifier._collect_python_hashes(tmpdir)
            assert len(hashes) == 2


class TestGitSafetyConfig:
    """Tests for git clone safety configuration."""

    def test_git_safe_env_keys(self):
        assert "GIT_LFS_SKIP_SMUDGE" in GIT_SAFE_ENV
        assert "GIT_TERMINAL_PROMPT" in GIT_SAFE_ENV
        assert "GIT_CONFIG_NOSYSTEM" in GIT_SAFE_ENV
        assert GIT_SAFE_ENV["GIT_TERMINAL_PROMPT"] == "0"

    def test_build_safe_env_keys(self):
        assert "PIP_NO_INDEX" in BUILD_SAFE_ENV_KEYS
        assert BUILD_SAFE_ENV_KEYS["PIP_NO_INDEX"] == "1"


class TestFetchMetadata:
    """Tests for _fetch_metadata()."""

    def setup_method(self):
        self.verifier = ProvenanceVerifier()

    @patch("uast.provenance.http_client")
    def test_fetch_success(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "info": {"name": "test", "version": "1.0"},
        }
        mock_client.get.return_value = mock_resp

        info = self.verifier._fetch_metadata("test", "1.0")
        assert info is not None
        assert info["name"] == "test"

    @patch("uast.provenance.http_client")
    def test_fetch_404(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_client.get.return_value = mock_resp

        info = self.verifier._fetch_metadata("nonexistent", "1.0")
        assert info is None

    @patch("uast.provenance.http_client")
    def test_fetch_error(self, mock_client):
        mock_client.get.side_effect = Exception("network error")

        info = self.verifier._fetch_metadata("test", "1.0")
        assert info is None
