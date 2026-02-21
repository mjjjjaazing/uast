"""
Version Diffing — detect suspicious changes between package versions.

Compares the current version of a package against the previous version,
flagging suspicious changes that may indicate supply chain compromise:
  - New subprocess/os.system/socket imports
  - New high-entropy strings (possible obfuscated payloads)
  - New file writes to sensitive paths
  - New install-time code in setup.py
  - Removed LICENSE/README (metadata stripping)
  - New dependency additions
"""

from __future__ import annotations

import ast
import logging
import math
import os
import re
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from uast.analyzer import PackageSignal
from uast.http_client import http_client
from uast.package_utils import download_package, extract_archive

logger = logging.getLogger("uast.version_diff")

# Imports considered suspicious when newly added in __init__.py or setup.py
SUSPICIOUS_IMPORTS = {
    "subprocess", "os.system", "socket", "ctypes", "signal",
    "smtplib", "ftplib", "telnetlib", "xmlrpc",
    "base64", "codecs", "marshal", "pickle",
}

# Sensitive paths (reused concept from payload.py)
SENSITIVE_PATHS = (
    ".ssh/", ".bashrc", ".bash_profile", ".zshrc",
    ".profile", "/etc/", ".aws/", ".config/",
)


@dataclass
class VersionChange:
    """A single suspicious change found between versions."""
    change_type: str     # e.g. "new_import", "high_entropy", "metadata_stripped"
    severity: str        # critical/high/medium/low
    description: str
    file_path: str
    score: float         # 0.0-1.0


@dataclass
class VersionDiffResult:
    """Full diff result between two versions."""
    package_name: str
    current_version: str
    previous_version: Optional[str]
    files_added: list[str] = field(default_factory=list)
    files_removed: list[str] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    suspicious_changes: list[VersionChange] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to serializable dict for reports."""
        return {
            "previous_version": self.previous_version,
            "files_added": len(self.files_added),
            "files_removed": len(self.files_removed),
            "files_modified": len(self.files_modified),
            "suspicious_changes": [
                {
                    "type": c.change_type,
                    "severity": c.severity,
                    "description": c.description,
                    "file": c.file_path,
                }
                for c in self.suspicious_changes
            ],
        }


class VersionDiffer:
    """Compares two versions of a package for suspicious changes."""

    PYPI_API = "https://pypi.org/pypi/{name}/json"
    ENTROPY_THRESHOLD = 4.5
    ENTROPY_MIN_LENGTH = 20

    def __init__(self, timeout: int = 60) -> None:
        self.timeout = timeout

    def diff_versions(
        self,
        name: str,
        current_version: str,
        previous_version: Optional[str] = None,
    ) -> VersionDiffResult:
        """
        Diff the current version against the previous version.

        If previous_version is None, discovers it from PyPI.

        Returns a VersionDiffResult with suspicious changes.
        """
        result = VersionDiffResult(
            package_name=name,
            current_version=current_version,
            previous_version=previous_version,
        )

        # Discover previous version if not given
        if previous_version is None:
            previous_version = self._find_previous_version(name, current_version)
            result.previous_version = previous_version

        if previous_version is None:
            result.error = "No previous version found"
            return result

        if previous_version == current_version:
            result.error = "Only one version exists"
            return result

        # Download and extract both versions
        with tempfile.TemporaryDirectory(prefix="uast_vdiff_") as tmpdir:
            curr_dir = os.path.join(tmpdir, "current")
            prev_dir = os.path.join(tmpdir, "previous")
            os.makedirs(curr_dir)
            os.makedirs(prev_dir)

            curr_dl_dir = os.path.join(tmpdir, "dl_curr")
            prev_dl_dir = os.path.join(tmpdir, "dl_prev")
            os.makedirs(curr_dl_dir)
            os.makedirs(prev_dl_dir)

            curr_archive = download_package(
                name, current_version, curr_dl_dir,
                sdist_only=True, timeout=self.timeout,
            )
            prev_archive = download_package(
                name, previous_version, prev_dl_dir,
                sdist_only=True, timeout=self.timeout,
            )

            if not curr_archive:
                result.error = f"Failed to download current version {current_version}"
                return result
            if not prev_archive:
                result.error = f"Failed to download previous version {previous_version}"
                return result

            if not extract_archive(curr_archive, curr_dir):
                result.error = f"Failed to extract current version {current_version}"
                return result
            if not extract_archive(prev_archive, prev_dir):
                result.error = f"Failed to extract previous version {previous_version}"
                return result

            # Collect file listings
            curr_files = self._collect_files(curr_dir)
            prev_files = self._collect_files(prev_dir)

            curr_set = set(curr_files.keys())
            prev_set = set(prev_files.keys())

            result.files_added = sorted(curr_set - prev_set)
            result.files_removed = sorted(prev_set - curr_set)

            # Find modified files
            for f in sorted(curr_set & prev_set):
                if curr_files[f] != prev_files[f]:
                    result.files_modified.append(f)

            # Run suspicious change checks
            self._check_new_suspicious_imports(
                result, curr_dir, prev_dir, curr_files, prev_files,
            )
            self._check_high_entropy_strings(
                result, curr_dir, prev_dir, curr_files, prev_files,
            )
            self._check_sensitive_file_writes(
                result, curr_dir, curr_files, prev_files,
            )
            self._check_setup_changes(
                result, curr_dir, prev_dir, curr_files, prev_files,
            )
            self._check_metadata_stripping(result)
            self._check_new_dependencies(result, curr_dir, prev_dir)

        return result

    def _find_previous_version(
        self, name: str, current_version: str
    ) -> Optional[str]:
        """Query PyPI to find the version immediately before current."""
        try:
            from packaging.version import InvalidVersion, Version

            resp = http_client.get(self.PYPI_API.format(name=name), timeout=8)
            if resp.status_code != 200:
                return None

            data = resp.json()
            releases = data.get("releases", {})

            versions = []
            for v in releases:
                try:
                    versions.append(Version(v))
                except InvalidVersion:
                    continue

            versions.sort()

            try:
                current = Version(current_version)
            except InvalidVersion:
                return None

            # Find version immediately before current
            prev = None
            for v in versions:
                if v < current:
                    prev = v
                else:
                    break

            return str(prev) if prev else None

        except Exception as e:
            logger.debug("Failed to find previous version for %s: %s", name, e)
            return None

    def _collect_files(self, directory: str) -> dict[str, str]:
        """Collect all Python files and their contents."""
        files: dict[str, str] = {}
        for root, _dirs, filenames in os.walk(directory):
            for fname in filenames:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, directory)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        files[rel_path] = f.read()
                except OSError:
                    continue
        return files

    def _check_new_suspicious_imports(
        self,
        result: VersionDiffResult,
        curr_dir: str,
        prev_dir: str,
        curr_files: dict[str, str],
        prev_files: dict[str, str],
    ) -> None:
        """Check for new suspicious imports in key files."""
        key_files = [
            f for f in curr_files
            if f.endswith(".py") and (
                "__init__.py" in f or "setup.py" in f or "install.py" in f
            )
        ]

        for fpath in key_files:
            curr_imports = self._extract_imports(curr_files.get(fpath, ""))
            prev_imports = self._extract_imports(prev_files.get(fpath, ""))
            new_imports = curr_imports - prev_imports

            for imp in new_imports:
                top_module = imp.split(".")[0]
                if top_module in SUSPICIOUS_IMPORTS or imp in SUSPICIOUS_IMPORTS:
                    result.suspicious_changes.append(VersionChange(
                        change_type="new_suspicious_import",
                        severity="high",
                        description=(
                            f"New import '{imp}' added to {fpath}. "
                            "This module provides system/network access."
                        ),
                        file_path=fpath,
                        score=0.7,
                    ))

    def _extract_imports(self, source: str) -> set[str]:
        """Extract all import names from Python source."""
        imports: set[str] = set()
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return imports

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module)
        return imports

    def _check_high_entropy_strings(
        self,
        result: VersionDiffResult,
        curr_dir: str,
        prev_dir: str,
        curr_files: dict[str, str],
        prev_files: dict[str, str],
    ) -> None:
        """Check for new high-entropy strings (possible obfuscated payloads)."""
        for fpath in result.files_added + result.files_modified:
            if not fpath.endswith(".py"):
                continue

            curr_content = curr_files.get(fpath, "")
            prev_content = prev_files.get(fpath, "")

            curr_strings = self._extract_string_literals(curr_content)
            prev_strings = self._extract_string_literals(prev_content)
            new_strings = curr_strings - prev_strings

            for s in new_strings:
                if len(s) >= self.ENTROPY_MIN_LENGTH:
                    entropy = self._shannon_entropy(s)
                    if entropy > self.ENTROPY_THRESHOLD:
                        result.suspicious_changes.append(VersionChange(
                            change_type="high_entropy_string",
                            severity="medium",
                            description=(
                                f"New high-entropy string in {fpath} "
                                f"(entropy={entropy:.2f}, len={len(s)}). "
                                "May indicate obfuscated payload."
                            ),
                            file_path=fpath,
                            score=0.5,
                        ))
                        break  # One per file is enough

    def _extract_string_literals(self, source: str) -> set[str]:
        """Extract string literals from Python source."""
        strings: set[str] = set()
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return strings

        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                strings.add(node.value)
        return strings

    def _shannon_entropy(self, data: str) -> float:
        """Compute Shannon entropy of a string."""
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )

    def _check_sensitive_file_writes(
        self,
        result: VersionDiffResult,
        curr_dir: str,
        curr_files: dict[str, str],
        prev_files: dict[str, str],
    ) -> None:
        """Check for new file writes to sensitive paths."""
        for fpath in result.files_added + result.files_modified:
            if not fpath.endswith(".py"):
                continue

            curr_content = curr_files.get(fpath, "")
            prev_content = prev_files.get(fpath, "")

            curr_sensitive = self._find_sensitive_writes(curr_content)
            prev_sensitive = self._find_sensitive_writes(prev_content)
            new_sensitive = curr_sensitive - prev_sensitive

            for path_str in new_sensitive:
                result.suspicious_changes.append(VersionChange(
                    change_type="new_sensitive_write",
                    severity="critical",
                    description=(
                        f"New file write to sensitive path '{path_str}' in {fpath}."
                    ),
                    file_path=fpath,
                    score=0.9,
                ))

    def _find_sensitive_writes(self, source: str) -> set[str]:
        """Find open() calls with write mode targeting sensitive paths."""
        writes: set[str] = set()
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return writes

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            if func_name != "open":
                continue

            # Check write mode
            is_write = False
            for arg in node.args[1:]:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if "w" in arg.value or "a" in arg.value:
                        is_write = True
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    if isinstance(kw.value.value, str) and (
                        "w" in kw.value.value or "a" in kw.value.value
                    ):
                        is_write = True

            if not is_write or not node.args:
                continue

            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                for sensitive in SENSITIVE_PATHS:
                    if sensitive in arg.value:
                        writes.add(arg.value)
        return writes

    def _check_setup_changes(
        self,
        result: VersionDiffResult,
        curr_dir: str,
        prev_dir: str,
        curr_files: dict[str, str],
        prev_files: dict[str, str],
    ) -> None:
        """Check for new install-time code in setup.py."""
        setup_files = [f for f in curr_files if "setup.py" in f]

        for fpath in setup_files:
            if fpath not in prev_files:
                # New setup.py — check for suspicious code
                curr_content = curr_files[fpath]
                if self._has_install_hooks(curr_content):
                    result.suspicious_changes.append(VersionChange(
                        change_type="new_setup_code",
                        severity="high",
                        description=f"New setup.py with install-time hooks in {fpath}.",
                        file_path=fpath,
                        score=0.7,
                    ))
            elif fpath in result.files_modified:
                curr_content = curr_files[fpath]
                prev_content = prev_files[fpath]
                if (self._has_install_hooks(curr_content)
                        and not self._has_install_hooks(prev_content)):
                    result.suspicious_changes.append(VersionChange(
                        change_type="new_setup_code",
                        severity="high",
                        description=f"New install-time hooks added to {fpath}.",
                        file_path=fpath,
                        score=0.7,
                    ))

    def _has_install_hooks(self, source: str) -> bool:
        """Check if source has install-time command overrides."""
        patterns = [
            r"class\s+\w+Install",
            r"cmdclass\s*=",
            r"subprocess\.\w+\(",
            r"os\.system\(",
            r"urllib\.request\.urlopen\(",
        ]
        for pattern in patterns:
            if re.search(pattern, source):
                return True
        return False

    def _check_metadata_stripping(self, result: VersionDiffResult) -> None:
        """Check if LICENSE or README was removed."""
        for fpath in result.files_removed:
            fname_lower = os.path.basename(fpath).lower()
            if fname_lower.startswith("license") or fname_lower.startswith("licence"):
                result.suspicious_changes.append(VersionChange(
                    change_type="metadata_stripped",
                    severity="medium",
                    description=f"LICENSE file removed: {fpath}",
                    file_path=fpath,
                    score=0.4,
                ))
            elif fname_lower.startswith("readme"):
                result.suspicious_changes.append(VersionChange(
                    change_type="metadata_stripped",
                    severity="low",
                    description=f"README file removed: {fpath}",
                    file_path=fpath,
                    score=0.2,
                ))

    def _check_new_dependencies(
        self,
        result: VersionDiffResult,
        curr_dir: str,
        prev_dir: str,
    ) -> None:
        """Check if new dependencies were added in setup.py or pyproject.toml."""
        for config_file in ("setup.cfg", "pyproject.toml"):
            curr_files_list = []
            prev_files_list = []
            for root, _dirs, files in os.walk(curr_dir):
                for f in files:
                    if f == config_file:
                        curr_files_list.append(os.path.join(root, f))
            for root, _dirs, files in os.walk(prev_dir):
                for f in files:
                    if f == config_file:
                        prev_files_list.append(os.path.join(root, f))

            if curr_files_list and prev_files_list:
                try:
                    with open(curr_files_list[0], "r", encoding="utf-8", errors="ignore") as f:
                        curr_content = f.read()
                    with open(prev_files_list[0], "r", encoding="utf-8", errors="ignore") as f:
                        prev_content = f.read()

                    curr_deps = self._extract_dependencies(curr_content)
                    prev_deps = self._extract_dependencies(prev_content)
                    new_deps = curr_deps - prev_deps

                    if new_deps:
                        result.suspicious_changes.append(VersionChange(
                            change_type="new_dependencies",
                            severity="low",
                            description=(
                                f"New dependencies added: {', '.join(sorted(new_deps)[:5])}"
                                + (f" (+{len(new_deps) - 5} more)" if len(new_deps) > 5 else "")
                            ),
                            file_path=config_file,
                            score=0.2,
                        ))
                except OSError:
                    continue

    def _extract_dependencies(self, content: str) -> set[str]:
        """Extract dependency names from setup.cfg or pyproject.toml content."""
        deps: set[str] = set()
        # Match lines like: package>=1.0  or  "package>=1.0"
        for match in re.finditer(r'["\']?([a-zA-Z0-9][\w.-]*)\s*[><=!~]', content):
            deps.add(match.group(1).lower())
        return deps


def diff_to_signals(diff_result: VersionDiffResult) -> list[PackageSignal]:
    """Convert a VersionDiffResult to PackageSignals for the analyzer."""
    if diff_result.error or not diff_result.suspicious_changes:
        return []

    signals = []
    # Group by severity — take the worst
    max_score = max(c.score for c in diff_result.suspicious_changes)

    # Map severity
    if max_score >= 0.8:
        severity = "critical"
    elif max_score >= 0.5:
        severity = "high"
    elif max_score >= 0.3:
        severity = "medium"
    else:
        severity = "low"

    detail_parts = [c.description for c in diff_result.suspicious_changes[:3]]
    if len(diff_result.suspicious_changes) > 3:
        detail_parts.append(
            f"...and {len(diff_result.suspicious_changes) - 3} more"
        )

    signals.append(PackageSignal(
        signal_id="VDIFF-001",
        severity=severity,
        title=(
            f"Suspicious changes from v{diff_result.previous_version} "
            f"to v{diff_result.current_version} "
            f"({len(diff_result.suspicious_changes)} issue(s))"
        ),
        detail="; ".join(detail_parts),
        score_contribution=max_score,
    ))

    return signals
