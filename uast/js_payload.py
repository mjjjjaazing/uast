"""
JS Payload Analyzer — regex-based scanning of npm package source for suspicious patterns.

Scans JavaScript/TypeScript files in npm packages for:
  - child_process imports (command execution)
  - eval()/new Function() with non-literals (dynamic code execution)
  - Base64 decoding near data (obfuscation)
  - File writes to sensitive paths
  - Environment variable gating
  - Network calls in install scripts
  - Raw socket usage (net/dgram)

Also checks package.json install scripts (preinstall/postinstall/install)
for suspicious content.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass
from typing import Optional

from uast.analyzer import PackageSignal

logger = logging.getLogger("uast.js_payload")


@dataclass
class JSFinding:
    """A single suspicious finding from JS regex analysis."""
    signal_id: str
    severity: str
    title: str
    detail: str
    file_path: str
    line_number: int
    score_contribution: float


# ---------------------------------------------------------------------------
# Suspicious JS patterns
# ---------------------------------------------------------------------------

JS_PATTERNS: list[tuple[str, re.Pattern, str, str, float]] = [
    # (signal_id, compiled_pattern, severity, title_template, score)
    (
        "JS-PAYLOAD-001",
        re.compile(
            r"""require\s*\(\s*['"]child_process['"]\s*\)"""
            r"""|import\s+.*?\s+from\s+['"]child_process['"]"""
            r"""|import\s*\(\s*['"]child_process['"]\s*\)""",
            re.IGNORECASE,
        ),
        "high",
        "child_process import detected",
        0.7,
    ),
    (
        "JS-PAYLOAD-002",
        re.compile(
            r"""(?<!\w)eval\s*\((?!\s*['"`])"""
            r"""|new\s+Function\s*\((?!\s*['"`])""",
        ),
        "high",
        "Dynamic code execution (eval/new Function with non-literal)",
        0.7,
    ),
    (
        "JS-PAYLOAD-003",
        re.compile(
            r"""Buffer\.from\s*\([^)]*,\s*['"]base64['"]"""
            r"""|atob\s*\("""
            r"""|btoa\s*\(""",
        ),
        "medium",
        "Base64 encoding/decoding detected",
        0.5,
    ),
    (
        "JS-PAYLOAD-004",
        re.compile(
            r"""(?:fs\.writeFile|fs\.writeFileSync|fs\.appendFile|fs\.appendFileSync)"""
            r"""\s*\(\s*['"`](?:.*(?:\.ssh|\.bashrc|\.bash_profile|\.zshrc|\.profile|/etc/|\.aws/|\.config/))""",
        ),
        "critical",
        "File write to sensitive path",
        0.9,
    ),
    (
        "JS-PAYLOAD-005",
        re.compile(
            r"""process\.env\.\w+""",
        ),
        "medium",
        "Environment variable access (potential execution gating)",
        0.3,
    ),
    (
        "JS-PAYLOAD-007",
        re.compile(
            r"""require\s*\(\s*['"](?:net|dgram)['"]\s*\)"""
            r"""|import\s+.*?\s+from\s+['"](?:net|dgram)['"]""",
        ),
        "high",
        "Raw socket module import (net/dgram)",
        0.7,
    ),
]

# Network patterns specifically for install scripts (elevated severity)
INSTALL_SCRIPT_NETWORK_PATTERN = re.compile(
    r"""(?:https?\.request|https?\.get|http\.request|http\.get)"""
    r"""\s*\("""
    r"""|fetch\s*\("""
    r"""|require\s*\(\s*['"](?:node-fetch|axios|got|request|superagent)['"]\s*\)""",
)

# Install script names in package.json
INSTALL_SCRIPT_KEYS = ("preinstall", "postinstall", "install")

# JS/TS file extensions to scan
JS_EXTENSIONS = (".js", ".ts", ".mjs", ".cjs")


class JSPayloadAnalyzer:
    """Analyzes npm package source code for suspicious patterns via regex."""

    def analyze_package(
        self, name: str, ecosystem: str, version: Optional[str] = None
    ) -> list[PackageSignal]:
        """Download, extract, and analyze an npm package. Returns signals."""
        if ecosystem != "npm":
            return []

        logger.info("JS payload analysis starting: %s version=%s", name, version)

        with tempfile.TemporaryDirectory(prefix="uast_js_payload_") as tmpdir:
            pkg_dir = self._download_and_extract(name, version, tmpdir)
            if not pkg_dir:
                logger.warning("Failed to download npm package %s for payload analysis", name)
                return []

            findings = self._scan_package(pkg_dir)
            logger.info("JS payload analysis complete: %s → %d findings", name, len(findings))
            return self._findings_to_signals(findings)

    def _download_and_extract(
        self, name: str, version: Optional[str], dest_dir: str
    ) -> Optional[str]:
        """Download npm tarball and extract it. Returns extracted directory."""
        from uast.package_utils import download_npm_package, extract_archive

        tarball_path = download_npm_package(name, version, dest_dir)
        if not tarball_path:
            return None

        extract_dir = os.path.join(dest_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        if not extract_archive(tarball_path, extract_dir):
            return None

        return extract_dir

    def _scan_package(self, directory: str) -> list[JSFinding]:
        """Scan all JS/TS files in the extracted package directory."""
        findings: list[JSFinding] = []

        # Find package.json for install script analysis
        install_script_files: set[str] = set()
        for root, _dirs, files in os.walk(directory):
            if "package.json" in files:
                pj_path = os.path.join(root, "package.json")
                install_findings, script_files = self._check_install_scripts(pj_path, root)
                findings.extend(install_findings)
                install_script_files.update(script_files)

        # Scan JS/TS files
        findings.extend(self._scan_js_files(directory, install_script_files))

        return findings

    def _scan_js_files(
        self, directory: str, install_script_files: set[str]
    ) -> list[JSFinding]:
        """Walk all JS/TS files and apply regex patterns."""
        findings: list[JSFinding] = []

        for root, _dirs, files in os.walk(directory):
            for fname in files:
                if not any(fname.endswith(ext) for ext in JS_EXTENSIONS):
                    continue

                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, directory)
                is_install_script = fpath in install_script_files

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        source = f.read()

                    file_findings = self._scan_file(source, rel_path, is_install_script)
                    findings.extend(file_findings)

                except (OSError, ValueError):
                    continue

        return findings

    def _scan_file(
        self, source: str, file_path: str, is_install_script: bool
    ) -> list[JSFinding]:
        """Apply regex patterns to a single file's source."""
        findings: list[JSFinding] = []

        for signal_id, pattern, severity, title, score in JS_PATTERNS:
            for match in pattern.finditer(source):
                line_number = source[:match.start()].count("\n") + 1
                # Elevate severity for install scripts
                effective_severity = severity
                effective_score = score
                if is_install_script and severity in ("medium", "high"):
                    effective_severity = "critical" if severity == "high" else "high"
                    effective_score = min(score + 0.2, 1.0)

                findings.append(JSFinding(
                    signal_id=signal_id,
                    severity=effective_severity,
                    title=f"{title} ({file_path})",
                    detail=(
                        f"Pattern matched in {'install script ' if is_install_script else ''}"
                        f"file {file_path} at line {line_number}: "
                        f"{match.group(0)[:60]}"
                    ),
                    file_path=file_path,
                    line_number=line_number,
                    score_contribution=effective_score,
                ))

        # Check network calls in install scripts specifically
        if is_install_script:
            for match in INSTALL_SCRIPT_NETWORK_PATTERN.finditer(source):
                line_number = source[:match.start()].count("\n") + 1
                findings.append(JSFinding(
                    signal_id="JS-PAYLOAD-006",
                    severity="critical",
                    title=f"Network call in install script ({file_path})",
                    detail=(
                        f"Network call detected in install script {file_path} "
                        f"at line {line_number}: {match.group(0)[:60]}. "
                        "Network calls during install are a strong malware indicator."
                    ),
                    file_path=file_path,
                    line_number=line_number,
                    score_contribution=0.9,
                ))

        return findings

    def _check_install_scripts(
        self, package_json_path: str, package_root: str
    ) -> tuple[list[JSFinding], set[str]]:
        """
        Parse package.json install scripts and return findings + script file paths.

        Returns:
            (findings for suspicious inline scripts, set of script file paths)
        """
        findings: list[JSFinding] = []
        script_files: set[str] = set()

        try:
            with open(package_json_path, "r", encoding="utf-8") as f:
                pkg_data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return findings, script_files

        scripts = pkg_data.get("scripts", {})
        if not scripts:
            return findings, script_files

        for key in INSTALL_SCRIPT_KEYS:
            script_value = scripts.get(key, "")
            if not script_value:
                continue

            # Check for suspicious inline commands
            if any(
                cmd in script_value.lower()
                for cmd in ("curl ", "wget ", "node -e", "eval ", "sh -c", "bash -c")
            ):
                findings.append(JSFinding(
                    signal_id="JS-PAYLOAD-006",
                    severity="critical",
                    title=f"Suspicious {key} script in package.json",
                    detail=(
                        f"Install script '{key}' contains suspicious command: "
                        f"{script_value[:100]}"
                    ),
                    file_path="package.json",
                    line_number=0,
                    score_contribution=0.9,
                ))

            # Resolve script files (e.g., "node scripts/install.js")
            parts = script_value.split()
            for part in parts:
                if any(part.endswith(ext) for ext in JS_EXTENSIONS):
                    script_path = os.path.join(package_root, part)
                    if os.path.isfile(script_path):
                        script_files.add(script_path)

        return findings, script_files

    def _findings_to_signals(self, findings: list[JSFinding]) -> list[PackageSignal]:
        """Convert JSFindings to PackageSignals, deduplicating by signal_id."""
        by_id: dict[str, JSFinding] = {}
        counts: dict[str, int] = {}

        for f in findings:
            counts[f.signal_id] = counts.get(f.signal_id, 0) + 1
            if (f.signal_id not in by_id
                    or f.score_contribution > by_id[f.signal_id].score_contribution):
                by_id[f.signal_id] = f

        signals = []
        for sig_id, finding in by_id.items():
            count = counts[sig_id]
            detail = finding.detail
            if count > 1:
                detail += f" ({count} occurrences across package)"

            signals.append(PackageSignal(
                signal_id=finding.signal_id,
                severity=finding.severity,
                title=finding.title,
                detail=detail,
                score_contribution=finding.score_contribution,
            ))

        return signals
