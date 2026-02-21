"""
Payload Analyzer — static AST analysis of package source for malicious patterns.

Downloads the package sdist/wheel, extracts Python files, and runs an
AST visitor to detect suspicious patterns:
  - Environment variable gating
  - Subprocess/os.system calls
  - Base64/codecs obfuscation
  - Network calls in setup.py
  - eval()/exec() with non-literal args
  - Dynamic imports with variable args
  - File writes to sensitive paths

Uses only stdlib: ast, tempfile, zipfile, tarfile.
"""

from __future__ import annotations

import ast
import logging
import os
import re
import sys
import tempfile
import tarfile
import zipfile
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from uast.analyzer import PackageSignal

logger = logging.getLogger("uast.payload")


@dataclass
class PayloadFinding:
    """A single suspicious finding from AST analysis."""
    signal_id: str
    severity: str
    title: str
    detail: str
    file_path: str
    line_number: int
    score_contribution: float


class SuspiciousPatternVisitor(ast.NodeVisitor):
    """AST visitor that detects suspicious code patterns."""

    SENSITIVE_PATHS = (
        ".ssh/", ".bashrc", ".bash_profile", ".zshrc",
        ".profile", "/etc/", ".aws/", ".config/",
    )

    def __init__(self, file_path: str, is_setup_file: bool = False) -> None:
        self.file_path = file_path
        self.is_setup_file = is_setup_file
        self.findings: list[PayloadFinding] = []

    def visit_Call(self, node: ast.Call) -> None:
        self._check_env_gating(node)
        self._check_subprocess(node)
        self._check_obfuscation(node)
        self._check_network_in_setup(node)
        self._check_eval_exec(node)
        self._check_dynamic_import(node)
        self._check_sensitive_file_write(node)
        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract dotted call name like 'os.system'."""
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return ""

    def _check_env_gating(self, node: ast.Call) -> None:
        """PAYLOAD-001: os.getenv()/os.environ used to gate code execution."""
        name = self._get_call_name(node)
        if name in ("os.getenv", "os.environ.get"):
            self.findings.append(PayloadFinding(
                signal_id="PAYLOAD-001",
                severity="high",
                title="Environment variable gating detected",
                detail=f"Call to {name}() may gate malicious behavior on production env variables.",
                file_path=self.file_path,
                line_number=getattr(node, "lineno", 0),
                score_contribution=0.6,
            ))

    def _check_subprocess(self, node: ast.Call) -> None:
        """PAYLOAD-002: subprocess.*/os.system/os.exec* calls."""
        name = self._get_call_name(node)
        suspicious = (
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "subprocess.check_output", "subprocess.check_call",
            "os.system", "os.popen", "os.execl", "os.execle",
            "os.execlp", "os.execlpe", "os.execv", "os.execve",
            "os.execvp", "os.execvpe", "os.spawnl", "os.spawnle",
        )
        if name in suspicious:
            self.findings.append(PayloadFinding(
                signal_id="PAYLOAD-002",
                severity="high",
                title=f"System command execution: {name}()",
                detail=f"Call to {name}() can execute arbitrary system commands.",
                file_path=self.file_path,
                line_number=getattr(node, "lineno", 0),
                score_contribution=0.7,
            ))

    def _check_obfuscation(self, node: ast.Call) -> None:
        """PAYLOAD-003: base64.b64decode/codecs.decode with string literals."""
        name = self._get_call_name(node)
        if name in ("base64.b64decode", "base64.b64encode", "codecs.decode", "codecs.encode"):
            has_literal = any(isinstance(a, (ast.Constant, ast.JoinedStr)) for a in node.args)
            if has_literal:
                self.findings.append(PayloadFinding(
                    signal_id="PAYLOAD-003",
                    severity="high",
                    title=f"Obfuscation pattern: {name}() with literal",
                    detail=f"Encoded literal passed to {name}() — common obfuscation technique.",
                    file_path=self.file_path,
                    line_number=getattr(node, "lineno", 0),
                    score_contribution=0.7,
                ))

    def _check_network_in_setup(self, node: ast.Call) -> None:
        """PAYLOAD-004: Network calls in setup.py."""
        if not self.is_setup_file:
            return
        name = self._get_call_name(node)
        network_calls = (
            "urllib.request.urlopen", "urllib.request.urlretrieve",
            "requests.get", "requests.post", "requests.put",
            "httpx.get", "httpx.post",
            "urllib2.urlopen", "urlopen",
        )
        if name in network_calls:
            self.findings.append(PayloadFinding(
                signal_id="PAYLOAD-004",
                severity="critical",
                title=f"Network call in setup.py: {name}()",
                detail=f"Setup file makes network request via {name}() — strong indicator of malicious install-time behavior.",
                file_path=self.file_path,
                line_number=getattr(node, "lineno", 0),
                score_contribution=0.9,
            ))

    def _check_eval_exec(self, node: ast.Call) -> None:
        """PAYLOAD-005: eval()/exec() with non-literal argument."""
        name = self._get_call_name(node)
        if name in ("eval", "exec"):
            # Check if argument is a simple string literal (less suspicious)
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                return  # Literal string — less suspicious
            self.findings.append(PayloadFinding(
                signal_id="PAYLOAD-005",
                severity="medium",
                title=f"Dynamic code execution: {name}()",
                detail=f"{name}() called with non-literal argument — can execute arbitrary code.",
                file_path=self.file_path,
                line_number=getattr(node, "lineno", 0),
                score_contribution=0.5,
            ))

    def _check_dynamic_import(self, node: ast.Call) -> None:
        """PAYLOAD-006: __import__()/importlib with variable arg."""
        name = self._get_call_name(node)
        if name in ("__import__", "importlib.import_module"):
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.findings.append(PayloadFinding(
                    signal_id="PAYLOAD-006",
                    severity="medium",
                    title=f"Dynamic import: {name}()",
                    detail=f"{name}() called with variable argument — can load arbitrary modules.",
                    file_path=self.file_path,
                    line_number=getattr(node, "lineno", 0),
                    score_contribution=0.4,
                ))

    def _check_sensitive_file_write(self, node: ast.Call) -> None:
        """PAYLOAD-007: File writes to sensitive paths."""
        name = self._get_call_name(node)
        if name not in ("open", "builtins.open"):
            return

        # Check if mode is write
        write_mode = False
        for arg in node.args[1:]:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if "w" in arg.value or "a" in arg.value:
                    write_mode = True
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                if isinstance(kw.value.value, str) and ("w" in kw.value.value or "a" in kw.value.value):
                    write_mode = True

        if not write_mode:
            return

        # Check if path is sensitive
        if node.args:
            arg = node.args[0]
            path_str = ""
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                path_str = arg.value
            elif isinstance(arg, ast.JoinedStr):
                # f-string — extract literal parts
                for val in arg.values:
                    if isinstance(val, ast.Constant):
                        path_str += str(val.value)

            if path_str:
                for sensitive in self.SENSITIVE_PATHS:
                    if sensitive in path_str:
                        self.findings.append(PayloadFinding(
                            signal_id="PAYLOAD-007",
                            severity="critical",
                            title=f"Write to sensitive path: {path_str}",
                            detail=f"File write targeting '{path_str}' — matches sensitive path '{sensitive}'.",
                            file_path=self.file_path,
                            line_number=getattr(node, "lineno", 0),
                            score_contribution=0.9,
                        ))
                        return


class PayloadAnalyzer:
    """Analyzes package source code for suspicious patterns via AST."""

    SETUP_FILES = {"setup.py", "setup.cfg", "__init__.py", "install.py"}

    def analyze_package(
        self, name: str, ecosystem: str, version: Optional[str] = None
    ) -> list[PackageSignal]:
        """Download, extract, and analyze a package. Returns signals."""
        logger.info("Payload analysis starting: %s (%s) version=%s", name, ecosystem, version)
        # Validate package name to prevent command injection
        if not re.match(r"^[a-zA-Z0-9][\w.\-]{0,213}$", name):
            logger.warning("Invalid package name for payload analysis: %r", name)
            return []
        if ecosystem != "pypi":
            logger.debug("Payload analysis only supports PyPI — skipping %s", ecosystem)
            return []  # Only Python packages supported for now

        with tempfile.TemporaryDirectory(prefix="uast_payload_") as tmpdir:
            pkg_path = self._download_package(name, version, tmpdir)
            if not pkg_path:
                logger.warning("Failed to download package %s for payload analysis", name)
                return []

            extract_dir = os.path.join(tmpdir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)

            if not self._extract_archive(pkg_path, extract_dir):
                logger.warning("Failed to extract package %s", name)
                return []

            findings = self._analyze_python_files(extract_dir)
            logger.info("Payload analysis complete: %s → %d findings", name, len(findings))
            return self._findings_to_signals(findings)

    def _download_package(
        self, name: str, version: Optional[str], dest_dir: str
    ) -> Optional[str]:
        """Download package sdist/wheel using pip download."""
        cmd = [
            sys.executable, "-m", "pip", "download",
            "--no-deps",
            "--no-binary", ":all:",  # Prefer sdist for source
            "-d", dest_dir,
        ]
        if version:
            cmd.append(f"{name}=={version}")
        else:
            cmd.append(name)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                # Fall back to allowing binary (wheel)
                cmd_wheel = [
                    sys.executable, "-m", "pip", "download",
                    "--no-deps",
                    "-d", dest_dir,
                ]
                if version:
                    cmd_wheel.append(f"{name}=={version}")
                else:
                    cmd_wheel.append(name)
                result = subprocess.run(
                    cmd_wheel,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if result.returncode != 0:
                    return None
        except (subprocess.TimeoutExpired, OSError):
            return None

        # Find downloaded file
        for f in os.listdir(dest_dir):
            if f.endswith((".tar.gz", ".zip", ".whl", ".tar.bz2")):
                return os.path.join(dest_dir, f)
        return None

    def _extract_archive(self, path: str, dest: str) -> bool:
        """Extract a .tar.gz, .tar.bz2, .zip, or .whl to dest."""
        try:
            if path.endswith((".tar.gz", ".tar.bz2")):
                with tarfile.open(path) as tf:
                    # Security: filter out absolute paths and path traversal
                    members = []
                    for m in tf.getmembers():
                        if m.name.startswith("/") or ".." in m.name:
                            continue
                        members.append(m)
                    tf.extractall(dest, members=members)
                return True
            elif path.endswith((".zip", ".whl")):
                with zipfile.ZipFile(path) as zf:
                    # Security: filter out absolute paths and path traversal
                    for info in zf.infolist():
                        if info.filename.startswith("/") or ".." in info.filename:
                            continue
                        zf.extract(info, dest)
                return True
        except (tarfile.TarError, zipfile.BadZipFile, OSError):
            pass
        return False

    def _analyze_python_files(self, directory: str) -> list[PayloadFinding]:
        """Walk all .py files and run AST visitor on each."""
        findings: list[PayloadFinding] = []

        for root, _dirs, files in os.walk(directory):
            for fname in files:
                if not fname.endswith(".py"):
                    continue

                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, directory)
                is_setup = fname.lower() in self.SETUP_FILES

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        source = f.read()

                    tree = ast.parse(source, filename=rel_path)
                    visitor = SuspiciousPatternVisitor(rel_path, is_setup_file=is_setup)
                    visitor.visit(tree)
                    findings.extend(visitor.findings)
                except (SyntaxError, ValueError):
                    continue

        return findings

    def _findings_to_signals(self, findings: list[PayloadFinding]) -> list[PackageSignal]:
        """Convert PayloadFindings to PackageSignals, deduplicating by signal_id."""
        # Group by signal_id, take highest severity instance
        by_id: dict[str, PayloadFinding] = {}
        counts: dict[str, int] = {}

        for f in findings:
            counts[f.signal_id] = counts.get(f.signal_id, 0) + 1
            if f.signal_id not in by_id or f.score_contribution > by_id[f.signal_id].score_contribution:
                by_id[f.signal_id] = f

        signals = []
        for sig_id, finding in by_id.items():
            count = counts[sig_id]
            detail = finding.detail
            if count > 1:
                detail += f" ({count} occurrences across package)"
            detail += f" [first seen: {finding.file_path}:{finding.line_number}]"

            signals.append(PackageSignal(
                signal_id=finding.signal_id,
                severity=finding.severity,
                title=finding.title,
                detail=detail,
                score_contribution=finding.score_contribution,
            ))

        return signals
