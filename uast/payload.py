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
import tempfile
from dataclasses import dataclass
from typing import Optional

from uast.analyzer import PackageSignal
from uast.package_utils import download_package, extract_archive

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

    # Patterns that indicate context poisoning
    ENV_MODIFY_TARGETS = (
        "os.environ", "os.putenv",
    )

    SYSPATH_MODIFY_PATTERNS = (
        "sys.path.insert", "sys.path.append", "sys.path.extend",
    )

    def __init__(self, file_path: str, is_setup_file: bool = False) -> None:
        self.file_path = file_path
        self.is_setup_file = is_setup_file
        self.findings: list[PayloadFinding] = []

    # Privilege escalation call patterns
    PRIV_ESCALATION_CALLS = (
        "os.setuid", "os.setgid", "os.seteuid", "os.setegid",
        "os.setreuid", "os.setregid", "os.setresuid", "os.setresgid",
        "os.chown", "os.fchown", "os.lchown",
    )

    # Suspicious imports that indicate scope creep when found in unexpected packages
    SCOPE_SENSITIVE_MODULES = {
        "socket", "smtplib", "ftplib", "telnetlib", "xmlrpc",
        "ctypes", "mmap", "signal", "resource",
    }

    def visit_Call(self, node: ast.Call) -> None:
        self._check_env_gating(node)
        self._check_subprocess(node)
        self._check_obfuscation(node)
        self._check_network_in_setup(node)
        self._check_eval_exec(node)
        self._check_dynamic_import(node)
        self._check_sensitive_file_write(node)
        self._check_context_poisoning(node)
        self._check_privilege_escalation(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect os.environ['KEY'] = value assignments."""
        self._check_env_assignment(node)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """SCOPE-001: Track imports of sensitive modules."""
        for alias in node.names:
            top_module = alias.name.split(".")[0]
            if top_module in self.SCOPE_SENSITIVE_MODULES:
                self.findings.append(PayloadFinding(
                    signal_id="SCOPE-001",
                    severity="medium",
                    title=f"Sensitive module import: {alias.name}",
                    detail=(
                        f"Import of '{alias.name}' provides low-level system/network access. "
                        f"Unusual in packages that don't advertise this capability."
                    ),
                    file_path=self.file_path,
                    line_number=getattr(node, "lineno", 0),
                    score_contribution=0.3,
                ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """SCOPE-001: Track from-imports of sensitive modules."""
        if node.module:
            top_module = node.module.split(".")[0]
            if top_module in self.SCOPE_SENSITIVE_MODULES:
                self.findings.append(PayloadFinding(
                    signal_id="SCOPE-001",
                    severity="medium",
                    title=f"Sensitive module import: from {node.module}",
                    detail=(
                        f"Import from '{node.module}' provides low-level system/network access. "
                        f"Unusual in packages that don't advertise this capability."
                    ),
                    file_path=self.file_path,
                    line_number=getattr(node, "lineno", 0),
                    score_contribution=0.3,
                ))
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
                detail=(
                    f"Setup file makes network request via {name}() "
                    "— strong indicator of malicious install-time behavior."
                ),
                file_path=self.file_path,
                line_number=getattr(node, "lineno", 0),
                score_contribution=0.9,
            ))

    def _check_eval_exec(self, node: ast.Call) -> None:
        """PAYLOAD-005: eval()/exec() with non-literal argument."""
        name = self._get_call_name(node)
        if name in ("eval", "exec"):
            # Check if argument is a simple string literal (less suspicious)
            if (node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
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
                if (isinstance(kw.value.value, str)
                        and ("w" in kw.value.value or "a" in kw.value.value)):
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
                            detail=(
                                f"File write targeting '{path_str}' "
                                f"— matches sensitive path '{sensitive}'."
                            ),
                            file_path=self.file_path,
                            line_number=getattr(node, "lineno", 0),
                            score_contribution=0.9,
                        ))
                        return

    def _check_context_poisoning(self, node: ast.Call) -> None:
        """POISON-001: Context poisoning — modifying env/sys.path at import time."""
        name = self._get_call_name(node)

        # Check os.putenv() calls
        if name == "os.putenv":
            self.findings.append(PayloadFinding(
                signal_id="POISON-001",
                severity="high",
                title="Environment modification: os.putenv()",
                detail=(
                    "Call to os.putenv() modifies environment "
                    "at import time — context poisoning risk."
                ),
                file_path=self.file_path,
                line_number=getattr(node, "lineno", 0),
                score_contribution=0.7,
            ))

        # Check sys.path modifications
        if name in self.SYSPATH_MODIFY_PATTERNS:
            self.findings.append(PayloadFinding(
                signal_id="POISON-001",
                severity="high",
                title=f"Python path manipulation: {name}()",
                detail=(
                    f"Call to {name}() modifies sys.path "
                    "— can redirect imports to malicious modules."
                ),
                file_path=self.file_path,
                line_number=getattr(node, "lineno", 0),
                score_contribution=0.7,
            ))

    def _check_privilege_escalation(self, node: ast.Call) -> None:
        """PRIV-001: Privilege escalation — setuid, setgid, chown, chmod 0o777, sudo."""
        name = self._get_call_name(node)

        # Direct privilege escalation calls
        if name in self.PRIV_ESCALATION_CALLS:
            self.findings.append(PayloadFinding(
                signal_id="PRIV-001",
                severity="critical",
                title=f"Privilege escalation: {name}()",
                detail=f"Call to {name}() modifies process or file ownership/permissions.",
                file_path=self.file_path,
                line_number=getattr(node, "lineno", 0),
                score_contribution=0.9,
            ))

        # os.chmod with overly permissive modes (0o777, 0o766, 0o667, etc.)
        if name == "os.chmod" and len(node.args) >= 2:
            mode_arg = node.args[1]
            if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, int):
                mode = mode_arg.value
                # Flag if world-writable (others have write: o+w)
                if mode & 0o002:
                    self.findings.append(PayloadFinding(
                        signal_id="PRIV-001",
                        severity="high",
                        title=f"Overly permissive chmod: {oct(mode)}",
                        detail=(
                            f"os.chmod() with mode {oct(mode)} grants world-writable permissions. "
                            f"This weakens file security and may enable privilege escalation."
                        ),
                        file_path=self.file_path,
                        line_number=getattr(node, "lineno", 0),
                        score_contribution=0.7,
                    ))

        # subprocess/os.system with sudo
        if name in ("subprocess.run", "subprocess.call", "subprocess.Popen",
                     "subprocess.check_output", "subprocess.check_call"):
            if node.args:
                first_arg = node.args[0]
                if self._arg_contains_sudo(first_arg):
                    self.findings.append(PayloadFinding(
                        signal_id="PRIV-001",
                        severity="critical",
                        title="Sudo execution via subprocess",
                        detail=(
                            "Subprocess call invokes sudo "
                            "— attempts to escalate to root privileges."
                        ),
                        file_path=self.file_path,
                        line_number=getattr(node, "lineno", 0),
                        score_contribution=0.95,
                    ))
        if name == "os.system" and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value.strip().startswith("sudo "):
                    self.findings.append(PayloadFinding(
                        signal_id="PRIV-001",
                        severity="critical",
                        title="Sudo execution via os.system",
                        detail="os.system() call starts with 'sudo' — attempts root privileges.",
                        file_path=self.file_path,
                        line_number=getattr(node, "lineno", 0),
                        score_contribution=0.95,
                    ))

    def _arg_contains_sudo(self, node: ast.expr) -> bool:
        """Check if a subprocess argument list starts with 'sudo'."""
        if isinstance(node, (ast.List, ast.Tuple)):
            if node.elts:
                first = node.elts[0]
                if isinstance(first, ast.Constant) and first.value == "sudo":
                    return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value.strip().startswith("sudo ")
        return False

    def _check_env_assignment(self, node: ast.Assign) -> None:
        """POISON-001: Detect os.environ['KEY'] = value and sys.path = [...]."""
        for target in node.targets:
            # os.environ['KEY'] = value
            if isinstance(target, ast.Subscript):
                if isinstance(target.value, ast.Attribute):
                    val = target.value
                    if (isinstance(val.value, ast.Name) and val.value.id == "os"
                            and val.attr == "environ"):
                        self.findings.append(PayloadFinding(
                            signal_id="POISON-001",
                            severity="high",
                            title="Environment variable modification via os.environ",
                            detail="Direct os.environ assignment modifies the process environment.",
                            file_path=self.file_path,
                            line_number=getattr(node, "lineno", 0),
                            score_contribution=0.7,
                        ))
                    # sys.path[:] = [...] (slice assignment)
                    if (isinstance(val.value, ast.Name) and val.value.id == "sys"
                            and val.attr == "path"):
                        self.findings.append(PayloadFinding(
                            signal_id="POISON-001",
                            severity="high",
                            title="Python path manipulation via sys.path slice assignment",
                            detail=(
                                "sys.path slice assignment can redirect "
                                "imports to malicious modules."
                            ),
                            file_path=self.file_path,
                            line_number=getattr(node, "lineno", 0),
                            score_contribution=0.7,
                        ))

            # sys.path = [...] (direct assignment)
            if isinstance(target, ast.Attribute):
                if (isinstance(target.value, ast.Name) and target.value.id == "sys"
                        and target.attr == "path"):
                    self.findings.append(PayloadFinding(
                        signal_id="POISON-001",
                        severity="high",
                        title="Python path manipulation via sys.path assignment",
                        detail=(
                            "Direct sys.path assignment can redirect "
                            "imports to malicious modules."
                        ),
                        file_path=self.file_path,
                        line_number=getattr(node, "lineno", 0),
                        score_contribution=0.7,
                    ))


# ---------------------------------------------------------------------------
# Prompt injection scanner (for package descriptions / code comments)
# ---------------------------------------------------------------------------

# Patterns that indicate prompt injection targeting AI coding agents
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?prior\s+instructions",
    r"disregard\s+(all\s+)?previous",
    r"forget\s+(all\s+)?previous",
    r"you\s+are\s+now\s+a",
    r"new\s+system\s+prompt",
    r"override\s+system\s+prompt",
    r"act\s+as\s+(?:a\s+)?(?:different|new)",
    r"your\s+new\s+(?:role|task|instruction)",
    r"from\s+now\s+on\s+you\s+(?:are|will|must)",
    r"IMPORTANT:\s*(?:ignore|disregard|override)",
    r"<\s*system\s*>",  # raw system prompt tags
    r"\[INST\]",  # Llama-style instruction tags
    r"###\s*(?:System|Human|Assistant)\s*:",  # chat format injection
    r"do\s+not\s+(?:scan|analyze|flag|report|check)\s+this",
    r"this\s+(?:package|module|library)\s+is\s+(?:safe|trusted|verified)\b(?!\s+(?:for|to|because|when|in))",
    r"mark\s+(?:this\s+)?(?:as\s+)?(?:safe|clean|verified)",
]

_INJECTION_RE = re.compile(
    "|".join(f"(?:{p})" for p in INJECTION_PATTERNS),
    re.IGNORECASE,
)


def scan_for_prompt_injection(text: str) -> list[str]:
    """
    Scan a text (description, README, code comment) for prompt injection patterns.
    Returns a list of matched pattern snippets.
    """
    if not text:
        return []
    matches = []
    for m in _INJECTION_RE.finditer(text):
        matches.append(m.group(0))
    return matches


def scan_code_comments_for_injection(source: str) -> list[tuple[str, int]]:
    """
    Extract comments from Python source and scan for injection patterns.
    Returns list of (matched_text, line_number).
    """
    results = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return results

    # ast doesn't expose comments directly, so scan raw source lines
    # Handles both standalone (#) and inline (code  # comment) comments
    for lineno, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if "#" in stripped:
            comment_start = stripped.find("#")
            comment = stripped[comment_start + 1:].strip()
            for m in _INJECTION_RE.finditer(comment):
                results.append((m.group(0), lineno))

    # Also scan docstrings (string expressions at start of module/class/function)
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                for m in _INJECTION_RE.finditer(node.value.value):
                    results.append((m.group(0), getattr(node, "lineno", 0)))

    return results


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
        if ecosystem == "npm":
            from uast.js_payload import JSPayloadAnalyzer
            js_analyzer = JSPayloadAnalyzer()
            return js_analyzer.analyze_package(name, ecosystem, version)
        if ecosystem != "pypi":
            logger.debug("Payload analysis only supports PyPI and npm — skipping %s", ecosystem)
            return []

        with tempfile.TemporaryDirectory(prefix="uast_payload_") as tmpdir:
            pkg_path = download_package(name, version, tmpdir, sdist_only=True)
            if not pkg_path:
                logger.warning("Failed to download package %s for payload analysis", name)
                return []

            extract_dir = os.path.join(tmpdir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)

            if not extract_archive(pkg_path, extract_dir):
                logger.warning("Failed to extract package %s", name)
                return []

            findings = self._analyze_python_files(extract_dir)
            logger.info("Payload analysis complete: %s → %d findings", name, len(findings))
            return self._findings_to_signals(findings)

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
            if (f.signal_id not in by_id
                    or f.score_contribution > by_id[f.signal_id].score_contribution):
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
