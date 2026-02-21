"""
AgentWatcher — dual interception engine.

Primary:   Process watcher — monitors system-wide for pip/npm install
           subprocesses spawned during the session. Works with every
           agent immediately, no wrapping required.

Secondary: File watcher — monitors requirements.txt, package.json,
           pyproject.toml for changes. Catches agents that write
           dependency files rather than running installs directly
           (common in Cursor and Copilot workflows).

Agent-specific:
  - Claude Code: Watches ~/.claude/ for MCP-related log files
  - Copilot: Installs/removes .git/hooks/pre-commit for package checks
  - Windsurf/Codeium: Generic process + file watchers (no public APIs)
"""

from __future__ import annotations

import logging
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

import psutil
from watchdog.events import FileModifiedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from uast.analyzer import SupplyChainAnalyzer
from uast.config import DEFAULT_CONFIG, get_watcher_config
from uast.display import Display
from uast.reporter import SessionReporter

logger = logging.getLogger("uast.watcher")

# Files the file watcher monitors for dependency changes
DEPENDENCY_FILES = {
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}

# Process name patterns that indicate a package install is happening
PIP_PATTERNS = [
    r"pip\s+install\s+(.+)",
    r"pip3\s+install\s+(.+)",
    r"python\s+-m\s+pip\s+install\s+(.+)",
    r"python3\s+-m\s+pip\s+install\s+(.+)",
    r"uv\s+pip\s+install\s+(.+)",           # uv support
    r"poetry\s+add\s+(.+)",                  # poetry support
    r"pipenv\s+install\s+(.+)",              # pipenv support
]

NPM_PATTERNS = [
    r"npm\s+install\s+(.+)",
    r"npm\s+i\s+(.+)",
    r"npm\s+add\s+(.+)",
    r"yarn\s+add\s+(.+)",
    r"pnpm\s+add\s+(.+)",
    r"pnpm\s+install\s+(.+)",
    r"bun\s+add\s+(.+)",                     # bun support
]

# Git hook script template for Copilot integration
GIT_HOOK_SCRIPT = """#!/bin/sh
# UAST pre-commit hook — checks newly added packages in dependency files
# Installed by: uast start --agent copilot
# This hook is automatically removed when the uast session ends.

UAST_MARKER="# managed by uast"

# Check if uast is available
if ! command -v uast >/dev/null 2>&1; then
    exit 0
fi

# Validate package name: only allow safe characters
validate_pkg_name() {
    echo "$1" | grep -qE '^[a-zA-Z0-9@][a-zA-Z0-9._@/-]{0,213}$'
}

# Check requirements.txt changes
for f in requirements.txt requirements-dev.txt; do
    if git diff --cached --name-only | grep -q "$f"; then
        ADDED=$(git diff --cached "$f" | grep '^+' | grep -v '^+++' \\
            | sed 's/^+//' | grep -v '^#' | grep -v '^-')
        for pkg in $ADDED; do
            PKG_NAME=$(echo "$pkg" | sed 's/[><=!~].*//')
            if [ -n "$PKG_NAME" ] && validate_pkg_name "$PKG_NAME"; then
                uast check "$PKG_NAME" --ecosystem pypi 2>/dev/null
            fi
        done
    fi
done

# Check package.json changes
if git diff --cached --name-only | grep -q "package.json"; then
    ADDED=$(git diff --cached package.json | grep '^+' \\
        | grep -v '^+++' | grep '"[^"]*":' \\
        | sed 's/.*"\\([^"]*\\)".*/\\1/')
    for pkg in $ADDED; do
        if [ -n "$pkg" ] && [ "$pkg" != "dependencies" ] \\
            && [ "$pkg" != "devDependencies" ] \\
            && validate_pkg_name "$pkg"; then
            uast check "$pkg" --ecosystem npm 2>/dev/null
        fi
    done
fi

exit 0
"""


def _extract_package_names(cmdline: str, ecosystem: str) -> list[tuple[str, str]]:
    """
    Parse a command line string and extract (package_name, ecosystem) tuples.
    Strips version specifiers, flags, and URLs.
    """
    patterns = PIP_PATTERNS if ecosystem == "pypi" else NPM_PATTERNS
    packages = []

    for pattern in patterns:
        match = re.search(pattern, cmdline, re.IGNORECASE)
        if match:
            args = match.group(1).split()
            for arg in args:
                # Skip flags
                if arg.startswith("-"):
                    continue
                # Skip URLs
                if arg.startswith(("http://", "https://", "git+")):
                    continue
                # Strip version specifiers: requests>=2.0, flask==2.3.1, etc.
                name = re.split(r"[><=!~\[]", arg)[0].strip()
                if name and len(name) > 1:
                    packages.append((name, ecosystem))
            break

    return packages


class DependencyFileHandler(FileSystemEventHandler):
    """
    Watchdog event handler for dependency file changes.

    When requirements.txt or package.json is modified, parse
    the new/changed packages and run them through the analyzer.
    """

    def __init__(
        self,
        watcher: "AgentWatcher",
        project_path: Path,
    ) -> None:
        self._watcher = watcher
        self._project_path = project_path
        self._last_snapshots: dict[str, set[str]] = {}
        super().__init__()

    def on_modified(self, event: FileModifiedEvent) -> None:  # type: ignore[override]
        if event.is_directory:
            return

        path = Path(event.src_path)
        if path.name not in DEPENDENCY_FILES:
            return

        self._handle_dep_file_change(path)

    def _handle_dep_file_change(self, path: Path) -> None:
        """Diff the dependency file and analyze newly added packages."""
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return

        filename = path.name
        new_packages = self._parse_dep_file(content, filename)
        old_packages = self._last_snapshots.get(str(path), set())
        added = new_packages - old_packages

        self._last_snapshots[str(path)] = new_packages

        for pkg_name in added:
            ecosystem = "npm" if filename in ("package.json", "package-lock.json") else "pypi"
            source = f"file:{filename}"
            self._watcher._queue_analysis(pkg_name, ecosystem, source)

    def _parse_dep_file(self, content: str, filename: str) -> set[str]:
        """Extract package names from common dependency file formats."""
        packages: set[str] = set()

        if filename == "package.json":
            import json
            try:
                data = json.loads(content)
                for section in ("dependencies", "devDependencies", "peerDependencies"):
                    packages.update(data.get(section, {}).keys())
            except json.JSONDecodeError:
                pass

        elif filename in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt"):
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "-r", "--")):
                    continue
                name = re.split(r"[><=!~\[;\s]", line)[0].strip()
                if name:
                    packages.add(name)

        elif filename == "pyproject.toml":
            for line in content.splitlines():
                line = line.strip().strip('"').strip("'").strip(",")
                if not line or line.startswith("#"):
                    continue
                name = re.split(r"[><=!~\[;\s]", line)[0].strip()
                if len(name) > 1 and re.match(r"^[a-zA-Z0-9]", name):
                    packages.add(name)

        return packages

    def snapshot(self, project_path: Path) -> None:
        """Take initial snapshots of all existing dependency files."""
        for filename in DEPENDENCY_FILES:
            path = project_path / filename
            if path.exists():
                try:
                    content = path.read_text(encoding="utf-8", errors="ignore")
                    self._last_snapshots[str(path)] = self._parse_dep_file(
                        content, filename
                    )
                except OSError:
                    pass


class ClaudeCodeLogHandler(FileSystemEventHandler):
    """
    Watches ~/.claude/ for MCP-related log files to detect
    install commands earlier than process monitoring.
    """

    INSTALL_PATTERNS = [
        r"pip\s+install\s+([\w\-\.]+)",
        r"npm\s+install\s+([\w\-\.@/]+)",
        r"yarn\s+add\s+([\w\-\.@/]+)",
    ]

    def __init__(self, watcher: "AgentWatcher") -> None:
        self._watcher = watcher
        self._seen_lines: set[str] = set()
        super().__init__()

    def on_modified(self, event: FileModifiedEvent) -> None:  # type: ignore[override]
        if event.is_directory:
            return

        path = Path(event.src_path)
        if path.suffix not in (".log", ".jsonl"):
            return

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                if line in self._seen_lines:
                    continue
                self._seen_lines.add(line)

                for pattern in self.INSTALL_PATTERNS:
                    match = re.search(pattern, line)
                    if match:
                        pkg_name = match.group(1)
                        ecosystem = "npm" if "npm" in pattern or "yarn" in pattern else "pypi"
                        self._watcher._queue_analysis(
                            pkg_name, ecosystem, "claude-code:log"
                        )
        except OSError:
            pass


class AgentWatcher:
    """
    Main watcher orchestrator.

    Runs detection loops in parallel threads:
      1. Process monitor — scans running processes every second
      2. File watcher   — uses watchdog for instant file change events
      3. Agent-specific  — Claude Code log watcher, Copilot git hooks

    All detected installs are queued and analyzed asynchronously
    so the monitoring loop never blocks.
    """

    PROCESS_POLL_INTERVAL = 1.0  # seconds between process scans

    def __init__(
        self,
        project_path: Path,
        agent: str,
        threshold: float,
        block: bool,
        display: Display,
        reporter: SessionReporter,
        aal: float = 0.5,
        deep: bool = False,
        config: Optional[dict] = None,
    ) -> None:
        self.project_path = project_path
        self.agent = agent
        self.threshold = threshold
        self.block = block
        self.display = display
        self.reporter = reporter
        self.config = config or DEFAULT_CONFIG

        watcher_cfg = get_watcher_config(self.config)
        self.PROCESS_POLL_INTERVAL = watcher_cfg.get("poll_interval", 1.0)

        self.analyzer = SupplyChainAnalyzer(aal=aal, deep=deep, config=self.config)
        self._seen_pids: dict[int, str] = {}  # pid → package_name
        self._analyzed: set[str] = set()  # "ecosystem:pkg" already analyzed
        self._lock = threading.Lock()
        self._running = False
        self._git_hook_installed = False
        self._claude_observer: Optional[Observer] = None

    def start(self) -> None:
        """Start all watchers and block until interrupted."""
        logger.info("Starting watchers for agent=%s project=%s", self.agent, self.project_path)
        self._running = True

        # Snapshot existing dep files before starting
        file_handler = DependencyFileHandler(self, self.project_path)
        file_handler.snapshot(self.project_path)

        # Start watchdog observer (file watcher)
        observer = Observer()
        observer.schedule(file_handler, str(self.project_path), recursive=True)
        observer.start()

        # Start process monitor in a background thread
        process_thread = threading.Thread(
            target=self._process_monitor_loop,
            daemon=True,
            name="uast-process-monitor",
        )
        process_thread.start()

        # Agent-specific setup
        self._setup_agent_specific()

        self.display.watching(self.project_path, self.agent, self.threshold)

        try:
            while self._running:
                time.sleep(0.5)
        finally:
            self._teardown_agent_specific()
            observer.stop()
            observer.join()

    def stop(self) -> None:
        self._running = False

    def _setup_agent_specific(self) -> None:
        """Set up agent-specific interception methods."""
        if self.agent == "claude-code":
            self._start_claude_code_watcher()
        elif self.agent == "copilot":
            self._install_git_hook()

    def _teardown_agent_specific(self) -> None:
        """Clean up agent-specific resources."""
        if self._claude_observer:
            self._claude_observer.stop()
            self._claude_observer.join()
            self._claude_observer = None
        if self._git_hook_installed:
            self._remove_git_hook()

    def _start_claude_code_watcher(self) -> None:
        """Watch ~/.claude/ for MCP-related log files."""
        claude_dir = Path.home() / ".claude"
        if not claude_dir.exists():
            return

        handler = ClaudeCodeLogHandler(self)
        self._claude_observer = Observer()
        self._claude_observer.schedule(handler, str(claude_dir), recursive=True)
        self._claude_observer.start()

    def _install_git_hook(self) -> None:
        """Install a .git/hooks/pre-commit script for Copilot integration."""
        git_dir = self.project_path / ".git"
        if not git_dir.exists():
            return

        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        hook_path = hooks_dir / "pre-commit"

        # Don't overwrite existing hooks
        if hook_path.exists():
            content = hook_path.read_text(encoding="utf-8", errors="ignore")
            if "managed by uast" not in content:
                return  # User has their own hook

        hook_path.write_text(GIT_HOOK_SCRIPT, encoding="utf-8")
        hook_path.chmod(0o755)
        self._git_hook_installed = True

    def _remove_git_hook(self) -> None:
        """Remove the uast-managed git hook."""
        hook_path = self.project_path / ".git" / "hooks" / "pre-commit"
        if hook_path.exists():
            try:
                content = hook_path.read_text(encoding="utf-8", errors="ignore")
                if "managed by uast" in content:
                    hook_path.unlink()
            except OSError:
                pass
        self._git_hook_installed = False

    def _process_monitor_loop(self) -> None:
        """Continuously scan running processes for pip/npm install commands."""
        while self._running:
            try:
                self._scan_processes()
            except (psutil.Error, OSError) as e:
                logger.debug("Process scan error: %s", e)
            time.sleep(self.PROCESS_POLL_INTERVAL)

    def _scan_processes(self) -> None:
        """Scan all running processes and detect install commands."""
        for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
            try:
                pid = proc.info["pid"]
                cmdline_parts = proc.info["cmdline"] or []

                if not cmdline_parts:
                    continue

                cmdline = " ".join(str(p) for p in cmdline_parts)

                # Skip if we've already processed this PID
                if pid in self._seen_pids:
                    continue

                # Detect pip installs
                if self._is_pip_install(cmdline):
                    packages = self._parse_pip_cmdline(cmdline)
                    for pkg_name in packages:
                        self._seen_pids[pid] = pkg_name
                        self._queue_analysis(pkg_name, "pypi", "process:pip")

                # Detect npm/yarn/pnpm installs
                elif self._is_npm_install(cmdline):
                    packages = self._parse_npm_cmdline(cmdline)
                    for pkg_name in packages:
                        self._seen_pids[pid] = pkg_name
                        self._queue_analysis(pkg_name, "npm", "process:npm")

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def _is_pip_install(self, cmdline: str) -> bool:
        return any(
            re.search(p, cmdline, re.IGNORECASE) for p in PIP_PATTERNS
        )

    def _is_npm_install(self, cmdline: str) -> bool:
        return any(
            re.search(p, cmdline, re.IGNORECASE) for p in NPM_PATTERNS
        )

    def _parse_pip_cmdline(self, cmdline: str) -> list[str]:
        packages = []
        for pattern in PIP_PATTERNS:
            match = re.search(pattern, cmdline, re.IGNORECASE)
            if match:
                args = match.group(1).split()
                for arg in args:
                    if arg.startswith("-"):
                        continue
                    if arg.startswith(("http://", "https://", "git+")):
                        continue
                    name = re.split(r"[><=!~\[]", arg)[0].strip()
                    if name and len(name) > 1:
                        packages.append(name)
                break
        return packages

    def _parse_npm_cmdline(self, cmdline: str) -> list[str]:
        packages = []
        for pattern in NPM_PATTERNS:
            match = re.search(pattern, cmdline, re.IGNORECASE)
            if match:
                args = match.group(1).split()
                for arg in args:
                    if arg.startswith("-") or arg.startswith("@") and "/" not in arg:
                        continue
                    # Scoped packages: @scope/name
                    name = re.split(r"@(?!^)", arg)[0] if "@" in arg[1:] else arg
                    name = name.strip()
                    if name and len(name) > 1:
                        packages.append(name)
                break
        return packages

    def _queue_analysis(
        self, package_name: str, ecosystem: str, source: str
    ) -> None:
        """Deduplicate and dispatch analysis for a detected package."""
        key = f"{ecosystem}:{package_name.lower()}"

        with self._lock:
            if key in self._analyzed:
                logger.debug("Already analyzed %s — skipping", key)
                return
            self._analyzed.add(key)

        logger.info("Queuing analysis: %s (%s) via %s", package_name, ecosystem, source)

        # Run analysis in a thread so we never block the monitor loop
        t = threading.Thread(
            target=self._run_analysis,
            args=(package_name, ecosystem, source),
            daemon=True,
            name=f"uast-analyze-{package_name}",
        )
        t.start()

    def _run_analysis(
        self, package_name: str, ecosystem: str, source: str
    ) -> None:
        """Run analysis and dispatch results to display and reporter."""
        self.display.analyzing(package_name, ecosystem, source)

        if ecosystem == "pypi":
            result = self.analyzer.analyze_pypi(package_name)
        else:
            result = self.analyzer.analyze_npm(package_name)

        self.display.show_result(result, self.threshold)
        self.reporter.add_result(result, source)

        # If blocking mode is on and score exceeds threshold, attempt to
        # kill the install process, then rollback if needed
        if self.block and result.ars_score >= self.threshold:
            blocked = self._attempt_block(package_name)
            if not blocked:
                self._rollback_install(package_name, ecosystem)

    def _attempt_block(self, package_name: str) -> bool:
        """
        Best-effort attempt to kill an in-progress install process.
        Only kills processes that UAST previously tracked via _seen_pids.
        Returns True if a process was found and killed.
        """
        for pid, tracked_pkg in list(self._seen_pids.items()):
            if tracked_pkg.lower() != package_name.lower():
                continue
            try:
                proc = psutil.Process(pid)
                if proc.is_running():
                    proc.kill()
                    self.display.blocked(package_name)
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False

    def _rollback_install(self, package_name: str, ecosystem: str) -> None:
        """
        Fallback: if the install process already completed before we could
        kill it, uninstall the package to roll back the change.
        """
        try:
            if ecosystem == "pypi":
                subprocess.run(
                    ["pip", "uninstall", "-y", package_name],
                    capture_output=True,
                    timeout=30,
                )
            else:
                subprocess.run(
                    ["npm", "uninstall", package_name],
                    capture_output=True,
                    timeout=30,
                    cwd=str(self.project_path),
                )
            self.display.rolled_back(package_name)
        except (subprocess.TimeoutExpired, OSError):
            pass
