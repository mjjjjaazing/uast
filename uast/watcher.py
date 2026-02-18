"""
AgentWatcher — dual interception engine.

Primary:   Process watcher — monitors system-wide for pip/npm install
           subprocesses spawned during the session. Works with every
           agent immediately, no wrapping required.

Secondary: File watcher — monitors requirements.txt, package.json,
           pyproject.toml for changes. Catches agents that write
           dependency files rather than running installs directly
           (common in Cursor and Copilot workflows).
"""

from __future__ import annotations

import re
import time
import threading
import subprocess
from pathlib import Path
from typing import Optional

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

from uast.analyzer import SupplyChainAnalyzer, AnalysisResult
from uast.display import Display
from uast.reporter import SessionReporter


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


class AgentWatcher:
    """
    Main watcher orchestrator.

    Runs two detection loops in parallel threads:
      1. Process monitor — scans running processes every second
      2. File watcher   — uses watchdog for instant file change events

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
    ) -> None:
        self.project_path = project_path
        self.agent = agent
        self.threshold = threshold
        self.block = block
        self.display = display
        self.reporter = reporter

        self.analyzer = SupplyChainAnalyzer()
        self._seen_pids: set[int] = set()
        self._analyzed: set[str] = set()  # "ecosystem:pkg" already analyzed
        self._lock = threading.Lock()
        self._running = False

    def start(self) -> None:
        """Start both watchers and block until interrupted."""
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

        self.display.watching(self.project_path, self.agent, self.threshold)

        try:
            while self._running:
                time.sleep(0.5)
        finally:
            observer.stop()
            observer.join()

    def stop(self) -> None:
        self._running = False

    def _process_monitor_loop(self) -> None:
        """Continuously scan running processes for pip/npm install commands."""
        while self._running:
            try:
                self._scan_processes()
            except Exception:
                pass
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
                    self._seen_pids.add(pid)
                    packages = self._parse_pip_cmdline(cmdline)
                    for pkg_name in packages:
                        self._queue_analysis(pkg_name, "pypi", "process:pip")

                # Detect npm/yarn/pnpm installs
                elif self._is_npm_install(cmdline):
                    self._seen_pids.add(pid)
                    packages = self._parse_npm_cmdline(cmdline)
                    for pkg_name in packages:
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
                return
            self._analyzed.add(key)

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
        # kill the install process (best-effort — process may already be done)
        if self.block and result.ars_score >= self.threshold:
            self._attempt_block(package_name)

    def _attempt_block(self, package_name: str) -> None:
        """
        Best-effort attempt to kill an in-progress install process.
        This is inherently racy — a fast install may already be complete.
        Future versions will use LD_PRELOAD / kernel hooks for reliable blocking.
        """
        for proc in psutil.process_iter(["pid", "cmdline"]):
            try:
                cmdline = " ".join(proc.info["cmdline"] or [])
                if package_name.lower() in cmdline.lower() and (
                    "pip" in cmdline or "npm" in cmdline
                ):
                    proc.kill()
                    self.display.blocked(package_name)
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
