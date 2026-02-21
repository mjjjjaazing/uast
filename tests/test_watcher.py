"""
Tests for the uast watcher module.

Covers:
  - Package name extraction from pip/npm command lines
  - Dependency file parsing (requirements.txt, package.json, pyproject.toml)
  - Agent-specific setup detection
  - Deduplication of analyzed packages
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from uast.watcher import (
    _extract_package_names,
    DependencyFileHandler,
    GIT_HOOK_SCRIPT,
)


# ---------------------------------------------------------------------------
# Command line parsing
# ---------------------------------------------------------------------------

class TestExtractPackageNames:

    def test_pip_install_single(self):
        result = _extract_package_names("pip install requests", "pypi")
        assert ("requests", "pypi") in result

    def test_pip_install_multiple(self):
        result = _extract_package_names("pip install flask django", "pypi")
        names = [r[0] for r in result]
        assert "flask" in names
        assert "django" in names

    def test_pip_install_with_version(self):
        result = _extract_package_names("pip install requests>=2.0", "pypi")
        assert ("requests", "pypi") in result

    def test_pip3_install(self):
        result = _extract_package_names("pip3 install flask", "pypi")
        assert ("flask", "pypi") in result

    def test_python_m_pip(self):
        result = _extract_package_names("python -m pip install numpy", "pypi")
        assert ("numpy", "pypi") in result

    def test_python3_m_pip(self):
        result = _extract_package_names("python3 -m pip install pandas", "pypi")
        assert ("pandas", "pypi") in result

    def test_pip_ignores_flags(self):
        result = _extract_package_names("pip install --upgrade requests", "pypi")
        names = [r[0] for r in result]
        assert "requests" in names
        assert "--upgrade" not in names

    def test_pip_ignores_urls(self):
        result = _extract_package_names(
            "pip install https://example.com/pkg.tar.gz requests", "pypi"
        )
        names = [r[0] for r in result]
        assert "requests" in names
        assert "https://example.com/pkg.tar.gz" not in names

    def test_npm_install_single(self):
        result = _extract_package_names("npm install lodash", "npm")
        assert ("lodash", "npm") in result

    def test_npm_i_shorthand(self):
        result = _extract_package_names("npm i express", "npm")
        assert ("express", "npm") in result

    def test_yarn_add(self):
        result = _extract_package_names("yarn add react", "npm")
        assert ("react", "npm") in result

    def test_pnpm_add(self):
        result = _extract_package_names("pnpm add vue", "npm")
        assert ("vue", "npm") in result

    def test_uv_pip_install(self):
        result = _extract_package_names("uv pip install httpx", "pypi")
        assert ("httpx", "pypi") in result

    def test_poetry_add(self):
        result = _extract_package_names("poetry add fastapi", "pypi")
        assert ("fastapi", "pypi") in result

    def test_bun_add(self):
        result = _extract_package_names("bun add esbuild", "npm")
        assert ("esbuild", "npm") in result

    def test_no_match_returns_empty(self):
        result = _extract_package_names("ls -la", "pypi")
        assert result == []

    def test_short_name_ignored(self):
        # Single character names are rejected (len > 1)
        result = _extract_package_names("pip install a", "pypi")
        assert len(result) == 0


# ---------------------------------------------------------------------------
# Dependency file parsing
# ---------------------------------------------------------------------------

class TestDependencyFileHandler:

    def _make_handler(self) -> DependencyFileHandler:
        watcher_mock = MagicMock()
        return DependencyFileHandler(watcher_mock, Path("/test"))

    def test_parse_requirements_txt(self):
        handler = self._make_handler()
        content = """
requests>=2.28
flask==2.3.1
# this is a comment
numpy
-r base.txt
--index-url https://pypi.org/simple
"""
        result = handler._parse_dep_file(content, "requirements.txt")
        assert "requests" in result
        assert "flask" in result
        assert "numpy" in result
        assert "-r" not in result
        assert "--index-url" not in result

    def test_parse_package_json(self):
        handler = self._make_handler()
        content = json.dumps({
            "dependencies": {"react": "^18.0", "axios": "^1.0"},
            "devDependencies": {"jest": "^29.0"},
        })
        result = handler._parse_dep_file(content, "package.json")
        assert "react" in result
        assert "axios" in result
        assert "jest" in result

    def test_parse_package_json_invalid(self):
        handler = self._make_handler()
        result = handler._parse_dep_file("not json {{{", "package.json")
        assert result == set()

    def test_parse_empty_requirements(self):
        handler = self._make_handler()
        result = handler._parse_dep_file("", "requirements.txt")
        assert result == set()

    def test_snapshot_captures_existing_deps(self):
        handler = self._make_handler()
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "requirements.txt"
            req_file.write_text("requests\nflask\n")
            handler.snapshot(Path(tmpdir))
            assert str(req_file) in handler._last_snapshots
            assert "requests" in handler._last_snapshots[str(req_file)]

    def test_diff_detects_new_packages(self):
        handler = self._make_handler()
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "requirements.txt"
            req_file.write_text("requests\n")
            handler.snapshot(Path(tmpdir))

            # Simulate adding a new package
            req_file.write_text("requests\nnumpy\n")
            handler._handle_dep_file_change(req_file)

            # Check that _queue_analysis was called with numpy
            calls = handler._watcher._queue_analysis.call_args_list
            pkg_names = [c.args[0] for c in calls]
            assert "numpy" in pkg_names


# ---------------------------------------------------------------------------
# Git hook script
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# AgentWatcher unit tests
# ---------------------------------------------------------------------------

class TestAgentWatcher:

    def _make_watcher(self, tmpdir, agent="cursor"):
        from uast.watcher import AgentWatcher
        display = MagicMock()
        reporter = MagicMock()
        return AgentWatcher(
            project_path=Path(tmpdir),
            agent=agent,
            threshold=6.0,
            block=False,
            display=display,
            reporter=reporter,
            aal=0.7,
        )

    def test_is_pip_install(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = self._make_watcher(tmpdir)
            assert watcher._is_pip_install("pip install requests") is True
            assert watcher._is_pip_install("pip3 install flask") is True
            assert watcher._is_pip_install("python -m pip install numpy") is True
            assert watcher._is_pip_install("ls -la") is False

    def test_is_npm_install(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = self._make_watcher(tmpdir)
            assert watcher._is_npm_install("npm install lodash") is True
            assert watcher._is_npm_install("yarn add react") is True
            assert watcher._is_npm_install("pnpm add vue") is True
            assert watcher._is_npm_install("ls -la") is False

    def test_parse_pip_cmdline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = self._make_watcher(tmpdir)
            result = watcher._parse_pip_cmdline("pip install flask django")
            assert "flask" in result
            assert "django" in result

    def test_parse_npm_cmdline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = self._make_watcher(tmpdir)
            result = watcher._parse_npm_cmdline("npm install express axios")
            assert "express" in result
            assert "axios" in result

    def test_queue_analysis_deduplication(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = self._make_watcher(tmpdir)
            with patch.object(watcher, "_run_analysis"):
                watcher._queue_analysis("requests", "pypi", "test")
                watcher._queue_analysis("requests", "pypi", "test")
                # Second call should be deduped
                assert "pypi:requests" in watcher._analyzed

    def test_queue_analysis_case_insensitive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = self._make_watcher(tmpdir)
            with patch.object(watcher, "_run_analysis"):
                watcher._queue_analysis("Requests", "pypi", "test")
                assert "pypi:requests" in watcher._analyzed

    def test_copilot_hook_install(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            git_dir = project / ".git" / "hooks"
            git_dir.mkdir(parents=True)

            watcher = self._make_watcher(tmpdir, agent="copilot")
            watcher._install_git_hook()

            hook = project / ".git" / "hooks" / "pre-commit"
            assert hook.exists()
            assert "managed by uast" in hook.read_text()
            watcher._git_hook_installed = True

    def test_copilot_hook_remove(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            hook_dir = project / ".git" / "hooks"
            hook_dir.mkdir(parents=True)
            hook = hook_dir / "pre-commit"
            hook.write_text("# managed by uast\necho test\n")

            watcher = self._make_watcher(tmpdir, agent="copilot")
            watcher._git_hook_installed = True
            watcher._remove_git_hook()
            assert not hook.exists()

    def test_copilot_hook_preserves_existing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            hook_dir = project / ".git" / "hooks"
            hook_dir.mkdir(parents=True)
            hook = hook_dir / "pre-commit"
            hook.write_text("#!/bin/sh\necho custom hook\n")

            watcher = self._make_watcher(tmpdir, agent="copilot")
            watcher._install_git_hook()
            # Should not overwrite existing non-uast hook
            assert "custom hook" in hook.read_text()
            assert not watcher._git_hook_installed


# ---------------------------------------------------------------------------
# Git hook script
# ---------------------------------------------------------------------------

class TestGitHookScript:

    def test_hook_script_has_marker(self):
        assert "managed by uast" in GIT_HOOK_SCRIPT

    def test_hook_script_checks_requirements(self):
        assert "requirements.txt" in GIT_HOOK_SCRIPT

    def test_hook_script_checks_package_json(self):
        assert "package.json" in GIT_HOOK_SCRIPT

    def test_hook_script_calls_uast_check(self):
        assert "uast check" in GIT_HOOK_SCRIPT
