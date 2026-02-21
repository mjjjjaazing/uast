"""
Tests for the uast display module.

Covers:
  - Banner output
  - Analysis result display
  - Shutdown message
  - Verdict display logic
  - Verbose vs non-verbose filtering
"""

import io
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from uast.display import Display, VERDICT_COLORS, VERDICT_ICONS, SEVERITY_COLORS
from uast.analyzer import AnalysisResult, PackageSignal


class TestDisplay:

    def _make_display(self, verbose: bool = False) -> tuple[Display, Console]:
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        display = Display(console, verbose=verbose)
        return display, console

    def _make_result(
        self,
        name="test-pkg",
        score=5.0,
        verdict="suspicious",
        signals=None,
    ) -> AnalysisResult:
        return AnalysisResult(
            package_name=name,
            ecosystem="pypi",
            version="1.0.0",
            ars_score=score,
            cvss_base=score * 0.8,
            verdict=verdict,
            signals=signals or [
                PackageSignal("AGE-001", "high", "New package", "detail", 0.85),
            ],
            avt_classes=["AVT-D3-01"],
        )

    def test_banner_no_crash(self):
        display, console = self._make_display()
        display.banner("cursor", "/test/project")

    def test_banner_with_version(self):
        display, console = self._make_display()
        display.banner("cursor", "/test/project", "0.1.0")

    def test_watching_message(self):
        display, console = self._make_display()
        display.watching(Path("/test"), "cursor", 6.0)

    def test_analyzing_message(self):
        display, console = self._make_display()
        display.analyzing("requests", "pypi", "process:pip")

    def test_show_result_critical(self):
        display, console = self._make_display()
        result = self._make_result(verdict="critical", score=9.0)
        display.show_result(result, threshold=6.0)

    def test_show_result_clean_verbose(self):
        display, console = self._make_display(verbose=True)
        result = self._make_result(verdict="clean", score=2.0)
        display.show_result(result, threshold=6.0)

    def test_show_result_clean_non_verbose_silent(self):
        display, console = self._make_display(verbose=False)
        result = self._make_result(verdict="clean", score=2.0)
        # Non-verbose mode should not show clean results
        display.show_result(result, threshold=6.0)

    def test_show_analysis_result(self):
        display, console = self._make_display()
        result = self._make_result()
        display.show_analysis_result(result)

    def test_shutdown_message(self):
        display, console = self._make_display()
        with tempfile.NamedTemporaryFile(suffix=".json") as f:
            display.shutdown(Path(f.name))

    def test_blocked_message(self):
        display, console = self._make_display()
        display.blocked("evil-pkg")

    def test_rolled_back_message(self):
        display, console = self._make_display()
        display.rolled_back("evil-pkg")


    def test_show_analysis_result_with_arsm(self):
        display, console = self._make_display()
        result = self._make_result(verdict="suspicious", score=7.0)
        result.arsm = {"aal": 0.7, "cis": 0.85, "pc": 0.6, "srf": 1.2}
        display.show_analysis_result(result)

    def test_show_analysis_result_with_did_you_mean(self):
        display, console = self._make_display()
        result = self._make_result(verdict="critical", score=9.0)
        result.did_you_mean = "requests"
        display.show_analysis_result(result)

    def test_show_result_verbose_with_arsm(self):
        display, console = self._make_display(verbose=True)
        result = self._make_result(verdict="suspicious", score=7.5)
        result.arsm = {"aal": 0.5, "cis": 0.9, "pc": 0.4, "srf": 2.0}
        display.show_result(result, threshold=6.0)

    def test_show_result_with_info_signal_non_verbose(self):
        display, console = self._make_display(verbose=False)
        result = self._make_result(
            verdict="suspicious",
            score=5.5,
            signals=[
                PackageSignal("INFO-001", "info", "Info signal", "detail", 0.1),
                PackageSignal("AGE-001", "high", "New package", "detail", 0.85),
            ],
        )
        display.show_result(result, threshold=6.0)

    def test_show_result_verbose_with_signal_detail(self):
        display, console = self._make_display(verbose=True)
        result = self._make_result(
            verdict="suspicious",
            score=5.5,
            signals=[
                PackageSignal("AGE-001", "high", "New package", "Created 2 days ago", 0.85),
            ],
        )
        display.show_result(result, threshold=6.0)

    def test_show_result_with_did_you_mean(self):
        display, console = self._make_display()
        result = self._make_result(verdict="critical", score=9.0)
        result.did_you_mean = "requests"
        display.show_result(result, threshold=6.0)

    def test_list_sessions_with_data(self):
        import json
        display, console = self._make_display()
        with tempfile.TemporaryDirectory() as tmpdir:
            sessions_dir = Path(tmpdir)
            report = {
                "agent": "cursor",
                "started_at": "2025-01-15T10:00:00",
                "summary": {"total_packages": 5, "alerts": 2, "suspicious": 1, "clean": 2},
                "results": [],
            }
            (sessions_dir / "session_001.json").write_text(json.dumps(report))
            display.list_sessions(sessions_dir)

    def test_list_sessions_with_bad_json(self):
        display, console = self._make_display()
        with tempfile.TemporaryDirectory() as tmpdir:
            sessions_dir = Path(tmpdir)
            (sessions_dir / "bad.json").write_text("not valid json {{{")
            display.list_sessions(sessions_dir)

    def test_list_sessions_empty_dir(self):
        display, console = self._make_display()
        with tempfile.TemporaryDirectory() as tmpdir:
            display.list_sessions(Path(tmpdir))

    def test_show_report(self):
        display, console = self._make_display()
        data = {
            "agent": "cursor",
            "project": "/test/project",
            "started_at": "2025-01-15T10:00:00",
            "summary": {"total_packages": 3, "alerts": 1, "suspicious": 1, "clean": 1},
            "results": [
                {"package_name": "evil-pkg", "ecosystem": "pypi", "ars_score": 9.0, "verdict": "critical"},
                {"package_name": "test-pkg", "ecosystem": "pypi", "ars_score": 5.0, "verdict": "suspicious"},
                {"package_name": "good-pkg", "ecosystem": "pypi", "ars_score": 1.0, "verdict": "clean"},
            ],
        }
        display.show_report(data)

    def test_show_report_empty_results(self):
        display, console = self._make_display()
        data = {
            "agent": "cursor",
            "project": "/test",
            "started_at": "2025-01-15T10:00:00",
            "summary": {},
            "results": [],
        }
        display.show_report(data)


class TestVerdictMappings:

    def test_all_verdicts_have_colors(self):
        for verdict in ("clean", "suspicious", "critical"):
            assert verdict in VERDICT_COLORS

    def test_all_verdicts_have_icons(self):
        for verdict in ("clean", "suspicious", "critical"):
            assert verdict in VERDICT_ICONS

    def test_all_severities_have_colors(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            assert sev in SEVERITY_COLORS
