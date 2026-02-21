"""
Tests for the uast session reporter.

Covers:
  - Report creation and file writing
  - Report schema v2 structure
  - Summary statistics computation
  - Multiple results accumulation
  - Empty session handling
"""

import json
import tempfile
from pathlib import Path

import pytest

from uast.reporter import SessionReporter
from uast.analyzer import AnalysisResult, PackageSignal


class TestSessionReporter:

    def _make_reporter(self, tmpdir: str) -> SessionReporter:
        return SessionReporter(
            agent="cursor",
            project="/test/project",
            output_path=Path(tmpdir) / "report.json",
        )

    def _make_result(
        self,
        name: str = "test-pkg",
        ecosystem: str = "pypi",
        score: float = 5.0,
        verdict: str = "suspicious",
    ) -> AnalysisResult:
        return AnalysisResult(
            package_name=name,
            ecosystem=ecosystem,
            version="1.0.0",
            ars_score=score,
            cvss_base=score * 0.8,
            verdict=verdict,
            signals=[
                PackageSignal("SIG-001", "medium", "Test signal", "detail", 0.5),
            ],
        )

    def test_save_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = self._make_reporter(tmpdir)
            path = reporter.save()
            assert path.exists()

    def test_save_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = SessionReporter(
                agent="cursor",
                project="/test",
                output_path=Path(tmpdir) / "nested" / "deep" / "report.json",
            )
            path = reporter.save()
            assert path.exists()

    def test_report_schema_v4(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = self._make_reporter(tmpdir)
            reporter.save()
            with open(reporter.output_path) as f:
                data = json.load(f)

            assert data["version"] == "4"
            assert data["agent"] == "cursor"
            assert data["project"] == "/test/project"
            assert "started_at" in data
            assert "ended_at" in data
            assert "summary" in data
            assert "results" in data

    def test_empty_session_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = self._make_reporter(tmpdir)
            reporter.save()
            with open(reporter.output_path) as f:
                data = json.load(f)

            summary = data["summary"]
            assert summary["total_packages"] == 0
            assert summary["alerts"] == 0
            assert summary["avg_ars_score"] == 0.0
            assert summary["max_ars_score"] == 0.0

    def test_add_result_included_in_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = self._make_reporter(tmpdir)
            result = self._make_result()
            reporter.add_result(result, "process:pip")
            reporter.save()

            with open(reporter.output_path) as f:
                data = json.load(f)

            assert data["summary"]["total_packages"] == 1
            assert len(data["results"]) == 1
            assert data["results"][0]["package_name"] == "test-pkg"
            assert data["results"][0]["source"] == "process:pip"

    def test_multiple_results(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = self._make_reporter(tmpdir)
            reporter.add_result(self._make_result("pkg-a", score=3.0, verdict="clean"), "file:req")
            reporter.add_result(self._make_result("pkg-b", score=8.0, verdict="critical"), "process:pip")
            reporter.add_result(self._make_result("pkg-c", score=6.0, verdict="suspicious"), "process:pip")
            reporter.save()

            with open(reporter.output_path) as f:
                data = json.load(f)

            summary = data["summary"]
            assert summary["total_packages"] == 3
            assert summary["clean"] == 1
            assert summary["critical"] == 1
            assert summary["suspicious"] == 1
            assert summary["alerts"] == 2  # suspicious + critical
            assert summary["max_ars_score"] == 8.0

    def test_result_count_property(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = self._make_reporter(tmpdir)
            assert reporter.result_count == 0
            reporter.add_result(self._make_result(), "test")
            assert reporter.result_count == 1

    def test_alert_count_property(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = self._make_reporter(tmpdir)
            reporter.add_result(self._make_result(verdict="clean", score=1.0), "test")
            assert reporter.alert_count == 0
            reporter.add_result(self._make_result(verdict="critical", score=9.0), "test")
            assert reporter.alert_count == 1

    def test_signals_serialized(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = self._make_reporter(tmpdir)
            result = self._make_result()
            reporter.add_result(result, "test")
            reporter.save()

            with open(reporter.output_path) as f:
                data = json.load(f)

            signals = data["results"][0]["signals"]
            assert len(signals) == 1
            assert signals[0]["signal_id"] == "SIG-001"
            assert signals[0]["severity"] == "medium"

    def test_report_json_valid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = self._make_reporter(tmpdir)
            reporter.add_result(self._make_result(), "test")
            reporter.save()

            # Should not raise
            with open(reporter.output_path) as f:
                data = json.load(f)
            assert isinstance(data, dict)
