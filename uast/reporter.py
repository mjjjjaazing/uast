"""
SessionReporter — writes JSON session reports to disk.

Every uast session produces a structured JSON report at
~/.uast/sessions/<timestamp>.json (or a user-specified path).

Report schema v2 adds ARSM dimensions and dependency tree summary.
"""

from __future__ import annotations

import json
import datetime
from pathlib import Path
from dataclasses import asdict

from uast.analyzer import AnalysisResult


class SessionReporter:
    """Accumulates analysis results and writes the final JSON report."""

    REPORT_VERSION = "2"

    def __init__(
        self,
        agent: str,
        project: str,
        output_path: Path,
    ) -> None:
        self.agent = agent
        self.project = project
        self.output_path = output_path
        self.started_at = datetime.datetime.utcnow().isoformat()
        self._results: list[dict] = []

    def add_result(self, result: AnalysisResult, source: str) -> None:
        """Add an analysis result to the session."""
        entry = {
            "package_name": result.package_name,
            "ecosystem": result.ecosystem,
            "version": result.version,
            "ars_score": result.ars_score,
            "cvss_base": result.cvss_base,
            "verdict": result.verdict,
            "avt_classes": result.avt_classes,
            "recommendation": result.recommendation,
            "source": source,
            "analyzed_at": result.analyzed_at,
            "signals": [
                {
                    "signal_id": s.signal_id,
                    "severity": s.severity,
                    "title": s.title,
                    "detail": s.detail,
                    "score_contribution": s.score_contribution,
                }
                for s in result.signals
            ],
            "metadata": result.metadata,
            "arsm": result.arsm,
            "did_you_mean": result.did_you_mean,
        }
        self._results.append(entry)

    def save(self) -> Path:
        """Write the full session report to disk and return the path."""
        ended_at = datetime.datetime.utcnow().isoformat()

        verdicts = [r["verdict"] for r in self._results]
        summary = {
            "total_packages": len(self._results),
            "alerts": sum(1 for v in verdicts if v in ("suspicious", "critical")),
            "suspicious": verdicts.count("suspicious"),
            "critical": verdicts.count("critical"),
            "clean": verdicts.count("clean"),
            "avg_ars_score": (
                round(
                    sum(r["ars_score"] for r in self._results) / len(self._results), 2
                )
                if self._results
                else 0.0
            ),
            "max_ars_score": (
                max(r["ars_score"] for r in self._results) if self._results else 0.0
            ),
        }

        report = {
            "version": self.REPORT_VERSION,
            "agent": self.agent,
            "project": self.project,
            "started_at": self.started_at,
            "ended_at": ended_at,
            "summary": summary,
            "results": self._results,
        }

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return self.output_path

    @property
    def result_count(self) -> int:
        return len(self._results)

    @property
    def alert_count(self) -> int:
        return sum(1 for r in self._results if r["verdict"] in ("suspicious", "critical"))
