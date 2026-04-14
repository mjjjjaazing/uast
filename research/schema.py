"""Detector-spec schema shared across drafter, eval runner, and reviewer.

Keep this deliberately small.  The drafter is an LLM and we want the surface
area of what it can propose to be narrow enough that the eval runner can be
deterministic and the resulting detectors can be reviewed by a human in a PR.

A *detector spec* proposes a single new signal for the UAST analyzer.  Fancy
ML-style detectors live outside this loop; this is for the kind of pattern
additions that a senior engineer would write in ten minutes after reading a
fresh malware advisory.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

# ---------------------------------------------------------------------------
# Detector spec
# ---------------------------------------------------------------------------

DetectorKind = Literal[
    "name_regex",              # package name matches regex
    "description_keyword",     # metadata description contains any keyword
    "age_threshold_days",      # package age below threshold (days)
    "maintainer_email_regex",  # author email matches regex
    "combined_and",            # all sub-detectors must fire (AND)
]

Ecosystem = Literal["pypi", "npm", "both"]
Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass
class DetectorSpec:
    """A single proposed detector, safe to apply to a package metadata dict."""

    detector_id: str                # e.g. "NAME-REGEX-2026-04-14-001"
    kind: DetectorKind
    severity: Severity
    ecosystem: Ecosystem
    title: str                       # human-readable signal name
    rationale: str                   # why this is a useful signal
    avt_class: str                   # AVT-D?-??  (from UAST taxonomy)

    # kind-specific fields — only one non-None at a time, except combined_and
    pattern: Optional[str] = None                  # name_regex / maintainer_email_regex
    keywords: list[str] = field(default_factory=list)  # description_keyword
    max_age_days: Optional[int] = None             # age_threshold_days
    sub_detectors: list["DetectorSpec"] = field(default_factory=list)  # combined_and

    # Traceability
    source_advisory_ids: list[str] = field(default_factory=list)
    """e.g. ["GHSA-xxxx-yyyy", "OSV-2025-0001"] — what inspired this detector."""

    def to_json(self) -> dict[str, Any]:
        import dataclasses
        return dataclasses.asdict(self)

    @staticmethod
    def from_json(data: dict[str, Any]) -> "DetectorSpec":
        subs = [DetectorSpec.from_json(s) for s in data.get("sub_detectors", [])]
        return DetectorSpec(
            detector_id=data["detector_id"],
            kind=data["kind"],
            severity=data["severity"],
            ecosystem=data["ecosystem"],
            title=data["title"],
            rationale=data["rationale"],
            avt_class=data["avt_class"],
            pattern=data.get("pattern"),
            keywords=list(data.get("keywords", [])),
            max_age_days=data.get("max_age_days"),
            sub_detectors=subs,
            source_advisory_ids=list(data.get("source_advisory_ids", [])),
        )


# ---------------------------------------------------------------------------
# Corpus entry
# ---------------------------------------------------------------------------

@dataclass
class CorpusEntry:
    """One labeled package in the eval corpus.

    The ``features`` dict mirrors the subset of package metadata that the
    detector kinds above can read, so evaluation is fully offline and
    deterministic.
    """

    name: str
    ecosystem: Ecosystem
    label: Literal["malicious", "benign"]
    features: dict[str, Any]
    """Fields used by detectors. Keys used today:
        - ``description``: str
        - ``age_days``: int | None
        - ``author_email``: str | None
    Add new keys only when adding a matching DetectorKind; the eval runner
    ignores unknown keys so forward-compat is trivial.
    """
    notes: str = ""
    source: str = ""   # e.g. advisory ID or "hand-labeled"


# ---------------------------------------------------------------------------
# Evaluation result
# ---------------------------------------------------------------------------

@dataclass
class EvalResult:
    tp: int
    fp: int
    fn: int
    tn: int
    fired_on: list[str] = field(default_factory=list)     # names of packages the detector flagged
    missed: list[str] = field(default_factory=list)       # malicious names it missed
    false_positives: list[str] = field(default_factory=list)  # benign names it wrongly flagged

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def fpr(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    def summary(self) -> str:
        return (
            f"precision={self.precision:.2f} recall={self.recall:.2f} "
            f"fpr={self.fpr:.2f}  TP={self.tp} FP={self.fp} FN={self.fn} TN={self.tn}"
        )


# ---------------------------------------------------------------------------
# Reviewer verdict
# ---------------------------------------------------------------------------

ReviewerDecision = Literal["accept", "reject", "needs_work"]


@dataclass
class ReviewerVerdict:
    decision: ReviewerDecision
    reasoning: str
    suggested_edits: str = ""   # free-form notes, only set when decision=needs_work
