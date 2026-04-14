"""Eval runner.

Apply a detector spec to the labeled corpus and compute precision/recall/FPR.

This module is the deterministic gate in the research loop.  No LLM calls,
no network — just Python evaluating the spec against the corpus so decisions
are reproducible.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Iterable

from research import config as cfg
from research.schema import CorpusEntry, DetectorSpec, EvalResult

logger = logging.getLogger("research.eval_runner")


# ---------------------------------------------------------------------------
# Corpus I/O
# ---------------------------------------------------------------------------

def load_corpus(path: Path | None = None) -> list[CorpusEntry]:
    path = path or cfg.CORPUS_PATH
    entries: list[CorpusEntry] = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            data = json.loads(line)
            entries.append(CorpusEntry(
                name=data["name"],
                ecosystem=data["ecosystem"],
                label=data["label"],
                features=data.get("features", {}),
                notes=data.get("notes", ""),
                source=data.get("source", ""),
            ))
    return entries


# ---------------------------------------------------------------------------
# Detector evaluation — one entry at a time
# ---------------------------------------------------------------------------

def _fires_name_regex(spec: DetectorSpec, entry: CorpusEntry) -> bool:
    if not spec.pattern:
        return False
    return re.search(spec.pattern, entry.name) is not None


def _fires_description_keyword(spec: DetectorSpec, entry: CorpusEntry) -> bool:
    desc = (entry.features.get("description") or "").lower()
    if not desc or not spec.keywords:
        return False
    return any(kw.lower() in desc for kw in spec.keywords)


def _fires_age_threshold(spec: DetectorSpec, entry: CorpusEntry) -> bool:
    if spec.max_age_days is None:
        return False
    age = entry.features.get("age_days")
    if age is None:
        return False
    return int(age) <= spec.max_age_days


def _fires_email_regex(spec: DetectorSpec, entry: CorpusEntry) -> bool:
    if not spec.pattern:
        return False
    email = entry.features.get("author_email") or ""
    return re.search(spec.pattern, email) is not None


def _fires_combined_and(spec: DetectorSpec, entry: CorpusEntry) -> bool:
    if not spec.sub_detectors:
        return False
    return all(detector_fires(sub, entry) for sub in spec.sub_detectors)


_DISPATCH = {
    "name_regex": _fires_name_regex,
    "description_keyword": _fires_description_keyword,
    "age_threshold_days": _fires_age_threshold,
    "maintainer_email_regex": _fires_email_regex,
    "combined_and": _fires_combined_and,
}


def detector_fires(spec: DetectorSpec, entry: CorpusEntry) -> bool:
    """Return True if ``spec`` flags ``entry``."""
    if spec.ecosystem != "both" and entry.ecosystem != spec.ecosystem:
        return False
    fn = _DISPATCH.get(spec.kind)
    if fn is None:
        logger.warning("unknown detector kind %s", spec.kind)
        return False
    return fn(spec, entry)


# ---------------------------------------------------------------------------
# Corpus-level metrics
# ---------------------------------------------------------------------------

def evaluate(spec: DetectorSpec, corpus: Iterable[CorpusEntry]) -> EvalResult:
    tp = fp = fn = tn = 0
    fired_on: list[str] = []
    missed: list[str] = []
    false_positives: list[str] = []

    for entry in corpus:
        fired = detector_fires(spec, entry)
        is_mal = entry.label == "malicious"
        if fired:
            fired_on.append(entry.name)
            if is_mal:
                tp += 1
            else:
                fp += 1
                false_positives.append(entry.name)
        else:
            if is_mal:
                fn += 1
                missed.append(entry.name)
            else:
                tn += 1

    return EvalResult(
        tp=tp, fp=fp, fn=fn, tn=tn,
        fired_on=fired_on, missed=missed, false_positives=false_positives,
    )


# ---------------------------------------------------------------------------
# Acceptance check (deterministic gate before the reviewer)
# ---------------------------------------------------------------------------

def passes_deterministic_gate(
    result: EvalResult,
    settings: cfg.LoopSettings | None = None,
) -> tuple[bool, str]:
    """Return (ok, reason).  A hard gate — reviewer is only called if this passes."""
    settings = settings or cfg.effective_settings()

    if result.tp + result.fp == 0:
        return False, "detector fired on nothing in the corpus"
    if result.precision < settings.min_precision:
        return False, f"precision {result.precision:.2f} < {settings.min_precision}"
    if result.fpr > settings.max_fpr:
        return False, f"false positive rate {result.fpr:.2f} > {settings.max_fpr}"
    return True, "passed deterministic gate"
