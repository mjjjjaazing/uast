"""Orchestrator — one-shot and recurring.

Usage:

    # Single tick (safe, offline):
    python -m research.loop tick

    # Recurring, 30-min interval:
    python -m research.loop run --interval 1800

    # Force live API even if ANTHROPIC_API_KEY is set (dry-run is default
    # when the key is missing):
    UAST_RESEARCH_DRY_RUN=0 python -m research.loop tick
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from research import config as cfg
from research import drafter, eval_runner, harvester, reviewer
from research.schema import DetectorSpec, EvalResult, ReviewerVerdict

logger = logging.getLogger("research.loop")

# ---------------------------------------------------------------------------
# Artifact layout
# ---------------------------------------------------------------------------

ARTIFACT_VERSION = 1


def _ts_slug() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def _write_artifact(
    artifacts_dir: Path,
    settings: cfg.LoopSettings,
    signals: list[dict[str, Any]],
    spec: DetectorSpec,
    eval_result: EvalResult,
    gate_ok: bool,
    gate_reason: str,
    verdict: ReviewerVerdict | None,
) -> Path:
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    slug = _ts_slug()
    decision = verdict.decision if verdict else "skipped"
    path = artifacts_dir / f"{slug}__{decision}__{spec.detector_id}.json"
    payload = {
        "version": ARTIFACT_VERSION,
        "generated_at": slug,
        "dry_run": settings.dry_run,
        "signals": signals,
        "spec": spec.to_json(),
        "evaluation": {
            **dataclasses.asdict(eval_result),
            "precision": eval_result.precision,
            "recall": eval_result.recall,
            "fpr": eval_result.fpr,
        },
        "deterministic_gate": {"passed": gate_ok, "reason": gate_reason},
        "reviewer_verdict": dataclasses.asdict(verdict) if verdict else None,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path


# ---------------------------------------------------------------------------
# One tick
# ---------------------------------------------------------------------------

def tick(settings: cfg.LoopSettings | None = None) -> dict[str, Any]:
    """Run one full iteration.  Returns the artifact payload."""
    settings = settings or cfg.effective_settings()
    logger.info("tick start dry_run=%s", settings.dry_run)

    signals = harvester.harvest(settings=settings)
    logger.info("harvest produced %d signals", len(signals))

    spec = drafter.draft(signals, settings=settings)
    logger.info("draft: %s (%s)", spec.detector_id, spec.kind)

    corpus = eval_runner.load_corpus(settings.corpus_path)
    eval_result = eval_runner.evaluate(spec, corpus)
    logger.info("eval: %s", eval_result.summary())

    gate_ok, gate_reason = eval_runner.passes_deterministic_gate(eval_result, settings)
    verdict = None
    if spec.detector_id == "NONE":
        gate_ok, gate_reason = False, "drafter returned NONE"
    if gate_ok:
        verdict = reviewer.review(spec, eval_result, signals, settings=settings)
    else:
        logger.info("skipping reviewer: %s", gate_reason)

    path = _write_artifact(
        settings.artifacts_dir, settings,
        signals, spec, eval_result, gate_ok, gate_reason, verdict,
    )
    logger.info("artifact: %s", path)
    return {
        "artifact_path": str(path),
        "decision": verdict.decision if verdict else ("skipped: " + gate_reason),
        "spec_id": spec.detector_id,
    }


# ---------------------------------------------------------------------------
# Recurring loop
# ---------------------------------------------------------------------------

_STOP = False


def _handle_sigterm(_signum, _frame):  # pragma: no cover - signal path
    global _STOP
    _STOP = True
    logger.info("received signal, stopping after current tick")


def run_forever(interval_seconds: int) -> None:  # pragma: no cover - long-running
    signal.signal(signal.SIGINT, _handle_sigterm)
    signal.signal(signal.SIGTERM, _handle_sigterm)
    while not _STOP:
        try:
            tick()
        except Exception:
            logger.exception("tick failed")
        if _STOP:
            break
        for _ in range(interval_seconds):
            if _STOP:
                break
            time.sleep(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="UAST research loop")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("tick", help="Run a single tick and exit.")
    run = sub.add_parser("run", help="Run ticks on an interval until interrupted.")
    run.add_argument("--interval", type=int, default=cfg.INTERVAL_SECONDS,
                     help="Seconds between ticks (default: %(default)s).")
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    args = _build_parser().parse_args(argv)
    if args.cmd == "tick":
        result = tick()
        print(json.dumps(result, indent=2))
        return 0
    if args.cmd == "run":   # pragma: no cover - long-running
        run_forever(args.interval)
        return 0
    return 2


if __name__ == "__main__":   # pragma: no cover
    sys.exit(main())
