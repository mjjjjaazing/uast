"""Reviewer.

The final gate before a detector becomes a PR.  Runs only after the
deterministic eval has already passed, so Opus is reserved for decisions that
actually matter.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from research import config as cfg
from research.prompts import REVIEWER_SYSTEM, reviewer_user_message
from research.schema import DetectorSpec, EvalResult, ReviewerVerdict

logger = logging.getLogger("research.reviewer")

REVIEWER_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "decision": {"type": "string", "enum": ["accept", "reject", "needs_work"]},
        "reasoning": {"type": "string"},
        "suggested_edits": {"type": "string"},
    },
    "required": ["decision", "reasoning", "suggested_edits"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Deterministic stub for dry-run
# ---------------------------------------------------------------------------

def _stub_review(
    spec: DetectorSpec,
    result: EvalResult,
    signals: list[dict[str, Any]],
) -> ReviewerVerdict:
    """Mirrors the accept rules in the reviewer system prompt, deterministically."""
    if spec.detector_id == "NONE":
        return ReviewerVerdict(
            decision="reject",
            reasoning="drafter returned a NONE detector",
        )
    if result.precision < 0.85:
        return ReviewerVerdict(
            decision="reject",
            reasoning=f"precision {result.precision:.2f} below 0.85",
        )
    if not spec.rationale or len(spec.rationale) < 40:
        return ReviewerVerdict(
            decision="needs_work",
            reasoning="rationale too thin",
            suggested_edits="Cite the specific advisory and why this pattern is not covered by existing detectors.",
        )
    return ReviewerVerdict(
        decision="accept",
        reasoning=(
            f"Clean fire on corpus (precision={result.precision:.2f}, "
            f"recall={result.recall:.2f}, FPR={result.fpr:.2f})."
        ),
    )


# ---------------------------------------------------------------------------
# Opus-backed review
# ---------------------------------------------------------------------------

def review(
    spec: DetectorSpec,
    result: EvalResult,
    signals: list[dict[str, Any]],
    settings: cfg.LoopSettings | None = None,
) -> ReviewerVerdict:
    settings = settings or cfg.effective_settings()

    if settings.dry_run:
        logger.info("reviewer: dry-run, using stub")
        return _stub_review(spec, result, signals)

    import anthropic  # lazy

    client = anthropic.Anthropic()
    eval_summary = {
        "precision": round(result.precision, 3),
        "recall": round(result.recall, 3),
        "fpr": round(result.fpr, 3),
        "tp": result.tp, "fp": result.fp, "fn": result.fn, "tn": result.tn,
        "fired_on": result.fired_on,
        "missed": result.missed,
        "false_positives": result.false_positives,
    }
    resp = client.messages.create(
        model=settings.reviewer_model,
        max_tokens=cfg.MAX_REVIEWER_OUTPUT_TOKENS,
        thinking={"type": "adaptive"},
        system=[{
            "type": "text",
            "text": REVIEWER_SYSTEM,
            "cache_control": {"type": "ephemeral"},
        }],
        messages=[{
            "role": "user",
            "content": reviewer_user_message(spec.to_json(), eval_summary, signals),
        }],
        output_config={
            "format": {
                "type": "json_schema",
                "schema": REVIEWER_OUTPUT_SCHEMA,
            }
        },
    )
    text = next((b.text for b in resp.content if b.type == "text"), "")
    data = json.loads(text)
    verdict = ReviewerVerdict(
        decision=data["decision"],
        reasoning=data["reasoning"],
        suggested_edits=data.get("suggested_edits", ""),
    )
    logger.info("reviewer: %s — %s", verdict.decision, verdict.reasoning[:120])
    return verdict
