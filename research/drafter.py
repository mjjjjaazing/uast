"""Detection-rule drafter.

Given threat signals from the harvester, propose a single candidate detector
spec.  The schema is intentionally narrow so the reviewer can sanity-check
what gets proposed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime
from typing import Any

from research import config as cfg
from research.prompts import DRAFTER_SYSTEM, drafter_user_message
from research.schema import DetectorSpec

logger = logging.getLogger("research.drafter")

# JSON schema for structured output.  Mirrors DetectorSpec.  Kept flat (no
# recursion into sub_detectors) because json_schema structured outputs reject
# recursive schemas.
DRAFTER_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "detector_id": {"type": "string"},
        "kind": {
            "type": "string",
            "enum": [
                "name_regex",
                "description_keyword",
                "age_threshold_days",
                "maintainer_email_regex",
            ],
        },
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "info"],
        },
        "ecosystem": {"type": "string", "enum": ["pypi", "npm", "both"]},
        "title": {"type": "string"},
        "rationale": {"type": "string"},
        "avt_class": {"type": "string"},
        "pattern": {"type": ["string", "null"]},
        "keywords": {"type": "array", "items": {"type": "string"}},
        "max_age_days": {"type": ["integer", "null"]},
        "source_advisory_ids": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "detector_id", "kind", "severity", "ecosystem",
        "title", "rationale", "avt_class",
        "pattern", "keywords", "max_age_days",
        "source_advisory_ids",
    ],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Deterministic stub — used in dry-run mode
# ---------------------------------------------------------------------------

_CLASS_PRIORITY = (
    # Highest-precision detector kinds first — mirrors what a human would
    # pick if given a choice of what to spend review time on.
    "maintainer-sockpuppet",
    "prompt-injection-in-description",
    "context-poisoning",
    "malicious-payload",
)


def _stub_draft(signals: list[dict[str, Any]]) -> DetectorSpec:
    """Deterministic detector chosen from the highest-priority signal class.

    Lets the full pipeline run offline with plausible output.  Outputs one of
    three kinds depending on the inferred attack class; falls back to a no-op
    detector_id=NONE when nothing is actionable.
    """
    if not signals:
        return _none_detector("no signals")

    chosen = None
    for klass in _CLASS_PRIORITY:
        chosen = next((s for s in signals if s.get("attack_class") == klass), None)
        if chosen is not None:
            break
    if chosen is None:
        chosen = signals[0]
    klass = chosen.get("attack_class", "")
    now_slug = datetime.utcnow().strftime("%Y-%m-%d")
    source_ids = list(chosen.get("advisory_ids", []))

    if klass == "prompt-injection-in-description":
        return DetectorSpec(
            detector_id=f"DESC-KEYWORD-{now_slug}-001",
            kind="description_keyword",
            severity="high",
            ecosystem="both",
            title="Prompt-injection keywords in package description",
            rationale=(
                "Packages whose description contains agent-directed instructions "
                "(e.g. 'ignore previous', 'system:') attempt to manipulate an AI "
                "coding agent reading the README. Inspired by: "
                + ", ".join(source_ids)
            ),
            avt_class="AVT-D1-01",
            keywords=[
                "ignore previous",
                "ignore all previous",
                "system instruction:",
                "disregard prior",
                "new instructions:",
            ],
            source_advisory_ids=source_ids,
        )

    if klass == "maintainer-sockpuppet":
        return DetectorSpec(
            detector_id=f"EMAIL-REGEX-{now_slug}-001",
            kind="maintainer_email_regex",
            severity="medium",
            ecosystem="both",
            title="Disposable / free-tier maintainer email",
            rationale=(
                "Sockpuppet maintainers frequently register on disposable email "
                "domains. Matches mailinator/guerrillamail/tempmail-class addresses. "
                "Inspired by: " + ", ".join(source_ids)
            ),
            avt_class="AVT-D4-01",
            pattern=r"^.+@(mailinator|guerrillamail|tempmail|10minutemail|trashmail)\.",
            source_advisory_ids=source_ids,
        )

    if klass == "malicious-payload":
        return DetectorSpec(
            detector_id=f"AGE-THRESH-{now_slug}-001",
            kind="age_threshold_days",
            severity="medium",
            ecosystem="both",
            title="Very young package",
            rationale=(
                "Freshly published packages are disproportionately used to stage "
                "install-time payloads. 7 days is the standard aggressive cutoff. "
                "Inspired by: " + ", ".join(source_ids)
            ),
            avt_class="AVT-D3-01",
            max_age_days=7,
            source_advisory_ids=source_ids,
        )

    return _none_detector(f"no stub rule for {klass}")


def _none_detector(reason: str) -> DetectorSpec:
    return DetectorSpec(
        detector_id="NONE",
        kind="name_regex",
        severity="info",
        ecosystem="both",
        title="no-op",
        rationale=reason,
        avt_class="AVT-NONE",
        pattern=None,
    )


# ---------------------------------------------------------------------------
# LLM drafter
# ---------------------------------------------------------------------------

def _validate_regex(pattern: str | None) -> None:
    if pattern is None:
        return
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"drafter proposed invalid regex: {pattern!r} ({exc})")


def _fingerprint(spec: DetectorSpec) -> str:
    blob = json.dumps(spec.to_json(), sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()[:12]


def draft(
    signals: list[dict[str, Any]],
    settings: cfg.LoopSettings | None = None,
) -> DetectorSpec:
    """Propose one detector spec.  Always returns a DetectorSpec — NONE if nothing fits."""
    settings = settings or cfg.effective_settings()

    if settings.dry_run:
        logger.info("drafter: dry-run, using stub")
        spec = _stub_draft(signals)
        _validate_regex(spec.pattern)
        return spec

    import anthropic  # lazy

    client = anthropic.Anthropic()
    resp = client.messages.create(
        model=settings.drafter_model,
        max_tokens=cfg.MAX_DRAFTER_OUTPUT_TOKENS,
        system=[{
            "type": "text",
            "text": DRAFTER_SYSTEM,
            "cache_control": {"type": "ephemeral"},
        }],
        messages=[{
            "role": "user",
            "content": drafter_user_message(signals),
        }],
        output_config={
            "format": {
                "type": "json_schema",
                "schema": DRAFTER_OUTPUT_SCHEMA,
            }
        },
    )
    text = next((b.text for b in resp.content if b.type == "text"), "")
    data = json.loads(text)
    data.setdefault("sub_detectors", [])  # not in output schema; always empty
    spec = DetectorSpec.from_json(data)
    _validate_regex(spec.pattern)
    logger.info("drafter: proposed %s (%s) fingerprint=%s",
                spec.detector_id, spec.kind, _fingerprint(spec))
    return spec
