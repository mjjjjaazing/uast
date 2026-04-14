"""Research-loop configuration.

All paths are relative to the repository root so the loop can be invoked from
either ``python -m research.loop`` or a scheduled cron job.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
RESEARCH_DIR = REPO_ROOT / "research"
CORPUS_PATH = RESEARCH_DIR / "corpus" / "seed.jsonl"
ARTIFACTS_DIR = RESEARCH_DIR / "artifacts"
PROMPTS_DIR = RESEARCH_DIR / "prompts"

# ---------------------------------------------------------------------------
# Models — per SKILL.md defaults
# ---------------------------------------------------------------------------

# Sonnet for the hourly drafting/harvesting — cheap, fast, high volume.
# Opus (adaptive thinking) for the final reviewer gate — runs only when a
# candidate actually survives eval, so the cost per decision is bounded.
HARVESTER_MODEL = "claude-sonnet-4-6"
DRAFTER_MODEL = "claude-sonnet-4-6"
REVIEWER_MODEL = "claude-opus-4-6"

# Caps for one tick.  Kept intentionally small so a single run is cheap to
# evaluate and easy to reason about.
MAX_HARVESTED_ITEMS = 8
MAX_DRAFTER_OUTPUT_TOKENS = 4096
MAX_REVIEWER_OUTPUT_TOKENS = 4096

# ---------------------------------------------------------------------------
# Acceptance thresholds
# ---------------------------------------------------------------------------

# Minimum precision / recall on the seed corpus before a detector is even
# shown to the reviewer.  Lift-over-baseline is measured against the current
# UAST analyzer output on the same corpus.
MIN_PRECISION = 0.85
MIN_RECALL_DELTA = 0.00   # tolerate equal-recall as long as precision holds
MAX_FALSE_POSITIVE_RATE = 0.05

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------

DRY_RUN = os.environ.get("UAST_RESEARCH_DRY_RUN", "").lower() in ("1", "true", "yes")
"""When ``True`` (or when no ANTHROPIC_API_KEY is set), the loop uses
deterministic stubs instead of calling the API.  Lets CI and local dev
exercise the whole pipeline without spending tokens."""

INTERVAL_SECONDS = int(os.environ.get("UAST_RESEARCH_INTERVAL", "1800"))  # 30m default


@dataclass(frozen=True)
class LoopSettings:
    """One immutable snapshot of settings for a single tick."""

    dry_run: bool = DRY_RUN
    harvester_model: str = HARVESTER_MODEL
    drafter_model: str = DRAFTER_MODEL
    reviewer_model: str = REVIEWER_MODEL
    min_precision: float = MIN_PRECISION
    min_recall_delta: float = MIN_RECALL_DELTA
    max_fpr: float = MAX_FALSE_POSITIVE_RATE
    corpus_path: Path = CORPUS_PATH
    artifacts_dir: Path = ARTIFACTS_DIR
    prompts_dir: Path = PROMPTS_DIR
    extra_env: dict = field(default_factory=dict)


def api_key_available() -> bool:
    """Whether a real API call is possible this run."""
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def effective_settings() -> LoopSettings:
    """Settings with dry_run forced on when no API key is available."""
    dry = DRY_RUN or not api_key_available()
    return LoopSettings(dry_run=dry)
