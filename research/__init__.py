"""UAST research loop — autonomous detection-rule ideation against a labeled corpus.

Pipeline (every tick):

    Threat Harvester (Sonnet)   ->  new threat signals
                 |
                 v
    Detection Drafter (Sonnet)  ->  candidate detector spec
                 |
                 v
    Eval Runner (deterministic) ->  precision / recall against corpus
                 |
                 v
    Reviewer (Opus, adaptive)   ->  accept / reject / needs-work verdict

Each tick produces an artifact in ``research/artifacts/``.  Accepted candidates
become PR-ready diffs; rejected ones are kept for learning.

The loop is designed to run unattended (see ``research/loop.py``) and is safe
to run without an ``ANTHROPIC_API_KEY`` — it falls back to deterministic stub
outputs so the plumbing is always testable.
"""

__all__ = ["config", "harvester", "drafter", "eval_runner", "reviewer", "loop"]
