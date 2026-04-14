# UAST Research Loop

A self-contained pipeline that ingests fresh supply-chain threat intel, drafts a candidate detector, evaluates it against a labeled corpus, and — only if the deterministic gate passes — asks Opus to make the final call on whether to ship it.

This is the prototype. It is **not** wired into the production UAST analyzer. Accepted detectors are written to `research/artifacts/` as JSON; turning one into a PR is a human step (on purpose, for now).

---

## Pipeline

```
┌─────────────────┐   ┌──────────────────┐   ┌─────────────────┐   ┌────────────────┐
│ Threat Harvester│──▶│ Detection Drafter│──▶│ Eval Runner     │──▶│ Reviewer (Opus)│
│  (Sonnet 4.6)   │   │  (Sonnet 4.6)    │   │  (deterministic)│   │  adaptive think│
└─────────────────┘   └──────────────────┘   └─────────────────┘   └────────────────┘
     OSV.dev             name_regex /           precision, recall,       accept /
     fixture             keyword / age /        FPR vs seed corpus       reject /
     JSON                email regex                                    needs_work
```

**Cost shape:** Sonnet runs every tick; Opus only runs when the deterministic gate passes. This keeps the loop cheap enough to run every 30 minutes unattended.

---

## Quick start

### Dry run (no API key needed)

The loop auto-falls-back to deterministic stubs when `ANTHROPIC_API_KEY` is unset, so you can run the whole thing offline:

```bash
python -m research.loop tick
```

Output is written to `research/artifacts/<timestamp>__<decision>__<id>.json`.

### Live run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python -m research.loop tick
```

### Recurring (every 30 min)

```bash
python -m research.loop run --interval 1800
```

Use `Ctrl-C` to stop; it finishes the current tick cleanly.

---

## Components

| File | Role | LLM? |
|---|---|---|
| `config.py` | Paths, model IDs, thresholds, dry-run logic | — |
| `schema.py` | `DetectorSpec`, `CorpusEntry`, `EvalResult`, `ReviewerVerdict` dataclasses | — |
| `prompts.py` | Static system prompts (stable bytes → prompt-cache hits) | — |
| `harvester.py` | Fetch OSV + distill into threat signals | Sonnet |
| `drafter.py` | Propose one detector spec from signals | Sonnet |
| `eval_runner.py` | Apply spec to corpus, compute precision/recall/FPR | — |
| `reviewer.py` | Final accept/reject/needs_work decision | Opus (adaptive) |
| `loop.py` | Orchestrator + CLI (`tick` / `run`) | — |

---

## Detector-spec surface

The drafter can only propose detectors of these kinds:

- `name_regex` — package name matches an anchored regex
- `description_keyword` — metadata description contains any of a short keyword list
- `age_threshold_days` — package is younger than N days
- `maintainer_email_regex` — author email matches a regex
- `combined_and` — all sub-detectors must fire (evaluator only — structured output stays flat)

This is deliberately narrow. Anything fancier (AST, ML, sandboxed replay) is out of scope for this loop — those features belong in the main analyzer after human review.

---

## Corpus

`research/corpus/seed.jsonl` — hand-seeded labeled packages. JSON Lines, one entry per line. Fields:

```json
{
  "name": "package-name",
  "ecosystem": "pypi" | "npm",
  "label": "malicious" | "benign",
  "features": {
    "description": "...",
    "age_days": 123,
    "author_email": "..."
  },
  "notes": "free-form",
  "source": "advisory ID or 'hand-labeled'"
}
```

Keep malicious examples realistic — typosquat real packages, use real disposable-email domains, and include an adversarial benign case (a recently-published internal package) so age-only detectors don't cheat.

---

## Acceptance gates

A detector ships only if **all three** pass:

1. **Deterministic gate** (`eval_runner.passes_deterministic_gate`):
   - precision ≥ `MIN_PRECISION` (default 0.85)
   - false-positive rate ≤ `MAX_FALSE_POSITIVE_RATE` (default 0.05)
   - fired on at least one entry
2. **Reviewer gate** (Opus, adaptive thinking): spec is non-redundant with existing coverage, rationale references the actual source signal, not LLM filler.
3. **Human gate** (outside this loop): turning an accepted artifact into a PR is still a human step — for now.

---

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Required for live runs. If unset, the loop uses stubs. |
| `UAST_RESEARCH_DRY_RUN` | `0` | Force stubs even when an API key is present. |
| `UAST_RESEARCH_INTERVAL` | `1800` | Default interval (seconds) for `loop.py run`. |

---

## Limits and known gaps

- Harvester's OSV probe is seeded with a small list of packages — real deployment should use the OSV bulk dump.
- Corpus is tiny (16 entries). Before the loop is meaningful as a credibility signal, this needs to grow to several hundred entries with real historical malicious packages (this is tracked separately as `uast-bench`).
- Detectors are schema-limited — no AST, no network, no sandbox. The loop is for the "pattern addition that a senior engineer would write in ten minutes after reading a fresh advisory" shape of change.
- There is no PR-opener yet. Accepted artifacts sit in `research/artifacts/`. Wiring this to the GitHub MCP server is a follow-up.
