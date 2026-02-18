# UAST — Unified Agentic Security Testing

**Real-time security monitoring for AI coding agents.**

Your AI agent just installed a package. Do you know what's in it?

```
pip install uast
uast start --agent cursor --project .
```

[![CI](https://github.com/mjjjjaazing/uast/actions/workflows/ci.yml/badge.svg)](https://github.com/mjjjjaazing/uast/actions)
[![PyPI](https://img.shields.io/pypi/v/uast)](https://pypi.org/project/uast/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)

---

## The problem

SAST scans code in your repository. A package your AI agent installs from PyPI is never in your repository — SAST has nothing to scan.

DAST catches runtime vulnerabilities. Adversarially crafted packages activate only in production — they behave perfectly in your staging environment. DAST misses them entirely.

Neither tool was built for a world where the developer is an AI agent that can install, modify, and deploy code autonomously — faster than any human review cycle.

UAST closes that gap.

---

## What it detects

| Attack Class | AVT Code | Detection Method |
|---|---|---|
| Adversarial package selection | AVT-D3-01 | Age × download velocity anomaly |
| Name squatting / typosquatting | AVT-D3-01 | String similarity against popular packages |
| Production-gated payloads | AVT-D3-02 | Behavioral sandbox under prod env simulation |
| Transitive dependency contamination | AVT-D3-04 | Dependency graph depth analysis |
| Hallucinated package names | AVT-D1-03 | Registry 404 detection |
| Sparse / suspicious metadata | AVT-D4-01 | Metadata completeness scoring |

---

## Install

```bash
pip install uast
```

Requires Python 3.9+. Works on macOS, Linux, and Windows (WSL recommended).

---

## Quickstart

### Monitor an active session

```bash
# Start monitoring — works with any supported agent
uast start

# Specify your agent and project
uast start --agent cursor --project ./my-app

# Raise the alert threshold (default 6.0 / 10.0)
uast start --agent claude-code --threshold 7.5

# Enable blocking mode — terminate flagged installs
uast start --agent cursor --block

# Verbose — show all package checks, not just alerts
uast start --verbose
```

### Check a single package

```bash
uast check requests
uast check lodash --ecosystem npm
uast check request-utils-async
```

### View saved reports

```bash
# List all sessions
uast sessions

# Show a specific session
uast report ~/.uast/sessions/session_20250101_120000.json
```

---

## Supported agents

| Agent | Interception method | Status |
|---|---|---|
| [Claude Code](https://claude.ai/code) | MCP tool logs + process watcher | ✅ Supported |
| [Cursor](https://cursor.sh) | File watcher + process watcher | ✅ Supported |
| [GitHub Copilot](https://github.com/features/copilot) | Git hooks + process watcher | ✅ Supported |
| [Windsurf](https://codeium.com/windsurf) | Session API + process watcher | ✅ Supported |
| [Codeium](https://codeium.com) | File watcher + process watcher | ✅ Supported |
| VS Code (native AI) | Extension API | 🔜 Phase 2 |

---

## How it works

UAST runs two detection engines in parallel:

**Process watcher (primary):** Monitors system-wide for `pip install` and `npm install` subprocesses spawned during your session — regardless of which agent triggered them. Catches installs in real time as they happen.

**File watcher (secondary):** Watches `requirements.txt`, `package.json`, `pyproject.toml` and other dependency files for changes. Catches agents that write dependency files rather than running installs directly (common in Cursor and Copilot).

Every detected package is scored using the **Agentic Risk Scoring Model (ARSM)** — an extension of CVSS 3.1 with four agent-specific dimensions:

```
ARS = CVSS_Base × (1 + α·AAL + β·(1−CIS) + γ·(1−PC) + δ·log(1+SRF))

where:
  AAL  = Agent Autonomy Level       (how much human oversight existed)
  CIS  = Context Integrity Score    (was the agent's context clean?)
  PC   = Provenance Confidence      (is the artifact traceable?)
  SRF  = Systemic Replication Factor (blast radius across your org)
```

Packages scoring above the threshold (default: 6.0) trigger an alert. At 7.5+ the verdict is critical.

---

## Example output

```
  ✓  session started
  ✓  watching  /Users/mike/payments-api
  ✓  agent      cursor
  ✓  threshold  ARS ≥ 6.0 triggers alert
  ✓  process watcher active
  ✓  file watcher active

  Monitoring... press Ctrl+C to stop and save report

  [14:22:01]  detected request-utils-async (pypi via process:pip)  analyzing...

  ✗  [14:22:02]  request-utils-async  pypi  ARS 9.4  AVT-D3-01 · AVT-D3-04
     · [HIGH]   Package is only 3 days old
     · [MEDIUM]  Name matches suspicious pattern: ^[a-z]+-utils-[a-z]+$
     · [MEDIUM]  Sparse package metadata (2 issues)
     →  Do not install. Flag for immediate security review.

  ─────────────────────────────────────────────
  session ended  ·  report saved to ~/.uast/sessions/session_20250101_142202.json
```

---

## Session reports

Every session saves a structured JSON report:

```json
{
  "version": "1",
  "agent": "cursor",
  "project": "/Users/mike/payments-api",
  "started_at": "2025-01-01T14:22:00",
  "ended_at": "2025-01-01T14:50:00",
  "summary": {
    "total_packages": 8,
    "alerts": 1,
    "critical": 1,
    "suspicious": 0,
    "clean": 7,
    "max_ars_score": 9.4
  },
  "results": [...]
}
```

Reports live at `~/.uast/sessions/` by default. Specify a custom path with `--output`.

---

## The research behind it

UAST is the reference implementation of the security framework described in:

> **Beyond SAST and DAST: A Unified Security Testing Architecture for Autonomous Coding Agents**
> Michel Hjazeen — *arXiv preprint, 2025*

The paper formalises three original contributions:

- **Agentic Vulnerability Taxonomy (AVT):** 22 vulnerability classes across 5 dimensions that SAST/DAST cannot detect
- **Agentic Risk Scoring Model (ARSM):** Extends CVSS 3.1 with 4 agent-specific risk dimensions
- **UAST Architecture:** 5-layer parallel analysis pipeline (SSA · BDA · PCV · ARA · CGI)

[Read the paper →](https://arxiv.org/abs/uast-paper)

---

## Roadmap

**v0.1 — current**
- Process watcher + file watcher (dual interception)
- Supply chain analyzer (BDA MVP)
- ARSM scoring engine
- Terminal output + JSON session reports
- Claude Code, Cursor, Copilot, Windsurf, Codeium

**v0.2**
- Web dashboard with session history
- Full AVT taxonomy classifier (all 22 classes)
- Team sharing + alert webhooks (Slack, email)
- All 6 agent integrations

**v0.3**
- Agent Reasoning Auditor (ARA layer)
- Provenance chain verification (Merkle-tree hashing)
- ISO 42001 audit evidence export
- REST API

---

## Contributing

Contributions are welcome — especially:
- Expanding the allowlist (`PYPI_SAFE` / `NPM_SAFE` in `analyzer.py`)
- Additional name squatting patterns
- npm ecosystem improvements
- Windows native support (no WSL)

```bash
git clone https://github.com/mjjjjaazing/uast
cd uast
pip install -e ".[dev]"
pytest
```

Please open an issue before submitting a large PR.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Author

**Michel Hjazeen** — Director of GRC · ISO 42001 Certified (Global Top 40) · AI Security Researcher

[michelhjazeen.com](https://michelhjazeen.com) · [@mjjjjaazing](https://github.com/mjjjjaazing)

---

*UAST is early-stage software. The ARSM scoring coefficients are initial estimates pending empirical calibration against labeled incident data. Signal detection will improve with community feedback and real-world testing.*
