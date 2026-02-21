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
| Production-gated payloads | AVT-D3-02 | Static AST analysis of package source |
| Transitive dependency contamination | AVT-D3-04 | Recursive dependency graph traversal |
| Hallucinated package names | AVT-D1-03 | Registry 404 detection + "did you mean?" |
| Sparse / suspicious metadata | AVT-D4-01 | Metadata completeness + repository URL verification |
| Download velocity anomalies | AVT-D3-01 | PyPI Stats / npm downloads API |
| Prompt injection in descriptions | AVT-D1-01 | Regex pattern matching (17 patterns) |
| Context poisoning | AVT-D1-01 | AST detection of env/sys.path manipulation |
| Privilege escalation in packages | AVT-D2-01 | AST detection of setuid/sudo/chmod patterns |
| Scope creep imports | AVT-D2-02 | Sensitive module import detection |
| Maintainer trust signals | AVT-D4-01 | Disposable email, missing identity detection |
| Metadata spoofing | AVT-D4-01 | Cross-reference description vs package identity |
| Release pattern anomalies | AVT-D3-01 | Single-version and rapid-fire release detection |

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

# Deep mode — enable static payload analysis (AST scanning)
uast start --agent cursor --deep
```

### Check a single package

```bash
uast check requests
uast check lodash --ecosystem npm
uast check request-utils-async

# JSON output
uast check some-package --json

# Specify agent context for ARSM scoring
uast check some-package --agent cursor
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
| [Claude Code](https://claude.ai/code) | Log file watcher + process watcher | ✅ Supported |
| [Cursor](https://cursor.sh) | File watcher + process watcher | ✅ Supported |
| [GitHub Copilot](https://github.com/features/copilot) | Git pre-commit hook + process watcher | ✅ Supported |
| [Windsurf](https://codeium.com/windsurf) | Generic process + file watchers | ✅ Supported |
| [Codeium](https://codeium.com) | Generic process + file watchers | ✅ Supported |
| VS Code (native AI) | Extension API | 🔜 Phase 2 |

**Note:** Windsurf and Codeium do not expose public APIs for deeper integration. UAST uses the same generic process monitoring and file watching that works across all agents. Claude Code additionally monitors `~/.claude/` log files for earlier install detection. Copilot installs a temporary `.git/hooks/pre-commit` that runs `uast check` on newly added packages (removed when the session ends).

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

coefficients:
  α = 0.30   β = 0.25   γ = 0.25   δ = 0.20
```

Agent Autonomy Levels (AAL) by agent:

| Agent | AAL | Rationale |
|---|---|---|
| Copilot | 0.5 | Suggestion-based, human accepts each change |
| Codeium | 0.5 | Similar suggestion-based model |
| Cursor | 0.7 | More autonomous — can execute commands |
| Windsurf | 0.7 | Autonomous command execution |
| Claude Code | 0.8 | Highest autonomy — can install, deploy, modify |

Packages scoring above the threshold (default: 6.0) trigger an alert. At 7.5+ the verdict is critical.

### Blocking mode

With `--block`, UAST will:
1. Attempt to kill the install process before it completes
2. If the install already finished, roll back by running `pip uninstall -y` / `npm uninstall`

### Deep analysis (`--deep`)

With `--deep` (or always on `uast check`), UAST downloads the package source and runs static AST analysis to detect:

| Signal | Pattern | Severity |
|---|---|---|
| PAYLOAD-001 | `os.getenv()`/`os.environ` gating code execution | high |
| PAYLOAD-002 | `subprocess.*`/`os.system`/`os.exec*` | high |
| PAYLOAD-003 | `base64.b64decode`/`codecs.decode` with literals | high |
| PAYLOAD-004 | Network calls in setup.py | critical |
| PAYLOAD-005 | `eval()`/`exec()` with non-literal arg | medium |
| PAYLOAD-006 | `__import__()`/`importlib` with variable arg | medium |
| PAYLOAD-007 | File writes to `~/.ssh/`, `~/.bashrc`, `/etc/` | critical |

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

Every session saves a structured JSON report (schema v2):

```json
{
  "version": "2",
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
  "results": [
    {
      "package_name": "request-utils-async",
      "ars_score": 9.4,
      "cvss_base": 7.5,
      "verdict": "critical",
      "avt_classes": ["AVT-D3-01", "AVT-D3-04"],
      "arsm": {"aal": 0.7, "cis": 1.0, "pc": 0.3, "srf": 0.0},
      "signals": [...]
    }
  ]
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

## Configuration

UAST supports TOML configuration with 3-level precedence:

```
CLI flags  >  project .uast.toml  >  user ~/.uast/config.toml  >  built-in defaults
```

```bash
# View resolved configuration
uast show-config

# View for a specific project
uast show-config --project ./my-app
```

Example `.uast.toml`:

```toml
threshold = 7.0

[arsm]
alpha = 0.30
beta = 0.25

[blocklist]
pypi = ["evil-package"]

[allowlist]
pypi = ["my-internal-package"]
```

---

## Roadmap

**v0.1 — initial release**
- Process watcher + file watcher (dual interception)
- Supply chain analyzer (BDA MVP)
- ARSM scoring engine with full formula implementation
- Hallucinated package detection with "did you mean?"
- Download velocity anomaly detection
- Transitive dependency graph resolution
- Static AST payload analysis (`--deep`)
- Repository URL verification
- Agent-specific interception (Claude Code logs, Copilot git hooks)
- Blocking mode with rollback fallback
- Terminal output + JSON session reports (schema v2)
- Claude Code, Cursor, Copilot, Windsurf, Codeium

**v0.2 (foundation hardening)**
- TOML configuration system (project + user + defaults)
- Structured logging with rotation and log injection prevention
- HTTP retry with exponential backoff
- Input sanitization (package names, URLs, config values)
- Security hardening (file permissions, process tracking, SSRF prevention)
- CI/CD pipeline (GitHub Actions, pre-commit, PyPI publishing)
- 322 tests, 85% coverage

**v0.3 — current (detection engine expansion)**
- AVT D1 detectors: prompt injection (INJECT-001), context poisoning (POISON-001)
- AVT D2 detectors: privilege escalation (PRIV-001), scope creep (SCOPE-001)
- AVT D4 detectors: maintainer trust (MAINTAINER-001), metadata spoofing (SPOOF-001)
- Dynamic CIS scoring (Context Integrity Score degrades on injection/poisoning signals)
- Scoring confidence levels (high/medium/low)
- Release pattern analysis (single-version, rapid-fire release detection)
- Rebalanced ARSM signal weights (9 categories)
- 424 tests, 87% coverage

**v0.4**
- Web dashboard with session history
- Threat intelligence integration (OSV.dev, safety-db)
- npm payload analysis (JS/TS AST scanning)
- Team sharing + alert webhooks (Slack, email)

**v0.4**
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
