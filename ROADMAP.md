# UAST Product Roadmap

**From MVP to Production-Grade Agentic Security Platform**

*Last updated: 2026-02-19 · v0.1.0 baseline*

This document is the living plan for evolving UAST from a working MVP into the definitive security scanning platform for agentic coding. Each phase includes a full PRD, granular task list with security/testing/remediation steps, and exit criteria. Every feature ships with tests, security review, and README updates.

---

## Table of Contents

- [Current State (v0.1.0)](#current-state-v010--baseline)
- [Quality Gates](#quality-gates-apply-to-every-task)
- [Remediation Protocol](#remediation-protocol)
- [Phase 1: Foundation Hardening (v0.2.0)](#phase-1-foundation-hardening-v020)
- [Phase 2: Detection Engine Expansion (v0.3.0)](#phase-2-detection-engine-expansion-v030)
- [Phase 3: Provenance Chain Verification (v0.4.0)](#phase-3-layer-3--provenance-chain-verification-v040)
- [Phase 4: Real-Time Intelligence & Integrations (v0.5.0)](#phase-4-real-time-intelligence--integrations-v050)
- [Phase 5: Agent Reasoning Auditor (v0.6.0)](#phase-5-layer-4--agent-reasoning-auditor-v060)
- [Phase 6: Compliance & Governance (v0.7.0)](#phase-6-layer-5--compliance--governance-v070)
- [Phase 7: Scale & Polish (v1.0.0)](#phase-7-scale--polish-v100)
- [Gap Inventory](#detailed-gap-inventory-current-v010)
- [Success Metrics](#success-metrics)

---

## Current State (v0.1.0 — Baseline)

### What Works
- CLI: `uast start`, `uast check`, `uast sessions`, `uast report`
- Dual interception: process watcher (psutil) + file watcher (watchdog)
- Agent-specific: Claude Code log watcher, Copilot git hooks
- Supply chain analyzer with 6 signal types
- ARSM scoring engine (formula implemented, coefficients uncalibrated)
- Hallucinated package detection with "did you mean?"
- Typosquatting / name-squatting detection
- Suspicious name pattern matching
- Metadata quality + repository URL verification
- Transitive dependency tree resolution (recursive, with cycle detection)
- Static AST payload analysis (`--deep`, PyPI only)
- Download velocity anomaly detection
- Blocking mode with process kill + rollback
- JSON session reports (schema v2)
- 5 agents: Claude Code, Cursor, Copilot, Windsurf, Codeium

### Coverage & Quality
- **Test coverage: 36%** (77 tests, all passing)
  - analyzer.py: 52%, resolver.py: 94%, payload.py: 62%
  - display.py: 0%, reporter.py: 0%, watcher.py: 0%, main.py: 0%
- **No CI/CD publishing pipeline**
- **No configuration file support** (all hardcoded)
- **No logging** (errors silently swallowed)
- **Paper claims 5 layers; only 2 partially implemented (SSA, BDA)**
- **Paper claims 22 AVT classes; only 4 detected**

---

## Quality Gates (Apply to EVERY Task)

Before any task is marked done, the implementer runs through this checklist:

```
QUALITY GATE CHECKLIST (copy into every PR)

BUILD & LINT
- [ ] `ruff check uast/` — zero violations
- [ ] `mypy --strict uast/` — zero errors
- [ ] `python -m pytest tests/ -v` — all tests pass

TESTING
- [ ] New code has ≥ 80% branch coverage
- [ ] Integration test covers the user-facing scenario
- [ ] Regression: no existing tests broken
- [ ] Edge cases: empty input, None, oversized, malformed, unicode

SECURITY
- [ ] `bandit -r uast/ -ll` — no HIGH or CRITICAL findings
- [ ] `pip-audit` — no known vulnerabilities in dependencies
- [ ] No secrets, tokens, or credentials in code
- [ ] No command injection vectors (subprocess + user input)
- [ ] No path traversal (user-controlled paths sanitized)
- [ ] No unbounded resource consumption (memory, disk, CPU)

DOCUMENTATION
- [ ] README updated if user-facing behavior changed
- [ ] CHANGELOG.md entry added
- [ ] Docstrings on all public functions/classes
```

---

## Remediation Protocol

When testing, security review, or pentesting finds issues:

### Severity Classification

| Severity | Definition | Response Time | Action |
|---|---|---|---|
| **CRITICAL** | Exploitable vulnerability, data loss, or crash | Immediate | Stop current work. Fix before any other task. |
| **HIGH** | Security weakness, significant bug, or data integrity issue | Within current sprint | Create blocking task. Fix before phase exit. |
| **MEDIUM** | Logic error, edge case failure, or code quality issue | Next sprint | Create task. Fix before next phase. |
| **LOW** | Minor issue, cosmetic, or optimization opportunity | Backlog | Create task. Schedule when convenient. |

### Remediation Workflow

```
1. DISCOVER — Issue found during testing/review/scan
2. DOCUMENT — Create GitHub issue with:
   - Reproduction steps
   - Root cause analysis (if known)
   - Affected files and line numbers
   - Severity classification
   - Suggested fix approach
3. TRIAGE — Classify severity (see table above)
4. FIX — Implement fix on a dedicated branch
5. VERIFY — Run targeted tests proving the fix works
6. REGRESSION — Run full test suite to ensure no side effects
7. RE-SCAN — Re-run the security scan/pentest that found the issue
8. CLOSE — Close the issue with evidence of fix + verification
```

### Redesign Triggers

If remediation reveals a deeper architectural issue, escalate to redesign:

- Same module has 3+ HIGH/CRITICAL findings → redesign that module
- Fix for one issue introduces a new issue → step back and redesign
- Performance degrades > 50% after fix → redesign the approach
- Security fix requires breaking the public API → plan deprecation + migration

---

## Phase 1: Foundation Hardening (v0.2.0)

### PRD-1: Foundation Hardening

**Objective:** Make the existing MVP features production-reliable. No new detection capabilities — focus entirely on reliability, configurability, testability, and security of the code we already have.

**Target Users:**
- Security engineers evaluating UAST for team adoption
- Developers running UAST alongside their AI coding agent
- CI/CD pipelines that need deterministic, configurable behavior

**User Stories:**

| ID | Story | Acceptance Criteria |
|---|---|---|
| US-1.1 | As a user, I want to configure UAST thresholds via a config file so I don't need to pass CLI flags every time | `.uast.toml` in project root is read; values override defaults; CLI flags override config |
| US-1.2 | As a security engineer, I want to add my organization's trusted packages to an allowlist so UAST doesn't flag our internal packages | `[allowlist]` section in config accepts package names; listed packages get ALLOW-001 verdict |
| US-1.3 | As a user, I want to see logs when something goes wrong so I can debug issues | Logs written to `~/.uast/logs/`; `--log-level` flag controls verbosity |
| US-1.4 | As a developer, I want UAST to handle network failures gracefully so it doesn't crash mid-session | Retry with backoff on transient errors; clear warnings on persistent failures |
| US-1.5 | As a contributor, I want 80%+ test coverage so I can refactor with confidence | All modules tested; coverage gate in CI enforced |
| US-1.6 | As a security researcher, I want UAST itself to be secure so I can trust the tool | No injection vectors, no world-readable secrets, bounded resource usage |
| US-1.7 | As a maintainer, I want CI/CD so every PR is validated automatically | GitHub Actions runs tests, lint, type-check, security scan on every PR |

**Technical Requirements:**
- Config system: TOML parser (stdlib `tomllib` on 3.11+, `tomli` fallback for 3.9/3.10)
- Logging: Python `logging` with `RotatingFileHandler`
- HTTP resilience: `urllib3.util.retry.Retry` or manual backoff
- Test framework: pytest with pytest-cov, pytest-mock
- CI: GitHub Actions with matrix builds

**Dependencies:** None (Phase 1 has no external blockers)

**Risks:**
- Refactoring for config may break existing CLI behavior → mitigate with integration tests
- Adding logging may leak sensitive data to log files → mitigate with log sanitization

---

### Phase 1 Task List

#### Sprint 1.1 — Configuration System

**T-1.1.1: Implement config file loader**
- [ ] Create `uast/config.py` with TOML parsing
- [ ] Support project-level (`.uast.toml`) and user-level (`~/.uast/config.toml`)
- [ ] Implement precedence: CLI flags > project config > user config > defaults
- [ ] Define schema for all configurable values (see Gap Inventory table)
- [ ] Wire config into `main.py` CLI commands
- [ ] Fallback gracefully when no config file exists

**T-1.1.1-TEST: Tests for config loader**
- [ ] Test: config file not found → uses defaults silently
- [ ] Test: project config overrides defaults
- [ ] Test: user config overrides defaults
- [ ] Test: CLI flags override config file
- [ ] Test: invalid TOML → clear error message, uses defaults
- [ ] Test: unknown keys in config → ignored with warning
- [ ] Test: type validation (string where int expected → error)
- [ ] Test: empty config file → uses defaults
- [ ] Test: config with only partial values → merges with defaults

**T-1.1.1-SECURITY: Security review of config loader**
- [ ] Review: config file path traversal (ensure `.uast.toml` can't be symlinked to `/etc/passwd`)
- [ ] Review: TOML parsing of untrusted input (adversarial config values)
- [ ] Review: no code execution from config values (eval, import, etc.)
- [ ] Review: config values used in shell commands are sanitized
- [ ] Scan: `bandit -r uast/config.py`

**T-1.1.2: Extract all hardcoded values into config**
- [ ] Move 23 hardcoded values (see Gap Inventory) into `DEFAULT_CONFIG` dict
- [ ] Update `analyzer.py` to accept config object instead of hardcoded constants
- [ ] Update `resolver.py` to accept `max_depth` and `max_packages` from config
- [ ] Update `http_client.py` to accept timeout/TTL/concurrency from config
- [ ] Update `watcher.py` to accept `poll_interval` from config

**T-1.1.2-TEST: Tests for configurable values**
- [ ] Test: each configurable value actually changes behavior when set
- [ ] Test: boundary values (threshold=0.0, threshold=10.0)
- [ ] Test: negative values rejected
- [ ] Test: ARSM coefficients change scoring output

**T-1.1.3: Custom allowlist/blocklist support**
- [ ] Add `[allowlist.pypi]` and `[allowlist.npm]` config sections
- [ ] Add `[blocklist.pypi]` and `[blocklist.npm]` config sections
- [ ] Merge user allowlist with built-in `PYPI_SAFE`/`NPM_SAFE`
- [ ] Blocklisted packages always flagged as critical regardless of analysis
- [ ] Add `--show-config` CLI flag to display resolved configuration

**T-1.1.3-TEST: Tests for allowlist/blocklist**
- [ ] Test: user-allowlisted package returns clean verdict
- [ ] Test: user-blocklisted package returns critical verdict
- [ ] Test: blocklist overrides allowlist (same package in both)
- [ ] Test: empty allowlist/blocklist → no effect
- [ ] Test: case-insensitive matching

**T-1.1.3-SECURITY: Security review of allowlist/blocklist**
- [ ] Review: can an attacker add a malicious package to the allowlist via config injection?
- [ ] Review: blocklist bypass (package name normalization — `requests` vs `Requests` vs `requests-`)

**T-1.1-REGRESSION: Sprint 1.1 regression testing**
- [ ] Run full test suite: `pytest tests/ -v`
- [ ] Run `uast check requests` — still returns clean
- [ ] Run `uast check request-utils-async` — still returns critical
- [ ] Run `uast check lodash --ecosystem npm` — still returns clean
- [ ] Verify JSON output schema unchanged (`uast check requests --json`)

---

#### Sprint 1.2 — Logging & Observability

**T-1.2.1: Implement structured logging**
- [ ] Create logging setup in `uast/logging.py`
- [ ] Configure `RotatingFileHandler` to `~/.uast/logs/uast.log`
- [ ] Log rotation: 5MB per file, keep 7 files
- [ ] Log levels: DEBUG, INFO, WARNING, ERROR
- [ ] Add `--log-level` CLI option (default: WARNING)
- [ ] Add `--quiet` flag (suppresses all terminal output)
- [ ] Add logging calls throughout all modules:
  - `analyzer.py`: log each API call, cache hit/miss, signal evaluation, final verdict
  - `resolver.py`: log each dependency resolved, cycle detected, limit hit
  - `watcher.py`: log each process detected, file change, analysis queued
  - `http_client.py`: log each request, response status, cache state
  - `payload.py`: log each file analyzed, finding detected

**T-1.2.1-TEST: Tests for logging**
- [ ] Test: log file created at expected path
- [ ] Test: `--log-level DEBUG` produces verbose output
- [ ] Test: `--log-level ERROR` suppresses info/warning
- [ ] Test: `--quiet` produces zero terminal output
- [ ] Test: log rotation works (write > 5MB, verify rotation)
- [ ] Test: log directory created if missing

**T-1.2.1-SECURITY: Security review of logging**
- [ ] Review: no sensitive data in logs (API responses with tokens, package contents)
- [ ] Review: log file permissions are 0o600 (not world-readable)
- [ ] Review: log injection attacks (malicious package names with newlines/control chars)
- [ ] Review: log file path not controllable by user input

**T-1.2-REGRESSION: Sprint 1.2 regression testing**
- [ ] Full test suite passes
- [ ] Existing CLI behavior unchanged (logs are additive, not replacing terminal output)
- [ ] `uast check` still works without `--log-level` flag

---

#### Sprint 1.3 — Error Handling & Resilience

**T-1.3.1: Replace broad exception handlers**
- [ ] Audit every `except Exception:` in codebase
- [ ] Replace with specific exceptions: `requests.RequestException`, `json.JSONDecodeError`, `OSError`, `psutil.Error`
- [ ] Add logging for every caught exception
- [ ] Ensure no exception is silently swallowed

**T-1.3.2: HTTP retry with exponential backoff**
- [ ] Add retry logic to `http_client.py` (3 attempts, 1s/2s/4s delays)
- [ ] Retry on: connection timeout, 429 rate limit, 500/502/503/504 server errors
- [ ] Do NOT retry on: 400, 401, 403, 404 (deterministic failures)
- [ ] Log each retry attempt with reason

**T-1.3.3: Malformed API response handling**
- [ ] Validate PyPI JSON response structure before accessing fields
- [ ] Validate npm JSON response structure before accessing fields
- [ ] On malformed response: log warning, return partial result with NET-001 signal
- [ ] Never crash on unexpected JSON shape

**T-1.3.4: Proxy support**
- [ ] Respect `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` environment variables
- [ ] Pass through to `requests.Session` in `http_client.py`
- [ ] Document proxy usage in README

**T-1.3.5: File watcher resilience**
- [ ] Debounce file change events (ignore changes within 500ms of each other)
- [ ] Handle symlinks: resolve to real path before monitoring
- [ ] Handle file deletion during parsing (catch `FileNotFoundError`)
- [ ] Handle large files: limit parsing to first 10,000 lines

**T-1.3.6: Process watcher resilience**
- [ ] Handle quoted arguments in command lines (e.g., `pip install "package name"`)
- [ ] Handle pip aliases (`python -m pip`, `pip3`, `uv pip`)
- [ ] Log when process scan takes > 500ms (performance warning)
- [ ] Graceful handling of `psutil.AccessDenied` on macOS with SIP

**T-1.3-TEST: Tests for all resilience features**
- [ ] Test: HTTP timeout → retry → succeed on 2nd attempt
- [ ] Test: HTTP 429 → retry → succeed after backoff
- [ ] Test: HTTP 500 → retry 3 times → fail gracefully
- [ ] Test: malformed JSON from PyPI → partial result, no crash
- [ ] Test: malformed JSON from npm → partial result, no crash
- [ ] Test: proxy env vars respected
- [ ] Test: file deleted during parsing → no crash
- [ ] Test: rapid file changes → debounced to single analysis
- [ ] Test: symlink in project path → resolved correctly
- [ ] Test: quoted pip arguments → packages extracted correctly

**T-1.3-SECURITY: Security review of resilience changes**
- [ ] Review: retry logic can't be abused for amplification (bounded retries)
- [ ] Review: proxy settings can't be used to redirect to malicious server
- [ ] Review: symlink resolution doesn't allow path traversal outside project
- [ ] Review: debounce doesn't create timing side-channel for race conditions
- [ ] Scan: `bandit -r uast/`

**T-1.3-REGRESSION: Sprint 1.3 regression testing**
- [ ] Full test suite passes
- [ ] End-to-end: `uast check requests` still works
- [ ] End-to-end: `uast check nonexistent-pkg-12345` still returns hallucinated
- [ ] Performance: `uast check requests --json` completes in < 2 seconds

---

#### Sprint 1.4 — Test Coverage Push

**T-1.4.1: watcher.py tests (target: 0% → 80%)**
- [ ] Test `_extract_package_names()` with all PIP_PATTERNS
- [ ] Test `_extract_package_names()` with all NPM_PATTERNS
- [ ] Test edge cases: flags, URLs, version specifiers, scoped packages
- [ ] Test `DependencyFileHandler._parse_dep_file()` for requirements.txt
- [ ] Test `DependencyFileHandler._parse_dep_file()` for package.json
- [ ] Test `DependencyFileHandler._parse_dep_file()` for pyproject.toml
- [ ] Test `DependencyFileHandler.snapshot()` creates initial state
- [ ] Test `DependencyFileHandler.on_modified()` detects new packages
- [ ] Test `ClaudeCodeLogHandler` parses install commands from logs
- [ ] Test `AgentWatcher._scan_processes()` with mock psutil (mock `process_iter`)
- [ ] Test `AgentWatcher._queue_analysis()` deduplication
- [ ] Test `AgentWatcher._attempt_block()` with mock process
- [ ] Test `AgentWatcher._rollback_install()` with mock subprocess
- [ ] Test `AgentWatcher._install_git_hook()` creates hook file
- [ ] Test `AgentWatcher._remove_git_hook()` removes only uast-managed hooks
- [ ] Test `AgentWatcher._setup_agent_specific()` for each agent type

**T-1.4.2: display.py tests (target: 0% → 70%)**
- [ ] Test `banner()` output contains agent and project
- [ ] Test `watching()` output contains threshold
- [ ] Test `show_result()` for clean verdict (non-verbose — one line)
- [ ] Test `show_result()` for critical verdict (full breakdown)
- [ ] Test `show_result()` verbose mode shows ARSM and signal details
- [ ] Test `show_analysis_result()` for clean package
- [ ] Test `show_analysis_result()` for flagged package with did_you_mean
- [ ] Test `blocked()` and `rolled_back()` output
- [ ] Test `list_sessions()` with mock session files
- [ ] Test `show_report()` with valid JSON report
- [ ] Test edge cases: empty signals list, missing arsm, None did_you_mean

**T-1.4.3: reporter.py tests (target: 0% → 90%)**
- [ ] Test `add_result()` accumulates results
- [ ] Test `save()` writes valid JSON file
- [ ] Test `save()` creates parent directories if missing
- [ ] Test report schema v2 structure (all required fields present)
- [ ] Test summary calculation: total, alerts, clean, suspicious, critical, avg, max
- [ ] Test empty session (no results added)
- [ ] Test `result_count` and `alert_count` properties
- [ ] Test roundtrip: save → read → verify identical data

**T-1.4.4: main.py tests (target: 0% → 80%)**
- [ ] Test `uast --version` outputs version
- [ ] Test `uast --help` outputs help text
- [ ] Test `uast check <package>` with mock analyzer
- [ ] Test `uast check <package> --json` returns valid JSON
- [ ] Test `uast check <package> --ecosystem npm` sets ecosystem
- [ ] Test `uast check <package> --agent cursor` sets correct AAL
- [ ] Test `uast sessions` with no sessions directory
- [ ] Test `uast sessions` with mock session files
- [ ] Test `uast report <path>` with valid JSON report
- [ ] Test `uast report <nonexistent>` shows error
- [ ] Test `uast start` launches watcher (mock, verify setup calls)

**T-1.4.5: http_client.py tests (target: 55% → 90%)**
- [ ] Test cache hit: second call returns cached response without HTTP request
- [ ] Test cache miss: expired entry triggers fresh request
- [ ] Test cache TTL: entry expires after configured seconds
- [ ] Test concurrent request limiting: semaphore blocks excess requests
- [ ] Test `clear_cache()` empties the cache
- [ ] Test `cache_size` property
- [ ] Test `head()` method not cached

**T-1.4.6: Integration tests (new)**
- [ ] Test: `uast check requests` end-to-end (mock HTTP, verify full pipeline)
- [ ] Test: `uast check fake-malicious-pkg` end-to-end (mock 404, verify hallucination)
- [ ] Test: full session lifecycle with mock process and file events
- [ ] Test: blocking mode kills mock process and triggers rollback
- [ ] Test: config file influences check results

**T-1.4-QA: QA validation of test suite**
- [ ] Verify no tests depend on network (all external calls mocked)
- [ ] Verify no tests depend on filesystem state (use tmp dirs)
- [ ] Verify test isolation (no shared mutable state between tests)
- [ ] Verify tests run deterministically (run 5x, same results)
- [ ] Run `pytest --cov=uast --cov-fail-under=80` passes

---

#### Sprint 1.5 — Security Hardening

**T-1.5.1: File permission hardening**
- [ ] `reporter.py`: set `0o600` on session report files after write
- [ ] `logging.py`: set `0o600` on log files
- [ ] Verify with test: file permissions are correct after creation

**T-1.5.2: HTTP client hardening**
- [ ] Add `User-Agent: UAST/{version}` header to all requests
- [ ] Bound cache to max 1000 entries with LRU eviction
- [ ] Add `--verify-ssl/--no-verify-ssl` flag (default: verify)
- [ ] Validate URL format before making requests (reject non-http(s) schemes)

**T-1.5.3: Input sanitization**
- [ ] Sanitize package names: allow only `[a-zA-Z0-9._-]`, reject others
- [ ] Sanitize before subprocess calls in `payload.py` (shell escape)
- [ ] Sanitize before log messages (strip control characters)
- [ ] Sanitize file paths in `watcher.py` (resolve, validate within project)

**T-1.5.4: Process blocking hardening**
- [ ] Fix `_attempt_block()`: match by PID tracked from process detection, not by name substring
- [ ] Store PID → package mapping in `_seen_pids` dict
- [ ] Only kill processes that UAST detected and tracked

**T-1.5.5: Git hook hardening**
- [ ] Validate package names in hook script (no shell metacharacters)
- [ ] Verify hook file wasn't modified after installation (hash check)
- [ ] Add comment in hook explaining it's temporary and session-scoped

**T-1.5.6: JSON validation**
- [ ] Create schema definitions for PyPI and npm API responses
- [ ] Validate before accessing nested fields
- [ ] On schema violation: log warning, continue with partial data

**T-1.5-PENTEST: Penetration testing of Phase 1 features**
- [ ] Test: supply crafted `.uast.toml` with shell injection in values → no execution
- [ ] Test: supply package name with shell metacharacters (`; rm -rf /`) → sanitized
- [ ] Test: supply very long package name (10,000 chars) → bounded, no DoS
- [ ] Test: supply unicode/emoji package name → handled gracefully
- [ ] Test: supply malformed JSON to `uast report` command → no crash
- [ ] Test: create symlink `.uast.toml` → `/etc/shadow` → path traversal blocked
- [ ] Test: concurrent `uast check` calls → no race conditions in cache
- [ ] Test: HTTP response with 100MB body → bounded, no OOM
- [ ] Test: process list with 10,000 entries → scan completes in reasonable time
- [ ] Test: requirements.txt with 50,000 lines → parsed without hang

**T-1.5-REMEDIATE: Remediation sprint (if pentest finds issues)**
- [ ] Triage all pentest findings by severity
- [ ] Fix all CRITICAL findings immediately
- [ ] Fix all HIGH findings before phase exit
- [ ] Document MEDIUM/LOW findings as issues for next phase
- [ ] Re-run pentest to verify fixes
- [ ] Run full regression suite after fixes

---

#### Sprint 1.6 — CI/CD Pipeline

**T-1.6.1: GitHub Actions CI**
- [ ] Create `.github/workflows/ci.yml`
- [ ] Matrix: Python 3.9, 3.10, 3.11, 3.12, 3.13
- [ ] Steps: checkout → install deps → ruff lint → mypy type-check → pytest with coverage → bandit scan → pip-audit
- [ ] Coverage gate: fail if < 80%
- [ ] Cache pip dependencies for speed

**T-1.6.2: Pre-commit hooks**
- [ ] Create `.pre-commit-config.yaml`
- [ ] Hooks: ruff (lint + format), mypy, bandit, trailing whitespace, TOML validation
- [ ] Document in CONTRIBUTING.md

**T-1.6.3: Automated PyPI publishing**
- [ ] Create `.github/workflows/publish.yml`
- [ ] Trigger: on GitHub release created (tagged `v*`)
- [ ] Steps: build sdist + wheel → publish to PyPI via trusted publisher (OIDC)
- [ ] Test: publish to TestPyPI first on pre-release tags

**T-1.6.4: CODEOWNERS**
- [ ] Create `CODEOWNERS` file requiring review for `uast/` changes
- [ ] Security-sensitive files (`payload.py`, `watcher.py`, `http_client.py`) require explicit security review tag

**T-1.6-TEST: CI validation**
- [ ] Verify CI runs on PR creation
- [ ] Verify CI fails when tests fail
- [ ] Verify CI fails when coverage drops below 80%
- [ ] Verify CI fails when bandit finds HIGH issue
- [ ] Verify publish workflow works with TestPyPI

---

#### Sprint 1.7 — Documentation

**T-1.7.1: CHANGELOG.md**
- [ ] Create with retroactive v0.1.0 entry
- [ ] Document format: [Keep a Changelog](https://keepachangelog.com/)
- [ ] Sections: Added, Changed, Fixed, Security, Removed

**T-1.7.2: CONTRIBUTING.md**
- [ ] Dev environment setup (venv, install -e, pre-commit)
- [ ] Testing guide (how to run, how to add tests, coverage requirements)
- [ ] PR process (branch naming, commit format, review process)
- [ ] Security issue reporting (link to SECURITY.md)
- [ ] Architecture overview

**T-1.7.3: SECURITY.md**
- [ ] Vulnerability reporting process (email, not public issue)
- [ ] Response SLA (acknowledge within 48h, fix CRITICAL within 7 days)
- [ ] Supported versions
- [ ] Security contact

**T-1.7.4: Architecture diagram in README**
- [ ] Mermaid diagram showing: CLI → Watcher → Analyzer → Display/Reporter
- [ ] Show dual interception (process + file watchers)
- [ ] Show ARSM scoring flow

**T-1.7.5: Update README for v0.2.0**
- [ ] Document `.uast.toml` configuration
- [ ] Document allowlist/blocklist feature
- [ ] Document logging and `--log-level`
- [ ] Update version references
- [ ] Add architecture diagram

**T-1.7-REVIEW: Documentation review**
- [ ] All code examples in docs actually work (test each one)
- [ ] No broken links
- [ ] No references to unimplemented features
- [ ] Consistent terminology

---

#### Phase 1 Exit Gate

```
PHASE 1 EXIT CHECKLIST

COVERAGE
- [ ] `pytest --cov=uast --cov-fail-under=80` passes
- [ ] All modules have tests (no 0% coverage modules)

CONFIGURATION
- [ ] `.uast.toml` works with all documented options
- [ ] Precedence (CLI > project > user > default) verified
- [ ] Allowlist/blocklist functional

RELIABILITY
- [ ] No bare `except Exception:` in codebase
- [ ] HTTP retries working (verified with mock server)
- [ ] Proxy support working (verified with mock proxy)

SECURITY
- [ ] bandit scan clean (no HIGH/CRITICAL)
- [ ] pip-audit clean
- [ ] All pentest findings CRITICAL/HIGH resolved
- [ ] File permissions correct (0o600 on reports/logs)
- [ ] Input sanitization on all user-controlled values

CI/CD
- [ ] GitHub Actions CI green on main
- [ ] Pre-commit hooks configured
- [ ] PyPI publish workflow tested on TestPyPI

DOCUMENTATION
- [ ] CHANGELOG, CONTRIBUTING, SECURITY docs exist
- [ ] README updated with v0.2.0 features
- [ ] Architecture diagram in README

FINAL VALIDATION
- [ ] Fresh install: `pip install .` in clean venv → works
- [ ] `uast check requests` → clean
- [ ] `uast check request-utils-async` → critical
- [ ] `uast start --agent cursor --project .` → starts without error
- [ ] `uast sessions` → lists sessions
```

---

## Phase 2: Detection Engine Expansion (v0.3.0)

### PRD-2: Detection Engine Expansion

**Objective:** Dramatically improve what UAST can detect. Move from 4/22 AVT classes to 12/22. Bring npm payload analysis to parity with PyPI. Integrate external threat intelligence. Calibrate the scoring model against real data.

**Target Users:**
- Security teams evaluating UAST detection capabilities
- Red teams testing AI agent supply chain resilience
- Developers who need confident "safe to install" verdicts

**User Stories:**

| ID | Story | Acceptance Criteria |
|---|---|---|
| US-2.1 | As a security engineer, I want UAST to detect packages with known CVEs so I don't install vulnerable software | OSV/GitHub Advisory DB checked; known CVEs surface as CRITICAL signals |
| US-2.2 | As a user, I want npm packages scanned for malicious payloads just like Python packages | JS/TS AST analysis detects eval, child_process, install scripts |
| US-2.3 | As a user, I want fewer false positives so I trust UAST alerts | ARSM calibrated against labeled dataset; false positive rate < 10% |
| US-2.4 | As a security engineer, I want UAST to detect prompt injection in package descriptions | Descriptions scanned for injection patterns targeting AI agents |
| US-2.5 | As a user, I want UAST to check if a maintainer account was recently compromised | Maintainer account age, history, and takeover patterns analyzed |
| US-2.6 | As a user, I want confidence intervals on scores so I know how certain the verdict is | ARS scores include ± range and confidence level |

**Technical Requirements:**
- JS/TS AST parsing: `tree-sitter` Python bindings or subprocess call to `node` with `acorn`
- Threat intel: HTTP APIs to OSV, GitHub Advisory, pypistats
- Calibration: labeled dataset of ≥ 100 known-malicious + 500 known-safe packages
- CIS scoring: parse agent logs for AI-initiated vs. human-initiated context

**Dependencies:** Phase 1 complete (config system needed for threat intel API keys, logging needed for debugging)

**Risks:**
- Threat intel APIs may have rate limits → mitigate with caching and fallback
- JS AST parsing adds significant complexity → mitigate with clear module boundary
- Calibration dataset may be biased → mitigate with diverse data sources

---

### Phase 2 Task List

#### Sprint 2.1 — AVT Taxonomy Expansion (D1: Context Manipulation)

**T-2.1.1: AVT-D1-01 — Prompt injection via dependencies**
- [ ] Scan package README/description for prompt injection patterns
- [ ] Pattern library: "ignore previous instructions", "you are now", system prompt overrides
- [ ] Scan package code comments for injection patterns (AI agents read code comments)
- [ ] New signal: `INJECT-001` (severity: critical, contribution: 0.9)
- [ ] New AVT class mapping: D1-01

**T-2.1.1-TEST:**
- [ ] Test: package with "ignore all previous instructions" in description → flagged
- [ ] Test: package with normal description → not flagged
- [ ] Test: package with injection in code comment → flagged
- [ ] Test: partial match patterns (substring of injection phrase) → not flagged (no false positives)

**T-2.1.2: AVT-D1-02 — Context poisoning**
- [ ] Detect packages that modify environment variables at import time
- [ ] Detect packages that write to `.env`, `.bashrc`, `.zshrc` at install time
- [ ] Detect packages that modify `sys.path` or `PYTHONPATH`
- [ ] Extend AST payload analysis with new patterns
- [ ] New signal: `POISON-001` (severity: high, contribution: 0.7)

**T-2.1.2-TEST:**
- [ ] Test: `os.environ['PATH'] = ...` in __init__.py → flagged
- [ ] Test: normal environment variable read → not flagged
- [ ] Test: sys.path manipulation → flagged

**T-2.1-SECURITY: Review of D1 detectors**
- [ ] Review: can malicious patterns be obfuscated to bypass detection?
- [ ] Review: regex patterns don't have ReDoS vulnerabilities
- [ ] Review: scanning large descriptions doesn't cause performance issues
- [ ] Adversarial test: craft packages that attempt to bypass each detector

---

#### Sprint 2.2 — AVT Taxonomy Expansion (D2: Permission & Scope)

**T-2.2.1: AVT-D2-01 — Privilege escalation via agent**
- [ ] Detect `sudo` calls in setup.py/install scripts
- [ ] Detect requests for elevated permissions (`os.setuid`, `os.chmod(0o777)`)
- [ ] Detect modification of system-level config files
- [ ] New signal: `PRIV-001` (severity: critical, contribution: 0.9)

**T-2.2.2: AVT-D2-02 — Scope creep detection**
- [ ] Compare package stated purpose (description/classifiers) against actual imports
- [ ] Flag: crypto library that imports `socket` and `subprocess`
- [ ] Flag: logging library that imports `ctypes` or `winreg`
- [ ] Requires: import graph analysis of package source
- [ ] New signal: `SCOPE-001` (severity: medium, contribution: 0.5)

**T-2.2-TEST:**
- [ ] Test: setup.py with `sudo pip install` → flagged
- [ ] Test: setup.py with normal install → not flagged
- [ ] Test: crypto library importing socket → flagged for scope creep
- [ ] Test: web framework importing socket → not flagged (expected)

**T-2.2-SECURITY: Review of D2 detectors**
- [ ] Review: scope analysis doesn't have false positives on legitimate multi-purpose packages
- [ ] Review: AST analysis handles obfuscated imports
- [ ] Adversarial test: package that hides privileged operations in nested helper module

---

#### Sprint 2.3 — AVT Taxonomy Expansion (D4: Trust & Identity)

**T-2.3.1: AVT-D4-01 — Metadata spoofing**
- [ ] Cross-reference package description against actual functionality
- [ ] Detect: description says "logging utility" but code makes network requests
- [ ] Detect: inconsistent license (MIT in metadata, GPL in code)
- [ ] Detect: homepage URL points to unrelated project
- [ ] New signal: `SPOOF-001` (severity: high, contribution: 0.7)

**T-2.3.2: AVT-D4-02 — Maintainer impersonation**
- [ ] Fetch maintainer profile from registry
- [ ] Check: account age (< 30 days = suspicious)
- [ ] Check: number of other packages maintained (0 = first package, elevated risk)
- [ ] Check: maintainer change on existing package (takeover pattern)
- [ ] Cross-reference maintainer email with GitHub commits
- [ ] New signal: `MAINTAINER-001` (severity: high, contribution: 0.7)

**T-2.3-TEST:**
- [ ] Test: package claiming "logging" but making network calls → flagged
- [ ] Test: new maintainer account (< 30d) → flagged
- [ ] Test: established maintainer (> 1yr, 10+ packages) → not flagged
- [ ] Test: maintainer change event → flagged

**T-2.3-SECURITY: Review of D4 detectors**
- [ ] Review: maintainer API calls respect rate limits
- [ ] Review: cross-referencing doesn't leak sensitive maintainer data
- [ ] Review: GitHub API calls use authentication if configured
- [ ] Adversarial test: maintainer with legitimately new account but valid package

---

#### Sprint 2.4 — npm Payload Analysis

**T-2.4.1: JavaScript AST scanner**
- [ ] Create `uast/payload_js.py` module
- [ ] Choose parser: `tree-sitter-javascript` Python bindings (preferred) or `node -e` with acorn (fallback)
- [ ] Detect patterns:
  - `eval()`, `new Function()`, `setTimeout(string)`, `setInterval(string)`
  - `child_process.exec()`, `child_process.spawn()`, `child_process.execSync()`
  - `require()` with variable argument
  - `process.env` gating (environment-conditional execution)
  - Encoded strings (base64, hex) being decoded and executed
  - `fs.writeFile` to sensitive paths
- [ ] Support scanning `.js`, `.mjs`, `.cjs`, `.ts` files

**T-2.4.2: npm install script detection**
- [ ] Parse `package.json` for `scripts.preinstall`, `scripts.postinstall`, `scripts.prepare`
- [ ] Flag any package with install lifecycle scripts (severity: medium)
- [ ] If install script contains network/exec calls (severity: critical)
- [ ] New signal: `INSTALLSCRIPT-001`

**T-2.4.3: Obfuscation detection**
- [ ] Detect high-entropy strings (likely encoded payloads)
- [ ] Detect minified/packed code in non-dist files (webpack/esbuild output where source expected)
- [ ] Entropy threshold: > 4.5 bits/char for strings > 50 chars

**T-2.4-TEST:**
- [ ] Test: JS file with `eval(variable)` → flagged PAYLOAD-005
- [ ] Test: JS file with `child_process.exec(cmd)` → flagged PAYLOAD-002
- [ ] Test: JS file with `console.log()` → not flagged
- [ ] Test: package.json with `postinstall` script → flagged INSTALLSCRIPT-001
- [ ] Test: package.json without install scripts → not flagged
- [ ] Test: high-entropy string in JS file → flagged
- [ ] Test: TypeScript file handling (`.ts` parsed correctly)

**T-2.4-SECURITY: Review of npm payload analysis**
- [ ] Review: tree-sitter parser handles malicious syntax without crash
- [ ] Review: no code execution during analysis (we parse, never execute)
- [ ] Review: temp directory cleanup after analysis (no leftover npm packages)
- [ ] Review: scoped packages (`@scope/name`) handled correctly in download
- [ ] Pentest: craft JS file that crashes tree-sitter parser

---

#### Sprint 2.5 — ARSM Calibration

**T-2.5.1: Build labeled dataset**
- [ ] Collect ≥ 100 known-malicious packages (from PyPI removals, npm advisories, Phylum reports)
- [ ] Collect ≥ 500 known-safe packages (top PyPI/npm packages)
- [ ] Store as JSON dataset: `calibration/dataset.json`
- [ ] Document source of each label

**T-2.5.2: Run baseline scoring**
- [ ] Score all dataset packages with current ARSM coefficients
- [ ] Calculate: true positive rate, false positive rate, precision, recall, F1
- [ ] Document baseline metrics

**T-2.5.3: Optimize coefficients**
- [ ] Grid search over alpha (0.1–0.5), beta (0.1–0.5), gamma (0.1–0.5), delta (0.05–0.3)
- [ ] Optimize for: maximize F1 score at threshold 6.0
- [ ] Secondary objective: minimize false positive rate at fixed recall ≥ 0.8
- [ ] Cross-validate: 5-fold to prevent overfitting

**T-2.5.4: Implement CIS scoring**
- [ ] Replace hardcoded `cis=1.0` with actual computation
- [ ] CIS factors: was package name from AI suggestion (0.7) vs. human input (1.0)
- [ ] CIS factors: is package in requirements.txt already (1.0) vs. new addition (0.8)
- [ ] Default CIS: 0.85 (cautious baseline)

**T-2.5.5: Implement confidence intervals**
- [ ] Calculate score variance from signal weights
- [ ] Return ARS as `{score: 7.2, confidence: "high", range: [6.5, 7.9]}`
- [ ] Confidence levels: "high" (range < 1.0), "medium" (range < 2.0), "low" (range ≥ 2.0)
- [ ] Update JSON output schema (backward compatible — new fields only)

**T-2.5-TEST:**
- [ ] Test: calibrated coefficients produce better F1 than defaults
- [ ] Test: CIS < 1.0 increases ARS score
- [ ] Test: confidence interval calculation is mathematically correct
- [ ] Test: JSON schema backward compatible (old consumers still work)

**T-2.5-SECURITY:**
- [ ] Review: calibration dataset doesn't contain actual malicious code (only metadata)
- [ ] Review: dataset not shipped in pip package (dev-only)

---

#### Sprint 2.6 — Threat Intelligence Integration

**T-2.6.1: OSV database integration**
- [ ] Create `uast/threat_intel.py` module
- [ ] Query OSV API: `https://api.osv.dev/v1/query`
- [ ] Check each package name + version against OSV
- [ ] Map OSV severity to UAST signal: GHSA-xxx → `CVE-001` signal
- [ ] Cache results (1 hour TTL)

**T-2.6.2: GitHub Advisory Database**
- [ ] Query GitHub Advisory API (no auth needed for public advisories)
- [ ] Supplement OSV results with GitHub-specific advisories
- [ ] Merge and deduplicate across sources

**T-2.6.3: Auto-updating allowlists**
- [ ] Fetch top-1000 PyPI packages weekly (from pypistats/hugovk)
- [ ] Fetch top-1000 npm packages weekly (from npm registry)
- [ ] Store in `~/.uast/allowlists/` with timestamp
- [ ] Merge with built-in and user allowlists
- [ ] `uast update-allowlists` command to trigger manual refresh

**T-2.6-TEST:**
- [ ] Test: known CVE package (e.g., old version of `requests`) → CVE signal returned
- [ ] Test: clean package → no CVE signals
- [ ] Test: OSV API down → graceful fallback, analysis continues
- [ ] Test: allowlist update command works
- [ ] Test: allowlist caching respects TTL

**T-2.6-SECURITY:**
- [ ] Review: OSV API responses validated before use
- [ ] Review: no code execution from advisory data
- [ ] Review: allowlist update can't be poisoned (validate source)
- [ ] Review: API keys (if any) stored securely (not in config file)

---

#### Sprint 2.7 — Maintainer Analysis & Velocity Improvements

**T-2.7.1: Maintainer analysis**
- [ ] PyPI: fetch maintainer info from package metadata
- [ ] npm: fetch maintainer list from registry
- [ ] Check account age, package count, email verification
- [ ] Detect maintainer changes (compare current vs. previous version)
- [ ] New signal: `MAINTAINER-001` through `MAINTAINER-003`

**T-2.7.2: Statistical velocity anomaly detection**
- [ ] Build baseline: mean/stddev downloads per age bucket per ecosystem
- [ ] Z-score calculation: flag if z > 3.0 for age bucket
- [ ] Replace hardcoded 10,000 threshold with statistical approach
- [ ] Historical tracking: detect sudden velocity spikes

**T-2.7-TEST:**
- [ ] Test: new maintainer (< 30d, 0 other packages) → flagged
- [ ] Test: established maintainer → not flagged
- [ ] Test: velocity z-score > 3.0 → anomaly flagged
- [ ] Test: high downloads on old package → not flagged (expected)

---

#### Phase 2 Pentest & Security Review

**T-2-PENTEST: Phase 2 comprehensive pentest**
- [ ] Craft package with prompt injection in description → verify detection
- [ ] Craft package with obfuscated JS payload → verify detection
- [ ] Craft package with install script that exfiltrates → verify detection
- [ ] Craft package that bypasses all current detectors → document gaps
- [ ] Test all new APIs against rate limiting and error conditions
- [ ] Test with packages that have intentionally malformed metadata
- [ ] Test JS parser with adversarial syntax (deeply nested, unicode abuse)
- [ ] Verify no new injection vectors introduced by threat intel integration

**T-2-REMEDIATE: Remediation sprint**
- [ ] Triage all findings from pentest
- [ ] Fix CRITICAL/HIGH issues
- [ ] Update detectors if bypass techniques found
- [ ] Re-run pentest to verify fixes
- [ ] Run full regression suite
- [ ] Update CHANGELOG with security fixes

**T-2-DOCS: Phase 2 documentation**
- [ ] Update README: new AVT classes, npm payload analysis, threat intel
- [ ] Document calibration methodology and results
- [ ] Update architecture diagram with new modules
- [ ] CHANGELOG entries for all Phase 2 features

---

#### Phase 2 Exit Gate

```
PHASE 2 EXIT CHECKLIST

DETECTION
- [ ] 12/22 AVT classes detectable (list each with test evidence)
- [ ] npm payload analysis functional (JS/TS files scanned)
- [ ] Threat intel: OSV + GitHub Advisory working
- [ ] Maintainer analysis working for PyPI and npm

SCORING
- [ ] ARSM coefficients calibrated (document F1, precision, recall)
- [ ] CIS scoring implemented (not hardcoded 1.0)
- [ ] Confidence intervals in output
- [ ] False positive rate measured and < 10%

TESTING
- [ ] Coverage remains ≥ 80%
- [ ] All new detectors have positive and negative tests
- [ ] Adversarial tests for each new detector
- [ ] Integration tests for full analysis pipeline

SECURITY
- [ ] Pentest complete, all CRITICAL/HIGH resolved
- [ ] No new bandit findings
- [ ] New APIs validated and rate-limited

DOCUMENTATION
- [ ] README updated with all new capabilities
- [ ] Calibration report documented
- [ ] CHANGELOG updated
```

---

## Phase 3: Layer 3 — Provenance Chain Verification (v0.4.0)

### PRD-3: Provenance Chain Verification

**Objective:** Implement PCV layer from the paper. Verify that packages on registries match their declared source code. Detect supply chain tampering at the build/publish stage.

**Target Users:**
- Security teams that need supply chain integrity guarantees
- Organizations with zero-trust dependency policies
- Compliance teams requiring artifact provenance documentation

**User Stories:**

| ID | Story | Acceptance Criteria |
|---|---|---|
| US-3.1 | As a security engineer, I want to verify a package was built from its stated source repo | Source cloned, built, hash compared against registry artifact |
| US-3.2 | As a user, I want to know if a package has a verified build provenance (Sigstore/SLSA) | Sigstore signature or SLSA provenance checked and reported |
| US-3.3 | As a user, I want to see what changed between package versions so I can spot suspicious updates | Version diff showing new imports, network calls, file writes |
| US-3.4 | As a compliance officer, I want a tamper-evident hash of the dependency tree for audit records | Merkle tree hash computed and stored in session reports |

**Technical Requirements:**
- Source build: `pip download --no-binary :all:` + local build + hash comparison
- Sigstore: `sigstore-python` library for PyPI verification
- Version diffing: download two versions, extract, unified diff with pattern matching
- Merkle tree: SHA-256 based content-addressable tree hashing

**Dependencies:** Phase 2 (threat intel for known-compromised versions, payload analysis for diff evaluation)

**Risks:**
- Source build may fail for packages with C extensions → mitigate with hash-only comparison where build fails
- Sigstore adoption is low → mitigate with graceful "not signed" info signal (not penalty)
- Version diffing on large packages is slow → mitigate with file-level hashing before full diff

---

### Phase 3 Task List

#### Sprint 3.1 — Source-to-Registry Verification

**T-3.1.1: Package build verification engine**
- [ ] Create `uast/provenance.py` module
- [ ] Download source from declared repo URL (git clone, shallow)
- [ ] Build package in isolated temp environment (`python -m build`)
- [ ] Download registry artifact (same version)
- [ ] Compare artifact hashes (SHA-256)
- [ ] Handle: build failure (C extensions) → fall back to file-level comparison
- [ ] Handle: no source repo declared → skip with info signal
- [ ] New signal: `PROV-001` (hash mismatch, severity: critical)
- [ ] New signal: `PROV-002` (no source repo, severity: low)
- [ ] Safety: build in sandboxed temp dir, timeout 120s, no network during build

**T-3.1.1-TEST:**
- [ ] Test: package where source matches registry → no provenance signal
- [ ] Test: package where source differs from registry → PROV-001 critical
- [ ] Test: package with no source repo → PROV-002 info
- [ ] Test: build failure (missing build deps) → graceful fallback
- [ ] Test: build timeout → handled, no hang
- [ ] Test: large repo (> 100MB) → skipped with warning

**T-3.1.1-SECURITY:**
- [ ] Review: git clone can't be exploited (no LFS, no submodules auto-init)
- [ ] Review: build sandbox is truly isolated (no access to host pip, no network)
- [ ] Review: temp directories cleaned up on all code paths (including exceptions)
- [ ] Review: hash comparison is timing-safe (use `hmac.compare_digest`)
- [ ] Pentest: repo URL points to malicious repo that runs code on clone → blocked

---

#### Sprint 3.2 — Signature & Provenance Verification

**T-3.2.1: Sigstore verification for PyPI**
- [ ] Integrate `sigstore-python` for PEP 740 attestation verification
- [ ] Check if package has Sigstore signature on PyPI
- [ ] Verify signature against Sigstore transparency log
- [ ] New signal: `SIG-001` (verified signature, severity: info, contribution: -0.2 — lowers risk)
- [ ] New signal: `SIG-002` (no signature, severity: info, contribution: 0.0 — neutral)
- [ ] New signal: `SIG-003` (invalid signature, severity: critical, contribution: 0.95)

**T-3.2.2: SLSA provenance check**
- [ ] Check for SLSA provenance metadata in package
- [ ] Verify SLSA level (1-4) and report in metadata
- [ ] Higher SLSA level → lower risk contribution

**T-3.2-TEST:**
- [ ] Test: package with valid Sigstore signature → SIG-001
- [ ] Test: package without signature → SIG-002
- [ ] Test: package with tampered signature → SIG-003
- [ ] Test: Sigstore API unavailable → graceful fallback

**T-3.2-SECURITY:**
- [ ] Review: signature verification is correct (no bypass via malformed cert)
- [ ] Review: Sigstore root of trust is pinned, not fetched from network
- [ ] Review: no confused deputy via Sigstore → UAST doesn't act on unverified data

---

#### Sprint 3.3 — Version Diffing

**T-3.3.1: Version diff engine**
- [ ] Create `uast/version_diff.py` module
- [ ] Download current version and previous version of package
- [ ] Extract and diff at file level (added, removed, modified files)
- [ ] For modified files: unified diff with context
- [ ] Flag suspicious changes:
  - New `setup.py`/`setup.cfg` install-time code
  - New `__init__.py` imports of network/subprocess modules
  - New high-entropy strings (potential encoded payloads)
  - New file writes to sensitive paths
  - New dependency additions
  - Removed license/readme (metadata stripping)
- [ ] New signal: `VDIFF-001` (suspicious version change, severity varies)

**T-3.3.1-TEST:**
- [ ] Test: version with no suspicious changes → no VDIFF signal
- [ ] Test: version adding `subprocess` import to __init__.py → flagged
- [ ] Test: version adding new dependency → flagged
- [ ] Test: version with only README changes → not flagged
- [ ] Test: first version (no previous to compare) → skip gracefully

**T-3.3-SECURITY:**
- [ ] Review: diff engine handles binary files safely (skip, don't crash)
- [ ] Review: large diffs bounded (max 10,000 lines diffed)
- [ ] Review: no path traversal in extracted package files

---

#### Sprint 3.4 — Merkle Tree Hashing

**T-3.4.1: Dependency tree hashing**
- [ ] Implement Merkle tree: `H(name || version || source_hash || sort([child_hashes]))`
- [ ] Hash algorithm: SHA-256
- [ ] Compute tree hash for every resolved dependency tree
- [ ] Store tree hash in session report (`dependency_tree_hash` field)
- [ ] `uast diff-trees <session1> <session2>` command to compare tree hashes
- [ ] Detect dependency drift between sessions

**T-3.4.1-TEST:**
- [ ] Test: same dependencies → same tree hash
- [ ] Test: different version of one dep → different tree hash
- [ ] Test: added dep → different tree hash
- [ ] Test: hash is deterministic (order-independent via sorting)

**T-3.4-SECURITY:**
- [ ] Review: hash algorithm is SHA-256 (not MD5/SHA1)
- [ ] Review: tree hash stored immutably in report (can't be recalculated to hide changes)

---

#### Phase 3 Pentest & Exit Gate

**T-3-PENTEST:**
- [ ] Craft package with source that differs from registry → verify PROV-001
- [ ] Craft package with forged Sigstore signature → verify SIG-003
- [ ] Craft version update that introduces subtle backdoor → verify VDIFF-001
- [ ] Test provenance on package with C extensions → verify graceful handling
- [ ] Test Merkle tree with circular dependencies → verify no infinite loop

**T-3-REMEDIATE:**
- [ ] Fix all CRITICAL/HIGH pentest findings
- [ ] Re-run pentest to verify
- [ ] Full regression suite passes

**T-3-DOCS:**
- [ ] Update README: provenance features, `--provenance` flag, version diffing
- [ ] Document Merkle tree schema
- [ ] CHANGELOG entries

```
PHASE 3 EXIT CHECKLIST
- [ ] Source-to-registry verification working for PyPI
- [ ] Sigstore verification working
- [ ] Version diffing detecting suspicious changes
- [ ] Merkle tree hashing in session reports
- [ ] Coverage ≥ 82%
- [ ] Pentest complete, all CRITICAL/HIGH resolved
- [ ] README updated
```

---

## Phase 4: Real-Time Intelligence & Integrations (v0.5.0)

### PRD-4: Integrations & CI/CD

**Objective:** Make UAST useful beyond a single developer's terminal. Enable team usage via dashboards, CI/CD integration, alert routing, and standard export formats. Add Go and Rust ecosystem support.

**Target Users:**
- DevSecOps teams integrating UAST into CI/CD pipelines
- Security operations teams monitoring across multiple projects
- Platform teams managing dependency policies organization-wide
- Go and Rust developers using AI coding agents

**User Stories:**

| ID | Story | Acceptance Criteria |
|---|---|---|
| US-4.1 | As a DevOps engineer, I want UAST to run in my CI pipeline and fail the build if a dangerous package is added | `uast ci` exits non-zero on critical findings; SARIF output for GitHub Code Scanning |
| US-4.2 | As a security ops team, I want alerts sent to Slack when a critical package is detected | Webhook fires within 5s of detection; Slack message includes package name, score, verdict |
| US-4.3 | As a team lead, I want a dashboard showing UAST findings across all projects | Web UI lists sessions, packages, trends; accessible via `uast dashboard` |
| US-4.4 | As a Go developer, I want UAST to monitor `go.mod` for suspicious dependencies | Go ecosystem: process watcher detects `go get`, file watcher monitors `go.mod`/`go.sum` |
| US-4.5 | As a Rust developer, I want UAST to analyze crates.io packages | Rust ecosystem: crates.io API integration, `Cargo.toml` monitoring |
| US-4.6 | As a compliance officer, I want SBOM export for audit records | CycloneDX and SPDX SBOM generation from session data |

**Technical Requirements:**
- CI mode: non-interactive, machine-readable output, configurable exit codes
- Web dashboard: FastAPI backend + htmx/Alpine.js frontend (minimal JS, no build step)
- Alerts: webhook system with pluggable transports (HTTP, Slack, email)
- SARIF: JSON output conforming to SARIF 2.1.0 schema
- Go/Rust: new analyzer modules with ecosystem-specific APIs
- REST API: FastAPI with OpenAPI spec, API key auth

**Dependencies:** Phase 2 (threat intel feeds used in CI mode), Phase 3 (provenance data in reports)

**Risks:**
- Web dashboard scope creep → mitigate with strict MVP (read-only, no auth in v1)
- REST API security → mitigate with localhost-only default, API key for remote
- New ecosystems add maintenance burden → mitigate with shared analyzer interface

---

### Phase 4 Task List

#### Sprint 4.1 — CI/CD Mode

**T-4.1.1: `uast ci` command**
- [ ] Create non-interactive CI command
- [ ] Input: list of packages from diff (stdin or `--packages` flag)
- [ ] Input: dependency file diff (`--diff` flag pointing to git diff output)
- [ ] Output modes: `--format json`, `--format sarif`, `--format junit`, `--format table`
- [ ] Exit codes: 0 (all clean), 1 (at least one critical), 2 (at least one suspicious)
- [ ] `--fail-on` flag: `critical` (default), `suspicious`, `any`
- [ ] No terminal colors/formatting in CI mode
- [ ] Configurable via `.uast.toml` `[ci]` section

**T-4.1.2: SARIF output**
- [ ] Implement SARIF 2.1.0 schema output
- [ ] Map UAST signals to SARIF `result` objects
- [ ] Map AVT classes to SARIF `rule` objects
- [ ] Map severity to SARIF `level` (error/warning/note)
- [ ] Include file location (dependency file + line) where possible
- [ ] Validate output against SARIF schema

**T-4.1.3: GitHub Action**
- [ ] Create `action.yml` for `mjjjjaazing/uast-action`
- [ ] Inputs: threshold, fail-on, ecosystems, config-path
- [ ] Steps: install UAST → detect changed deps from PR diff → run `uast ci` → post SARIF
- [ ] Post results as PR comment (optional)
- [ ] Upload SARIF to GitHub Code Scanning
- [ ] Document usage in action README

**T-4.1-TEST:**
- [ ] Test: `uast ci` with all-clean packages → exit 0
- [ ] Test: `uast ci` with critical package → exit 1
- [ ] Test: SARIF output validates against schema
- [ ] Test: JUnit output parseable by CI tools
- [ ] Test: `--diff` input correctly extracts new packages
- [ ] Test: GitHub Action end-to-end with mock PR

**T-4.1-SECURITY:**
- [ ] Review: CI mode doesn't leak sensitive data in output
- [ ] Review: SARIF output doesn't include internal paths
- [ ] Review: GitHub Action doesn't expose secrets
- [ ] Review: stdin input sanitized

---

#### Sprint 4.2 — Alert & Notification System

**T-4.2.1: Webhook alert engine**
- [ ] Create `uast/alerts.py` module
- [ ] Pluggable transport interface: `class AlertTransport(Protocol)`
- [ ] HTTP webhook transport: POST JSON payload to configured URL
- [ ] Slack transport: format as Slack Block Kit message
- [ ] Email transport: SMTP with configurable server
- [ ] Config: `[alerts]` section in `.uast.toml`
- [ ] Alert routing: configurable per severity level
- [ ] Rate limiting: max 1 alert per package per session

**T-4.2.1-TEST:**
- [ ] Test: webhook fires on critical detection (mock HTTP server)
- [ ] Test: Slack message format is valid Block Kit JSON
- [ ] Test: rate limiting prevents duplicate alerts
- [ ] Test: alert routing respects severity config
- [ ] Test: transport failure → logged, doesn't crash session

**T-4.2-SECURITY:**
- [ ] Review: webhook URLs validated (HTTPS only for non-localhost)
- [ ] Review: webhook payload doesn't include sensitive config data
- [ ] Review: SMTP credentials stored securely (env var, not config file)
- [ ] Review: no SSRF via webhook URL (restrict to user-configured URLs only)
- [ ] Pentest: webhook URL pointing to internal service → blocked or documented risk

---

#### Sprint 4.3 — Web Dashboard

**T-4.3.1: Dashboard backend**
- [ ] Create `uast/dashboard/` package
- [ ] FastAPI app serving at `localhost:9090` (configurable port)
- [ ] Endpoints:
  - `GET /` — dashboard HTML
  - `GET /api/sessions` — list sessions
  - `GET /api/sessions/:id` — session detail
  - `GET /api/packages` — search packages across sessions
  - `GET /api/stats` — aggregate statistics
- [ ] Read from `~/.uast/sessions/` directory
- [ ] No database (JSON files are the data store for v1)

**T-4.3.2: Dashboard frontend**
- [ ] HTML templates with htmx for interactivity
- [ ] Session list view with sort/filter
- [ ] Session detail view with package breakdown
- [ ] Package search across all sessions
- [ ] Risk trend chart (simple, inline SVG or CSS-only)
- [ ] `uast dashboard` CLI command to start server

**T-4.3-TEST:**
- [ ] Test: API endpoints return correct JSON
- [ ] Test: dashboard renders with mock session data
- [ ] Test: empty sessions directory → friendly empty state
- [ ] Test: malformed session file → skipped with warning

**T-4.3-SECURITY:**
- [ ] Review: dashboard binds to localhost only by default
- [ ] Review: no XSS in session data rendered in HTML (escape all user content)
- [ ] Review: no path traversal via session ID parameter
- [ ] Review: no injection via package name in search
- [ ] Pentest: session file with XSS payload in package name → escaped
- [ ] Pentest: session ID with `../../etc/passwd` → blocked

---

#### Sprint 4.4 — REST API

**T-4.4.1: API server**
- [ ] `uast serve` command — starts API server
- [ ] Endpoints:
  - `POST /api/v1/check` — analyze a package `{name, ecosystem, agent}`
  - `GET /api/v1/sessions` — list sessions
  - `GET /api/v1/sessions/:id` — session detail
  - `GET /api/v1/health` — health check
- [ ] API key authentication (`X-API-Key` header)
- [ ] Rate limiting: 100 requests/minute per key
- [ ] OpenAPI/Swagger spec auto-generated by FastAPI

**T-4.4-TEST:**
- [ ] Test: check endpoint returns valid analysis result
- [ ] Test: missing API key → 401
- [ ] Test: invalid API key → 403
- [ ] Test: rate limit exceeded → 429
- [ ] Test: OpenAPI spec is valid

**T-4.4-SECURITY:**
- [ ] Review: API key generation is cryptographically secure
- [ ] Review: API keys not logged
- [ ] Review: rate limiting prevents abuse
- [ ] Review: input validation on all endpoints
- [ ] Pentest: SQL/NoSQL injection (though no DB — verify nothing injectable)
- [ ] Pentest: large payload body → bounded

---

#### Sprint 4.5 — Additional Ecosystems (Go, Rust)

**T-4.5.1: Go ecosystem support**
- [ ] Create `uast/ecosystems/go.py` module
- [ ] Analyzer: query `proxy.golang.org` for module metadata
- [ ] Watcher: detect `go get`, `go install` processes
- [ ] Watcher: monitor `go.mod`, `go.sum` for changes
- [ ] Detection: age, maintainer, dependency tree, name patterns
- [ ] Add Go-specific safe modules list
- [ ] `--ecosystem go` flag on `uast check`

**T-4.5.2: Rust ecosystem support**
- [ ] Create `uast/ecosystems/rust.py` module
- [ ] Analyzer: query `crates.io` API for crate metadata
- [ ] Watcher: detect `cargo add`, `cargo install` processes
- [ ] Watcher: monitor `Cargo.toml`, `Cargo.lock` for changes
- [ ] Detection: age, maintainer, dependency tree, name patterns
- [ ] Add Rust-specific safe crates list
- [ ] `--ecosystem crates` flag on `uast check`

**T-4.5-TEST:**
- [ ] Test: `uast check serde --ecosystem crates` → clean
- [ ] Test: `uast check fake-crate-123 --ecosystem crates` → hallucinated
- [ ] Test: `uast check net/http --ecosystem go` → clean
- [ ] Test: Go process detection picks up `go get`
- [ ] Test: Rust process detection picks up `cargo add`
- [ ] Test: file watcher detects `go.mod` changes

**T-4.5-SECURITY:**
- [ ] Review: Go proxy API responses validated
- [ ] Review: crates.io API responses validated
- [ ] Review: new ecosystem modules follow same security patterns as PyPI/npm

---

#### Sprint 4.6 — Export Formats

**T-4.6.1: SBOM export**
- [ ] CycloneDX 1.5 JSON export from session data
- [ ] SPDX 2.3 JSON export from session data
- [ ] `uast export --format cyclonedx --session <path>` command
- [ ] Include: package name, version, ecosystem, license, hashes

**T-4.6.2: CSV export**
- [ ] `uast export --format csv --session <path>`
- [ ] Columns: package, ecosystem, version, ars_score, verdict, avt_classes, signals

**T-4.6-TEST:**
- [ ] Test: CycloneDX output validates against schema
- [ ] Test: SPDX output validates against schema
- [ ] Test: CSV is parseable and columns correct

---

#### Phase 4 Pentest & Exit Gate

**T-4-PENTEST:**
- [ ] Pentest dashboard for XSS, path traversal, CSRF
- [ ] Pentest API for injection, auth bypass, rate limit bypass
- [ ] Pentest webhook for SSRF, data leakage
- [ ] Pentest CI mode for output injection in PR comments
- [ ] Pentest new ecosystem analyzers with malformed API responses

**T-4-REMEDIATE:**
- [ ] Fix all findings, re-test, verify regression suite passes

```
PHASE 4 EXIT CHECKLIST
- [ ] `uast ci` working with SARIF, JUnit, JSON output
- [ ] GitHub Action functional and documented
- [ ] Webhook alerts working (HTTP, Slack)
- [ ] Dashboard shows sessions and package details
- [ ] REST API with auth and rate limiting
- [ ] Go and Rust ecosystems functional
- [ ] CycloneDX/SPDX export validates
- [ ] Coverage ≥ 84%
- [ ] Pentest complete, all CRITICAL/HIGH resolved
- [ ] README updated with all new features
```

---

## Phase 5: Layer 4 — Agent Reasoning Auditor (v0.6.0)

### PRD-5: Agent Reasoning Auditor

**Objective:** Implement ARA layer — understand WHY the agent chose a specific package, validate that reasoning, and suggest safer alternatives. This is the most novel layer — no other tool does this.

**Target Users:**
- Security teams auditing AI agent decision-making
- Developers who want to understand why their agent chose a particular package
- Compliance teams documenting AI decision provenance

**User Stories:**

| ID | Story | Acceptance Criteria |
|---|---|---|
| US-5.1 | As a user, I want to see why my AI agent chose a specific package | Agent conversation context captured and displayed alongside analysis |
| US-5.2 | As a user, I want UAST to suggest safer alternatives for flagged packages | Top 3 alternatives shown with comparative safety scores |
| US-5.3 | As a security engineer, I want UAST to detect when an agent was manipulated into choosing a package | Agent reasoning validated: does package match task? Were alternatives considered? |
| US-5.4 | As a user, I want UAST to lower its risk score when I explicitly approved a package | Dynamic AAL adjustment based on human oversight observed |

**Technical Requirements:**
- Claude Code: parse `~/.claude/` JSONL logs for conversation context
- Cursor: parse terminal output / log files for package selection reasoning
- Alternative suggestion: query PyPI/npm for related packages by keywords
- Dynamic AAL: track human interaction patterns during session

**Dependencies:** Phase 2 (scoring model needed for alternative ranking), Phase 4 (dashboard for displaying reasoning)

---

### Phase 5 Task List

#### Sprint 5.1 — Agent Context Capture

**T-5.1.1: Claude Code context parser**
- [ ] Create `uast/reasoning/claude_code.py`
- [ ] Parse JSONL log files in `~/.claude/`
- [ ] Extract: conversation turn that led to package install
- [ ] Extract: agent's stated reasoning for package choice
- [ ] Extract: what task the agent was performing
- [ ] Store context in `AnalysisResult.agent_context` field

**T-5.1.2: Cursor context parser**
- [ ] Create `uast/reasoning/cursor.py`
- [ ] Parse Cursor log/terminal files for package selection context
- [ ] Best-effort extraction (Cursor logs less structured than Claude Code)

**T-5.1.3: Generic context interface**
- [ ] Define `AgentContextProvider` protocol
- [ ] Allow future agents to implement context extraction
- [ ] Fallback: no context available → mark as "unknown" (default AAL applies)

**T-5.1-TEST:**
- [ ] Test: Claude Code log with pip install → context extracted
- [ ] Test: Claude Code log without install → no context (no crash)
- [ ] Test: malformed log → graceful handling
- [ ] Test: generic fallback when agent has no context provider

**T-5.1-SECURITY:**
- [ ] Review: log parsing doesn't expose sensitive conversation content in reports
- [ ] Review: context storage is opt-in (privacy consideration)
- [ ] Review: no arbitrary file read via log path manipulation

---

#### Sprint 5.2 — Alternative Package Suggestion

**T-5.2.1: Alternative finder**
- [ ] Create `uast/alternatives.py`
- [ ] For flagged package: extract keywords from name and description
- [ ] Query PyPI/npm search API for related packages
- [ ] Filter: only suggest packages in allowlist or with ARS < 3.0
- [ ] Rank by: safety score + download count + maintenance recency
- [ ] Return top 3 alternatives with comparative scores
- [ ] Add to `AnalysisResult.alternatives` field

**T-5.2.1-TEST:**
- [ ] Test: flagged `reqeusts` → suggests `requests` (typo correction)
- [ ] Test: flagged `crypto-utils-helper` → suggests `cryptography`
- [ ] Test: no alternatives found → empty list (no crash)
- [ ] Test: API failure → graceful fallback

---

#### Sprint 5.3 — Dynamic AAL Adjustment

**T-5.3.1: Interaction tracker**
- [ ] Create `uast/reasoning/aal_tracker.py`
- [ ] Monitor: did human approve the install? (check for confirmation in logs)
- [ ] Monitor: is agent in auto-approve mode? (check agent config)
- [ ] Adjust AAL per-action: human-approved → AAL * 0.5, auto → AAL * 1.2
- [ ] Report per-action AAL in session report

**T-5.3-TEST:**
- [ ] Test: human-approved install → lower AAL → lower ARS
- [ ] Test: auto-mode install → higher AAL → higher ARS
- [ ] Test: no interaction data → default AAL unchanged

**T-5.3-SECURITY:**
- [ ] Review: AAL manipulation can't be spoofed by the agent itself
- [ ] Review: interaction detection doesn't rely on agent-controlled signals

---

#### Phase 5 Exit Gate

```
PHASE 5 EXIT CHECKLIST
- [ ] Claude Code context capture working
- [ ] Alternative suggestions for all flagged packages
- [ ] Dynamic AAL adjusts based on human oversight
- [ ] Agent reasoning displayed in dashboard and reports
- [ ] Coverage ≥ 85%
- [ ] Pentest: agent context can't be used to manipulate UAST decisions
- [ ] README updated
```

---

## Phase 6: Layer 5 — Compliance & Governance (v0.7.0)

### PRD-6: Compliance & Governance

**Objective:** Implement CGI layer — make UAST useful for compliance teams. Provide audit trails, policy enforcement, and ISO 42001 evidence generation.

**Target Users:**
- GRC (Governance, Risk, Compliance) teams
- ISO 42001 auditors
- CISO offices requiring AI governance documentation
- Enterprise security teams with policy enforcement needs

**User Stories:**

| ID | Story | Acceptance Criteria |
|---|---|---|
| US-6.1 | As a compliance officer, I want an immutable audit trail of all UAST actions | Append-only log with cryptographic chaining; tamper detectable |
| US-6.2 | As an ISO 42001 auditor, I want evidence export mapping to control requirements | PDF/JSON report mapping UAST findings to ISO 42001 controls |
| US-6.3 | As a security admin, I want to define policies that UAST enforces automatically | Policy-as-code in TOML; violation → block or alert based on policy |
| US-6.4 | As a team lead, I want shared UAST configuration across my team | Team-level config with override hierarchy |

**Technical Requirements:**
- Audit trail: append-only JSONL with SHA-256 chain
- ISO 42001: mapping document + evidence template generator
- Policy engine: TOML-based rules evaluated against analysis results
- Team config: git-hosted `.uast.toml` with team/org hierarchy

**Dependencies:** Phase 4 (dashboard for displaying audit logs, REST API for team features)

---

### Phase 6 Task List

#### Sprint 6.1 — Audit Trail

**T-6.1.1: Cryptographic audit log**
- [ ] Create `uast/audit.py`
- [ ] Append-only JSONL file: `~/.uast/audit/audit.jsonl`
- [ ] Each entry: `{timestamp, action, data, previous_hash, hash}`
- [ ] Hash: `SHA-256(timestamp || action || data || previous_hash)`
- [ ] Actions: session_start, package_analyzed, alert_fired, block_executed, session_end
- [ ] `uast audit verify` command to verify chain integrity
- [ ] `uast audit export` command to export for SIEM

**T-6.1.1-TEST:**
- [ ] Test: chain integrity verifies after normal session
- [ ] Test: tampering detected (modify one entry, verify fails)
- [ ] Test: export produces valid JSON

**T-6.1.1-SECURITY:**
- [ ] Review: audit file permissions 0o600
- [ ] Review: hash chain can't be replayed
- [ ] Review: audit file rotation doesn't break chain
- [ ] Pentest: can attacker truncate audit log undetected?

---

#### Sprint 6.2 — Policy Engine

**T-6.2.1: Policy definition and evaluation**
- [ ] Create `uast/policy.py`
- [ ] Policy format in `.uast.toml`:
  ```toml
  [[policy]]
  name = "no-new-packages"
  description = "Block packages less than 30 days old"
  condition = "age_days < 30"
  action = "block"
  severity = "high"

  [[policy]]
  name = "require-license"
  description = "All packages must declare a license"
  condition = "license == ''"
  action = "alert"
  severity = "medium"
  ```
- [ ] Evaluate policies against AnalysisResult fields
- [ ] Actions: `block`, `alert`, `warn`, `log`
- [ ] New signal: `POLICY-001` (policy violation) with configurable severity
- [ ] `uast policy check <package>` — evaluate package against all policies

**T-6.2.1-TEST:**
- [ ] Test: package violating policy → blocked/alerted per action
- [ ] Test: package passing all policies → clean
- [ ] Test: multiple policies, one violated → correct policy identified
- [ ] Test: malformed policy → clear error message

**T-6.2.1-SECURITY:**
- [ ] Review: policy conditions can't execute arbitrary code (no eval)
- [ ] Review: policy conditions are a safe DSL (field comparisons only)

---

#### Sprint 6.3 — ISO 42001 Evidence Export

**T-6.3.1: Evidence generator**
- [ ] Map UAST data to ISO 42001 Annex A controls
- [ ] Generate evidence document (JSON and PDF)
- [ ] Include: AI system inventory, risk assessments, incident records
- [ ] `uast compliance export --standard iso42001 --period 30d`

**T-6.3-TEST:**
- [ ] Test: export generates valid document with session data
- [ ] Test: empty period → document with "no findings" sections

---

#### Phase 6 Exit Gate

```
PHASE 6 EXIT CHECKLIST
- [ ] Audit trail with cryptographic chaining
- [ ] Policy engine evaluating TOML-defined rules
- [ ] ISO 42001 evidence export (validated by compliance reviewer)
- [ ] Team configuration hierarchy working
- [ ] Coverage ≥ 86%
- [ ] Pentest: audit trail tamper-proof, policy engine safe
- [ ] README updated
```

---

## Phase 7: Scale & Polish (v1.0.0)

### PRD-7: Production Hardening

**Objective:** Ship v1.0.0. Performance optimization, platform support (Windows, Docker), IDE extensions, MCP server, and enterprise features.

**Target Users:**
- Enterprise security teams deploying at scale
- Windows developers
- IDE users wanting inline UAST warnings
- Claude Code users wanting agent-integrated security

**User Stories:**

| ID | Story | Acceptance Criteria |
|---|---|---|
| US-7.1 | As a user, I want UAST to analyze 100 packages in under 60 seconds | Parallel analysis with thread pool; persistent disk cache |
| US-7.2 | As a Windows developer, I want UAST to work natively without WSL | Process monitoring via WMI/PowerShell; Windows file watcher |
| US-7.3 | As a VS Code user, I want inline warnings when I import a flagged package | VS Code extension with status bar, inline diagnostics, quick-fix |
| US-7.4 | As a Claude Code user, I want my agent to self-check packages before installing | MCP server: `uast_check` tool callable by agent |
| US-7.5 | As an enterprise admin, I want SSO for the dashboard | SAML/OIDC integration; RBAC for dashboard access |

---

### Phase 7 Task List

#### Sprint 7.1 — Performance

**T-7.1.1: Parallel analysis**
- [ ] Thread pool for concurrent package analysis (configurable, default 4)
- [ ] Persistent disk cache (SQLite) for API responses
- [ ] Incremental dependency resolution (only re-resolve changed packages)
- [ ] Benchmark: 100 packages in < 60 seconds

**T-7.1.1-TEST:**
- [ ] Benchmark test: 100 mock packages analyzed in < 60s
- [ ] Test: cache hit rate > 80% on repeated analysis
- [ ] Test: concurrent analysis doesn't cause data races

#### Sprint 7.2 — Platform Support

**T-7.2.1: Windows native**
- [ ] Process monitoring via `psutil` (already cross-platform, test on Windows)
- [ ] File watcher via `watchdog` (already cross-platform, test on Windows)
- [ ] Path handling: use `pathlib` consistently (no hardcoded `/`)
- [ ] Test in Windows CI (GitHub Actions `windows-latest`)

**T-7.2.2: Docker image**
- [ ] Create `Dockerfile` (Python 3.12 slim base)
- [ ] Publish to GitHub Container Registry
- [ ] `docker run ghcr.io/mjjjjaazing/uast check <package>`

**T-7.2.3: Distribution**
- [ ] Homebrew formula: `brew install uast`
- [ ] Conda package

#### Sprint 7.3 — IDE Extensions

**T-7.3.1: VS Code extension**
- [ ] Status bar: UAST monitoring active/inactive
- [ ] Inline diagnostics: warning squiggle on flagged `import`/`require`
- [ ] Quick-fix: "Replace with safe alternative"
- [ ] Settings: threshold, agent, enable/disable

#### Sprint 7.4 — MCP Server

**T-7.4.1: UAST MCP server**
- [ ] Create `uast/mcp_server.py`
- [ ] Tool: `uast_check` — agent calls before `pip install`
- [ ] Tool: `uast_status` — agent queries current session status
- [ ] Register as MCP server for Claude Code
- [ ] Document MCP setup in README

**T-7.4-SECURITY:**
- [ ] Review: MCP server can't be used to bypass UAST blocking
- [ ] Review: agent can't modify UAST config via MCP
- [ ] Review: MCP responses don't leak sensitive analysis data

#### Sprint 7.5 — Enterprise Features

**T-7.5.1: SSO integration**
- [ ] SAML provider integration for dashboard
- [ ] OIDC provider integration
- [ ] Role-based access: admin, viewer, analyst

**T-7.5.2: Air-gapped mode**
- [ ] Bundle threat intel DB locally
- [ ] Offline analysis without API calls
- [ ] `uast update-db` for periodic refresh

---

#### Phase 7 Exit Gate

```
PHASE 7 / v1.0.0 EXIT CHECKLIST

COMPLETENESS
- [ ] All 5 paper layers implemented (SSA, BDA, PCV, ARA, CGI)
- [ ] 22/22 AVT classes detectable
- [ ] 4+ ecosystems (PyPI, npm, Go, Rust)
- [ ] 5+ agents + CI mode + IDE extensions

QUALITY
- [ ] Test coverage ≥ 90%
- [ ] False positive rate < 5% (measured on labeled dataset)
- [ ] Detection rate > 90% on known malware dataset
- [ ] Average analysis time < 1s per package

SECURITY
- [ ] Comprehensive pentest by external firm (or thorough self-pentest)
- [ ] All CRITICAL/HIGH findings resolved
- [ ] Security advisory process documented and tested
- [ ] bandit + pip-audit clean

PLATFORM
- [ ] Works on macOS, Linux, Windows
- [ ] Docker image published
- [ ] Homebrew formula published
- [ ] PyPI package published with Sigstore attestation

DOCUMENTATION
- [ ] Complete README with all features
- [ ] Architecture documentation
- [ ] API documentation (OpenAPI spec)
- [ ] Compliance mapping guide
- [ ] Troubleshooting guide
- [ ] Migration guide from v0.x

RELEASE
- [ ] Git tag v1.0.0
- [ ] GitHub Release with changelog
- [ ] PyPI publish
- [ ] Announcement blog post
```

---

## Detailed Gap Inventory (Current v0.1.0)

### Hardcoded Values Requiring Configuration

| Value | Location | Current | Config Key |
|---|---|---|---|
| Alert threshold | main.py:89 | 6.0 | `threshold` |
| Age: critical days | analyzer.py:668 | 7 | `age_thresholds.critical_days` |
| Age: warning days | analyzer.py:682 | 30 | `age_thresholds.warning_days` |
| Age: notice days | analyzer.py:696 | 90 | `age_thresholds.notice_days` |
| Similarity: critical | analyzer.py:780 | 0.85 | `similarity.critical` |
| Similarity: high | analyzer.py:793 | 0.70 | `similarity.high` |
| Similarity: suggest | analyzer.py:628 | 0.60 | `similarity.suggest` |
| Velocity anomaly | analyzer.py:662 | 10000 | `velocity.anomaly_downloads` |
| Velocity age window | analyzer.py:662 | 30 | `velocity.age_window_days` |
| Max tree depth | resolver.py:61 | 5 | `resolver.max_depth` |
| Max tree packages | resolver.py:62 | 200 | `resolver.max_packages` |
| Dep count: high | analyzer.py:936 | 50 | `dependencies.high_count` |
| Dep count: elevated | analyzer.py:950 | 25 | `dependencies.elevated_count` |
| Tree depth flag | analyzer.py:962 | 4 | `dependencies.deep_chain` |
| ARSM alpha | analyzer.py:142 | 0.30 | `arsm.alpha` |
| ARSM beta | analyzer.py:143 | 0.25 | `arsm.beta` |
| ARSM gamma | analyzer.py:144 | 0.25 | `arsm.gamma` |
| ARSM delta | analyzer.py:145 | 0.20 | `arsm.delta` |
| HTTP timeout | http_client.py:25 | 8 | `http.timeout` |
| Cache TTL | http_client.py:26 | 300 | `http.cache_ttl` |
| Max concurrent | http_client.py:27 | 5 | `http.max_concurrent` |
| Process poll interval | watcher.py:293 | 1.0 | `watcher.poll_interval` |
| PYPI_SAFE allowlist | analyzer.py:89-99 | ~60 pkgs | `allowlist.pypi` (file) |
| NPM_SAFE allowlist | analyzer.py:101-109 | ~50 pkgs | `allowlist.npm` (file) |

### Security Issues in Current Code

| Issue | Location | Severity | Fix |
|---|---|---|---|
| Session reports world-readable | reporter.py:100 | Medium | Set 0o600 permissions |
| No User-Agent header | http_client.py:54 | Low | Add `UAST/{version}` header |
| Broad exception swallowing | resolver.py:129, analyzer.py:988 | Medium | Specific exceptions + logging |
| Repo URL check returns True on error | analyzer.py:919 | Medium | Return False or "unknown" |
| No proxy support | http_client.py | Low | Respect `HTTP_PROXY` env vars |
| Process kill by name match | watcher.py:552 | High | Match by PID, not name substring |
| Unvalidated external JSON | analyzer.py:236 | Medium | Schema validation |
| Package name in shell command | payload.py:272-276 | Medium | Sanitize before subprocess |
| Cache unbounded growth | http_client.py:59 | Low | LRU eviction at 1000 entries |
| Git hook injection via package name | watcher.py:94 | Low | Sanitize package names in hook |

### Test Coverage Gaps

| Module | Current | Target | Missing |
|---|---|---|---|
| analyzer.py | 52% | 90% | Live API paths, all signal combinations, edge cases |
| watcher.py | 0% | 80% | All process/file detection, blocking, rollback |
| display.py | 0% | 70% | All output methods, edge cases |
| reporter.py | 0% | 90% | Schema validation, roundtrip, summaries |
| main.py | 0% | 80% | CLI parsing, all subcommands |
| http_client.py | 55% | 90% | Cache expiry, concurrency, error paths |
| payload.py | 62% | 85% | Download/extract flows, edge cases |
| resolver.py | 94% | 95% | Keep high, add network error tests |
| **TOTAL** | **36%** | **85%** | |

### Paper vs. Implementation Gap

| Paper Layer | Name | Status | Phase |
|---|---|---|---|
| Layer 1 | Static Semantic Analysis (SSA) | Partial | Phase 2 |
| Layer 2 | Behavioral Dynamic Analysis (BDA) | Partial | Phase 2 |
| Layer 3 | Provenance Chain Verification (PCV) | Minimal | Phase 3 |
| Layer 4 | Agent Reasoning Auditor (ARA) | Not started | Phase 5 |
| Layer 5 | Compliance & Governance (CGI) | Not started | Phase 6 |

| AVT Dimension | Classes in Paper | Detected | Phase |
|---|---|---|---|
| D1: Context Manipulation | 4 | 1 | Phase 2 |
| D2: Permission & Scope | 3 | 0 | Phase 2 |
| D3: Supply Chain | 5 | 4 | Phase 2 |
| D4: Trust & Identity | 4 | 0 | Phase 2 |
| D5: Systemic & Emergent | 6 | 0 | Phase 2+3 |
| **Total** | **22** | **5** | |

---

## Success Metrics

| Metric | v0.2 | v0.3 | v0.5 | v1.0 |
|---|---|---|---|---|
| Test coverage | 80% | 82% | 85% | 90% |
| AVT classes detected | 5 | 12 | 15 | 22 |
| Ecosystems | 2 | 2 | 4 | 6 |
| Agents supported | 5 | 5 | 5+CI | 5+CI+IDE |
| False positive rate | Unknown | < 10% | < 7% | < 5% |
| Detection rate | Unknown | > 70% | > 80% | > 90% |
| Avg analysis time | ~3s | ~2s | ~1.5s | < 1s |
| Open security findings | 10 | 0 HIGH+ | 0 HIGH+ | 0 MED+ |

---

## Process & Workflow

### For Each Task

```
1. Read task description and acceptance criteria
2. Branch from main: feat/<task-id>-<short-name>
3. Implement with tests (TDD preferred)
4. Run quality gates (see checklist above)
5. Self-review against security checklist
6. Update README if user-facing
7. Update CHANGELOG.md
8. PR with description + quality gate evidence
9. Code review (security-focused for security-tagged tasks)
10. Merge to main
11. If pentest/security review finds issues → enter Remediation Protocol
```

### Release Cadence

- **Patch releases** (0.x.y): bug fixes, security patches — as needed
- **Minor releases** (0.x.0): phase milestones — every 4-6 weeks
- **Major release** (1.0.0): all 5 layers, enterprise-ready

---

*This roadmap is a living document. Update it as phases complete and priorities shift.*
