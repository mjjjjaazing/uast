# Changelog

All notable changes to UAST will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

### Added
- **AVT D1 detectors**: Prompt injection detection (INJECT-001) with 17 regex patterns scanning package descriptions and code comments (standalone + inline). Context poisoning detection (POISON-001) for `os.putenv`, `os.environ` modification, `sys.path` manipulation (insert/append/extend/assign/slice).
- **AVT D2 detectors**: Privilege escalation detection (PRIV-001) for `os.setuid/setgid/chown`, `os.chmod` with world-writable modes, `sudo` in subprocess/os.system calls. Scope creep detection (SCOPE-001) for imports of `socket`, `smtplib`, `ftplib`, `ctypes`, `mmap`, and other sensitive modules.
- **AVT D4 detectors**: Maintainer trust analysis (MAINTAINER-001) checking for disposable email domains (30+ providers), missing author identity. Metadata spoofing detection (SPOOF-001) flagging descriptions that reference a different popular package.
- **Dynamic CIS scoring**: Context Integrity Score now computed from detected signals — INJECT lowers by 0.5, POISON by 0.3, SPOOF by 0.2, HALLUC by 0.8. Previously hardcoded to 1.0.
- **Scoring confidence levels**: Each analysis result now includes `confidence` field (high/medium/low) based on signal coverage and data availability.
- **Release pattern analysis**: RELEASE-001 (single-version packages) and RELEASE-002 (rapid-fire releases: >2/day over <7 days).
- `AVT-D1-01`, `AVT-D2-01`, `AVT-D2-02`, `AVT-D4-01` classes in `_compute_verdict`
- 424 tests (up from 322), 87% coverage (up from 85%)

### Changed
- ARSM signal weights rebalanced from 7 to 9 categories (added trust=0.08, spoofing=0.06)
- `_compute_verdict` is now sole authority for AVT class assignment
- `_check_prompt_injection` normalizes `None` descriptions to empty string
- Injection pattern for "this package is safe" tightened with negative lookahead to reduce false positives

### Fixed
- `_compute_verdict` no longer overwrites AVT classes set earlier in analysis pipeline
- Inline code comments (e.g., `import os  # ignore instructions`) now scanned for injection
- `sys.path = [...]` and `sys.path[:] = [...]` direct assignment now detected as POISON-001

## [0.2.0] - Unreleased

### Added
- **Configuration system**: TOML-based config with 3-level precedence (CLI > project `.uast.toml` > user `~/.uast/config.toml` > defaults)
- **Structured logging**: Rotating file handler at `~/.uast/logs/uast.log` with log injection prevention
- **HTTP retry**: Exponential backoff (1s/2s/4s) on transient errors (429, 500-504, ConnectionError, Timeout)
- **Input sanitization**: Package name validation rejecting shell metacharacters, control characters, and oversized names
- **URL validation**: SSRF prevention — only http/https schemes allowed in HTTP client
- **User-Agent header**: All HTTP requests now send `UAST/0.1.0`
- **Cache size limits**: LRU eviction at 1000 entries prevents unbounded memory growth
- **File permission hardening**: Session reports and log files created with `0o600` (user-only)
- **Process blocking hardening**: `_attempt_block()` now only kills PIDs that UAST tracked, not arbitrary name matches
- **Git hook hardening**: Package name validation in pre-commit hook script
- **CI/CD pipeline**: GitHub Actions with Python 3.9-3.13 matrix, coverage gate (80%), bandit security scan, pip-audit
- **Pre-commit hooks**: ruff lint/format, bandit, trailing whitespace, TOML validation
- **PyPI publishing workflow**: Trusted publisher (OIDC) on GitHub release
- `show-config` CLI command to display resolved configuration
- `--log-level` and `--quiet` CLI flags
- 322 tests (up from ~50), 85% coverage (up from 36%)

### Changed
- Replaced 7 broad `except Exception:` handlers with specific exception types
- ARSM coefficients, age thresholds, similarity thresholds now configurable via TOML
- `_seen_pids` changed from `set[int]` to `dict[int, str]` for PID-to-package tracking

### Fixed
- `tree.dependency_tree` AttributeError — corrected to `tree.nodes`
- Test that used generic `Exception("timeout")` now uses `requests.ConnectionError`

### Security
- Package names validated against `[a-zA-Z0-9._@/-]` pattern before any processing
- HTTP client rejects `file://`, `ftp://`, `javascript:` and other non-http(s) schemes
- Log messages sanitized to prevent log injection (newlines, carriage returns, null bytes stripped)
- Config values with shell metacharacters rejected during validation

## [0.1.0] - 2025-02-18

### Added
- Initial release: supply chain detector MVP
- Process watcher (psutil) — monitors system-wide for pip/npm install subprocesses
- File watcher (watchdog) — monitors requirements.txt, package.json, pyproject.toml
- Supply chain analyzer with ARSM scoring engine
- Hallucinated package detection (registry 404 + "did you mean?" suggestions)
- Name squatting / typosquatting detection via string similarity
- Download velocity anomaly detection (PyPI Stats + npm downloads API)
- Transitive dependency graph resolution with cycle detection
- Static AST payload analysis (`--deep` mode)
- Repository URL verification
- Agent-specific interception (Claude Code log watcher, Copilot git pre-commit hook)
- Blocking mode with rollback fallback (`--block`)
- Terminal output via Rich + JSON session reports (schema v2)
- Support for Claude Code, Cursor, Copilot, Windsurf, Codeium agents
