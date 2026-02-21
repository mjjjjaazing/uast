# Changelog

All notable changes to UAST will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
