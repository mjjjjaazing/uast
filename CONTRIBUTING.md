# Contributing to UAST

Thank you for your interest in contributing to UAST. This guide covers everything you need to get started.

## Development setup

```bash
# Clone the repository
git clone https://github.com/mjjjjaazing/uast
cd uast

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks (optional but recommended)
pip install pre-commit
pre-commit install
```

## Running tests

```bash
# Run all tests with coverage
pytest

# Run a specific test file
pytest tests/test_analyzer_integration.py

# Run tests matching a pattern
pytest -k "test_hallucinated"

# Run with verbose output
pytest -v --tb=long
```

### Coverage requirements

All PRs must maintain **80%+ test coverage**. The CI pipeline will reject PRs that drop below this threshold.

```bash
# Check coverage locally
pytest --cov-fail-under=80
```

### Writing tests

- Place tests in `tests/test_<module>.py`
- Use `unittest.mock` for external dependencies (HTTP calls, subprocess, filesystem)
- Integration tests that hit real APIs should be clearly marked and skippable
- Security tests go in `tests/test_security.py`

## Code style

UAST uses [ruff](https://github.com/astral-sh/ruff) for linting and formatting.

```bash
# Lint
ruff check uast/

# Auto-fix
ruff check --fix uast/

# Format
ruff format uast/
```

Configuration is in `pyproject.toml`:
- Line length: 100 characters
- Target: Python 3.9+

## PR process

1. **Open an issue first** for large changes or new features
2. Create a branch: `git checkout -b feat/my-feature` or `fix/bug-description`
3. Make your changes with tests
4. Ensure all tests pass: `pytest`
5. Ensure linting passes: `ruff check uast/`
6. Submit a PR against `main`

### Branch naming

- `feat/` — new features
- `fix/` — bug fixes
- `docs/` — documentation changes
- `refactor/` — code restructuring
- `test/` — test additions/changes
- `ci/` — CI/CD changes

### Commit messages

Use conventional commit format:

```
feat: add npm ecosystem support for payload analysis
fix: handle missing 'time' field in npm registry response
docs: update ARSM formula documentation
test: add integration tests for hallucinated package detection
```

## Architecture overview

```
uast/
  analyzer.py     — Core detection engine + ARSM scoring
  config.py       — TOML configuration system
  display.py      — Rich terminal output
  http_client.py  — Cached HTTP client with retry
  logging.py      — Structured logging setup
  main.py         — Click CLI entry points
  payload.py      — Static AST analysis of package source
  reporter.py     — JSON session report writer
  resolver.py     — Transitive dependency graph resolution
  watcher.py      — Process + file watchers (dual interception)
```

### Key data flow

1. **Watcher** detects a package install (process or file change)
2. **Analyzer** fetches registry metadata and runs signal checks
3. **ARSM engine** computes the Agentic Risk Score
4. **Display** shows the result in the terminal
5. **Reporter** saves the result to the session JSON report

## Security issues

Please report security vulnerabilities via the process described in [SECURITY.md](SECURITY.md). Do **not** open public GitHub issues for security bugs.

## Areas where contributions are especially welcome

- Expanding the allowlist (`PYPI_SAFE` / `NPM_SAFE` in `analyzer.py`)
- Additional name squatting patterns
- npm ecosystem improvements (more signal checks)
- Windows native support (no WSL)
- Performance profiling and optimization
- Documentation improvements
