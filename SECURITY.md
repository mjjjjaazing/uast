# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Reporting a vulnerability

If you discover a security vulnerability in UAST, please report it responsibly.

**Do NOT open a public GitHub issue.**

Instead, email: **michel@michelhjazeen.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

## Response SLA

| Severity | Acknowledge | Fix |
|----------|-------------|-----|
| Critical | 24 hours    | 7 days |
| High     | 48 hours    | 14 days |
| Medium   | 1 week      | 30 days |
| Low      | 2 weeks     | Next release |

## Security measures in UAST

UAST implements the following security controls:

- **Input sanitization**: All package names validated against `[a-zA-Z0-9._@/-]` before processing
- **SSRF prevention**: HTTP client rejects non-http(s) URL schemes
- **Log injection prevention**: All log messages sanitized (newlines, carriage returns, null bytes stripped)
- **File permissions**: Session reports and log files created with `0o600` (user-only read/write)
- **Process isolation**: Blocking mode only kills PIDs that UAST explicitly tracked
- **No shell execution**: All subprocess calls use list args (no `shell=True`)
- **Path traversal protection**: Archive extraction rejects absolute paths and `..` components
- **Cache bounds**: HTTP response cache limited to 1000 entries with LRU eviction
- **Dependency auditing**: CI pipeline runs `pip-audit` and `bandit` on every PR

## Scope

The following are in-scope for security reports:

- Command injection via package names or config values
- Path traversal in file operations
- SSRF via HTTP client
- Log injection / log forging
- Denial of service (memory exhaustion, CPU spin)
- Privilege escalation in blocking mode
- Information disclosure in session reports

The following are out-of-scope:

- Attacks requiring local filesystem access (UAST is a local tool)
- Social engineering
- Denial of service via network flooding (not a server)
