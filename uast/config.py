"""
Configuration system for UAST.

Loads settings from three sources with this precedence:
  1. CLI flags (highest — override everything)
  2. Project config (.uast.toml in project root)
  3. User config (~/.uast/config.toml)
  4. Built-in defaults (lowest)

Uses tomllib (3.11+) or tomli (3.9/3.10 fallback) for TOML parsing.
"""

from __future__ import annotations

import copy
import logging
import re
from pathlib import Path
from typing import Any, Optional

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

logger = logging.getLogger("uast.config")

# ---------------------------------------------------------------------------
# Package name validation
# ---------------------------------------------------------------------------

_VALID_PACKAGE_NAME = re.compile(r"^[a-zA-Z0-9._\-@/]+$")


def _is_valid_package_name(name: str) -> bool:
    """Check if a package name contains only safe characters."""
    return bool(_VALID_PACKAGE_NAME.match(name)) and len(name) <= 200


# ---------------------------------------------------------------------------
# Default configuration — single source of truth for all thresholds
# ---------------------------------------------------------------------------

DEFAULT_CONFIG: dict[str, Any] = {
    # Alert threshold
    "threshold": 6.0,

    # Package age thresholds (days)
    "age_thresholds": {
        "critical_days": 7,
        "warning_days": 30,
        "notice_days": 90,
    },

    # Name similarity thresholds (0.0–1.0)
    "similarity": {
        "critical": 0.85,
        "high": 0.70,
        "suggest": 0.60,
    },

    # Download velocity anomaly detection
    "velocity": {
        "anomaly_downloads": 10000,
        "age_window_days": 30,
    },

    # Dependency tree resolution limits
    "resolver": {
        "max_depth": 5,
        "max_packages": 200,
    },

    # Dependency count signal thresholds
    "dependencies": {
        "high_count": 50,
        "elevated_count": 25,
        "deep_chain": 4,
    },

    # ARSM scoring coefficients
    "arsm": {
        "alpha": 0.30,
        "beta": 0.25,
        "gamma": 0.25,
        "delta": 0.20,
    },

    # Agent Autonomy Levels
    "agent_aal": {
        "copilot": 0.5,
        "cursor": 0.7,
        "claude-code": 0.8,
        "windsurf": 0.7,
        "codeium": 0.5,
        "auto": 0.6,
    },

    # HTTP client settings
    "http": {
        "timeout": 8,
        "cache_ttl": 300,
        "max_concurrent": 5,
    },

    # Watcher settings
    "watcher": {
        "poll_interval": 1.0,
    },

    # Custom allowlists (user additions — merged with built-in)
    "allowlist": {
        "pypi": [],
        "npm": [],
    },

    # Custom blocklists (always flagged as critical)
    "blocklist": {
        "pypi": [],
        "npm": [],
    },
}


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _deep_merge(base: dict, override: dict) -> dict:
    """
    Recursively merge override into base. Override values win.
    Lists are replaced, not appended. Returns a new dict.
    """
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _load_toml_file(path: Path) -> dict[str, Any]:
    """Load and parse a TOML file. Returns empty dict on any failure."""
    if tomllib is None:
        logger.debug("TOML parser not available (install tomli for Python <3.11)")
        return {}

    if not path.is_file():
        logger.debug("Config file not found: %s", path)
        return {}

    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
        logger.info("Loaded config from %s", path)
        return data
    except Exception as e:
        logger.warning("Failed to parse config file %s: %s", path, e)
        return {}


def _validate_config(config: dict[str, Any]) -> list[str]:
    """
    Validate config values. Returns list of warning messages for invalid
    values (which are silently replaced with defaults).
    """
    warnings: list[str] = []

    # threshold must be 0.0–10.0
    if "threshold" in config:
        t = config["threshold"]
        if not isinstance(t, (int, float)) or t < 0.0 or t > 10.0:
            warnings.append(f"threshold must be 0.0–10.0, got {t!r}")
            del config["threshold"]

    # age_thresholds must be positive integers
    if "age_thresholds" in config:
        for key in ("critical_days", "warning_days", "notice_days"):
            val = config["age_thresholds"].get(key)
            if val is not None and (not isinstance(val, int) or val < 0):
                warnings.append(f"age_thresholds.{key} must be non-negative int, got {val!r}")
                del config["age_thresholds"][key]

    # similarity must be 0.0–1.0
    if "similarity" in config:
        for key in ("critical", "high", "suggest"):
            val = config["similarity"].get(key)
            if val is not None and (not isinstance(val, (int, float)) or val < 0.0 or val > 1.0):
                warnings.append(f"similarity.{key} must be 0.0–1.0, got {val!r}")
                del config["similarity"][key]

    # arsm coefficients must be 0.0–1.0
    if "arsm" in config:
        for key in ("alpha", "beta", "gamma", "delta"):
            val = config["arsm"].get(key)
            if val is not None and (not isinstance(val, (int, float)) or val < 0.0 or val > 1.0):
                warnings.append(f"arsm.{key} must be 0.0–1.0, got {val!r}")
                del config["arsm"][key]

    # allowlist/blocklist: validate package names
    for section in ("allowlist", "blocklist"):
        if section in config:
            for ecosystem in ("pypi", "npm"):
                items = config[section].get(ecosystem)
                if items is not None:
                    if not isinstance(items, list):
                        warnings.append(f"{section}.{ecosystem} must be a list")
                        config[section][ecosystem] = []
                    else:
                        cleaned = []
                        for name in items:
                            if isinstance(name, str) and _is_valid_package_name(name):
                                cleaned.append(name)
                            else:
                                warnings.append(
                                    f"{section}.{ecosystem}: invalid package name {name!r}"
                                )
                        config[section][ecosystem] = cleaned

    # http settings
    if "http" in config:
        for key, limits in [("timeout", (1, 120)), ("cache_ttl", (0, 3600)), ("max_concurrent", (1, 50))]:
            val = config["http"].get(key)
            if val is not None and (not isinstance(val, (int, float)) or val < limits[0] or val > limits[1]):
                warnings.append(f"http.{key} must be {limits[0]}–{limits[1]}, got {val!r}")
                del config["http"][key]

    return warnings


def load_config(
    project_path: Optional[Path] = None,
    cli_overrides: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Load configuration with precedence:
      CLI overrides > project .uast.toml > user ~/.uast/config.toml > defaults

    Args:
        project_path: Path to project directory (for .uast.toml lookup).
        cli_overrides: Dict of values from CLI flags (only non-None flags).

    Returns:
        Fully resolved config dict.
    """
    # Start with defaults
    config = copy.deepcopy(DEFAULT_CONFIG)

    # Layer 1: user-level config
    user_config_path = Path.home() / ".uast" / "config.toml"
    user_config = _load_toml_file(user_config_path)
    if user_config:
        user_warnings = _validate_config(user_config)
        for w in user_warnings:
            logger.warning("User config: %s", w)
        config = _deep_merge(config, user_config)

    # Layer 2: project-level config
    if project_path is not None:
        project_config_path = Path(project_path) / ".uast.toml"
        project_config = _load_toml_file(project_config_path)
        if project_config:
            project_warnings = _validate_config(project_config)
            for w in project_warnings:
                logger.warning("Project config: %s", w)
            config = _deep_merge(config, project_config)

    # Layer 3: CLI overrides (highest precedence)
    if cli_overrides:
        cli_warnings = _validate_config(cli_overrides)
        for w in cli_warnings:
            logger.warning("CLI override: %s", w)
        config = _deep_merge(config, cli_overrides)

    return config


# ---------------------------------------------------------------------------
# Config accessors — typed convenience functions
# ---------------------------------------------------------------------------

def get_threshold(config: dict[str, Any]) -> float:
    return float(config.get("threshold", DEFAULT_CONFIG["threshold"]))


def get_age_thresholds(config: dict[str, Any]) -> dict[str, int]:
    return config.get("age_thresholds", DEFAULT_CONFIG["age_thresholds"])


def get_similarity_thresholds(config: dict[str, Any]) -> dict[str, float]:
    return config.get("similarity", DEFAULT_CONFIG["similarity"])


def get_velocity_config(config: dict[str, Any]) -> dict[str, int]:
    return config.get("velocity", DEFAULT_CONFIG["velocity"])


def get_resolver_config(config: dict[str, Any]) -> dict[str, int]:
    return config.get("resolver", DEFAULT_CONFIG["resolver"])


def get_dependency_config(config: dict[str, Any]) -> dict[str, int]:
    return config.get("dependencies", DEFAULT_CONFIG["dependencies"])


def get_arsm_coefficients(config: dict[str, Any]) -> dict[str, float]:
    return config.get("arsm", DEFAULT_CONFIG["arsm"])


def get_agent_aal(config: dict[str, Any], agent: str) -> float:
    aal_map = config.get("agent_aal", DEFAULT_CONFIG["agent_aal"])
    return float(aal_map.get(agent, aal_map.get("auto", 0.6)))


def get_http_config(config: dict[str, Any]) -> dict[str, int]:
    return config.get("http", DEFAULT_CONFIG["http"])


def get_watcher_config(config: dict[str, Any]) -> dict[str, float]:
    return config.get("watcher", DEFAULT_CONFIG["watcher"])


def get_allowlist(config: dict[str, Any], ecosystem: str) -> set[str]:
    """Get custom allowlist for an ecosystem (user additions only)."""
    items = config.get("allowlist", {}).get(ecosystem, [])
    return {name.lower() for name in items}


def get_blocklist(config: dict[str, Any], ecosystem: str) -> set[str]:
    """Get blocklist for an ecosystem."""
    items = config.get("blocklist", {}).get(ecosystem, [])
    return {name.lower() for name in items}
