"""
Tests for the uast configuration system.

Covers:
  - Default config loading
  - TOML file parsing and merging
  - Config validation (bounds, types, bad values)
  - Config accessors (typed getters)
  - Deep merge behaviour
  - Allowlist / blocklist package name validation
  - CLI override precedence
"""

import copy
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from uast.config import (
    DEFAULT_CONFIG,
    _deep_merge,
    _is_valid_package_name,
    _validate_config,
    load_config,
    get_threshold,
    get_age_thresholds,
    get_similarity_thresholds,
    get_velocity_config,
    get_resolver_config,
    get_dependency_config,
    get_arsm_coefficients,
    get_agent_aal,
    get_http_config,
    get_watcher_config,
    get_allowlist,
    get_blocklist,
)


# ---------------------------------------------------------------------------
# Default config sanity checks
# ---------------------------------------------------------------------------

class TestDefaultConfig:

    def test_default_config_has_required_keys(self):
        required = [
            "threshold", "age_thresholds", "similarity", "velocity",
            "resolver", "dependencies", "arsm", "agent_aal", "http",
            "watcher", "allowlist", "blocklist",
        ]
        for key in required:
            assert key in DEFAULT_CONFIG, f"Missing default config key: {key}"

    def test_default_threshold_in_range(self):
        assert 0.0 <= DEFAULT_CONFIG["threshold"] <= 10.0

    def test_default_arsm_coefficients_sum(self):
        arsm = DEFAULT_CONFIG["arsm"]
        total = arsm["alpha"] + arsm["beta"] + arsm["gamma"] + arsm["delta"]
        assert abs(total - 1.0) < 0.01

    def test_default_allowlists_are_empty(self):
        assert DEFAULT_CONFIG["allowlist"]["pypi"] == []
        assert DEFAULT_CONFIG["allowlist"]["npm"] == []

    def test_default_blocklists_are_empty(self):
        assert DEFAULT_CONFIG["blocklist"]["pypi"] == []
        assert DEFAULT_CONFIG["blocklist"]["npm"] == []


# ---------------------------------------------------------------------------
# Package name validation
# ---------------------------------------------------------------------------

class TestPackageNameValidation:

    def test_valid_pypi_name(self):
        assert _is_valid_package_name("requests") is True

    def test_valid_npm_scoped_name(self):
        assert _is_valid_package_name("@types/node") is True

    def test_valid_hyphenated_name(self):
        assert _is_valid_package_name("my-package-name") is True

    def test_valid_dotted_name(self):
        assert _is_valid_package_name("zope.interface") is True

    def test_rejects_empty_string(self):
        assert _is_valid_package_name("") is False

    def test_rejects_spaces(self):
        assert _is_valid_package_name("my package") is False

    def test_rejects_shell_injection(self):
        assert _is_valid_package_name("pkg; rm -rf /") is False

    def test_rejects_backtick_injection(self):
        assert _is_valid_package_name("`whoami`") is False

    def test_rejects_very_long_name(self):
        assert _is_valid_package_name("a" * 201) is False

    def test_accepts_max_length_name(self):
        assert _is_valid_package_name("a" * 200) is True


# ---------------------------------------------------------------------------
# Deep merge
# ---------------------------------------------------------------------------

class TestDeepMerge:

    def test_simple_override(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 3}

    def test_nested_override(self):
        base = {"http": {"timeout": 8, "cache_ttl": 300}}
        override = {"http": {"timeout": 15}}
        result = _deep_merge(base, override)
        assert result["http"]["timeout"] == 15
        assert result["http"]["cache_ttl"] == 300  # preserved

    def test_does_not_mutate_base(self):
        base = {"a": {"x": 1}}
        override = {"a": {"x": 2}}
        _deep_merge(base, override)
        assert base["a"]["x"] == 1

    def test_adds_new_keys(self):
        base = {"a": 1}
        override = {"b": 2}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 2}

    def test_list_replacement_not_append(self):
        base = {"allowlist": {"pypi": ["requests"]}}
        override = {"allowlist": {"pypi": ["flask"]}}
        result = _deep_merge(base, override)
        assert result["allowlist"]["pypi"] == ["flask"]


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

class TestConfigValidation:

    def test_valid_config_no_warnings(self):
        config = copy.deepcopy(DEFAULT_CONFIG)
        warnings = _validate_config(config)
        assert warnings == []

    def test_invalid_threshold_removed(self):
        config = {"threshold": 15.0}
        warnings = _validate_config(config)
        assert len(warnings) == 1
        assert "threshold" in warnings[0]
        assert "threshold" not in config

    def test_negative_threshold_removed(self):
        config = {"threshold": -1.0}
        warnings = _validate_config(config)
        assert len(warnings) == 1
        assert "threshold" not in config

    def test_string_threshold_removed(self):
        config = {"threshold": "high"}
        warnings = _validate_config(config)
        assert len(warnings) == 1
        assert "threshold" not in config

    def test_valid_threshold_kept(self):
        config = {"threshold": 7.5}
        warnings = _validate_config(config)
        assert warnings == []
        assert config["threshold"] == 7.5

    def test_negative_age_removed(self):
        config = {"age_thresholds": {"critical_days": -5}}
        warnings = _validate_config(config)
        assert len(warnings) == 1
        assert "critical_days" not in config["age_thresholds"]

    def test_float_age_removed(self):
        config = {"age_thresholds": {"critical_days": 7.5}}
        warnings = _validate_config(config)
        assert len(warnings) == 1

    def test_invalid_similarity_removed(self):
        config = {"similarity": {"critical": 1.5}}
        warnings = _validate_config(config)
        assert len(warnings) == 1
        assert "critical" not in config["similarity"]

    def test_invalid_arsm_coefficient_removed(self):
        config = {"arsm": {"alpha": -0.5}}
        warnings = _validate_config(config)
        assert len(warnings) == 1
        assert "alpha" not in config["arsm"]

    def test_invalid_http_timeout_removed(self):
        config = {"http": {"timeout": 999}}
        warnings = _validate_config(config)
        assert len(warnings) == 1
        assert "timeout" not in config["http"]

    def test_blocklist_shell_injection_rejected(self):
        config = {"blocklist": {"pypi": ["pkg; rm -rf /"]}}
        warnings = _validate_config(config)
        assert len(warnings) == 1
        assert config["blocklist"]["pypi"] == []

    def test_blocklist_valid_names_kept(self):
        config = {"blocklist": {"pypi": ["malicious-pkg", "bad-lib"]}}
        warnings = _validate_config(config)
        assert warnings == []
        assert config["blocklist"]["pypi"] == ["malicious-pkg", "bad-lib"]

    def test_allowlist_non_list_replaced(self):
        config = {"allowlist": {"pypi": "not-a-list"}}
        warnings = _validate_config(config)
        assert len(warnings) == 1
        assert config["allowlist"]["pypi"] == []


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

class TestLoadConfig:

    def test_returns_defaults_when_no_files(self):
        config = load_config(project_path=Path("/nonexistent"))
        assert config["threshold"] == DEFAULT_CONFIG["threshold"]
        assert config["arsm"] == DEFAULT_CONFIG["arsm"]

    def test_cli_overrides_win(self):
        config = load_config(
            project_path=Path("/nonexistent"),
            cli_overrides={"threshold": 8.0},
        )
        assert config["threshold"] == 8.0

    def test_cli_invalid_override_ignored(self):
        config = load_config(
            project_path=Path("/nonexistent"),
            cli_overrides={"threshold": 99.0},
        )
        # Invalid threshold gets removed, falls back to default
        assert config["threshold"] == DEFAULT_CONFIG["threshold"]

    @patch("uast.config._load_toml_file")
    def test_user_config_merged(self, mock_load):
        # First call = user config, second call = project config (not found)
        mock_load.side_effect = [
            {"threshold": 7.0},  # user config
            {},  # project config
        ]
        config = load_config(project_path=Path("/some/project"))
        assert config["threshold"] == 7.0

    @patch("uast.config._load_toml_file")
    def test_project_overrides_user(self, mock_load):
        mock_load.side_effect = [
            {"threshold": 7.0},  # user config
            {"threshold": 5.0},  # project config
        ]
        config = load_config(project_path=Path("/some/project"))
        assert config["threshold"] == 5.0

    @patch("uast.config._load_toml_file")
    def test_cli_overrides_project(self, mock_load):
        mock_load.side_effect = [
            {},                  # user config
            {"threshold": 5.0},  # project config
        ]
        config = load_config(
            project_path=Path("/some/project"),
            cli_overrides={"threshold": 9.0},
        )
        assert config["threshold"] == 9.0


# ---------------------------------------------------------------------------
# Typed accessors
# ---------------------------------------------------------------------------

class TestAccessors:

    def test_get_threshold_default(self):
        assert get_threshold(DEFAULT_CONFIG) == 6.0

    def test_get_threshold_custom(self):
        config = {**DEFAULT_CONFIG, "threshold": 8.5}
        assert get_threshold(config) == 8.5

    def test_get_age_thresholds(self):
        t = get_age_thresholds(DEFAULT_CONFIG)
        assert t["critical_days"] == 7
        assert t["warning_days"] == 30
        assert t["notice_days"] == 90

    def test_get_similarity_thresholds(self):
        s = get_similarity_thresholds(DEFAULT_CONFIG)
        assert s["critical"] == 0.85
        assert s["high"] == 0.70
        assert s["suggest"] == 0.60

    def test_get_velocity_config(self):
        v = get_velocity_config(DEFAULT_CONFIG)
        assert v["anomaly_downloads"] == 10000
        assert v["age_window_days"] == 30

    def test_get_resolver_config(self):
        r = get_resolver_config(DEFAULT_CONFIG)
        assert r["max_depth"] == 5
        assert r["max_packages"] == 200

    def test_get_dependency_config(self):
        d = get_dependency_config(DEFAULT_CONFIG)
        assert d["high_count"] == 50
        assert d["elevated_count"] == 25
        assert d["deep_chain"] == 4

    def test_get_arsm_coefficients(self):
        a = get_arsm_coefficients(DEFAULT_CONFIG)
        assert a["alpha"] == 0.30
        assert a["beta"] == 0.25

    def test_get_agent_aal_known(self):
        assert get_agent_aal(DEFAULT_CONFIG, "cursor") == 0.7
        assert get_agent_aal(DEFAULT_CONFIG, "claude-code") == 0.8

    def test_get_agent_aal_unknown_fallback(self):
        assert get_agent_aal(DEFAULT_CONFIG, "unknown-agent") == 0.6  # auto fallback

    def test_get_http_config(self):
        h = get_http_config(DEFAULT_CONFIG)
        assert h["timeout"] == 8
        assert h["cache_ttl"] == 300
        assert h["max_concurrent"] == 5

    def test_get_watcher_config(self):
        w = get_watcher_config(DEFAULT_CONFIG)
        assert w["poll_interval"] == 1.0

    def test_get_allowlist_empty_default(self):
        assert get_allowlist(DEFAULT_CONFIG, "pypi") == set()
        assert get_allowlist(DEFAULT_CONFIG, "npm") == set()

    def test_get_allowlist_custom(self):
        config = copy.deepcopy(DEFAULT_CONFIG)
        config["allowlist"]["pypi"] = ["My-Custom-Pkg"]
        result = get_allowlist(config, "pypi")
        assert "my-custom-pkg" in result  # lowercased

    def test_get_blocklist_custom(self):
        config = copy.deepcopy(DEFAULT_CONFIG)
        config["blocklist"]["pypi"] = ["Evil-Package"]
        result = get_blocklist(config, "pypi")
        assert "evil-package" in result  # lowercased


# ---------------------------------------------------------------------------
# Integration: config wired into analyzer
# ---------------------------------------------------------------------------

class TestConfigInAnalyzer:

    def test_analyzer_uses_custom_config(self):
        from uast.analyzer import SupplyChainAnalyzer
        config = copy.deepcopy(DEFAULT_CONFIG)
        config["arsm"]["alpha"] = 0.5
        analyzer = SupplyChainAnalyzer(config=config)
        assert analyzer.config["arsm"]["alpha"] == 0.5

    def test_analyzer_defaults_without_config(self):
        from uast.analyzer import SupplyChainAnalyzer
        analyzer = SupplyChainAnalyzer()
        assert analyzer.config["threshold"] == DEFAULT_CONFIG["threshold"]

    def test_analyzer_blocklist_blocks_package(self):
        from uast.analyzer import SupplyChainAnalyzer
        config = copy.deepcopy(DEFAULT_CONFIG)
        config["blocklist"]["pypi"] = ["evil-pkg"]
        analyzer = SupplyChainAnalyzer(config=config)
        result = analyzer.analyze_pypi("evil-pkg")
        assert result.verdict == "critical"
        assert result.ars_score == 10.0
        assert any(s.signal_id == "BLOCK-001" for s in result.signals)

    def test_analyzer_allowlist_allows_custom_package(self):
        from uast.analyzer import SupplyChainAnalyzer
        config = copy.deepcopy(DEFAULT_CONFIG)
        config["allowlist"]["pypi"] = ["my-internal-pkg"]
        analyzer = SupplyChainAnalyzer(config=config)
        result = analyzer.analyze_pypi("my-internal-pkg")
        assert result.verdict == "clean"
        assert any(s.signal_id == "ALLOW-001" for s in result.signals)


# ---------------------------------------------------------------------------
# Integration: config wired into resolver
# ---------------------------------------------------------------------------

class TestConfigInResolver:

    def test_resolver_accepts_max_depth(self):
        from uast.resolver import DependencyResolver
        resolver = DependencyResolver(max_depth=3, max_packages=100)
        assert resolver.MAX_DEPTH == 3
        assert resolver.MAX_PACKAGES == 100

    def test_resolver_defaults(self):
        from uast.resolver import DependencyResolver
        resolver = DependencyResolver()
        assert resolver.MAX_DEPTH == 5
        assert resolver.MAX_PACKAGES == 200
