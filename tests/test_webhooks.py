"""
Tests for alert webhooks (Slack + generic).

Covers:
  - WebhookDispatcher configuration
  - Should-fire logic (verdict, score, rate limiting)
  - Slack Block Kit payload generation
  - Generic JSON payload generation
  - Session summary notifications
  - Error handling
  - Watcher integration
"""

import time
from unittest.mock import MagicMock, patch

from uast.analyzer import AnalysisResult, PackageSignal
from uast.webhooks import WebhookDispatcher

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_dispatcher(
    slack_url="",
    generic_url="",
    min_ars=6.0,
    on_verdict=None,
    rate_limit=10,
    include_signals=True,
):
    config = {
        "webhooks": {
            "slack_url": slack_url,
            "generic_url": generic_url,
            "min_ars_score": min_ars,
            "on_verdict": on_verdict or ["critical", "suspicious"],
            "rate_limit_seconds": rate_limit,
            "include_signals": include_signals,
        }
    }
    return WebhookDispatcher(config)


def _make_result(
    name="test-pkg",
    ars_score=8.0,
    verdict="critical",
    signals=None,
):
    result = AnalysisResult(
        package_name=name,
        ecosystem="pypi",
        version="1.0.0",
        ars_score=ars_score,
        cvss_base=7.0,
        verdict=verdict,
        recommendation="Do not install.",
    )
    if signals:
        result.signals = signals
    else:
        result.signals = [
            PackageSignal(
                signal_id="AGE-001",
                severity="high",
                title="Very new package",
                detail="Package is 2 days old.",
                score_contribution=0.85,
            ),
        ]
    return result


# ---------------------------------------------------------------------------
# Configuration tests
# ---------------------------------------------------------------------------

class TestWebhookConfiguration:

    def test_not_configured_by_default(self):
        dispatcher = _make_dispatcher()
        assert not dispatcher.is_configured

    def test_configured_with_slack(self):
        dispatcher = _make_dispatcher(slack_url="https://hooks.slack.com/test")
        assert dispatcher.is_configured

    def test_configured_with_generic(self):
        dispatcher = _make_dispatcher(generic_url="https://api.example.com/webhook")
        assert dispatcher.is_configured

    def test_configured_with_both(self):
        dispatcher = _make_dispatcher(
            slack_url="https://hooks.slack.com/test",
            generic_url="https://api.example.com/webhook",
        )
        assert dispatcher.is_configured

    def test_default_config_values(self):
        dispatcher = _make_dispatcher()
        assert dispatcher.min_ars == 6.0
        assert dispatcher.on_verdict == ["critical", "suspicious"]
        assert dispatcher.rate_limit == 10
        assert dispatcher.include_signals is True

    def test_empty_config(self):
        dispatcher = WebhookDispatcher({})
        assert not dispatcher.is_configured
        assert dispatcher.min_ars == 6.0


# ---------------------------------------------------------------------------
# Should-fire logic
# ---------------------------------------------------------------------------

class TestShouldFire:

    def test_fires_for_critical_above_threshold(self):
        dispatcher = _make_dispatcher(generic_url="https://test.com")
        result = _make_result(ars_score=8.0, verdict="critical")
        assert dispatcher._should_fire(result) is True

    def test_fires_for_suspicious_above_threshold(self):
        dispatcher = _make_dispatcher(generic_url="https://test.com")
        result = _make_result(ars_score=7.0, verdict="suspicious")
        assert dispatcher._should_fire(result) is True

    def test_does_not_fire_for_clean(self):
        dispatcher = _make_dispatcher(generic_url="https://test.com")
        result = _make_result(ars_score=2.0, verdict="clean")
        assert dispatcher._should_fire(result) is False

    def test_does_not_fire_below_threshold(self):
        dispatcher = _make_dispatcher(generic_url="https://test.com", min_ars=8.0)
        result = _make_result(ars_score=7.5, verdict="critical")
        assert dispatcher._should_fire(result) is False

    def test_rate_limiting(self):
        dispatcher = _make_dispatcher(generic_url="https://test.com", rate_limit=60)
        result = _make_result()
        # Simulate previous notification
        dispatcher._recently_notified["test-pkg"] = time.time()
        assert dispatcher._should_fire(result) is False

    def test_rate_limit_expired(self):
        dispatcher = _make_dispatcher(generic_url="https://test.com", rate_limit=0)
        result = _make_result()
        dispatcher._recently_notified["test-pkg"] = time.time() - 1
        assert dispatcher._should_fire(result) is True

    def test_custom_verdict_list(self):
        dispatcher = _make_dispatcher(
            generic_url="https://test.com",
            on_verdict=["critical"],
        )
        result_sus = _make_result(verdict="suspicious")
        result_crit = _make_result(verdict="critical")
        assert dispatcher._should_fire(result_sus) is False
        assert dispatcher._should_fire(result_crit) is True


# ---------------------------------------------------------------------------
# Fire tests
# ---------------------------------------------------------------------------

class TestFireWebhooks:

    def test_fire_not_configured(self):
        dispatcher = _make_dispatcher()
        result = _make_result()
        assert dispatcher.fire(result) is False

    def test_fire_slack(self):
        dispatcher = _make_dispatcher(slack_url="https://hooks.slack.com/test")
        result = _make_result()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch.object(dispatcher._http, "post", return_value=mock_resp) as mock_post:
            fired = dispatcher.fire(result)

        assert fired is True
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == "https://hooks.slack.com/test"

    def test_fire_generic(self):
        dispatcher = _make_dispatcher(generic_url="https://api.example.com/hook")
        result = _make_result()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch.object(dispatcher._http, "post", return_value=mock_resp) as mock_post:
            fired = dispatcher.fire(result)

        assert fired is True
        payload = mock_post.call_args[1]["json"]
        assert payload["package_name"] == "test-pkg"
        assert payload["ars_score"] == 8.0
        assert payload["verdict"] == "critical"

    def test_fire_both(self):
        dispatcher = _make_dispatcher(
            slack_url="https://hooks.slack.com/test",
            generic_url="https://api.example.com/hook",
        )
        result = _make_result()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch.object(dispatcher._http, "post", return_value=mock_resp) as mock_post:
            fired = dispatcher.fire(result)

        assert fired is True
        assert mock_post.call_count == 2

    def test_fire_records_timestamp(self):
        dispatcher = _make_dispatcher(generic_url="https://test.com")
        result = _make_result()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch.object(dispatcher._http, "post", return_value=mock_resp):
            dispatcher.fire(result)

        assert "test-pkg" in dispatcher._recently_notified

    def test_fire_calls_display_webhook_fired(self):
        mock_display = MagicMock()
        dispatcher = _make_dispatcher(generic_url="https://test.com")
        dispatcher._display = mock_display
        result = _make_result()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch.object(dispatcher._http, "post", return_value=mock_resp):
            dispatcher.fire(result)

        mock_display.webhook_fired.assert_called_once()

    def test_fire_handles_slack_error(self):
        dispatcher = _make_dispatcher(slack_url="https://hooks.slack.com/test")
        result = _make_result()

        with patch.object(dispatcher._http, "post", side_effect=Exception("network")):
            fired = dispatcher.fire(result)
        # Should return False since the exception was caught but nothing succeeded
        assert fired is False


# ---------------------------------------------------------------------------
# Payload generation
# ---------------------------------------------------------------------------

class TestSlackPayload:

    def test_slack_blocks_structure(self):
        dispatcher = _make_dispatcher(slack_url="https://test.com")
        result = _make_result()
        blocks = dispatcher._build_slack_blocks(result)

        assert len(blocks) >= 3
        assert blocks[0]["type"] == "header"
        assert "test-pkg" in blocks[0]["text"]["text"]
        assert blocks[1]["type"] == "section"

    def test_slack_blocks_include_signals(self):
        dispatcher = _make_dispatcher(slack_url="https://test.com", include_signals=True)
        result = _make_result()
        blocks = dispatcher._build_slack_blocks(result)
        # Find the signals block
        signal_block = [b for b in blocks if "Signals" in str(b)]
        assert len(signal_block) > 0

    def test_slack_blocks_no_signals(self):
        dispatcher = _make_dispatcher(slack_url="https://test.com", include_signals=False)
        result = _make_result()
        blocks = dispatcher._build_slack_blocks(result)
        signal_blocks = [b for b in blocks if "Signals" in str(b)]
        assert len(signal_blocks) == 0


class TestGenericPayload:

    def test_generic_payload_structure(self):
        dispatcher = _make_dispatcher(generic_url="https://test.com")
        result = _make_result()
        payload = dispatcher._build_generic_payload(result)

        assert payload["package_name"] == "test-pkg"
        assert payload["ecosystem"] == "pypi"
        assert payload["ars_score"] == 8.0
        assert payload["verdict"] == "critical"
        assert "signals" in payload

    def test_generic_payload_no_signals(self):
        dispatcher = _make_dispatcher(
            generic_url="https://test.com",
            include_signals=False,
        )
        result = _make_result()
        payload = dispatcher._build_generic_payload(result)
        assert "signals" not in payload

    def test_generic_payload_includes_signals(self):
        dispatcher = _make_dispatcher(generic_url="https://test.com")
        result = _make_result()
        payload = dispatcher._build_generic_payload(result)
        assert len(payload["signals"]) == 1
        assert payload["signals"][0]["signal_id"] == "AGE-001"


# ---------------------------------------------------------------------------
# Session notification
# ---------------------------------------------------------------------------

class TestSessionNotification:

    def test_notify_session_generic(self):
        dispatcher = _make_dispatcher(generic_url="https://test.com")
        session_data = {
            "agent": "cursor",
            "project": "/test",
            "summary": {
                "total_packages": 5,
                "alerts": 2,
                "critical": 1,
                "suspicious": 1,
                "max_ars_score": 9.0,
            },
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch.object(dispatcher._http, "post", return_value=mock_resp) as mock_post:
            sent = dispatcher.notify_session(session_data)

        assert sent is True
        payload = mock_post.call_args[1]["json"]
        assert payload["type"] == "session_summary"
        assert payload["alerts"] == 2

    def test_notify_session_no_alerts(self):
        dispatcher = _make_dispatcher(generic_url="https://test.com")
        session_data = {
            "summary": {"alerts": 0, "total_packages": 5},
        }
        sent = dispatcher.notify_session(session_data)
        assert sent is False

    def test_notify_session_not_configured(self):
        dispatcher = _make_dispatcher()
        sent = dispatcher.notify_session({"summary": {"alerts": 1}})
        assert sent is False

    def test_notify_session_slack(self):
        dispatcher = _make_dispatcher(slack_url="https://hooks.slack.com/test")
        session_data = {
            "agent": "cursor",
            "project": "/test",
            "summary": {
                "total_packages": 10,
                "alerts": 3,
                "critical": 2,
                "suspicious": 1,
                "max_ars_score": 9.5,
            },
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch.object(dispatcher._http, "post", return_value=mock_resp) as mock_post:
            sent = dispatcher.notify_session(session_data)

        assert sent is True
        call_kwargs = mock_post.call_args[1]
        assert "blocks" in call_kwargs["json"]
