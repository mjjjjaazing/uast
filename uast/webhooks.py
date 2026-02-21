"""
Webhook Dispatcher — fire alerts to Slack and generic HTTP endpoints.

Sends notifications when packages exceed ARS score threshold or match
configured verdict levels. Supports Slack Block Kit format and a generic
JSON payload mode.

Rate-limited per package to prevent spam during batch analysis.
"""

from __future__ import annotations

import logging
import time

from uast.analyzer import AnalysisResult
from uast.http_client import CachedHTTPClient

logger = logging.getLogger("uast.webhooks")


class WebhookDispatcher:
    """Dispatches analysis alerts to configured webhook endpoints."""

    def __init__(
        self,
        config: dict,
        display: object = None,
    ) -> None:
        wh_config = config.get("webhooks", {})
        self.slack_url = wh_config.get("slack_url", "")
        self.generic_url = wh_config.get("generic_url", "")
        self.min_ars = wh_config.get("min_ars_score", 6.0)
        self.on_verdict = wh_config.get("on_verdict", ["critical", "suspicious"])
        self.rate_limit = wh_config.get("rate_limit_seconds", 10)
        self.include_signals = wh_config.get("include_signals", True)
        self._display = display
        self._recently_notified: dict[str, float] = {}
        self._http = CachedHTTPClient(timeout=10, max_concurrent=2, max_retries=2)

    @property
    def is_configured(self) -> bool:
        """Return True if at least one webhook endpoint is configured."""
        return bool(self.slack_url or self.generic_url)

    def fire(self, result: AnalysisResult) -> bool:
        """
        Fire webhooks if result meets criteria.

        Returns True if any webhook was fired, False otherwise.
        """
        if not self.is_configured:
            return False

        if not self._should_fire(result):
            return False

        fired = False

        if self.slack_url:
            try:
                self._fire_slack(result)
                fired = True
            except Exception as e:
                logger.warning("Slack webhook failed: %s", e)

        if self.generic_url:
            try:
                self._fire_generic(result)
                fired = True
            except Exception as e:
                logger.warning("Generic webhook failed: %s", e)

        if fired:
            self._recently_notified[result.package_name] = time.time()
            if self._display and hasattr(self._display, "webhook_fired"):
                self._display.webhook_fired(
                    "slack" if self.slack_url else "generic",
                    result.package_name,
                )

        return fired

    def _should_fire(self, result: AnalysisResult) -> bool:
        """Check verdict, score, and rate limit."""
        # Check verdict
        if result.verdict not in self.on_verdict:
            return False

        # Check minimum ARS score
        if result.ars_score < self.min_ars:
            return False

        # Check rate limit
        last_notified = self._recently_notified.get(result.package_name)
        if last_notified is not None:
            elapsed = time.time() - last_notified
            if elapsed < self.rate_limit:
                logger.debug(
                    "Rate-limited webhook for %s (%.0fs remaining)",
                    result.package_name, self.rate_limit - elapsed,
                )
                return False

        return True

    def _fire_slack(self, result: AnalysisResult) -> None:
        """POST a Slack Block Kit message."""
        blocks = self._build_slack_blocks(result)
        payload = {"blocks": blocks}

        resp = self._http.post(self.slack_url, json=payload)
        if resp.status_code != 200:
            logger.warning(
                "Slack webhook returned %d: %s",
                resp.status_code,
                resp.text[:200] if hasattr(resp, "text") else "",
            )

    def _fire_generic(self, result: AnalysisResult) -> None:
        """POST full result dict to generic endpoint."""
        payload = self._build_generic_payload(result)
        resp = self._http.post(self.generic_url, json=payload)
        if resp.status_code not in (200, 201, 202, 204):
            logger.warning(
                "Generic webhook returned %d", resp.status_code,
            )

    def _build_slack_blocks(self, result: AnalysisResult) -> list[dict]:
        """Build Slack Block Kit blocks for an alert."""
        verdict_emoji = {
            "critical": ":rotating_light:",
            "suspicious": ":warning:",
            "clean": ":white_check_mark:",
        }
        emoji = verdict_emoji.get(result.verdict, ":question:")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} UAST Alert: {result.package_name}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Package:*\n{result.package_name}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*ARS Score:*\n{result.ars_score:.1f} / 10.0",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Verdict:*\n{result.verdict.upper()}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Ecosystem:*\n{result.ecosystem}",
                    },
                ],
            },
        ]

        # Add recommendation
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Recommendation:*\n{result.recommendation}",
            },
        })

        # Add signals summary if enabled
        if self.include_signals and result.signals:
            signal_lines = []
            for sig in result.signals[:5]:
                signal_lines.append(
                    f"• `{sig.signal_id}` [{sig.severity.upper()}] {sig.title}"
                )
            if len(result.signals) > 5:
                signal_lines.append(f"_...and {len(result.signals) - 5} more_")

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Signals:*\n" + "\n".join(signal_lines),
                },
            })

        return blocks

    def _build_generic_payload(self, result: AnalysisResult) -> dict:
        """Build a generic JSON payload (same format as `uast check --json`)."""
        payload: dict = {
            "package_name": result.package_name,
            "ecosystem": result.ecosystem,
            "version": result.version,
            "ars_score": result.ars_score,
            "cvss_base": result.cvss_base,
            "verdict": result.verdict,
            "avt_classes": result.avt_classes,
            "recommendation": result.recommendation,
            "analyzed_at": result.analyzed_at,
        }

        if self.include_signals:
            payload["signals"] = [
                {
                    "signal_id": s.signal_id,
                    "severity": s.severity,
                    "title": s.title,
                    "detail": s.detail,
                    "score_contribution": s.score_contribution,
                }
                for s in result.signals
            ]

        return payload

    def notify_session(self, session_data: dict) -> bool:
        """
        Send a session summary (for `uast notify` command).

        Returns True if at least one notification was sent.
        """
        if not self.is_configured:
            return False

        fired = False

        summary = session_data.get("summary", {})
        alerts = summary.get("alerts", 0)

        if alerts == 0:
            return False

        payload = {
            "type": "session_summary",
            "agent": session_data.get("agent", "unknown"),
            "project": session_data.get("project", "unknown"),
            "total_packages": summary.get("total_packages", 0),
            "alerts": alerts,
            "critical": summary.get("critical", 0),
            "suspicious": summary.get("suspicious", 0),
            "max_ars_score": summary.get("max_ars_score", 0.0),
        }

        if self.slack_url:
            try:
                blocks = [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": ":clipboard: UAST Session Summary",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Agent:*\n{payload['agent']}"},
                            {"type": "mrkdwn", "text": f"*Packages:*\n{payload['total_packages']}"},
                            {"type": "mrkdwn", "text": f"*Alerts:*\n{payload['alerts']}"},
                            {"type": "mrkdwn", "text": f"*Max ARS:*\n{payload['max_ars_score']:.1f}"},  # noqa: E501
                        ],
                    },
                ]
                self._http.post(self.slack_url, json={"blocks": blocks})
                fired = True
            except Exception as e:
                logger.warning("Slack session notification failed: %s", e)

        if self.generic_url:
            try:
                self._http.post(self.generic_url, json=payload)
                fired = True
            except Exception as e:
                logger.warning("Generic session notification failed: %s", e)

        return fired
