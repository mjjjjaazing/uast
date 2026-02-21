"""
Threat Intelligence — OSV.dev vulnerability checking.

Queries the Open Source Vulnerability (OSV) database for known
vulnerabilities in analyzed packages. Produces VULN-001 and VULN-002
signals when CVEs or other advisories are found.

API: https://api.osv.dev/v1/query
"""

from __future__ import annotations

import logging
from typing import Optional

from uast.analyzer import PackageSignal
from uast.http_client import CachedHTTPClient

logger = logging.getLogger("uast.threat_intel")

# OSV uses title-cased ecosystem names
ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
}


class ThreatIntelChecker:
    """Query OSV.dev for known vulnerabilities in a package."""

    OSV_API = "https://api.osv.dev/v1/query"

    def __init__(self, config: dict) -> None:
        ti_config = config.get("threat_intel", {})
        self.enabled = ti_config.get("enabled", True)
        cache_ttl = ti_config.get("cache_ttl", 3600)
        # Dedicated HTTP client with longer TTL for vulnerability data
        self._http = CachedHTTPClient(
            timeout=10,
            cache_ttl=cache_ttl,
            max_concurrent=3,
            max_retries=2,
        )

    def check(
        self,
        name: str,
        ecosystem: str,
        version: Optional[str] = None,
    ) -> tuple[list[PackageSignal], float, list[dict]]:
        """
        Query OSV.dev for known vulnerabilities.

        Args:
            name: Package name.
            ecosystem: "pypi" or "npm".
            version: Package version (optional but recommended).

        Returns:
            (signals, max_contribution, vuln_dicts)
        """
        if not self.enabled:
            return [], 0.0, []

        osv_ecosystem = ECOSYSTEM_MAP.get(ecosystem)
        if not osv_ecosystem:
            logger.debug("Unsupported ecosystem for OSV: %s", ecosystem)
            return [], 0.0, []

        vulns = self._query_osv(name, osv_ecosystem, version)
        if not vulns:
            return [], 0.0, []

        signals: list[PackageSignal] = []
        vuln_dicts: list[dict] = []
        max_contribution = 0.0

        for vuln in vulns:
            vuln_dict = self._parse_vuln(vuln)
            vuln_dicts.append(vuln_dict)

        # Determine highest severity across all vulnerabilities
        max_severity = self._max_severity(vuln_dicts)
        score = self._severity_to_score(max_severity)

        # VULN-001: At least one known vulnerability
        detail_parts = []
        for v in vuln_dicts[:5]:  # Show up to 5
            fixed = f" (fixed in {v['fixed_in']})" if v.get("fixed_in") else ""
            detail_parts.append(
                f"{v['id']}: {v['summary'][:80]} [{v['severity']}]{fixed}"
            )
        detail = "; ".join(detail_parts)
        if len(vuln_dicts) > 5:
            detail += f" ... and {len(vuln_dicts) - 5} more"

        signals.append(PackageSignal(
            signal_id="VULN-001",
            severity=self._score_to_severity_label(score),
            title=f"Known vulnerability ({len(vuln_dicts)} advisory/ies)",
            detail=detail,
            score_contribution=score,
        ))
        max_contribution = max(max_contribution, score)

        # VULN-002: Multiple vulnerabilities (>=3)
        if len(vuln_dicts) >= 3:
            signals.append(PackageSignal(
                signal_id="VULN-002",
                severity="critical",
                title=f"Multiple known vulnerabilities ({len(vuln_dicts)})",
                detail=(
                    f"Package has {len(vuln_dicts)} known vulnerabilities. "
                    "Packages with many unpatched advisories carry extreme risk."
                ),
                score_contribution=0.95,
            ))
            max_contribution = max(max_contribution, 0.95)

        return signals, max_contribution, vuln_dicts

    def _query_osv(
        self, name: str, osv_ecosystem: str, version: Optional[str]
    ) -> list[dict]:
        """POST to OSV.dev API and return vulnerability list."""
        payload: dict = {
            "package": {
                "name": name,
                "ecosystem": osv_ecosystem,
            },
        }
        if version:
            payload["version"] = version

        try:
            resp = self._http.post(self.OSV_API, json=payload, timeout=10)
            if resp.status_code != 200:
                logger.debug(
                    "OSV API returned %d for %s/%s",
                    resp.status_code, osv_ecosystem, name,
                )
                return []
            data = resp.json()
            return data.get("vulns", [])
        except Exception as e:
            logger.warning("OSV query failed for %s: %s", name, e)
            return []

    def _parse_vuln(self, vuln: dict) -> dict:
        """Extract structured data from an OSV vulnerability entry."""
        vuln_id = vuln.get("id", "UNKNOWN")
        summary = vuln.get("summary", vuln.get("details", "No summary")[:120])
        severity = self._extract_severity(vuln)
        fixed_in = self._extract_fixed_version(vuln)

        return {
            "id": vuln_id,
            "summary": summary,
            "severity": severity,
            "fixed_in": fixed_in,
        }

    def _extract_severity(self, vuln: dict) -> str:
        """Extract severity from CVSS score in OSV data."""
        # OSV provides severity in database_specific or severity array
        severity_list = vuln.get("severity", [])
        max_score = 0.0

        for sev in severity_list:
            if sev.get("type") == "CVSS_V3":
                score = self._parse_cvss_score(sev.get("score", ""))
                max_score = max(max_score, score)

        # Also check database_specific for CVSS
        db_specific = vuln.get("database_specific", {})
        if "severity" in db_specific:
            sev_str = db_specific["severity"]
            if isinstance(sev_str, str):
                return sev_str.lower()

        if max_score >= 9.0:
            return "critical"
        elif max_score >= 7.0:
            return "high"
        elif max_score >= 4.0:
            return "medium"
        elif max_score > 0.0:
            return "low"
        return "unknown"

    def _parse_cvss_score(self, score_str: str) -> float:
        """Parse a CVSS vector string and extract the base score."""
        # CVSS vectors look like: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        # The numeric score isn't always directly in the string, but
        # sometimes OSV provides it as a float
        try:
            return float(score_str)
        except (ValueError, TypeError):
            pass
        # Rough heuristic from vector components
        if not score_str or not isinstance(score_str, str):
            return 0.0
        upper = score_str.upper()
        # Count high-impact indicators
        high_indicators = sum(1 for x in ["/C:H", "/I:H", "/A:H"] if x in upper)
        if high_indicators >= 2:
            return 9.0
        elif high_indicators == 1:
            return 7.0
        elif "/C:L" in upper or "/I:L" in upper or "/A:L" in upper:
            return 4.0
        return 3.0

    def _extract_fixed_version(self, vuln: dict) -> Optional[str]:
        """Extract the first fixed version from affected ranges."""
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    fixed = event.get("fixed")
                    if fixed:
                        return fixed
        return None

    def _max_severity(self, vuln_dicts: list[dict]) -> str:
        """Return the highest severity across all vulnerabilities."""
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
        best = "unknown"
        for v in vuln_dicts:
            sev = v.get("severity", "unknown")
            if order.get(sev, 0) > order.get(best, 0):
                best = sev
        return best

    def _severity_to_score(self, severity: str) -> float:
        """Map severity string to a score contribution."""
        mapping = {
            "critical": 0.95,
            "high": 0.75,
            "medium": 0.55,
            "low": 0.35,
            "unknown": 0.5,
        }
        return mapping.get(severity, 0.5)

    def _score_to_severity_label(self, score: float) -> str:
        """Map a score contribution to a PackageSignal severity label."""
        if score >= 0.9:
            return "critical"
        elif score >= 0.7:
            return "high"
        elif score >= 0.4:
            return "medium"
        return "low"
