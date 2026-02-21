"""
Supply chain analyzer — the core detection engine.

Implements UAST Layer 2 (Behavioral Dynamic Analysis) and the
Agentic Risk Scoring Model (ARSM) for dependency risk assessment.

Detection signals:
  - Package age vs. download velocity (typosquatting / adversarial packages)
  - Name similarity to popular packages (name-squatting)
  - Maintainer account age and history
  - Transitive dependency depth and anomalies
  - Known malicious pattern database
  - PyPI/npm metadata integrity signals
  - Hallucinated package detection (registry 404 + "did you mean?")
  - Download velocity anomaly detection
  - Repository URL verification
  - Static payload analysis (AST-based)
  - ARSM scoring with agent-specific dimensions
"""

from __future__ import annotations

import datetime
import logging
import math
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Optional

import requests

from uast.config import (
    DEFAULT_CONFIG,
    get_age_thresholds,
    get_allowlist,
    get_arsm_coefficients,
    get_blocklist,
    get_dependency_config,
    get_similarity_thresholds,
    get_velocity_config,
)
from uast.http_client import http_client

logger = logging.getLogger("uast.analyzer")

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PackageSignal:
    """A single detection signal for a package."""
    signal_id: str
    severity: str          # "critical", "high", "medium", "low", "info"
    title: str
    detail: str
    score_contribution: float  # 0.0-1.0 contribution to risk


@dataclass
class ARSMContext:
    """Context for ARSM scoring dimensions."""
    aal: float = 0.5   # Agent Autonomy Level (0-1)
    cis: float = 1.0   # Context Integrity Score (0-1)
    pc: float = 1.0    # Provenance Confidence (0-1)
    srf: float = 0.0   # Systemic Replication Factor


@dataclass
class AnalysisResult:
    """Full analysis result for a single package."""
    package_name: str
    ecosystem: str          # "pypi" or "npm"
    version: str
    ars_score: float        # 0.0-10.0 Agentic Risk Score
    cvss_base: float        # 0.0-10.0 estimated base severity
    signals: list[PackageSignal] = field(default_factory=list)
    avt_classes: list[str] = field(default_factory=list)
    verdict: str = "clean"  # "clean", "suspicious", "critical"
    recommendation: str = "No issues detected."
    metadata: dict = field(default_factory=dict)
    analyzed_at: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())
    arsm: Optional[dict] = None          # ARSM breakdown
    dependency_tree: Optional[dict] = None  # dep tree summary
    did_you_mean: Optional[str] = None   # suggestion for hallucinated packages
    confidence: str = "high"             # "high", "medium", "low" — scoring confidence
    dependency_tree_hash: Optional[str] = None  # Merkle root hash of dep tree
    provenance: Optional[dict] = None    # provenance verification results
    version_diff: Optional[dict] = None  # version diff results

    @property
    def is_flagged(self) -> bool:
        return self.verdict in ("suspicious", "critical")

    @property
    def signal_count(self) -> int:
        return len(self.signals)


# ---------------------------------------------------------------------------
# Known safe packages (abbreviated allowlist — expand in production)
# ---------------------------------------------------------------------------

PYPI_SAFE = {
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "sqlalchemy",
    "pydantic", "pytest", "boto3", "click", "rich", "typer", "httpx",
    "aiohttp", "celery", "redis", "pillow", "matplotlib", "scikit-learn",
    "torch", "tensorflow", "transformers", "openai", "anthropic", "langchain",
    "psutil", "watchdog", "packaging", "setuptools", "wheel", "pip",
    "black", "ruff", "mypy", "isort", "flake8", "pylint", "bandit",
    "cryptography", "paramiko", "fabric", "ansible", "docker", "kubernetes",
    "stripe", "twilio", "sendgrid", "jinja2", "markupsafe", "werkzeug",
    "gunicorn", "uvicorn", "starlette", "httptools", "websockets",
}

NPM_SAFE = {
    "react", "vue", "angular", "express", "lodash", "axios", "typescript",
    "webpack", "babel", "eslint", "prettier", "jest", "mocha", "chai",
    "next", "nuxt", "gatsby", "vite", "rollup", "esbuild", "tailwindcss",
    "prisma", "mongoose", "sequelize", "typeorm", "knex", "pg", "mysql2",
    "redis", "ioredis", "socket.io", "nodemailer", "passport", "jsonwebtoken",
    "bcrypt", "dotenv", "cross-env", "rimraf", "concurrently", "nodemon",
    "zod", "yup", "formik", "react-query", "zustand", "redux", "mobx",
}

# Patterns that appear in known malicious or typosquatting packages
SUSPICIOUS_NAME_PATTERNS = [
    r"^[a-z]+-utils-[a-z]+$",          # e.g. request-utils-async
    r"^[a-z]+-[a-z]+-helper$",          # e.g. lodash-array-helper
    r"^[a-z]{1,3}-[a-z]{1,3}-[a-z]+$", # very short prefix patterns
    r"secure-.*",                        # "secure-" prefix abuse
    r".*-official$",                     # fake "official" packages
    r".*-stable$",                       # fake "stable" variants
    r".*-latest$",                       # fake "latest" variants
    r"^node-[a-z]+-[a-z]+$",           # node- prefix typosquatting
    r"^py-[a-z]+-[a-z]+$",             # py- prefix typosquatting
]

# Popular packages to check name similarity against (typosquatting targets)
POPULAR_PYPI = [
    "requests", "urllib3", "boto3", "botocore", "setuptools", "pip",
    "numpy", "pandas", "flask", "django", "fastapi", "pydantic",
    "cryptography", "paramiko", "pillow", "matplotlib", "sqlalchemy",
]

POPULAR_NPM = [
    "lodash", "axios", "express", "react", "typescript", "webpack",
    "babel", "eslint", "jest", "moment", "underscore", "async",
    "request", "commander", "chalk", "debug", "fs-extra", "glob",
]

# Download stats APIs
PYPISTATS_API = "https://pypistats.org/api/packages/{name}/recent"
NPM_DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-week/{name}"

# ARSM coefficients
ARSM_ALPHA = 0.3   # Agent Autonomy Level weight
ARSM_BETA = 0.25   # Context Integrity Score weight
ARSM_GAMMA = 0.25  # Provenance Confidence weight
ARSM_DELTA = 0.2   # Systemic Replication Factor weight

# AAL mapping for known agents
AGENT_AAL = {
    "copilot": 0.5,
    "cursor": 0.7,
    "claude-code": 0.8,
    "windsurf": 0.7,
    "codeium": 0.5,
    "auto": 0.6,
}


# ---------------------------------------------------------------------------
# Input sanitization
# ---------------------------------------------------------------------------

# Valid package name pattern: alphanumeric, hyphens, underscores, dots, @, /
# npm allows @scope/name, PyPI allows dots/hyphens/underscores
_VALID_PACKAGE_NAME = re.compile(r"^[@a-zA-Z0-9][\w.@/\-]{0,213}$")
MAX_PACKAGE_NAME_LENGTH = 214  # npm maximum


def sanitize_package_name(name: str) -> str:
    """
    Validate and sanitize a package name.

    Rejects names with shell metacharacters, control characters,
    or names that exceed length limits.

    Returns the stripped name if valid, raises ValueError if not.
    """
    name = name.strip()
    if not name:
        raise ValueError("Empty package name")
    if len(name) > MAX_PACKAGE_NAME_LENGTH:
        raise ValueError(
            f"Package name too long "
            f"({len(name)} chars, max {MAX_PACKAGE_NAME_LENGTH})"
        )
    if not _VALID_PACKAGE_NAME.match(name):
        raise ValueError(f"Invalid package name: {name!r} — contains disallowed characters")
    return name


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class SupplyChainAnalyzer:
    """
    Lightweight supply chain risk analyzer implementing UAST Layer 2 (BDA)
    and Layer 1 (SSA) heuristics for dependency risk scoring.

    Scoring follows ARSM:
        ARS = CVSS_Base x (1 + alpha*AAL + beta*(1-CIS) + gamma*(1-PC) + delta*log(1+SRF))

    Each signal contributes a weighted score component.
    Final ARS is normalized to 0.0-10.0.
    """

    PYPI_API = "https://pypi.org/pypi/{name}/json"
    NPM_API = "https://registry.npmjs.org/{name}"
    REQUEST_TIMEOUT = 8  # seconds

    # Signal weights (sum to 1.0)
    WEIGHTS = {
        "age_velocity":   0.18,
        "name_squatting": 0.14,
        "pattern_match":  0.05,
        "metadata":       0.05,
        "depth":          0.08,
        "payload":        0.18,
        "injection":      0.10,
        "trust":          0.07,
        "spoofing":       0.05,
        "provenance":     0.10,
    }

    def __init__(
        self,
        aal: float = 0.5,
        deep: bool = False,
        config: Optional[dict] = None,
        provenance: bool = False,
    ) -> None:
        self.aal = aal
        self.deep = deep
        self.provenance = provenance
        self.config = config or DEFAULT_CONFIG
        self._resolver = None  # Lazy import to avoid circular

    def _get_resolver(self):
        if self._resolver is None:
            from uast.resolver import DependencyResolver
            resolver_cfg = self.config.get("resolver", DEFAULT_CONFIG["resolver"])
            self._resolver = DependencyResolver(
                max_depth=resolver_cfg.get("max_depth", 5),
                max_packages=resolver_cfg.get("max_packages", 200),
            )
        return self._resolver

    def _get_payload_analyzer(self):
        from uast.payload import PayloadAnalyzer
        return PayloadAnalyzer()

    def analyze_pypi(self, package_name: str) -> AnalysisResult:
        """Analyze a PyPI package and return an AnalysisResult."""
        try:
            package_name = sanitize_package_name(package_name)
        except ValueError as e:
            logger.warning("Invalid package name rejected: %s", e)
            return AnalysisResult(
                package_name=package_name[:100],
                ecosystem="pypi",
                version="unknown",
                ars_score=0.0,
                cvss_base=0.0,
                verdict="clean",
                recommendation=f"Invalid package name: {e}",
            )
        logger.info("Analyzing PyPI package: %s", package_name)
        result = AnalysisResult(
            package_name=package_name,
            ecosystem="pypi",
            version="unknown",
            ars_score=0.0,
            cvss_base=0.0,
        )

        # Check blocklist first — always flag regardless of allowlist
        blocklist = get_blocklist(self.config, "pypi")
        if package_name.lower() in blocklist:
            logger.warning("Package %s is on the blocklist — returning critical", package_name)
            result.signals.append(PackageSignal(
                signal_id="BLOCK-001",
                severity="critical",
                title="Package is on the blocklist",
                detail=f"{package_name} is explicitly blocklisted in UAST configuration.",
                score_contribution=1.0,
            ))
            result.ars_score = 10.0
            result.verdict = "critical"
            result.avt_classes = ["AVT-D3-01"]
            result.recommendation = "Do not install. Package is blocklisted by your organization."
            return result

        # Fast path — known safe packages (built-in + user allowlist)
        user_allowlist = get_allowlist(self.config, "pypi")
        if package_name.lower() in PYPI_SAFE or package_name.lower() in user_allowlist:
            logger.debug("Package %s is in allowlist — skipping analysis", package_name)
            result.verdict = "clean"
            result.recommendation = "Package is in the known-safe allowlist."
            result.signals.append(PackageSignal(
                signal_id="ALLOW-001",
                severity="info",
                title="Known-safe package",
                detail=f"{package_name} is a well-established package in the UAST allowlist.",
                score_contribution=0.0,
            ))
            return result

        # Fetch PyPI metadata
        try:
            logger.debug("Fetching PyPI metadata for %s", package_name)
            resp = http_client.get(
                self.PYPI_API.format(name=package_name),
                timeout=self.REQUEST_TIMEOUT,
            )
            if resp.status_code == 404:
                logger.info("Package %s not found on PyPI (404)", package_name)
                return self._handle_hallucinated_package(result, package_name, "pypi")

            resp.raise_for_status()
            data = resp.json()
            logger.debug("PyPI metadata fetched for %s (status %d)", package_name, resp.status_code)

        except requests.RequestException as e:
            logger.warning("Network error fetching PyPI data for %s: %s", package_name, e)
            result.signals.append(PackageSignal(
                signal_id="NET-001",
                severity="low",
                title="Could not reach PyPI API",
                detail=f"Network error: {e}. Skipping deep analysis.",
                score_contribution=0.0,
            ))
            result.recommendation = "Could not analyze — check network connectivity."
            return result

        info = data.get("info", {})
        releases = data.get("releases", {})

        result.version = info.get("version", "unknown")
        result.metadata = {
            "author": info.get("author", ""),
            "home_page": info.get("home_page", ""),
            "summary": info.get("summary", ""),
            "license": info.get("license", ""),
            "requires_dist": info.get("requires_dist") or [],
        }

        raw_score = 0.0

        # -- Signal 1: Package age vs. download velocity ----------------------
        age_signal, age_contribution = self._check_age_velocity_pypi(
            package_name, releases, info
        )
        if age_signal:
            result.signals.append(age_signal)
        raw_score += age_contribution * self.WEIGHTS["age_velocity"]

        # -- Signal 1b: Release pattern analysis --------------------------------
        release_signal, release_contribution = self._check_release_pattern(
            releases, package_name
        )
        if release_signal:
            result.signals.append(release_signal)
            # Add release contribution to age_velocity (shared weight)
            raw_score += release_contribution * self.WEIGHTS["age_velocity"] * 0.3

        # -- Signal 2: Name squatting -----------------------------------------
        squatting_signal, squatting_contribution = self._check_name_squatting(
            package_name, POPULAR_PYPI
        )
        if squatting_signal:
            result.signals.append(squatting_signal)
        raw_score += squatting_contribution * self.WEIGHTS["name_squatting"]

        # -- Signal 3: Suspicious name pattern --------------------------------
        pattern_signal, pattern_contribution = self._check_name_patterns(package_name)
        if pattern_signal:
            result.signals.append(pattern_signal)
        raw_score += pattern_contribution * self.WEIGHTS["pattern_match"]

        # -- Signal 4: Metadata quality + repo URL verification ---------------
        meta_signal, meta_contribution = self._check_metadata_quality(info)
        if meta_signal:
            result.signals.append(meta_signal)
        raw_score += meta_contribution * self.WEIGHTS["metadata"]

        # -- Signal 5: Dependency tree ----------------------------------------
        depth_signals, depth_contribution = self._check_dependency_tree(
            package_name, "pypi", info.get("requires_dist") or []
        )
        for s in depth_signals:
            result.signals.append(s)
        raw_score += depth_contribution * self.WEIGHTS["depth"]

        # -- Signal 6: Payload analysis (deep mode or check command) ----------
        payload_contribution = 0.0
        if self.deep:
            payload_signals = self._check_payload(package_name, "pypi", result.version)
            for s in payload_signals:
                result.signals.append(s)
                payload_contribution = max(payload_contribution, s.score_contribution)
        raw_score += payload_contribution * self.WEIGHTS["payload"]

        # -- Signal 7: Prompt injection in description ------------------------
        inject_signal, inject_contribution = self._check_prompt_injection(
            info.get("summary", "") or info.get("description", ""),
            package_name,
        )
        if inject_signal:
            result.signals.append(inject_signal)
        raw_score += inject_contribution * self.WEIGHTS["injection"]

        # -- Signal 8: Maintainer trust -----------------------------------------
        trust_signal, trust_contribution = self._check_maintainer_trust(info, "pypi")
        if trust_signal:
            result.signals.append(trust_signal)
        raw_score += trust_contribution * self.WEIGHTS["trust"]

        # -- Signal 9: Metadata spoofing ----------------------------------------
        spoof_signal, spoof_contribution = self._check_metadata_spoofing(
            info, package_name, "pypi"
        )
        if spoof_signal:
            result.signals.append(spoof_signal)
        raw_score += spoof_contribution * self.WEIGHTS["spoofing"]

        # -- Signal 10: Provenance verification --------------------------------
        provenance_contribution = 0.0
        if self.provenance:
            prov_signals = self._check_provenance(
                package_name, result.version, info
            )
            for s in prov_signals:
                result.signals.append(s)
                if s.score_contribution > 0:
                    provenance_contribution = max(
                        provenance_contribution, s.score_contribution
                    )
                elif s.score_contribution < 0:
                    # Negative contribution lowers risk
                    provenance_contribution = min(
                        provenance_contribution, s.score_contribution
                    )
        raw_score += max(provenance_contribution, 0.0) * self.WEIGHTS["provenance"]

        # -- Version diff (deep mode) -----------------------------------------
        if self.deep and result.version != "unknown":
            vdiff_signals = self._check_version_diff(package_name, result.version)
            for s in vdiff_signals:
                result.signals.append(s)
                raw_score += s.score_contribution * self.WEIGHTS["payload"] * 0.3

        # -- Compute ARSM score -----------------------------------------------
        result.cvss_base = round(min(raw_score * 10.0, 10.0), 1)

        cis = self._compute_cis(result.signals)
        arsm_ctx = ARSMContext(
            aal=self.aal,
            cis=cis,
            pc=self._estimate_provenance_confidence(info, result.signals),
            srf=self._estimate_systemic_replication(package_name, "pypi"),
        )
        result.ars_score = round(self._compute_arsm(result.cvss_base, arsm_ctx), 1)
        coeff = get_arsm_coefficients(self.config)
        result.arsm = {
            "aal": arsm_ctx.aal,
            "cis": round(arsm_ctx.cis, 2),
            "pc": arsm_ctx.pc,
            "srf": round(arsm_ctx.srf, 2),
            "alpha": coeff.get("alpha", 0.30),
            "beta": coeff.get("beta", 0.25),
            "gamma": coeff.get("gamma", 0.25),
            "delta": coeff.get("delta", 0.20),
        }

        # Set verdict, AVT classes, and confidence
        result.verdict, result.avt_classes, result.recommendation = (
            self._compute_verdict(result.ars_score, result.signals)
        )
        result.confidence = self._compute_confidence(result.signals, "pypi")

        logger.info(
            "PyPI analysis complete: %s → ARS=%.1f verdict=%s confidence=%s signals=%d",
            package_name, result.ars_score, result.verdict, result.confidence, len(result.signals),
        )
        return result

    def analyze_npm(self, package_name: str) -> AnalysisResult:
        """Analyze an npm package and return an AnalysisResult."""
        try:
            package_name = sanitize_package_name(package_name)
        except ValueError as e:
            logger.warning("Invalid package name rejected: %s", e)
            return AnalysisResult(
                package_name=package_name[:100],
                ecosystem="npm",
                version="unknown",
                ars_score=0.0,
                cvss_base=0.0,
                verdict="clean",
                recommendation=f"Invalid package name: {e}",
            )
        logger.info("Analyzing npm package: %s", package_name)
        result = AnalysisResult(
            package_name=package_name,
            ecosystem="npm",
            version="unknown",
            ars_score=0.0,
            cvss_base=0.0,
        )

        # Check blocklist first
        blocklist = get_blocklist(self.config, "npm")
        if package_name.lower() in blocklist:
            result.signals.append(PackageSignal(
                signal_id="BLOCK-001",
                severity="critical",
                title="Package is on the blocklist",
                detail=f"{package_name} is explicitly blocklisted in UAST configuration.",
                score_contribution=1.0,
            ))
            result.ars_score = 10.0
            result.verdict = "critical"
            result.avt_classes = ["AVT-D3-01"]
            result.recommendation = "Do not install. Package is blocklisted by your organization."
            return result

        user_allowlist = get_allowlist(self.config, "npm")
        if package_name.lower() in NPM_SAFE or package_name.lower() in user_allowlist:
            result.verdict = "clean"
            result.recommendation = "Package is in the known-safe allowlist."
            result.signals.append(PackageSignal(
                signal_id="ALLOW-001",
                severity="info",
                title="Known-safe package",
                detail=f"{package_name} is a well-established package in the UAST allowlist.",
                score_contribution=0.0,
            ))
            return result

        try:
            resp = http_client.get(
                self.NPM_API.format(name=package_name),
                timeout=self.REQUEST_TIMEOUT,
            )
            if resp.status_code == 404:
                return self._handle_hallucinated_package(result, package_name, "npm")

            resp.raise_for_status()
            data = resp.json()

        except requests.RequestException as e:
            result.signals.append(PackageSignal(
                signal_id="NET-001",
                severity="low",
                title="Could not reach npm registry",
                detail=f"Network error: {e}",
                score_contribution=0.0,
            ))
            result.recommendation = "Could not analyze — check network connectivity."
            return result

        latest_version = data.get("dist-tags", {}).get("latest", "unknown")
        result.version = latest_version
        latest_info = data.get("versions", {}).get(latest_version, {})

        result.metadata = {
            "description": data.get("description", ""),
            "author": str(data.get("author", "")),
            "license": latest_info.get("license", ""),
            "dependencies": list((latest_info.get("dependencies") or {}).keys()),
            "maintainers": [m.get("name", "") for m in data.get("maintainers", [])],
        }

        raw_score = 0.0

        # -- Signal 1: Package age --------------------------------------------
        age_signal, age_contribution = self._check_age_velocity_npm(data)
        if age_signal:
            result.signals.append(age_signal)
        raw_score += age_contribution * self.WEIGHTS["age_velocity"]

        # -- Signal 2: Name squatting -----------------------------------------
        squatting_signal, squatting_contribution = self._check_name_squatting(
            package_name, POPULAR_NPM
        )
        if squatting_signal:
            result.signals.append(squatting_signal)
        raw_score += squatting_contribution * self.WEIGHTS["name_squatting"]

        # -- Signal 3: Pattern match ------------------------------------------
        pattern_signal, pattern_contribution = self._check_name_patterns(package_name)
        if pattern_signal:
            result.signals.append(pattern_signal)
        raw_score += pattern_contribution * self.WEIGHTS["pattern_match"]

        # -- Signal 4: Metadata quality ---------------------------------------
        meta_signal, meta_contribution = self._check_metadata_quality_npm(data)
        if meta_signal:
            result.signals.append(meta_signal)
        raw_score += meta_contribution * self.WEIGHTS["metadata"]

        # -- Signal 5: Dependency tree ----------------------------------------
        deps = list((latest_info.get("dependencies") or {}).keys())
        depth_signals, depth_contribution = self._check_dependency_tree(
            package_name, "npm", deps
        )
        for s in depth_signals:
            result.signals.append(s)
        raw_score += depth_contribution * self.WEIGHTS["depth"]

        # -- Signal 6: Payload (npm not supported yet) ------------------------
        # payload analysis only for pypi currently

        # -- Signal 7: Prompt injection in description ------------------------
        inject_signal, inject_contribution = self._check_prompt_injection(
            data.get("description", ""),
            package_name,
        )
        if inject_signal:
            result.signals.append(inject_signal)
        raw_score += inject_contribution * self.WEIGHTS["injection"]

        # -- Signal 8: Maintainer trust -----------------------------------------
        trust_signal, trust_contribution = self._check_maintainer_trust(data, "npm")
        if trust_signal:
            result.signals.append(trust_signal)
        raw_score += trust_contribution * self.WEIGHTS["trust"]

        # -- Signal 9: Metadata spoofing ----------------------------------------
        spoof_signal, spoof_contribution = self._check_metadata_spoofing(
            data, package_name, "npm"
        )
        if spoof_signal:
            result.signals.append(spoof_signal)
        raw_score += spoof_contribution * self.WEIGHTS["spoofing"]

        # -- Compute ARSM score -----------------------------------------------
        result.cvss_base = round(min(raw_score * 10.0, 10.0), 1)

        cis = self._compute_cis(result.signals)
        arsm_ctx = ARSMContext(
            aal=self.aal,
            cis=cis,
            pc=self._estimate_provenance_confidence_npm(data),
            srf=self._estimate_systemic_replication(package_name, "npm"),
        )
        result.ars_score = round(self._compute_arsm(result.cvss_base, arsm_ctx), 1)
        coeff = get_arsm_coefficients(self.config)
        result.arsm = {
            "aal": arsm_ctx.aal,
            "cis": round(arsm_ctx.cis, 2),
            "pc": arsm_ctx.pc,
            "srf": round(arsm_ctx.srf, 2),
            "alpha": coeff.get("alpha", 0.30),
            "beta": coeff.get("beta", 0.25),
            "gamma": coeff.get("gamma", 0.25),
            "delta": coeff.get("delta", 0.20),
        }

        result.verdict, result.avt_classes, result.recommendation = (
            self._compute_verdict(result.ars_score, result.signals)
        )
        result.confidence = self._compute_confidence(result.signals, "npm")

        logger.info(
            "npm analysis complete: %s → ARS=%.1f verdict=%s confidence=%s signals=%d",
            package_name, result.ars_score, result.verdict, result.confidence, len(result.signals),
        )
        return result

    # -- ARSM computation -----------------------------------------------------

    def _compute_arsm(self, cvss_base: float, ctx: ARSMContext) -> float:
        """
        Compute Agentic Risk Score using ARSM formula:
        ARS = CVSS_Base x (1 + alpha*AAL + beta*(1-CIS) + gamma*(1-PC) + delta*log(1+SRF))
        """
        if cvss_base == 0.0:
            return 0.0

        coeff = get_arsm_coefficients(self.config)
        alpha = coeff.get("alpha", ARSM_ALPHA)
        beta = coeff.get("beta", ARSM_BETA)
        gamma = coeff.get("gamma", ARSM_GAMMA)
        delta = coeff.get("delta", ARSM_DELTA)

        multiplier = (
            1.0
            + alpha * ctx.aal
            + beta * (1.0 - ctx.cis)
            + gamma * (1.0 - ctx.pc)
            + delta * math.log(1.0 + ctx.srf)
        )

        ars = min(cvss_base * multiplier, 10.0)
        logger.debug(
            "ARSM: base=%.1f multiplier=%.3f → ARS=%.1f (AAL=%.2f CIS=%.2f PC=%.2f SRF=%.2f)",
            cvss_base, multiplier, ars, ctx.aal, ctx.cis, ctx.pc, ctx.srf,
        )
        return ars

    def _estimate_provenance_confidence(
        self, info: dict, signals: Optional[list[PackageSignal]] = None
    ) -> float:
        """Estimate Provenance Confidence (0-1) from PyPI metadata and signals."""
        score = 0.0
        checks = 0

        # Repo URL exists
        checks += 1
        project_urls = info.get("project_urls") or {}
        home_page = info.get("home_page", "")
        has_url = bool(home_page) or bool(project_urls)
        if has_url:
            score += 1.0

        # Author email present
        checks += 1
        if info.get("author_email"):
            score += 1.0

        # Classifiers present
        checks += 1
        if info.get("classifiers"):
            score += 1.0

        # License present
        checks += 1
        if info.get("license"):
            score += 1.0

        # Multiple releases (not just a single version)
        checks += 1
        # (We don't have releases here; give benefit of doubt)
        score += 0.5

        base_pc = score / checks if checks > 0 else 0.5

        # Adjust based on provenance/attestation signals
        if signals:
            signal_ids = {s.signal_id for s in signals}
            if "PROV-003" in signal_ids:
                base_pc = min(base_pc + 0.3, 1.0)
            if "SIG-001" in signal_ids:
                base_pc = min(base_pc + 0.2, 1.0)
            if "SIG-003" in signal_ids:
                base_pc = max(base_pc - 0.5, 0.0)
            if "PROV-001" in signal_ids:
                base_pc = max(base_pc - 0.4, 0.0)

        return base_pc

    def _estimate_provenance_confidence_npm(self, data: dict) -> float:
        """Estimate Provenance Confidence (0-1) from npm metadata."""
        score = 0.0
        checks = 0

        checks += 1
        if data.get("repository"):
            score += 1.0

        checks += 1
        if data.get("author"):
            score += 1.0

        checks += 1
        if data.get("maintainers"):
            score += 1.0

        checks += 1
        latest = data.get("dist-tags", {}).get("latest", "")
        latest_info = data.get("versions", {}).get(latest, {})
        if latest_info.get("license"):
            score += 1.0

        checks += 1
        if len(data.get("versions", {})) > 1:
            score += 1.0

        return score / checks if checks > 0 else 0.5

    def _estimate_systemic_replication(self, name: str, ecosystem: str) -> float:
        """Estimate Systemic Replication Factor from download stats."""
        try:
            downloads = self._fetch_download_stats(name, ecosystem)
            if downloads is None:
                return 0.0
            # Normalize: 1M+ downloads/week = SRF 1.0
            return min(downloads / 1_000_000.0, 5.0)
        except (requests.RequestException, ValueError, KeyError) as e:
            logger.debug("SRF estimation failed for %s: %s", name, e)
            return 0.0

    def _fetch_download_stats(self, name: str, ecosystem: str) -> Optional[int]:
        """Fetch weekly download count. Returns None on failure."""
        try:
            if ecosystem == "pypi":
                resp = http_client.get(
                    PYPISTATS_API.format(name=name),
                    timeout=5,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("data", {}).get("last_week", None)
            else:
                resp = http_client.get(
                    NPM_DOWNLOADS_API.format(name=name),
                    timeout=5,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("downloads", None)
        except (requests.RequestException, ValueError, KeyError) as e:
            logger.debug("Download stats fetch failed for %s: %s", name, e)
        return None

    # -- CIS & confidence computation ------------------------------------------

    def _compute_cis(self, signals: list[PackageSignal]) -> float:
        """
        Compute Context Integrity Score (0-1) from detected signals.

        CIS measures whether the agent's decision context was compromised.
        Signals that indicate context manipulation lower CIS:
          - INJECT-001: Prompt injection attempts → severe CIS degradation
          - POISON-001: Context poisoning → moderate CIS degradation
          - SPOOF-001: Metadata spoofing → moderate CIS degradation
          - HALLUC-001: Hallucinated package → CIS near zero (agent hallucinated)
        """
        cis = 1.0
        signal_ids = {s.signal_id for s in signals}

        # Hallucinated package = CIS near zero (context is completely unreliable)
        if "HALLUC-001" in signal_ids:
            cis -= 0.8

        # Prompt injection = severe context compromise
        if "INJECT-001" in signal_ids:
            cis -= 0.5

        # Context poisoning = moderate context compromise
        if "POISON-001" in signal_ids:
            cis -= 0.3

        # Metadata spoofing = moderate context compromise
        if "SPOOF-001" in signal_ids:
            cis -= 0.2

        return max(cis, 0.0)

    def _compute_confidence(self, signals: list[PackageSignal], ecosystem: str) -> str:
        """
        Compute confidence level in the ARS score.

        High: Multiple signal categories checked, clear pattern
        Medium: Some signals checked, partial data
        Low: Limited data available, few checks possible
        """
        signal_ids = {s.signal_id for s in signals}
        categories_checked = 0

        # Count distinct signal categories that returned data
        if any(sid.startswith("AGE-") or sid.startswith("VEL-") for sid in signal_ids):
            categories_checked += 1
        if any(sid.startswith("SQUAT-") for sid in signal_ids):
            categories_checked += 1
        if any(sid.startswith("META-") for sid in signal_ids):
            categories_checked += 1
        if any(sid.startswith("DEPTH-") for sid in signal_ids):
            categories_checked += 1
        if any(sid.startswith("PAYLOAD-") for sid in signal_ids):
            categories_checked += 1
        if any(sid.startswith("INJECT-") for sid in signal_ids):
            categories_checked += 1
        if any(sid.startswith("MAINTAINER-") or sid.startswith("SPOOF-") for sid in signal_ids):
            categories_checked += 1

        # Network errors reduce confidence
        has_net_error = any(sid == "NET-001" for sid in signal_ids)
        if has_net_error:
            return "low"

        # Hallucinated package — high confidence in the result
        if "HALLUC-001" in signal_ids:
            return "high"

        # Clean packages with allowlist match — high confidence
        if "ALLOW-001" in signal_ids:
            return "high"

        # Multiple categories with signals — high confidence
        if categories_checked >= 3:
            return "high"
        if categories_checked >= 1:
            return "medium"

        # No signals at all — the package looks clean but we checked
        return "medium"

    # -- Hallucinated package detection ---------------------------------------

    def _handle_hallucinated_package(
        self, result: AnalysisResult, package_name: str, ecosystem: str
    ) -> AnalysisResult:
        """Handle a 404 — package doesn't exist on registry."""
        # Find closest match ("did you mean?")
        suggestion = self._find_closest_package(package_name, ecosystem)
        detail = (
            f"Package '{package_name}' does not exist on "
            f"{'PyPI' if ecosystem == 'pypi' else 'npm'}. "
            "The AI agent may have hallucinated this package name."
        )
        if suggestion:
            detail += f" Did you mean '{suggestion}'?"
            result.did_you_mean = suggestion

        result.signals.append(PackageSignal(
            signal_id="HALLUC-001",
            severity="critical",
            title="Hallucinated package — does not exist on registry",
            detail=detail,
            score_contribution=0.9,
        ))
        result.ars_score = 9.0
        result.verdict = "critical"
        result.avt_classes = ["AVT-D1-03"]
        result.recommendation = (
            "Do not install. Package does not exist — likely hallucinated by the AI agent."
        )
        if suggestion:
            result.recommendation += f" Did you mean '{suggestion}'?"
        return result

    def _find_closest_package(self, name: str, ecosystem: str) -> Optional[str]:
        """Find the closest known package name for 'did you mean?' suggestions."""
        safe = PYPI_SAFE if ecosystem == "pypi" else NPM_SAFE
        popular = POPULAR_PYPI if ecosystem == "pypi" else POPULAR_NPM
        candidates = list(safe) + popular

        clean = name.lower().replace("-", "").replace("_", "")
        best_match = None
        best_ratio = 0.0

        for candidate in candidates:
            clean_candidate = candidate.lower().replace("-", "").replace("_", "")
            ratio = SequenceMatcher(None, clean, clean_candidate).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_match = candidate

        sim_cfg = get_similarity_thresholds(self.config)
        suggest_threshold = sim_cfg.get("suggest", 0.60)
        if best_ratio >= suggest_threshold and best_match:
            return best_match
        return None

    # -- Private signal checks ------------------------------------------------

    def _check_age_velocity_pypi(
        self, name: str, releases: dict, info: dict
    ) -> tuple[Optional[PackageSignal], float]:
        """Check package age against download velocity."""
        if not releases:
            return None, 0.0

        # Find first release date
        first_upload: Optional[datetime.datetime] = None
        for version_files in releases.values():
            for f in version_files:
                upload_str = f.get("upload_time", "")
                if upload_str:
                    try:
                        dt = datetime.datetime.fromisoformat(upload_str)
                        if first_upload is None or dt < first_upload:
                            first_upload = dt
                    except ValueError:
                        pass

        if first_upload is None:
            return None, 0.0

        age_days = (datetime.datetime.utcnow() - first_upload).days

        # Check download velocity for anomaly detection
        vel_cfg = get_velocity_config(self.config)
        age_cfg = get_age_thresholds(self.config)
        critical_days = age_cfg.get("critical_days", 7)
        warning_days = age_cfg.get("warning_days", 30)
        notice_days = age_cfg.get("notice_days", 90)
        anomaly_downloads = vel_cfg.get("anomaly_downloads", 10000)
        age_window = vel_cfg.get("age_window_days", 30)

        velocity_note = ""
        downloads = self._fetch_download_stats(name, "pypi")
        if downloads is not None and age_days < age_window and downloads > anomaly_downloads:
            velocity_note = (
                f" Anomalous download velocity: {downloads:,} downloads/week "
                f"for a {age_days}-day-old package."
            )

        if age_days < critical_days:
            return PackageSignal(
                signal_id="AGE-001",
                severity="high",
                title=f"Package is only {age_days} day(s) old",
                detail=(
                    f"{name} was first published {age_days} day(s) ago. "
                    "Adversarially crafted packages targeting AI agent heuristics "
                    "are typically published within days of deployment."
                    + velocity_note
                ),
                score_contribution=0.85,
            ), 0.85

        if age_days < warning_days:
            contribution = 0.55 if velocity_note else 0.45
            return PackageSignal(
                signal_id="VEL-001" if velocity_note else "AGE-002",
                severity="high" if velocity_note else "medium",
                title=(
                    f"Package is {age_days} days old"
                    + (" with anomalous velocity" if velocity_note else "")
                ),
                detail=(
                    f"{name} was published {age_days} days ago. "
                    "Recent packages have not yet been peer-reviewed by the community."
                    + velocity_note
                ),
                score_contribution=contribution,
            ), contribution

        if age_days < notice_days:
            return PackageSignal(
                signal_id="AGE-003",
                severity="low",
                title=f"Package is {age_days} days old",
                detail=f"{name} is relatively new ({age_days} days). Moderate caution advised.",
                score_contribution=0.2,
            ), 0.2

        return None, 0.0

    def _check_age_velocity_npm(self, data: dict) -> tuple[Optional[PackageSignal], float]:
        """Check npm package age with velocity analysis."""
        time_data = data.get("time", {})
        created_str = time_data.get("created", "")
        name = data.get("name", "unknown")

        if not created_str:
            return None, 0.0

        try:
            created = datetime.datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            created = created.replace(tzinfo=None)
        except ValueError:
            return None, 0.0

        age_days = (datetime.datetime.utcnow() - created).days

        vel_cfg = get_velocity_config(self.config)
        age_cfg = get_age_thresholds(self.config)
        critical_days = age_cfg.get("critical_days", 7)
        warning_days = age_cfg.get("warning_days", 30)
        anomaly_downloads = vel_cfg.get("anomaly_downloads", 10000)
        age_window = vel_cfg.get("age_window_days", 30)

        velocity_note = ""
        downloads = self._fetch_download_stats(name, "npm")
        if downloads is not None and age_days < age_window and downloads > anomaly_downloads:
            velocity_note = (
                f" Anomalous download velocity: {downloads:,} downloads/week "
                f"for a {age_days}-day-old package."
            )

        if age_days < critical_days:
            return PackageSignal(
                signal_id="AGE-001",
                severity="high",
                title=f"Package is only {age_days} day(s) old",
                detail=(
                    f"{name} was published {age_days} day(s) ago. "
                    "Very new packages should be treated with elevated scrutiny."
                    + velocity_note
                ),
                score_contribution=0.85,
            ), 0.85

        if age_days < warning_days:
            contribution = 0.55 if velocity_note else 0.45
            return PackageSignal(
                signal_id="VEL-001" if velocity_note else "AGE-002",
                severity="high" if velocity_note else "medium",
                title=(
                    f"Package is {age_days} days old"
                    + (" with anomalous velocity" if velocity_note else "")
                ),
                detail=(
                    f"{name} is a relatively new package ({age_days} days)."
                    + velocity_note
                ),
                score_contribution=contribution,
            ), contribution

        return None, 0.0

    def _check_release_pattern(
        self, releases: dict, package_name: str
    ) -> tuple[Optional[PackageSignal], float]:
        """
        Analyze release history for suspicious patterns.

        Flags:
          - Single version only (common in throwaway malicious packages)
          - Rapid-fire releases (many versions in a short window)
        """
        version_count = len(releases)
        if version_count == 0:
            return None, 0.0

        # Single version — common in adversarial packages
        if version_count == 1:
            return PackageSignal(
                signal_id="RELEASE-001",
                severity="low",
                title="Single release version",
                detail=(
                    f"{package_name} has only 1 published version. "
                    "Single-version packages are more common in adversarial scenarios."
                ),
                score_contribution=0.2,
            ), 0.2

        # Check for rapid-fire releases (many versions in short window)
        timestamps = []
        for version_files in releases.values():
            for f in version_files:
                upload_str = f.get("upload_time", "")
                if upload_str:
                    try:
                        timestamps.append(datetime.datetime.fromisoformat(upload_str))
                    except ValueError:
                        pass

        if len(timestamps) >= 3:
            timestamps.sort()
            span_days = (timestamps[-1] - timestamps[0]).days
            if span_days > 0:
                releases_per_day = len(timestamps) / span_days
                # More than 2 releases per day sustained is unusual
                if releases_per_day > 2.0 and span_days < 7:
                    return PackageSignal(
                        signal_id="RELEASE-002",
                        severity="medium",
                        title=f"Rapid-fire releases ({len(timestamps)} in {span_days} days)",
                        detail=(
                            f"{package_name} published {len(timestamps)} versions "
                            f"in {span_days} days "
                            f"({releases_per_day:.1f}/day). Rapid releases can indicate "
                            "an attacker iterating on payload delivery."
                        ),
                        score_contribution=0.4,
                    ), 0.4

        return None, 0.0

    def _check_name_squatting(
        self, name: str, popular: list[str]
    ) -> tuple[Optional[PackageSignal], float]:
        """Detect name similarity to popular packages (typosquatting)."""
        clean = name.lower().replace("-", "").replace("_", "")

        best_match: Optional[str] = None
        best_ratio = 0.0

        for popular_pkg in popular:
            if popular_pkg.lower() == name.lower():
                return None, 0.0  # Exact match = it IS the popular package

            clean_popular = popular_pkg.lower().replace("-", "").replace("_", "")
            ratio = SequenceMatcher(None, clean, clean_popular).ratio()

            if ratio > best_ratio:
                best_ratio = ratio
                best_match = popular_pkg

        sim_cfg = get_similarity_thresholds(self.config)
        critical_threshold = sim_cfg.get("critical", 0.85)
        high_threshold = sim_cfg.get("high", 0.70)

        if best_ratio >= critical_threshold and best_match:
            return PackageSignal(
                signal_id="SQUAT-001",
                severity="critical",
                title=f"High name similarity to '{best_match}' ({best_ratio:.0%})",
                detail=(
                    f"'{name}' is {best_ratio:.0%} similar to the popular package '{best_match}'. "
                    f"This is a strong indicator of typosquatting. "
                    f"Verify you intended '{best_match}', not '{name}'."
                ),
                score_contribution=0.95,
            ), 0.95

        if best_ratio >= high_threshold and best_match:
            return PackageSignal(
                signal_id="SQUAT-002",
                severity="high",
                title=f"Moderate name similarity to '{best_match}' ({best_ratio:.0%})",
                detail=(
                    f"'{name}' shares {best_ratio:.0%} character similarity with '{best_match}'. "
                    f"Potential typosquatting. Verify the intended package."
                ),
                score_contribution=0.6,
            ), 0.6

        return None, 0.0

    def _check_name_patterns(self, name: str) -> tuple[Optional[PackageSignal], float]:
        """Match name against known suspicious naming patterns."""
        for pattern in SUSPICIOUS_NAME_PATTERNS:
            if re.match(pattern, name.lower()):
                return PackageSignal(
                    signal_id="PATTERN-001",
                    severity="medium",
                    title=f"Name matches suspicious pattern: {pattern}",
                    detail=(
                        f"'{name}' matches a naming pattern commonly used in "
                        f"adversarially crafted packages targeting AI agent selection heuristics. "
                        f"Pattern: {pattern}"
                    ),
                    score_contribution=0.5,
                ), 0.5

        return None, 0.0

    def _check_metadata_quality(self, info: dict) -> tuple[Optional[PackageSignal], float]:
        """Check PyPI metadata completeness with repo URL verification."""
        issues = []
        score = 0.0

        if not info.get("summary") or len(info.get("summary", "")) < 10:
            issues.append("missing or very short description")
            score += 0.3

        if not info.get("author") and not info.get("author_email"):
            issues.append("no author information")
            score += 0.2

        if not info.get("home_page") and not info.get("project_urls"):
            issues.append("no project URL or homepage")
            score += 0.15
        else:
            # Verify repo URL if present
            repo_url = self._extract_repo_url(info)
            if repo_url and not self._verify_repository_url(repo_url):
                issues.append(f"repository URL returns 404: {repo_url}")
                score += 0.35

        if not info.get("license"):
            issues.append("no license specified")
            score += 0.1

        if issues:
            return PackageSignal(
                signal_id="META-001",
                severity="medium" if score >= 0.5 else "low",
                title=f"Sparse package metadata ({len(issues)} issue(s))",
                detail=(
                    f"Missing: {', '.join(issues)}. "
                    "Legitimate packages typically have complete metadata."
                ),
                score_contribution=min(score, 1.0),
            ), min(score, 1.0)

        return None, 0.0

    def _check_metadata_quality_npm(self, data: dict) -> tuple[Optional[PackageSignal], float]:
        """Check npm metadata quality with repo URL verification."""
        issues = []
        score = 0.0

        if not data.get("description") or len(data.get("description", "")) < 10:
            issues.append("missing or very short description")
            score += 0.3

        if not data.get("repository"):
            issues.append("no repository URL")
            score += 0.2
        else:
            # Verify repo URL
            repo = data.get("repository", {})
            repo_url = repo.get("url", "") if isinstance(repo, dict) else str(repo)
            repo_url = repo_url.replace("git+", "").replace("git://", "https://").rstrip(".git")
            if (repo_url and repo_url.startswith("http")
                    and not self._verify_repository_url(repo_url)):
                issues.append(f"repository URL returns 404: {repo_url}")
                score += 0.35

        if not data.get("author") and not data.get("maintainers"):
            issues.append("no author or maintainer information")
            score += 0.2

        if issues:
            return PackageSignal(
                signal_id="META-001",
                severity="medium" if score >= 0.5 else "low",
                title=f"Sparse package metadata ({len(issues)} issue(s))",
                detail=f"Missing: {', '.join(issues)}.",
                score_contribution=min(score, 1.0),
            ), min(score, 1.0)

        return None, 0.0

    def _extract_repo_url(self, info: dict) -> Optional[str]:
        """Extract a GitHub/GitLab URL from PyPI metadata."""
        project_urls = info.get("project_urls") or {}
        for key in ("Source", "Repository", "Homepage", "Source Code", "Code"):
            url = project_urls.get(key, "")
            if url and ("github.com" in url or "gitlab.com" in url):
                return url

        home_page = info.get("home_page", "")
        if home_page and ("github.com" in home_page or "gitlab.com" in home_page):
            return home_page

        return None

    def _verify_repository_url(self, url: str) -> bool:
        """HEAD request to verify a repository URL is reachable."""
        try:
            resp = http_client.head(url, timeout=5)
            return resp.status_code < 400
        except (requests.RequestException, OSError) as e:
            logger.debug("Repository URL verification failed for %s: %s", url, e)
            return True  # Network error — give benefit of doubt

    def _check_dependency_tree(
        self, package_name: str, ecosystem: str, direct_deps: list[str]
    ) -> tuple[list[PackageSignal], float]:
        """Resolve transitive dependency tree and check for anomalies."""
        signals: list[PackageSignal] = []
        max_contribution = 0.0

        dep_cfg = get_dependency_config(self.config)
        high_count = dep_cfg.get("high_count", 50)
        elevated_count = dep_cfg.get("elevated_count", 25)
        deep_chain = dep_cfg.get("deep_chain", 4)

        try:
            resolver = self._get_resolver()
            tree = resolver.resolve_tree(package_name, ecosystem)

            if tree.nodes:
                pass  # Store for display later

            # Check total transitive count
            if tree.total_count > high_count:
                sig = PackageSignal(
                    signal_id="DEPTH-001",
                    severity="medium",
                    title=f"Very high transitive dependency count ({tree.total_count})",
                    detail=(
                        f"Package has {tree.total_count} transitive dependencies. "
                        "High counts expand the attack surface "
                        "for supply chain attacks (AVT-D3-04)."
                    ),
                    score_contribution=0.5,
                )
                signals.append(sig)
                max_contribution = max(max_contribution, 0.5)

            elif tree.total_count > elevated_count:
                sig = PackageSignal(
                    signal_id="DEPTH-002",
                    severity="low",
                    title=f"Elevated transitive dependency count ({tree.total_count})",
                    detail=f"Package has {tree.total_count} transitive dependencies.",
                    score_contribution=0.3,
                )
                signals.append(sig)
                max_contribution = max(max_contribution, 0.3)

            # Check max depth
            if tree.max_depth > deep_chain:
                sig = PackageSignal(
                    signal_id="DEPTH-003",
                    severity="medium",
                    title=f"Deep dependency chain (depth {tree.max_depth})",
                    detail=(
                        f"Dependency tree reaches depth {tree.max_depth}. "
                        "Deep chains are harder to audit."
                    ),
                    score_contribution=0.35,
                )
                signals.append(sig)
                max_contribution = max(max_contribution, 0.35)

            # Check for suspicious packages in tree
            if tree.suspicious_packages:
                sig = PackageSignal(
                    signal_id="DEPTH-SUSP",
                    severity="critical",
                    title=(
                        "Suspicious package(s) in dependency tree: "
                        f"{', '.join(tree.suspicious_packages[:3])}"
                    ),
                    detail=(
                        f"Found {len(tree.suspicious_packages)} suspicious transitive "
                        f"dependencies: {', '.join(tree.suspicious_packages[:5])}."
                    ),
                    score_contribution=0.9,
                )
                signals.append(sig)
                max_contribution = max(max_contribution, 0.9)

        except (requests.RequestException, ValueError, KeyError, OSError) as e:
            logger.debug("Dependency tree resolution failed for %s: %s", package_name, e)
            # Fallback to simple direct dep count check
            count = len(direct_deps)
            if count > 25:
                sig = PackageSignal(
                    signal_id="DEPTH-001",
                    severity="medium",
                    title=f"Unusually high dependency count ({count} direct deps)",
                    detail=f"This package declares {count} direct dependencies.",
                    score_contribution=0.4,
                )
                signals.append(sig)
                max_contribution = 0.4
            elif count > 15:
                sig = PackageSignal(
                    signal_id="DEPTH-002",
                    severity="low",
                    title=f"Elevated dependency count ({count} direct deps)",
                    detail=f"Package has {count} direct dependencies.",
                    score_contribution=0.2,
                )
                signals.append(sig)
                max_contribution = 0.2

        return signals, max_contribution

    def _check_payload(
        self, package_name: str, ecosystem: str, version: str
    ) -> list[PackageSignal]:
        """Run static payload analysis on the package source."""
        try:
            analyzer = self._get_payload_analyzer()
            return analyzer.analyze_package(package_name, ecosystem, version)
        except (OSError, ValueError, ImportError) as e:
            logger.warning("Payload analysis failed for %s: %s", package_name, e)
            return []

    def _check_prompt_injection(
        self, description: str, package_name: str
    ) -> tuple[Optional[PackageSignal], float]:
        """Check package description for prompt injection patterns."""
        from uast.payload import scan_for_prompt_injection

        description = description or ""
        matches = scan_for_prompt_injection(description)
        if matches:
            sample = matches[0][:80]
            logger.warning(
                "Prompt injection detected in %s description: %s", package_name, sample
            )
            return (
                PackageSignal(
                    signal_id="INJECT-001",
                    severity="critical",
                    title="Prompt injection pattern in package description",
                    detail=(
                        f"Package description contains text that may attempt to manipulate "
                        f"AI coding agents: \"{sample}\". "
                        f"Found {len(matches)} injection pattern(s)."
                    ),
                    score_contribution=0.9,
                ),
                0.9,
            )
        return None, 0.0

    # -- AVT-D4: Trust & Identity checks ----------------------------------------

    # Disposable email domains commonly used in throwaway accounts
    DISPOSABLE_EMAIL_DOMAINS = {
        "mailinator.com", "tempmail.com", "throwaway.email", "guerrillamail.com",
        "sharklasers.com", "guerrillamail.info", "grr.la", "guerrillamail.biz",
        "guerrillamail.de", "guerrillamail.net", "guerrillamail.org",
        "yopmail.com", "yopmail.fr", "cool.fr.nf", "jetable.fr.nf",
        "trashmail.com", "trashmail.org", "trashmail.me", "trashmail.net",
        "dispostable.com", "maildrop.cc", "mailnesia.com", "tempail.com",
        "tempr.email", "10minutemail.com", "20minutemail.com",
        "mohmal.com", "getnada.com", "emailondeck.com", "temp-mail.org",
    }

    def _check_maintainer_trust(
        self, info: dict, ecosystem: str
    ) -> tuple[Optional[PackageSignal], float]:
        """MAINTAINER-001: Check maintainer trustworthiness signals."""
        issues = []

        if ecosystem == "pypi":
            author_email = info.get("author_email", "") or ""
            author = info.get("author", "") or ""

            # Check disposable email
            if author_email:
                domain = author_email.split("@")[-1].lower() if "@" in author_email else ""
                if domain in self.DISPOSABLE_EMAIL_DOMAINS:
                    issues.append(f"author email uses disposable domain: {domain}")

            # No author identity at all
            if not author and not author_email:
                issues.append("no author identity (name or email)")

        elif ecosystem == "npm":
            maintainers = info.get("maintainers", [])
            author = info.get("author", {})

            # Single maintainer with no other identity signals
            if len(maintainers) == 1:
                maintainers[0].get("name", "") if maintainers else ""
                m_email = maintainers[0].get("email", "") if maintainers else ""
                if m_email:
                    domain = m_email.split("@")[-1].lower() if "@" in m_email else ""
                    if domain in self.DISPOSABLE_EMAIL_DOMAINS:
                        issues.append(f"sole maintainer uses disposable email: {domain}")

            if not maintainers and not author:
                issues.append("no maintainer or author information")

        if issues:
            score = min(0.3 * len(issues), 0.7)
            return PackageSignal(
                signal_id="MAINTAINER-001",
                severity="medium" if len(issues) >= 2 else "low",
                title=f"Maintainer trust concern ({len(issues)} issue(s))",
                detail=(
                    f"Maintainer identity signals: {'; '.join(issues)}. "
                    "Packages with weak maintainer provenance carry higher impersonation risk."
                ),
                score_contribution=score,
            ), score

        return None, 0.0

    def _check_metadata_spoofing(
        self, info: dict, package_name: str, ecosystem: str
    ) -> tuple[Optional[PackageSignal], float]:
        """SPOOF-001: Detect metadata that appears deliberately misleading."""
        issues = []

        if ecosystem == "pypi":
            summary = (info.get("summary", "") or "").lower()
            description = (info.get("description", "") or "").lower()
            (info.get("author", "") or "").lower()
            (info.get("home_page", "") or "").lower()

            # Check if description mentions a different popular package name
            for popular in POPULAR_PYPI:
                pop_lower = popular.lower()
                if pop_lower != package_name.lower() and pop_lower in summary:
                    # The description references a different well-known package
                    # This could be a squatter copying descriptions
                    issues.append(
                        f"description references popular package '{popular}' "
                        f"but package name is '{package_name}'"
                    )
                    break

        elif ecosystem == "npm":
            description = (info.get("description", "") or "").lower()

            for popular in POPULAR_NPM:
                pop_lower = popular.lower()
                if pop_lower != package_name.lower() and pop_lower in description:
                    issues.append(
                        f"description references popular package '{popular}' "
                        f"but package name is '{package_name}'"
                    )
                    break

        if issues:
            score = min(0.4 * len(issues), 0.8)
            return PackageSignal(
                signal_id="SPOOF-001",
                severity="high" if len(issues) >= 2 else "medium",
                title=f"Potential metadata spoofing ({len(issues)} indicator(s))",
                detail=(
                    f"Metadata inconsistencies: {'; '.join(issues)}. "
                    "This may indicate a deliberately misleading package."
                ),
                score_contribution=score,
            ), score

        return None, 0.0

    # -- Provenance & version diff checks -----------------------------------

    def _check_provenance(
        self, package_name: str, version: str, info: dict
    ) -> list[PackageSignal]:
        """Run provenance verification on a package."""
        try:
            from uast.provenance import ProvenanceVerifier

            prov_cfg = self.config.get("provenance", {})
            verifier = ProvenanceVerifier(
                clone_timeout=prov_cfg.get("clone_timeout", 60),
                build_timeout=prov_cfg.get("build_timeout", 120),
                max_repo_size_mb=prov_cfg.get("max_repo_size_mb", 100),
            )

            prov_result, signals = verifier.verify_source(
                package_name, version, info=info,
            )

            # Store provenance result on the analysis result (via metadata)
            # Will be attached by the caller
            self._last_provenance = prov_result

            # Also check attestations
            attestation_status, att_signals = verifier.check_attestation(
                package_name, version,
            )
            signals.extend(att_signals)

            if prov_result:
                prov_result.attestation = attestation_status

            return signals
        except Exception as e:
            logger.warning("Provenance check failed for %s: %s", package_name, e)
            return []

    def _check_version_diff(
        self, package_name: str, version: str
    ) -> list[PackageSignal]:
        """Run version diff check on a package."""
        try:
            from uast.version_diff import VersionDiffer, diff_to_signals

            differ = VersionDiffer()
            diff_result = differ.diff_versions(package_name, version)

            # Store for report
            self._last_version_diff = diff_result

            return diff_to_signals(diff_result)
        except Exception as e:
            logger.debug("Version diff failed for %s: %s", package_name, e)
            return []

    # -- Legacy compat method (used by tests) ---------------------------------

    def _check_dependency_depth(
        self, deps: list[str]
    ) -> tuple[Optional[PackageSignal], float]:
        """Flag unusual direct dependency counts (legacy, non-tree version)."""
        count = len(deps)

        if count > 25:
            return PackageSignal(
                signal_id="DEPTH-001",
                severity="medium",
                title=f"Unusually high dependency count ({count} direct deps)",
                detail=(
                    f"This package declares {count} direct dependencies. "
                    f"High dependency counts expand the attack surface for "
                    f"transitive supply chain attacks (AVT-D3-04)."
                ),
                score_contribution=0.4,
            ), 0.4

        if count > 15:
            return PackageSignal(
                signal_id="DEPTH-002",
                severity="low",
                title=f"Elevated dependency count ({count} direct deps)",
                detail=f"Package has {count} direct dependencies. Moderate transitive risk.",
                score_contribution=0.2,
            ), 0.2

        return None, 0.0

    def _compute_verdict(
        self, ars_score: float, signals: list[PackageSignal]
    ) -> tuple[str, list[str], str]:
        """Compute final verdict, AVT classes, and recommendation."""
        avt_classes: list[str] = []
        has_critical = any(s.severity == "critical" for s in signals)
        has_squatting = any("SQUAT" in s.signal_id for s in signals)
        has_halluc = any("HALLUC" in s.signal_id for s in signals)
        has_age = any("AGE-001" in s.signal_id for s in signals)
        has_pattern = any("PATTERN" in s.signal_id for s in signals)
        has_payload = any("PAYLOAD" in s.signal_id for s in signals)
        has_depth_susp = any("DEPTH-SUSP" in s.signal_id for s in signals)
        has_inject = any("INJECT" in s.signal_id for s in signals)
        has_poison = any("POISON" in s.signal_id for s in signals)
        has_priv = any("PRIV" in s.signal_id for s in signals)
        has_scope = any("SCOPE" in s.signal_id for s in signals)
        has_spoof = any("SPOOF" in s.signal_id for s in signals)
        has_maintainer = any("MAINTAINER" in s.signal_id for s in signals)
        has_prov_fail = any(
            s.signal_id in ("PROV-001", "SIG-003") for s in signals
        )

        if has_inject or has_poison:
            avt_classes.append("AVT-D1-01")
        if has_priv:
            avt_classes.append("AVT-D2-01")
        if has_scope:
            avt_classes.append("AVT-D2-02")
        if has_spoof or has_maintainer:
            avt_classes.append("AVT-D4-01")
        if has_squatting:
            avt_classes.append("AVT-D3-01")
        if has_halluc:
            avt_classes.append("AVT-D1-03")
        if has_age or has_pattern or has_depth_susp:
            avt_classes.append("AVT-D3-04")
        if has_payload:
            avt_classes.append("AVT-D3-02")
        if has_prov_fail:
            avt_classes.append("AVT-D3-05")

        # Deduplicate
        avt_classes = list(dict.fromkeys(avt_classes))

        if ars_score >= 7.5 or has_critical:
            return (
                "critical",
                avt_classes,
                "Do not install. Flag for immediate security review. "
                "This package exhibits multiple indicators of adversarial crafting.",
            )

        if ars_score >= 5.0:
            return (
                "suspicious",
                avt_classes,
                "Treat with caution. Manually verify the package source, "
                "maintainer, and intended behavior before installing.",
            )

        return (
            "clean",
            avt_classes,
            "No significant risk signals detected. Standard due diligence applies.",
        )
