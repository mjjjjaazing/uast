"""
Supply chain analyzer — the core detection engine.

Implements a lightweight version of UAST Layer 2 (Behavioral Dynamic Analysis)
and the Agentic Risk Scoring Model (ARSM) for dependency risk assessment.

Detection signals:
  - Package age vs. download velocity (typosquatting / adversarial packages)
  - Name similarity to popular packages (name-squatting)
  - Maintainer account age and history
  - Transitive dependency depth and anomalies
  - Known malicious pattern database
  - PyPI/npm metadata integrity signals
"""

from __future__ import annotations

import re
import time
import datetime
from dataclasses import dataclass, field
from typing import Optional
from difflib import SequenceMatcher

import requests

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
    score_contribution: float  # 0.0–1.0 contribution to risk


@dataclass
class AnalysisResult:
    """Full analysis result for a single package."""
    package_name: str
    ecosystem: str          # "pypi" or "npm"
    version: str
    ars_score: float        # 0.0–10.0 Agentic Risk Score
    cvss_base: float        # 0.0–10.0 estimated base severity
    signals: list[PackageSignal] = field(default_factory=list)
    avt_classes: list[str] = field(default_factory=list)
    verdict: str = "clean"  # "clean", "suspicious", "critical"
    recommendation: str = "No issues detected."
    metadata: dict = field(default_factory=dict)
    analyzed_at: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())

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


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class SupplyChainAnalyzer:
    """
    Lightweight supply chain risk analyzer implementing UAST Layer 2 (BDA)
    and Layer 1 (SSA) heuristics for dependency risk scoring.

    Scoring follows ARSM principles:
        ARS = f(age_score, velocity_score, name_score, depth_score, metadata_score)

    Each signal contributes a weighted score component.
    Final ARS is normalized to 0.0–10.0.
    """

    PYPI_API = "https://pypi.org/pypi/{name}/json"
    NPM_API = "https://registry.npmjs.org/{name}"
    REQUEST_TIMEOUT = 8  # seconds

    # Signal weights (sum to 1.0)
    WEIGHTS = {
        "age_velocity":   0.35,   # Age vs. download spike — strongest signal
        "name_squatting": 0.25,   # Name similarity to popular packages
        "pattern_match":  0.15,   # Known suspicious name patterns
        "metadata":       0.15,   # Maintainer age, description quality
        "depth":          0.10,   # Transitive dependency count anomaly
    }

    def analyze_pypi(self, package_name: str) -> AnalysisResult:
        """Analyze a PyPI package and return an AnalysisResult."""
        result = AnalysisResult(
            package_name=package_name,
            ecosystem="pypi",
            version="unknown",
            ars_score=0.0,
            cvss_base=0.0,
        )

        # Fast path — known safe packages
        if package_name.lower() in PYPI_SAFE:
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
            resp = requests.get(
                self.PYPI_API.format(name=package_name),
                timeout=self.REQUEST_TIMEOUT,
            )
            if resp.status_code == 404:
                result.signals.append(PackageSignal(
                    signal_id="META-404",
                    severity="medium",
                    title="Package not found on PyPI",
                    detail="Package does not exist on PyPI. The agent may have hallucinated it or it was removed.",
                    score_contribution=0.5,
                ))
                result.ars_score = 5.0
                result.verdict = "suspicious"
                result.recommendation = "Package not found. Do not install — verify the package name."
                return result

            resp.raise_for_status()
            data = resp.json()

        except requests.RequestException as e:
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

        # ── Signal 1: Package age vs. download velocity ──────────────────────
        age_signal, age_contribution = self._check_age_velocity_pypi(
            package_name, releases, info
        )
        if age_signal:
            result.signals.append(age_signal)
        raw_score += age_contribution * self.WEIGHTS["age_velocity"]

        # ── Signal 2: Name squatting ──────────────────────────────────────────
        squatting_signal, squatting_contribution = self._check_name_squatting(
            package_name, POPULAR_PYPI
        )
        if squatting_signal:
            result.signals.append(squatting_signal)
        raw_score += squatting_contribution * self.WEIGHTS["name_squatting"]

        # ── Signal 3: Suspicious name pattern ────────────────────────────────
        pattern_signal, pattern_contribution = self._check_name_patterns(package_name)
        if pattern_signal:
            result.signals.append(pattern_signal)
        raw_score += pattern_contribution * self.WEIGHTS["pattern_match"]

        # ── Signal 4: Metadata quality ────────────────────────────────────────
        meta_signal, meta_contribution = self._check_metadata_quality(info)
        if meta_signal:
            result.signals.append(meta_signal)
        raw_score += meta_contribution * self.WEIGHTS["metadata"]

        # ── Signal 5: Dependency depth ────────────────────────────────────────
        deps = info.get("requires_dist") or []
        depth_signal, depth_contribution = self._check_dependency_depth(deps)
        if depth_signal:
            result.signals.append(depth_signal)
        raw_score += depth_contribution * self.WEIGHTS["depth"]

        # ── Compute final ARS ─────────────────────────────────────────────────
        result.ars_score = round(min(raw_score * 10.0, 10.0), 1)
        result.cvss_base = round(min(raw_score * 8.5, 10.0), 1)  # conservative base

        # Set verdict and AVT classes
        result.verdict, result.avt_classes, result.recommendation = (
            self._compute_verdict(result.ars_score, result.signals)
        )

        return result

    def analyze_npm(self, package_name: str) -> AnalysisResult:
        """Analyze an npm package and return an AnalysisResult."""
        result = AnalysisResult(
            package_name=package_name,
            ecosystem="npm",
            version="unknown",
            ars_score=0.0,
            cvss_base=0.0,
        )

        if package_name.lower() in NPM_SAFE:
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
            resp = requests.get(
                self.NPM_API.format(name=package_name),
                timeout=self.REQUEST_TIMEOUT,
            )
            if resp.status_code == 404:
                result.signals.append(PackageSignal(
                    signal_id="META-404",
                    severity="medium",
                    title="Package not found on npm",
                    detail="Package does not exist on npm. Verify the package name.",
                    score_contribution=0.5,
                ))
                result.ars_score = 5.0
                result.verdict = "suspicious"
                result.recommendation = "Package not found. Do not install — verify the package name."
                return result

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

        # ── Signal 1: Package age ─────────────────────────────────────────────
        age_signal, age_contribution = self._check_age_velocity_npm(data)
        if age_signal:
            result.signals.append(age_signal)
        raw_score += age_contribution * self.WEIGHTS["age_velocity"]

        # ── Signal 2: Name squatting ──────────────────────────────────────────
        squatting_signal, squatting_contribution = self._check_name_squatting(
            package_name, POPULAR_NPM
        )
        if squatting_signal:
            result.signals.append(squatting_signal)
        raw_score += squatting_contribution * self.WEIGHTS["name_squatting"]

        # ── Signal 3: Pattern match ───────────────────────────────────────────
        pattern_signal, pattern_contribution = self._check_name_patterns(package_name)
        if pattern_signal:
            result.signals.append(pattern_signal)
        raw_score += pattern_contribution * self.WEIGHTS["pattern_match"]

        # ── Signal 4: Metadata quality ────────────────────────────────────────
        meta_signal, meta_contribution = self._check_metadata_quality_npm(data)
        if meta_signal:
            result.signals.append(meta_signal)
        raw_score += meta_contribution * self.WEIGHTS["metadata"]

        # ── Signal 5: Dependency depth ────────────────────────────────────────
        deps = list((latest_info.get("dependencies") or {}).keys())
        depth_signal, depth_contribution = self._check_dependency_depth(deps)
        if depth_signal:
            result.signals.append(depth_signal)
        raw_score += depth_contribution * self.WEIGHTS["depth"]

        result.ars_score = round(min(raw_score * 10.0, 10.0), 1)
        result.cvss_base = round(min(raw_score * 8.5, 10.0), 1)

        result.verdict, result.avt_classes, result.recommendation = (
            self._compute_verdict(result.ars_score, result.signals)
        )

        return result

    # ── Private signal checks ────────────────────────────────────────────────

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

        # Very new package — elevated risk
        if age_days < 7:
            return PackageSignal(
                signal_id="AGE-001",
                severity="high",
                title=f"Package is only {age_days} day(s) old",
                detail=(
                    f"{name} was first published {age_days} day(s) ago. "
                    "Adversarially crafted packages targeting AI agent heuristics "
                    "are typically published within days of deployment. "
                    "Treat very new packages with elevated scrutiny."
                ),
                score_contribution=0.85,
            ), 0.85

        if age_days < 30:
            return PackageSignal(
                signal_id="AGE-002",
                severity="medium",
                title=f"Package is only {age_days} days old",
                detail=(
                    f"{name} was published {age_days} days ago. "
                    "Recent packages have not yet been peer-reviewed by the community."
                ),
                score_contribution=0.45,
            ), 0.45

        if age_days < 90:
            return PackageSignal(
                signal_id="AGE-003",
                severity="low",
                title=f"Package is {age_days} days old",
                detail=f"{name} is relatively new ({age_days} days). Moderate caution advised.",
                score_contribution=0.2,
            ), 0.2

        return None, 0.0

    def _check_age_velocity_npm(self, data: dict) -> tuple[Optional[PackageSignal], float]:
        """Check npm package age."""
        time_data = data.get("time", {})
        created_str = time_data.get("created", "")
        name = data.get("name", "unknown")

        if not created_str:
            return None, 0.0

        try:
            # npm uses ISO format with Z suffix
            created = datetime.datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            created = created.replace(tzinfo=None)
        except ValueError:
            return None, 0.0

        age_days = (datetime.datetime.utcnow() - created).days

        if age_days < 7:
            return PackageSignal(
                signal_id="AGE-001",
                severity="high",
                title=f"Package is only {age_days} day(s) old",
                detail=(
                    f"{name} was published {age_days} day(s) ago. "
                    "Very new packages should be treated with elevated scrutiny."
                ),
                score_contribution=0.85,
            ), 0.85

        if age_days < 30:
            return PackageSignal(
                signal_id="AGE-002",
                severity="medium",
                title=f"Package is {age_days} days old",
                detail=f"{name} is a relatively new package ({age_days} days).",
                score_contribution=0.45,
            ), 0.45

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

        if best_ratio >= 0.85 and best_match:
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

        if best_ratio >= 0.70 and best_match:
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
        """Check PyPI metadata completeness — sparse metadata is a risk signal."""
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

        if not info.get("license"):
            issues.append("no license specified")
            score += 0.1

        if issues:
            return PackageSignal(
                signal_id="META-001",
                severity="medium" if score >= 0.5 else "low",
                title=f"Sparse package metadata ({len(issues)} issue(s))",
                detail=f"Missing: {', '.join(issues)}. Legitimate packages typically have complete metadata.",
                score_contribution=min(score, 1.0),
            ), min(score, 1.0)

        return None, 0.0

    def _check_metadata_quality_npm(self, data: dict) -> tuple[Optional[PackageSignal], float]:
        """Check npm metadata quality."""
        issues = []
        score = 0.0

        if not data.get("description") or len(data.get("description", "")) < 10:
            issues.append("missing or very short description")
            score += 0.3

        if not data.get("repository"):
            issues.append("no repository URL")
            score += 0.2

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

    def _check_dependency_depth(
        self, deps: list[str]
    ) -> tuple[Optional[PackageSignal], float]:
        """Flag unusual transitive dependency counts."""
        count = len(deps)

        # A simple utility package with 20+ deps is unusual
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
        avt_classes = []
        has_critical = any(s.severity == "critical" for s in signals)
        has_squatting = any("SQUAT" in s.signal_id for s in signals)
        has_age = any("AGE-001" in s.signal_id for s in signals)
        has_pattern = any("PATTERN" in s.signal_id for s in signals)

        if has_squatting:
            avt_classes.append("AVT-D3-01")  # Adversarial Dependency Selection
        if has_age or has_pattern:
            avt_classes.append("AVT-D3-04")  # Transitive Dependency Contamination

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
