"""
Dependency Resolver — recursive transitive dependency graph traversal.

Builds a dependency tree for a given package by recursively fetching
dependency metadata from PyPI / npm. Includes safety limits:
  - MAX_DEPTH (5) — stops descending further
  - MAX_PACKAGES (200) — circuit breaker for total node count
  - Cycle detection via visited set
  - Memoization cache for cross-analysis reuse
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Optional

import requests

from uast.analyzer import (
    NPM_SAFE,
    POPULAR_NPM,
    POPULAR_PYPI,
    PYPI_SAFE,
    SUSPICIOUS_NAME_PATTERNS,
)
from uast.http_client import http_client

logger = logging.getLogger("uast.resolver")


@dataclass
class DependencyNode:
    """A single node in the dependency tree."""
    name: str
    ecosystem: str
    depth: int
    children: list["DependencyNode"] = field(default_factory=list)
    suspicious: bool = False
    suspicion_reason: Optional[str] = None


@dataclass
class DependencyTree:
    """Full resolved dependency tree."""
    root: str
    ecosystem: str
    nodes: list[DependencyNode] = field(default_factory=list)
    total_count: int = 0
    max_depth: int = 0
    suspicious_packages: list[str] = field(default_factory=list)
    truncated: bool = False


class DependencyResolver:
    """Resolves transitive dependency graphs with safety limits."""

    PYPI_API = "https://pypi.org/pypi/{name}/json"
    NPM_API = "https://registry.npmjs.org/{name}"

    DEFAULT_MAX_DEPTH = 5
    DEFAULT_MAX_PACKAGES = 200

    def __init__(
        self,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_packages: int = DEFAULT_MAX_PACKAGES,
    ) -> None:
        self.MAX_DEPTH = max_depth
        self.MAX_PACKAGES = max_packages
        self._memo: dict[str, list[str]] = {}  # name -> direct deps
        self._visited: set[str] = set()
        self._total_count = 0

    def resolve_tree(self, package_name: str, ecosystem: str) -> DependencyTree:
        """Build the full transitive dependency tree for a package."""
        logger.info("Resolving dependency tree for %s (%s)", package_name, ecosystem)
        self._visited = set()
        self._total_count = 0

        tree = DependencyTree(root=package_name, ecosystem=ecosystem)
        root_node = self._resolve_node(package_name, ecosystem, depth=0)

        if root_node:
            tree.nodes = root_node.children
            tree.total_count = self._total_count
            tree.max_depth = self._compute_max_depth(root_node)
            tree.suspicious_packages = self._collect_suspicious(root_node)
            tree.truncated = self._total_count >= self.MAX_PACKAGES

        logger.info(
            "Dependency tree resolved: %s → %d packages, max depth %d, %d suspicious",
            package_name, tree.total_count, tree.max_depth, len(tree.suspicious_packages),
        )
        return tree

    def _resolve_node(
        self, name: str, ecosystem: str, depth: int
    ) -> Optional[DependencyNode]:
        """Recursively resolve a single dependency node."""
        # Safety limits
        if depth > self.MAX_DEPTH:
            logger.debug("Max depth reached (%d) for %s", self.MAX_DEPTH, name)
            return None
        if self._total_count >= self.MAX_PACKAGES:
            logger.debug("Max packages reached (%d) — stopping", self.MAX_PACKAGES)
            return None

        key = f"{ecosystem}:{name.lower()}"
        if key in self._visited:
            logger.debug("Cycle detected: %s already visited", name)
            return None  # Cycle detected
        self._visited.add(key)
        self._total_count += 1

        node = DependencyNode(name=name, ecosystem=ecosystem, depth=depth)

        # Check if this dep is suspicious (lightweight checks)
        self._check_node_suspicion(node, ecosystem)

        # Fetch direct dependencies
        deps = self._fetch_deps(name, ecosystem)

        for dep_name in deps:
            child = self._resolve_node(dep_name, ecosystem, depth + 1)
            if child:
                node.children.append(child)

        return node

    def _fetch_deps(self, name: str, ecosystem: str) -> list[str]:
        """Fetch direct dependencies from registry (with memoization)."""
        cache_key = f"{ecosystem}:{name.lower()}"
        if cache_key in self._memo:
            return self._memo[cache_key]

        deps: list[str] = []
        try:
            if ecosystem == "pypi":
                deps = self._fetch_deps_pypi(name)
            else:
                deps = self._fetch_deps_npm(name)
        except (requests.RequestException, ValueError, KeyError):
            pass

        self._memo[cache_key] = deps
        return deps

    def _fetch_deps_pypi(self, name: str) -> list[str]:
        """Fetch direct dependencies from PyPI."""
        resp = http_client.get(self.PYPI_API.format(name=name))
        if resp.status_code != 200:
            return []

        data = resp.json()
        requires_dist = data.get("info", {}).get("requires_dist") or []

        deps = []
        for req_str in requires_dist:
            # Skip extras: "package ; extra == 'dev'"
            if "extra ==" in req_str or "extra==" in req_str:
                continue
            # Extract base package name
            dep_name = re.split(r"[><=!~\[;\s]", req_str)[0].strip()
            if dep_name:
                deps.append(dep_name)

        return deps

    def _fetch_deps_npm(self, name: str) -> list[str]:
        """Fetch direct dependencies from npm."""
        resp = http_client.get(self.NPM_API.format(name=name))
        if resp.status_code != 200:
            return []

        data = resp.json()
        latest = data.get("dist-tags", {}).get("latest", "")
        if not latest:
            return []

        version_info = data.get("versions", {}).get(latest, {})
        return list((version_info.get("dependencies") or {}).keys())

    def _check_node_suspicion(self, node: DependencyNode, ecosystem: str) -> None:
        """Lightweight check if a transitive dep looks suspicious."""
        name = node.name.lower()
        safe = PYPI_SAFE if ecosystem == "pypi" else NPM_SAFE
        popular = POPULAR_PYPI if ecosystem == "pypi" else POPULAR_NPM

        if name in safe:
            return

        # Check name patterns
        for pattern in SUSPICIOUS_NAME_PATTERNS:
            if re.match(pattern, name):
                node.suspicious = True
                node.suspicion_reason = f"Matches suspicious pattern: {pattern}"
                return

        # Check name similarity to popular packages
        clean = name.replace("-", "").replace("_", "")
        for pop in popular:
            if pop.lower() == name:
                return  # Exact match
            clean_pop = pop.lower().replace("-", "").replace("_", "")
            ratio = SequenceMatcher(None, clean, clean_pop).ratio()
            if ratio >= 0.85:
                node.suspicious = True
                node.suspicion_reason = f"Name similar to '{pop}' ({ratio:.0%})"
                return

    def _compute_max_depth(self, node: DependencyNode) -> int:
        """Compute maximum depth of the tree."""
        if not node.children:
            return node.depth
        return max(self._compute_max_depth(c) for c in node.children)

    def _collect_suspicious(self, node: DependencyNode) -> list[str]:
        """Collect all suspicious package names from the tree."""
        result = []
        if node.suspicious:
            result.append(node.name)
        for child in node.children:
            result.extend(self._collect_suspicious(child))
        return result
