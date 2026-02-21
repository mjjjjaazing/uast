"""
Merkle Tree Hashing — tamper-evident hash of dependency trees.

Computes a deterministic SHA-256 Merkle root hash over a dependency tree,
enabling audit trails and drift detection between sessions.

Hash formula per node:
    H(name || version || sort([child_hashes]))

Properties:
  - Deterministic: same tree always produces the same hash
  - Order-independent: child ordering doesn't affect hash
  - Tamper-evident: any change in name/version/structure changes root hash
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Optional

from uast.resolver import DependencyNode, DependencyTree

logger = logging.getLogger("uast.merkle")


def compute_node_hash(
    node: DependencyNode,
    version_map: dict[str, str],
) -> str:
    """
    Compute the SHA-256 hash for a single dependency node.

    The hash incorporates:
      - The package name (lowercased for consistency)
      - The resolved version from version_map (or "unknown")
      - Sorted hashes of all child nodes (order-independent)

    Args:
        node: A DependencyNode from the resolved tree.
        version_map: Mapping of package name → version string.

    Returns:
        Hex-encoded SHA-256 hash string.
    """
    name = node.name.lower()
    version = version_map.get(name, version_map.get(node.name, "unknown"))

    child_hashes = sorted(
        compute_node_hash(c, version_map) for c in node.children
    )

    payload = f"{name}||{version}||{'|'.join(child_hashes)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_tree_hash(
    tree: DependencyTree,
    version_map: Optional[dict[str, str]] = None,
) -> str:
    """
    Compute the Merkle root hash for an entire dependency tree.

    Creates a synthetic root node that encompasses all direct dependencies,
    producing a single deterministic hash for the full tree.

    Args:
        tree: A resolved DependencyTree.
        version_map: Optional mapping of package name → version.
                     If None, all versions default to "unknown".

    Returns:
        Hex-encoded SHA-256 Merkle root hash.
    """
    if version_map is None:
        version_map = {}

    if not tree.nodes:
        # Empty tree — hash just the root name
        root_name = tree.root.lower()
        root_version = version_map.get(root_name, version_map.get(tree.root, "unknown"))
        payload = f"{root_name}||{root_version}||"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    # Create a synthetic root that has tree.nodes as children
    child_hashes = sorted(
        compute_node_hash(n, version_map) for n in tree.nodes
    )

    root_name = tree.root.lower()
    root_version = version_map.get(root_name, version_map.get(tree.root, "unknown"))
    payload = f"{root_name}||{root_version}||{'|'.join(child_hashes)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def diff_tree_hashes(
    hash_a: str,
    hash_b: str,
    label_a: str = "session A",
    label_b: str = "session B",
) -> dict:
    """
    Compare two Merkle root hashes and return a diff summary.

    Args:
        hash_a: Merkle root hash from first session.
        hash_b: Merkle root hash from second session.
        label_a: Human-readable label for first session.
        label_b: Human-readable label for second session.

    Returns:
        Dict with match status and details.
    """
    match = hash_a == hash_b
    return {
        "match": match,
        "drift_detected": not match,
        label_a: hash_a,
        label_b: hash_b,
        "summary": (
            "Dependency trees are identical."
            if match
            else "Dependency tree drift detected — trees differ."
        ),
    }


def load_session_hash(report_path: str) -> Optional[str]:
    """
    Load the dependency_tree_hash from a saved session report.

    Args:
        report_path: Path to a JSON session report file.

    Returns:
        The Merkle root hash string, or None if not present.
    """
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        results = data.get("results", [])
        if results:
            return results[0].get("dependency_tree_hash")
        return None
    except (OSError, json.JSONDecodeError, KeyError) as e:
        logger.warning("Failed to load session hash from %s: %s", report_path, e)
        return None
