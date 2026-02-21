"""Tests for Merkle tree hashing (Sprint 3.4)."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile

import pytest

from uast.merkle import (
    compute_node_hash,
    compute_tree_hash,
    diff_tree_hashes,
    load_session_hash,
)
from uast.resolver import DependencyNode, DependencyTree


class TestComputeNodeHash:
    """Tests for compute_node_hash()."""

    def test_leaf_node_deterministic(self):
        node = DependencyNode(name="requests", ecosystem="pypi", depth=1)
        version_map = {"requests": "2.31.0"}
        h1 = compute_node_hash(node, version_map)
        h2 = compute_node_hash(node, version_map)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest

    def test_leaf_node_unknown_version(self):
        node = DependencyNode(name="foo", ecosystem="pypi", depth=1)
        h = compute_node_hash(node, {})
        expected_payload = "foo||unknown||"
        expected = hashlib.sha256(expected_payload.encode("utf-8")).hexdigest()
        assert h == expected

    def test_leaf_node_with_version(self):
        node = DependencyNode(name="click", ecosystem="pypi", depth=1)
        version_map = {"click": "8.1.7"}
        h = compute_node_hash(node, version_map)
        expected_payload = "click||8.1.7||"
        expected = hashlib.sha256(expected_payload.encode("utf-8")).hexdigest()
        assert h == expected

    def test_name_is_lowercased(self):
        node1 = DependencyNode(name="Requests", ecosystem="pypi", depth=1)
        node2 = DependencyNode(name="requests", ecosystem="pypi", depth=1)
        version_map = {"requests": "2.31.0"}
        assert compute_node_hash(node1, version_map) == compute_node_hash(node2, version_map)

    def test_different_versions_different_hash(self):
        node = DependencyNode(name="requests", ecosystem="pypi", depth=1)
        h1 = compute_node_hash(node, {"requests": "2.31.0"})
        h2 = compute_node_hash(node, {"requests": "2.32.0"})
        assert h1 != h2

    def test_different_names_different_hash(self):
        node1 = DependencyNode(name="foo", ecosystem="pypi", depth=1)
        node2 = DependencyNode(name="bar", ecosystem="pypi", depth=1)
        assert compute_node_hash(node1, {}) != compute_node_hash(node2, {})

    def test_node_with_children(self):
        child1 = DependencyNode(name="urllib3", ecosystem="pypi", depth=2)
        child2 = DependencyNode(name="certifi", ecosystem="pypi", depth=2)
        parent = DependencyNode(
            name="requests", ecosystem="pypi", depth=1,
            children=[child1, child2],
        )
        version_map = {"requests": "2.31.0", "urllib3": "2.0.0", "certifi": "2023.7.22"}
        h = compute_node_hash(parent, version_map)
        assert isinstance(h, str)
        assert len(h) == 64

    def test_child_order_independence(self):
        """Child order should not affect the hash."""
        child_a = DependencyNode(name="alpha", ecosystem="pypi", depth=2)
        child_b = DependencyNode(name="beta", ecosystem="pypi", depth=2)

        parent1 = DependencyNode(
            name="root", ecosystem="pypi", depth=1,
            children=[child_a, child_b],
        )
        parent2 = DependencyNode(
            name="root", ecosystem="pypi", depth=1,
            children=[child_b, child_a],
        )

        version_map = {"root": "1.0", "alpha": "1.0", "beta": "1.0"}
        assert compute_node_hash(parent1, version_map) == compute_node_hash(parent2, version_map)

    def test_adding_child_changes_hash(self):
        child = DependencyNode(name="urllib3", ecosystem="pypi", depth=2)
        parent_no_child = DependencyNode(name="requests", ecosystem="pypi", depth=1)
        parent_with_child = DependencyNode(
            name="requests", ecosystem="pypi", depth=1,
            children=[child],
        )
        version_map = {"requests": "2.31.0", "urllib3": "2.0.0"}
        h1 = compute_node_hash(parent_no_child, version_map)
        h2 = compute_node_hash(parent_with_child, version_map)
        assert h1 != h2

    def test_deep_tree(self):
        """Hash works for deeply nested trees."""
        leaf = DependencyNode(name="leaf", ecosystem="pypi", depth=5)
        mid = DependencyNode(name="mid", ecosystem="pypi", depth=4, children=[leaf])
        top = DependencyNode(name="top", ecosystem="pypi", depth=3, children=[mid])
        root = DependencyNode(name="root", ecosystem="pypi", depth=2, children=[top])

        version_map = {"root": "1.0", "top": "1.0", "mid": "1.0", "leaf": "1.0"}
        h = compute_node_hash(root, version_map)
        assert isinstance(h, str)
        assert len(h) == 64

    def test_version_map_case_insensitive_lookup(self):
        """Version map should work with case-insensitive name lookup."""
        node = DependencyNode(name="Flask", ecosystem="pypi", depth=1)
        version_map = {"flask": "3.0.0"}
        h = compute_node_hash(node, version_map)
        expected_payload = "flask||3.0.0||"
        expected = hashlib.sha256(expected_payload.encode("utf-8")).hexdigest()
        assert h == expected


class TestComputeTreeHash:
    """Tests for compute_tree_hash()."""

    def test_empty_tree(self):
        tree = DependencyTree(root="empty-pkg", ecosystem="pypi")
        h = compute_tree_hash(tree)
        assert isinstance(h, str)
        assert len(h) == 64

    def test_empty_tree_with_version(self):
        tree = DependencyTree(root="empty-pkg", ecosystem="pypi")
        h = compute_tree_hash(tree, {"empty-pkg": "1.0.0"})
        expected_payload = "empty-pkg||1.0.0||"
        expected = hashlib.sha256(expected_payload.encode("utf-8")).hexdigest()
        assert h == expected

    def test_tree_with_nodes(self):
        child1 = DependencyNode(name="urllib3", ecosystem="pypi", depth=1)
        child2 = DependencyNode(name="certifi", ecosystem="pypi", depth=1)
        tree = DependencyTree(
            root="requests",
            ecosystem="pypi",
            nodes=[child1, child2],
            total_count=3,
            max_depth=1,
        )
        version_map = {"requests": "2.31.0", "urllib3": "2.0.0", "certifi": "2023.7.22"}
        h = compute_tree_hash(tree, version_map)
        assert isinstance(h, str)
        assert len(h) == 64

    def test_deterministic(self):
        """Same tree always produces the same hash."""
        child = DependencyNode(name="click", ecosystem="pypi", depth=1)
        tree = DependencyTree(
            root="flask",
            ecosystem="pypi",
            nodes=[child],
            total_count=2,
        )
        version_map = {"flask": "3.0.0", "click": "8.1.7"}
        h1 = compute_tree_hash(tree, version_map)
        h2 = compute_tree_hash(tree, version_map)
        assert h1 == h2

    def test_node_order_independence(self):
        """Node ordering in tree.nodes doesn't affect hash."""
        child_a = DependencyNode(name="alpha", ecosystem="pypi", depth=1)
        child_b = DependencyNode(name="beta", ecosystem="pypi", depth=1)

        tree1 = DependencyTree(root="root", ecosystem="pypi", nodes=[child_a, child_b])
        tree2 = DependencyTree(root="root", ecosystem="pypi", nodes=[child_b, child_a])

        version_map = {"root": "1.0", "alpha": "1.0", "beta": "1.0"}
        assert compute_tree_hash(tree1, version_map) == compute_tree_hash(tree2, version_map)

    def test_version_change_detected(self):
        """Changing a dependency version changes the tree hash."""
        child = DependencyNode(name="dep", ecosystem="pypi", depth=1)
        tree = DependencyTree(root="pkg", ecosystem="pypi", nodes=[child])

        h1 = compute_tree_hash(tree, {"pkg": "1.0", "dep": "1.0"})
        h2 = compute_tree_hash(tree, {"pkg": "1.0", "dep": "2.0"})
        assert h1 != h2

    def test_added_dep_detected(self):
        """Adding a dependency changes the tree hash."""
        child1 = DependencyNode(name="dep1", ecosystem="pypi", depth=1)
        child2 = DependencyNode(name="dep2", ecosystem="pypi", depth=1)

        tree1 = DependencyTree(root="pkg", ecosystem="pypi", nodes=[child1])
        tree2 = DependencyTree(root="pkg", ecosystem="pypi", nodes=[child1, child2])

        version_map = {"pkg": "1.0", "dep1": "1.0", "dep2": "1.0"}
        assert compute_tree_hash(tree1, version_map) != compute_tree_hash(tree2, version_map)

    def test_removed_dep_detected(self):
        """Removing a dependency changes the tree hash."""
        child1 = DependencyNode(name="dep1", ecosystem="pypi", depth=1)
        child2 = DependencyNode(name="dep2", ecosystem="pypi", depth=1)

        tree_with = DependencyTree(root="pkg", ecosystem="pypi", nodes=[child1, child2])
        tree_without = DependencyTree(root="pkg", ecosystem="pypi", nodes=[child1])

        version_map = {"pkg": "1.0", "dep1": "1.0", "dep2": "1.0"}
        assert compute_tree_hash(tree_with, version_map) != compute_tree_hash(tree_without, version_map)

    def test_none_version_map(self):
        """Passing None for version_map uses 'unknown' for all."""
        child = DependencyNode(name="dep", ecosystem="pypi", depth=1)
        tree = DependencyTree(root="pkg", ecosystem="pypi", nodes=[child])
        h = compute_tree_hash(tree, None)
        assert isinstance(h, str)
        assert len(h) == 64

    def test_npm_ecosystem(self):
        """Works with npm ecosystem."""
        child = DependencyNode(name="lodash", ecosystem="npm", depth=1)
        tree = DependencyTree(root="express", ecosystem="npm", nodes=[child])
        version_map = {"express": "4.18.2", "lodash": "4.17.21"}
        h = compute_tree_hash(tree, version_map)
        assert isinstance(h, str)
        assert len(h) == 64


class TestDiffTreeHashes:
    """Tests for diff_tree_hashes()."""

    def test_identical_hashes(self):
        h = "abc123" * 10 + "abcd"
        result = diff_tree_hashes(h, h)
        assert result["match"] is True
        assert result["drift_detected"] is False
        assert "identical" in result["summary"]

    def test_different_hashes(self):
        h1 = "a" * 64
        h2 = "b" * 64
        result = diff_tree_hashes(h1, h2)
        assert result["match"] is False
        assert result["drift_detected"] is True
        assert "drift" in result["summary"].lower()

    def test_custom_labels(self):
        h1 = "a" * 64
        h2 = "b" * 64
        result = diff_tree_hashes(h1, h2, label_a="before", label_b="after")
        assert result["before"] == h1
        assert result["after"] == h2

    def test_default_labels(self):
        h = "a" * 64
        result = diff_tree_hashes(h, h)
        assert "session A" in result
        assert "session B" in result


class TestLoadSessionHash:
    """Tests for load_session_hash()."""

    def test_load_valid_report(self):
        report = {
            "version": "3",
            "results": [
                {"package_name": "test", "dependency_tree_hash": "abc123"}
            ],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(report, f)
            f.flush()
            path = f.name

        try:
            h = load_session_hash(path)
            assert h == "abc123"
        finally:
            os.unlink(path)

    def test_load_report_without_hash(self):
        report = {
            "version": "2",
            "results": [{"package_name": "test"}],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(report, f)
            f.flush()
            path = f.name

        try:
            h = load_session_hash(path)
            assert h is None
        finally:
            os.unlink(path)

    def test_load_empty_results(self):
        report = {"version": "3", "results": []}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(report, f)
            f.flush()
            path = f.name

        try:
            h = load_session_hash(path)
            assert h is None
        finally:
            os.unlink(path)

    def test_load_nonexistent_file(self):
        h = load_session_hash("/nonexistent/path/report.json")
        assert h is None

    def test_load_invalid_json(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write("not valid json{{{")
            f.flush()
            path = f.name

        try:
            h = load_session_hash(path)
            assert h is None
        finally:
            os.unlink(path)
