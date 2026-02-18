"""
Tests for the dependency resolver.
"""

import pytest
from unittest.mock import patch, MagicMock

from uast.resolver import DependencyResolver, DependencyNode, DependencyTree


class TestDependencyResolver:

    def setup_method(self):
        self.resolver = DependencyResolver()

    # -- Node suspicion checks ------------------------------------------------

    def test_suspicious_pattern_detected(self):
        node = DependencyNode(name="request-utils-async", ecosystem="pypi", depth=1)
        self.resolver._check_node_suspicion(node, "pypi")
        assert node.suspicious is True
        assert "pattern" in node.suspicion_reason.lower()

    def test_safe_package_not_suspicious(self):
        node = DependencyNode(name="requests", ecosystem="pypi", depth=1)
        self.resolver._check_node_suspicion(node, "pypi")
        assert node.suspicious is False

    def test_similar_name_detected(self):
        node = DependencyNode(name="reqeusts", ecosystem="pypi", depth=1)
        self.resolver._check_node_suspicion(node, "pypi")
        assert node.suspicious is True
        assert "similar" in node.suspicion_reason.lower()

    def test_npm_safe_not_suspicious(self):
        node = DependencyNode(name="lodash", ecosystem="npm", depth=1)
        self.resolver._check_node_suspicion(node, "npm")
        assert node.suspicious is False

    # -- Max depth computation ------------------------------------------------

    def test_max_depth_leaf(self):
        node = DependencyNode(name="pkg", ecosystem="pypi", depth=3)
        assert self.resolver._compute_max_depth(node) == 3

    def test_max_depth_with_children(self):
        child = DependencyNode(name="child", ecosystem="pypi", depth=2)
        grandchild = DependencyNode(name="gc", ecosystem="pypi", depth=3)
        child.children = [grandchild]
        root = DependencyNode(name="root", ecosystem="pypi", depth=0, children=[child])
        assert self.resolver._compute_max_depth(root) == 3

    # -- Suspicious collection ------------------------------------------------

    def test_collect_suspicious_empty(self):
        node = DependencyNode(name="clean", ecosystem="pypi", depth=0)
        assert self.resolver._collect_suspicious(node) == []

    def test_collect_suspicious_finds_flagged(self):
        child = DependencyNode(
            name="evil-pkg", ecosystem="pypi", depth=1,
            suspicious=True, suspicion_reason="test",
        )
        root = DependencyNode(name="root", ecosystem="pypi", depth=0, children=[child])
        result = self.resolver._collect_suspicious(root)
        assert "evil-pkg" in result

    # -- Dependency fetching (mocked) -----------------------------------------

    @patch("uast.resolver.http_client")
    def test_fetch_deps_pypi(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "info": {"requires_dist": ["click>=8.0", "rich>=13.0; extra == 'dev'"]},
        }
        mock_client.get.return_value = mock_resp

        deps = self.resolver._fetch_deps_pypi("test-pkg")
        assert "click" in deps
        # Extras should be filtered out
        assert "rich" not in deps

    @patch("uast.resolver.http_client")
    def test_fetch_deps_pypi_404(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_client.get.return_value = mock_resp

        deps = self.resolver._fetch_deps_pypi("nonexistent")
        assert deps == []

    @patch("uast.resolver.http_client")
    def test_fetch_deps_npm(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "dist-tags": {"latest": "1.0.0"},
            "versions": {
                "1.0.0": {
                    "dependencies": {"lodash": "^4.0.0", "axios": "^1.0.0"},
                }
            },
        }
        mock_client.get.return_value = mock_resp

        deps = self.resolver._fetch_deps_npm("test-pkg")
        assert "lodash" in deps
        assert "axios" in deps

    # -- Full tree resolution (mocked) ----------------------------------------

    @patch("uast.resolver.http_client")
    def test_resolve_tree_simple(self, mock_client):
        def mock_get(url, timeout=None):
            resp = MagicMock()
            if "test-root" in url:
                resp.status_code = 200
                resp.json.return_value = {
                    "info": {"requires_dist": ["dep-a", "dep-b"]},
                }
            elif "dep-a" in url or "dep-b" in url:
                resp.status_code = 200
                resp.json.return_value = {
                    "info": {"requires_dist": []},
                }
            else:
                resp.status_code = 404
            return resp

        mock_client.get.side_effect = mock_get

        tree = self.resolver.resolve_tree("test-root", "pypi")
        assert tree.total_count >= 1  # At least root
        assert tree.root == "test-root"

    @patch("uast.resolver.http_client")
    def test_resolve_tree_handles_cycle(self, mock_client):
        """Ensure cycles don't cause infinite recursion."""
        def mock_get(url, timeout=None):
            resp = MagicMock()
            resp.status_code = 200
            if "pkg-a" in url:
                resp.json.return_value = {"info": {"requires_dist": ["pkg-b"]}}
            elif "pkg-b" in url:
                resp.json.return_value = {"info": {"requires_dist": ["pkg-a"]}}
            else:
                resp.json.return_value = {"info": {"requires_dist": []}}
            return resp

        mock_client.get.side_effect = mock_get

        tree = self.resolver.resolve_tree("pkg-a", "pypi")
        # Should complete without hanging
        assert tree.total_count <= 3

    def test_max_packages_limit(self):
        """Ensure circuit breaker works."""
        resolver = DependencyResolver()
        resolver.MAX_PACKAGES = 5
        resolver._total_count = 5
        resolver._visited = set()

        node = resolver._resolve_node("test", "pypi", depth=0)
        assert node is None

    def test_max_depth_limit(self):
        """Ensure depth limit works."""
        resolver = DependencyResolver()
        node = resolver._resolve_node("test", "pypi", depth=resolver.MAX_DEPTH + 1)
        assert node is None
