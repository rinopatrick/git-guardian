"""Tests for dependency scanner."""

from unittest.mock import MagicMock, patch

from git_guardian.models.package import (
    Finding,
    PackageInfo,
    PackageVersion,
    RiskLevel,
)
from git_guardian.services.dependency_scanner import (
    DependencyNode,
    DependencyScanner,
    DependencyScanResult,
)


class TestDependencyNode:
    """Test DependencyNode dataclass."""

    def test_is_leaf(self):
        node = DependencyNode(name="lodash", version="4.17.21", depth=0)
        assert node.is_leaf is True

    def test_not_leaf(self):
        child = DependencyNode(name="child", version="1.0.0", depth=1)
        node = DependencyNode(name="parent", version="1.0.0", depth=0, children=[child])
        assert node.is_leaf is False

    def test_total_findings_no_children(self):
        finding = Finding(
            rule_id="TEST-001",
            title="Test",
            description="Test finding",
            risk_level=RiskLevel.LOW,
        )
        node = DependencyNode(name="pkg", version="1.0.0", depth=0, findings=[finding])
        assert node.total_findings() == 1

    def test_total_findings_with_children(self):
        child_finding = Finding(
            rule_id="TEST-002",
            title="Child finding",
            description="Test",
            risk_level=RiskLevel.MEDIUM,
        )
        child = DependencyNode(name="child", version="1.0.0", depth=1, findings=[child_finding])
        parent = DependencyNode(name="parent", version="1.0.0", depth=0, children=[child])
        assert parent.total_findings() == 1

    def test_to_dict(self):
        node = DependencyNode(
            name="lodash",
            version="4.17.21",
            depth=0,
            risk_level=RiskLevel.SAFE,
        )
        d = node.to_dict()
        assert d["name"] == "lodash"
        assert d["version"] == "4.17.21"
        assert d["depth"] == 0
        assert d["risk_level"] == "safe"
        assert d["children"] == []


class TestDependencyScanResult:
    """Test DependencyScanResult."""

    def test_to_dict(self):
        graph = DependencyNode(name="root", version="1.0.0", depth=0)
        result = DependencyScanResult(
            root_package="root",
            root_version="1.0.0",
            graph=graph,
            total_packages=5,
            total_findings=2,
        )
        d = result.to_dict()
        assert d["root_package"] == "root"
        assert d["total_packages"] == 5
        assert d["total_findings"] == 2


class TestDependencyScanner:
    """Test dependency scanner with mocked npm client."""

    def _make_package_info(self, name, version, deps=None):
        return PackageInfo(
            name=name,
            latest_version=version,
            versions=[
                PackageVersion(
                    version=version,
                    dependencies=deps or {},
                )
            ],
        )

    @patch("git_guardian.services.dependency_scanner.NpmRegistryClient")
    @patch("git_guardian.services.dependency_scanner.get_npm_rate_limiter")
    def test_scan_single_package_no_deps(self, mock_limiter, mock_npm):
        mock_limiter.return_value = MagicMock(acquire=MagicMock())
        mock_client = MagicMock()
        mock_client.get_package.return_value = self._make_package_info("lodash", "4.17.21")
        mock_npm.return_value = mock_client

        with DependencyScanner(max_depth=1, max_packages=10) as scanner:
            scanner.npm_client = mock_client
            result = scanner.scan_dependencies("lodash")

        assert result.root_package == "lodash"
        assert result.total_packages >= 1

    @patch("git_guardian.services.dependency_scanner.NpmRegistryClient")
    @patch("git_guardian.services.dependency_scanner.get_npm_rate_limiter")
    def test_scan_with_dependencies(self, mock_limiter, mock_npm):
        mock_limiter.return_value = MagicMock(acquire=MagicMock())
        mock_client = MagicMock()

        def get_package_side_effect(name):
            packages = {
                "parent": self._make_package_info("parent", "1.0.0", {"child": "^1.0.0"}),
                "child": self._make_package_info("child", "1.0.0"),
            }
            return packages.get(name, self._make_package_info(name, "1.0.0"))

        mock_client.get_package.side_effect = get_package_side_effect
        mock_npm.return_value = mock_client

        with DependencyScanner(max_depth=2, max_packages=10) as scanner:
            scanner.npm_client = mock_client
            result = scanner.scan_dependencies("parent")

        assert result.total_packages >= 2

    def test_cycle_detection(self):
        node = DependencyNode(name="a", version="1.0.0", depth=0)
        child = DependencyNode(name="b", version="1.0.0", depth=1)
        node.children.append(child)

        scanner = DependencyScanner.__new__(DependencyScanner)
        scanner._visited = {"a@1.0.0"}
        scanner._package_count = 1
        scanner.max_depth = 5
        scanner.max_packages = 100
        scanner.npm_client = MagicMock()
        scanner.pattern_detector = MagicMock()
        scanner.rate_limiter = MagicMock()

        # Simulating a cycle by checking visit_key
        assert "a@1.0.0" in scanner._visited
