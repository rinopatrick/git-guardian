"""Dependency graph scanner for transitive dependency analysis."""

import json
from dataclasses import dataclass, field

from git_guardian.models.package import Finding, RiskLevel
from git_guardian.scanner.npm import NpmRegistryClient
from git_guardian.scanner.patterns import PatternDetector
from git_guardian.scanner.rate_limiter import get_npm_rate_limiter


@dataclass
class DependencyNode:
    """A node in the dependency graph."""

    name: str
    version: str
    depth: int
    findings: list[Finding] = field(default_factory=list)
    children: list["DependencyNode"] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.SAFE
    error: str | None = None

    @property
    def is_leaf(self) -> bool:
        return len(self.children) == 0

    def total_findings(self) -> int:
        """Count findings in this node and all children."""
        count = len(self.findings)
        for child in self.children:
            count += child.total_findings()
        return count

    def to_dict(self) -> dict:
        """Convert to dict for serialization."""
        return {
            "name": self.name,
            "version": self.version,
            "depth": self.depth,
            "risk_level": self.risk_level.value,
            "findings_count": len(self.findings),
            "findings": [f.model_dump() for f in self.findings],
            "children": [c.to_dict() for c in self.children],
            "error": self.error,
        }


@dataclass
class DependencyScanResult:
    """Result of scanning a dependency tree."""

    root_package: str
    root_version: str
    graph: DependencyNode
    total_packages: int = 0
    total_findings: int = 0
    packages_with_findings: int = 0
    max_depth_reached: int = 0
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        """Convert to dict for serialization."""
        return {
            "root_package": self.root_package,
            "root_version": self.root_version,
            "graph": self.graph.to_dict(),
            "total_packages": self.total_packages,
            "total_findings": self.total_findings,
            "packages_with_findings": self.packages_with_findings,
            "max_depth_reached": self.max_depth_reached,
            "scan_duration_seconds": self.scan_duration_seconds,
        }


class DependencyScanner:
    """Scans transitive dependencies of npm packages."""

    def __init__(
        self,
        max_depth: int = 3,
        max_packages: int = 50,
        enable_ai: bool = False,
    ) -> None:
        """Initialize dependency scanner.

        Args:
            max_depth: Maximum depth to traverse
            max_packages: Maximum total packages to scan
            enable_ai: Whether to enable AI analysis
        """
        self.max_depth = max_depth
        self.max_packages = max_packages
        self.enable_ai = enable_ai
        self.npm_client = NpmRegistryClient()
        self.pattern_detector = PatternDetector()
        self.rate_limiter = get_npm_rate_limiter()
        self._visited: set[str] = set()
        self._package_count = 0

    def scan_dependencies(
        self,
        package_name: str,
        version: str | None = None,
    ) -> DependencyScanResult:
        """Scan a package and its transitive dependencies.

        Args:
            package_name: Root package name
            version: Specific version (defaults to latest)

        Returns:
            DependencyScanResult with full dependency graph
        """
        import time

        start_time = time.time()
        self._visited = set()
        self._package_count = 0

        # Get root package info
        self.rate_limiter.acquire()
        package_info = self.npm_client.get_package(package_name)
        root_version = version or package_info.latest_version

        # Build dependency graph
        graph = self._scan_node(package_name, root_version, depth=0)

        scan_duration = time.time() - start_time

        # Calculate stats
        total_findings = graph.total_findings()
        packages_with_findings = self._count_packages_with_findings(graph)

        return DependencyScanResult(
            root_package=package_name,
            root_version=root_version,
            graph=graph,
            total_packages=self._package_count,
            total_findings=total_findings,
            packages_with_findings=packages_with_findings,
            max_depth_reached=self._max_depth(graph),
            scan_duration_seconds=scan_duration,
        )

    def _scan_node(
        self,
        package_name: str,
        version: str,
        depth: int,
    ) -> DependencyNode:
        """Recursively scan a package node.

        Args:
            package_name: Package name
            version: Package version
            depth: Current depth in the tree

        Returns:
            DependencyNode with findings and children
        """
        node = DependencyNode(
            name=package_name,
            version=version,
            depth=depth,
        )

        # Check limits
        if depth > self.max_depth:
            node.error = "Max depth exceeded"
            return node

        if self._package_count >= self.max_packages:
            node.error = "Max packages limit reached"
            return node

        # Check for cycles
        visit_key = f"{package_name}@{version}"
        if visit_key in self._visited:
            node.error = "Cycle detected"
            return node

        self._visited.add(visit_key)
        self._package_count += 1

        try:
            # Rate limit
            self.rate_limiter.acquire()

            # Get package metadata
            package_info = self.npm_client.get_package(package_name)

            # Find the specific version
            target_version = None
            for v in package_info.versions:
                if v.version == version:
                    target_version = v
                    break

            if target_version is None:
                target_version = package_info.versions[0] if package_info.versions else None

            # Scan for patterns in package.json scripts
            if target_version and target_version.scripts:
                scripts_json = json.dumps(target_version.scripts)
                findings = self.pattern_detector.scan_file(
                    "package.json", scripts_json
                )
                node.findings.extend(findings)

            # Get dependencies
            if target_version and target_version.dependencies:
                for dep_name, dep_version_spec in target_version.dependencies.items():
                    # Clean version spec (remove ^, ~, etc.)
                    clean_version = dep_version_spec.lstrip("^~>=<").split(" ")[0]

                    child = self._scan_node(
                        dep_name,
                        clean_version,
                        depth + 1,
                    )
                    node.children.append(child)

            # Determine risk level for this node
            node.risk_level = self._determine_risk(node.findings)

        except Exception as e:
            node.error = str(e)

        return node

    def _determine_risk(self, findings: list[Finding]) -> RiskLevel:
        """Determine risk level from findings."""
        if not findings:
            return RiskLevel.SAFE

        risk_order = [
            RiskLevel.CRITICAL,
            RiskLevel.HIGH,
            RiskLevel.MEDIUM,
            RiskLevel.LOW,
        ]
        for level in risk_order:
            if any(f.risk_level == level for f in findings):
                return level
        return RiskLevel.SAFE

    def _count_packages_with_findings(self, node: DependencyNode) -> int:
        """Count packages that have findings."""
        count = 1 if node.findings else 0
        for child in node.children:
            count += self._count_packages_with_findings(child)
        return count

    def _max_depth(self, node: DependencyNode) -> int:
        """Get maximum depth in the tree."""
        if not node.children:
            return node.depth
        return max(self._max_depth(child) for child in node.children)

    def close(self) -> None:
        """Release resources."""
        self.npm_client.close()

    def __enter__(self) -> "DependencyScanner":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
