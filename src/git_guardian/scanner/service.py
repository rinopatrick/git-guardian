"""Centralized scan service — single source of truth for the scan pipeline."""

import time

from git_guardian.models.package import Finding, RiskLevel, ScanResult
from git_guardian.scanner.ai_analyzer import AICodeAnalyzer
from git_guardian.scanner.npm import NpmRegistryClient
from git_guardian.scanner.patterns import PatternDetector
from git_guardian.scanner.typosquat import TyposquatDetector


def determine_risk_level(findings: list[Finding]) -> RiskLevel:
    """Determine overall risk level from a list of findings.

    Returns the highest risk level present, or SAFE if no findings.
    """
    if not findings:
        return RiskLevel.SAFE
    risk_order = [
        RiskLevel.CRITICAL,
        RiskLevel.HIGH,
        RiskLevel.MEDIUM,
        RiskLevel.LOW,
        RiskLevel.SAFE,
    ]
    for level in risk_order:
        if any(f.risk_level == level for f in findings):
            return level
    return RiskLevel.SAFE


class ScanService:
    """Synchronous scan pipeline for CLI usage."""

    def __init__(self, enable_ai: bool = False) -> None:
        self.npm_client = NpmRegistryClient()
        self.pattern_detector = PatternDetector()
        self.typosquat_detector = TyposquatDetector(
            self.npm_client.get_popular_packages()
        )
        self.ai_analyzer = AICodeAnalyzer(enabled=enable_ai)

    def scan_package(
        self,
        package_name: str,
        version: str | None = None,
    ) -> ScanResult:
        """Run the full scan pipeline synchronously.

        Args:
            package_name: npm package name
            version: Specific version (defaults to latest)

        Returns:
            ScanResult with all findings
        """
        start_time = time.time()

        # 1. Fetch metadata
        package_info = self.npm_client.get_package(package_name)

        # 2. Typosquat check
        all_findings: list[Finding] = self.typosquat_detector.scan_package_name(
            package_name
        )

        # 3. Download and pattern scan
        files = self.npm_client.get_package_files(package_name, version)
        all_findings.extend(self.pattern_detector.scan_package(files))

        # 4. AI analysis (if enabled)
        ai_finding = None
        if self.ai_analyzer.enabled:
            ai_finding = self.ai_analyzer.analyze_package(
                package_info, files, all_findings
            )
            if ai_finding:
                all_findings.append(ai_finding)

        # 5. Determine risk
        risk_level = determine_risk_level(all_findings)

        scan_duration = time.time() - start_time

        return ScanResult(
            package=package_info,
            risk_level=risk_level,
            findings=all_findings,
            ai_analysis=ai_finding.description if ai_finding else None,
            scan_duration_seconds=scan_duration,
        )

    def close(self) -> None:
        """Release resources."""
        self.npm_client.close()

    def __enter__(self) -> "ScanService":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
