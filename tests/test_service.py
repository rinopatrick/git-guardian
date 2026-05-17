"""Tests for the scan service."""

from unittest.mock import MagicMock, patch

from git_guardian.models.package import (
    Finding,
    PackageAuthor,
    PackageInfo,
    PackageVersion,
    RiskLevel,
    ScanResult,
)
from git_guardian.scanner.service import ScanService, determine_risk_level


def _mock_package_info() -> PackageInfo:
    return PackageInfo(
        name="test-package",
        description="A test package",
        latest_version="1.0.0",
        versions=[
            PackageVersion(
                version="1.0.0",
                description="A test package",
                author=PackageAuthor(name="Test Author"),
                license="MIT",
                dependencies={},
                scripts={},
                dist={},
            )
        ],
        author=PackageAuthor(name="Test Author"),
        license="MIT",
    )


def _finding(risk: RiskLevel = RiskLevel.MEDIUM) -> Finding:
    return Finding(
        rule_id="TEST-001",
        title="Test finding",
        description="Test description",
        risk_level=risk,
        file_path="index.js",
    )


# --- determine_risk_level tests ---


def test_risk_level_no_findings() -> None:
    assert determine_risk_level([]) == RiskLevel.SAFE


def test_risk_level_single_low() -> None:
    assert determine_risk_level([_finding(RiskLevel.LOW)]) == RiskLevel.LOW


def test_risk_level_single_critical() -> None:
    assert determine_risk_level([_finding(RiskLevel.CRITICAL)]) == RiskLevel.CRITICAL


def test_risk_level_mixed_takes_highest() -> None:
    findings = [
        _finding(RiskLevel.LOW),
        _finding(RiskLevel.MEDIUM),
        _finding(RiskLevel.HIGH),
        _finding(RiskLevel.LOW),
    ]
    assert determine_risk_level(findings) == RiskLevel.HIGH


def test_risk_level_all_safe() -> None:
    assert determine_risk_level([_finding(RiskLevel.SAFE)]) == RiskLevel.SAFE


# --- ScanService tests ---


@patch("git_guardian.scanner.service.AICodeAnalyzer")
@patch("git_guardian.scanner.service.NpmRegistryClient")
def test_scan_safe_package(mock_npm_class: MagicMock, mock_ai_class: MagicMock) -> None:
    mock_npm = MagicMock()
    mock_npm_class.return_value = mock_npm
    mock_npm.get_popular_packages.return_value = ["lodash"]
    mock_npm.get_package.return_value = _mock_package_info()
    mock_npm.get_package_files.return_value = {"index.js": 'console.log("hi");'}

    mock_ai = MagicMock()
    mock_ai_class.return_value = mock_ai
    mock_ai.enabled = False

    service = ScanService(enable_ai=False)
    result = service.scan_package("test-package")

    assert isinstance(result, ScanResult)
    assert result.risk_level == RiskLevel.SAFE
    assert len(result.findings) == 0
    service.close()


@patch("git_guardian.scanner.service.AICodeAnalyzer")
@patch("git_guardian.scanner.service.NpmRegistryClient")
def test_scan_package_with_findings(mock_npm_class: MagicMock, mock_ai_class: MagicMock) -> None:
    mock_npm = MagicMock()
    mock_npm_class.return_value = mock_npm
    mock_npm.get_popular_packages.return_value = ["lodash"]
    mock_npm.get_package.return_value = _mock_package_info()
    mock_npm.get_package_files.return_value = {
        "index.js": 'const { spawn } = require("child_process");',
    }

    mock_ai = MagicMock()
    mock_ai_class.return_value = mock_ai
    mock_ai.enabled = False

    service = ScanService(enable_ai=False)
    result = service.scan_package("test-package")

    assert result.risk_level == RiskLevel.HIGH
    assert len(result.findings) > 0
    assert any(f.rule_id == "EXEC-001" for f in result.findings)
    service.close()


@patch("git_guardian.scanner.service.AICodeAnalyzer")
@patch("git_guardian.scanner.service.NpmRegistryClient")
def test_scan_package_ai_enabled(mock_npm_class: MagicMock, mock_ai_class: MagicMock) -> None:
    mock_npm = MagicMock()
    mock_npm_class.return_value = mock_npm
    mock_npm.get_popular_packages.return_value = ["lodash"]
    mock_npm.get_package.return_value = _mock_package_info()
    mock_npm.get_package_files.return_value = {"index.js": 'console.log("hi");'}

    mock_ai = MagicMock()
    mock_ai_class.return_value = mock_ai
    mock_ai.enabled = True
    mock_ai.analyze_package.return_value = None

    service = ScanService(enable_ai=True)
    result = service.scan_package("test-package")

    mock_ai.analyze_package.assert_called_once()
    assert result.risk_level == RiskLevel.SAFE
    service.close()


@patch("git_guardian.scanner.service.AICodeAnalyzer")
@patch("git_guardian.scanner.service.NpmRegistryClient")
def test_scan_package_context_manager(mock_npm_class: MagicMock, mock_ai_class: MagicMock) -> None:
    mock_npm = MagicMock()
    mock_npm_class.return_value = mock_npm
    mock_npm.get_popular_packages.return_value = ["lodash"]
    mock_npm.get_package.return_value = _mock_package_info()
    mock_npm.get_package_files.return_value = {}

    mock_ai = MagicMock()
    mock_ai_class.return_value = mock_ai
    mock_ai.enabled = False

    with ScanService() as service:
        result = service.scan_package("test-package")

    assert result.risk_level == RiskLevel.SAFE
    mock_npm.close.assert_called_once()
