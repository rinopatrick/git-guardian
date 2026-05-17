"""Tests for the scan command."""

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from git_guardian.cli import app
from git_guardian.models.package import (
    Finding,
    PackageAuthor,
    PackageInfo,
    PackageVersion,
    RiskLevel,
    ScanResult,
)

runner = CliRunner()


def _mock_scan_result(
    risk: RiskLevel = RiskLevel.SAFE, findings: list[Finding] | None = None,
) -> ScanResult:
    return ScanResult(
        package=PackageInfo(
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
        ),
        risk_level=risk,
        findings=findings or [],
        ai_analysis=None,
        scan_duration_seconds=0.5,
    )


@patch("git_guardian.scanner.service.ScanService")
def test_scan_safe_package(mock_service_class: MagicMock) -> None:
    mock_service = MagicMock()
    mock_service_class.return_value = mock_service
    mock_service.__enter__ = MagicMock(return_value=mock_service)
    mock_service.__exit__ = MagicMock(return_value=False)
    mock_service.scan_package.return_value = _mock_scan_result()

    result = runner.invoke(app, ["scan", "test-package"])

    assert result.exit_code == 0
    assert "SAFE" in result.output or "No security issues" in result.output


@patch("git_guardian.scanner.service.ScanService")
def test_scan_package_with_findings(mock_service_class: MagicMock) -> None:
    finding = Finding(
        rule_id="EXEC-001",
        title="Child process execution",
        description="Code executes child processes",
        risk_level=RiskLevel.HIGH,
        file_path="index.js",
    )
    mock_service = MagicMock()
    mock_service_class.return_value = mock_service
    mock_service.__enter__ = MagicMock(return_value=mock_service)
    mock_service.__exit__ = MagicMock(return_value=False)
    mock_service.scan_package.return_value = _mock_scan_result(
        risk=RiskLevel.HIGH, findings=[finding]
    )

    result = runner.invoke(app, ["scan", "test-package"])

    assert result.exit_code == 0
    assert "HIGH" in result.output
    assert "Child process" in result.output


@patch("git_guardian.scanner.service.ScanService")
def test_scan_package_json_output(mock_service_class: MagicMock) -> None:
    mock_service = MagicMock()
    mock_service_class.return_value = mock_service
    mock_service.__enter__ = MagicMock(return_value=mock_service)
    mock_service.__exit__ = MagicMock(return_value=False)
    mock_service.scan_package.return_value = _mock_scan_result()

    result = runner.invoke(app, ["scan", "test-package", "--json"])

    assert result.exit_code == 0
    assert '"risk_level"' in result.output
    assert '"package"' in result.output
