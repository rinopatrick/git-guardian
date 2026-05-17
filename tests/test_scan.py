"""Tests for the scan command."""

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from git_guardian.cli import app
from git_guardian.models.package import PackageAuthor, PackageInfo, PackageVersion

runner = CliRunner()


def _mock_package_info() -> PackageInfo:
    """Create a mock package info."""
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


@patch("git_guardian.scanner.npm.NpmRegistryClient")
def test_scan_safe_package(mock_client_class: MagicMock) -> None:
    """Test scanning a safe package."""
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    mock_client.get_package.return_value = _mock_package_info()
    mock_client.get_popular_packages.return_value = ["lodash", "express"]
    mock_client.get_package_files.return_value = {
        "index.js": 'console.log("hello");',
    }

    result = runner.invoke(app, ["scan", "test-package"])

    assert result.exit_code == 0
    assert "SAFE" in result.output or "No security issues" in result.output


@patch("git_guardian.scanner.npm.NpmRegistryClient")
def test_scan_package_with_findings(mock_client_class: MagicMock) -> None:
    """Test scanning a package with security findings."""
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    mock_client.get_package.return_value = _mock_package_info()
    mock_client.get_popular_packages.return_value = ["lodash", "express"]
    mock_client.get_package_files.return_value = {
        "index.js": 'const { spawn } = require("child_process");',
    }

    result = runner.invoke(app, ["scan", "test-package"])

    assert result.exit_code == 0
    assert "HIGH" in result.output
    assert "Child process" in result.output


@patch("git_guardian.scanner.npm.NpmRegistryClient")
def test_scan_package_json_output(mock_client_class: MagicMock) -> None:
    """Test scan with JSON output."""
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    mock_client.get_package.return_value = _mock_package_info()
    mock_client.get_popular_packages.return_value = ["lodash", "express"]
    mock_client.get_package_files.return_value = {
        "index.js": 'console.log("hello");',
    }

    result = runner.invoke(app, ["scan", "test-package", "--json"])

    assert result.exit_code == 0
    assert '"risk_level"' in result.output
    assert '"package"' in result.output
