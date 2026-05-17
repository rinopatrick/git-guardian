"""Tests for the API routes."""

from unittest.mock import MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from git_guardian.api.app import app
from git_guardian.models.package import (
    Finding,
    PackageAuthor,
    PackageInfo,
    RiskLevel,
    ScanResult,
)


def _mock_scan_result() -> ScanResult:
    return ScanResult(
        package=PackageInfo(
            name="test-pkg",
            description="A test",
            latest_version="1.0.0",
            author=PackageAuthor(name="Test"),
            license="MIT",
        ),
        risk_level=RiskLevel.SAFE,
        findings=[],
        ai_analysis=None,
        scan_duration_seconds=0.5,
    )


def _mock_scan_result_with_findings() -> ScanResult:
    return ScanResult(
        package=PackageInfo(
            name="bad-pkg",
            description="A bad package",
            latest_version="2.0.0",
            author=PackageAuthor(name="Bad Actor"),
            license="MIT",
        ),
        risk_level=RiskLevel.HIGH,
        findings=[
            Finding(
                rule_id="EXEC-001",
                title="Child process execution",
                description="Executes child processes",
                risk_level=RiskLevel.HIGH,
                file_path="index.js",
            )
        ],
        ai_analysis=None,
        scan_duration_seconds=1.2,
    )


@pytest.fixture
def anyio_backend():
    return "asyncio"


@patch("git_guardian.api.routes.scan.ScanService")
@pytest.mark.anyio
async def test_post_scan_safe(mock_service_class: MagicMock) -> None:
    mock_service = MagicMock()
    mock_service_class.return_value = mock_service
    mock_service.__enter__ = MagicMock(return_value=mock_service)
    mock_service.__exit__ = MagicMock(return_value=False)
    mock_service.scan_package.return_value = _mock_scan_result()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/api/scan",
            json={"package_name": "test-pkg"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["package_name"] == "test-pkg"
    assert data["risk_level"] == "safe"
    assert data["findings"] == []


@patch("git_guardian.api.routes.scan.ScanService")
@pytest.mark.anyio
async def test_post_scan_with_findings(mock_service_class: MagicMock) -> None:
    mock_service = MagicMock()
    mock_service_class.return_value = mock_service
    mock_service.__enter__ = MagicMock(return_value=mock_service)
    mock_service.__exit__ = MagicMock(return_value=False)
    mock_service.scan_package.return_value = _mock_scan_result_with_findings()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/api/scan",
            json={"package_name": "bad-pkg", "deep": True},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["package_name"] == "bad-pkg"
    assert data["risk_level"] == "high"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "EXEC-001"


@patch("git_guardian.api.routes.scan.ScanService")
@pytest.mark.anyio
async def test_post_scan_error(mock_service_class: MagicMock) -> None:
    mock_service = MagicMock()
    mock_service_class.return_value = mock_service
    mock_service.__enter__ = MagicMock(return_value=mock_service)
    mock_service.__exit__ = MagicMock(return_value=False)
    mock_service.scan_package.side_effect = Exception("Package not found")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/api/scan",
            json={"package_name": "nonexistent"},
        )

    assert resp.status_code == 500


@pytest.mark.anyio
async def test_list_scans_empty() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/scan")

    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.anyio
async def test_get_scan_not_found() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/scan/nonexistent-id")

    assert resp.status_code == 404
