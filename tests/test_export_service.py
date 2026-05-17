"""Tests for export service."""

import json

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from git_guardian.db.models import Base, ScanRecord
from git_guardian.services.export_service import ExportService


@pytest_asyncio.fixture
async def db_session():
    """Create an in-memory SQLite database for testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        # Seed test data
        for i in range(5):
            record = ScanRecord(
                package_name=f"package-{i}",
                package_version=f"1.0.{i}",
                risk_level=["safe", "low", "medium", "high", "critical"][i],
                findings_json=json.dumps([
                    {"rule_id": f"RULE-{i}", "title": f"Finding {i}", "risk_level": ["safe", "low", "medium", "high", "critical"][i]}
                ]),
                scan_duration=1.0 + i * 0.5,
            )
            session.add(record)
        await session.commit()
        yield session

    await engine.dispose()


@pytest.mark.asyncio
class TestExportService:
    """Test export service operations."""

    async def test_export_json(self, db_session: AsyncSession):
        service = ExportService(db_session)
        data = await service.export_scans_json()
        parsed = json.loads(data)
        assert "scans" in parsed
        assert len(parsed["scans"]) == 5
        assert "exported_at" in parsed

    async def test_export_json_with_limit(self, db_session: AsyncSession):
        service = ExportService(db_session)
        data = await service.export_scans_json(limit=2)
        parsed = json.loads(data)
        assert len(parsed["scans"]) == 2

    async def test_export_json_filter_risk(self, db_session: AsyncSession):
        service = ExportService(db_session)
        data = await service.export_scans_json(risk_level="high")
        parsed = json.loads(data)
        assert len(parsed["scans"]) == 1
        assert parsed["scans"][0]["risk_level"] == "high"

    async def test_export_json_filter_package(self, db_session: AsyncSession):
        service = ExportService(db_session)
        data = await service.export_scans_json(package_name="package-0")
        parsed = json.loads(data)
        assert len(parsed["scans"]) == 1

    async def test_export_csv(self, db_session: AsyncSession):
        service = ExportService(db_session)
        data = await service.export_scans_csv()
        lines = data.strip().split("\n")
        assert len(lines) == 6  # header + 5 rows
        assert "id" in lines[0]
        assert "package_name" in lines[0]

    async def test_export_csv_with_limit(self, db_session: AsyncSession):
        service = ExportService(db_session)
        data = await service.export_scans_csv(limit=3)
        lines = data.strip().split("\n")
        assert len(lines) == 4  # header + 3 rows

    async def test_export_findings_csv(self, db_session: AsyncSession):
        service = ExportService(db_session)
        data = await service.export_findings_csv()
        lines = data.strip().split("\n")
        assert len(lines) == 6  # header + 5 findings
        assert "rule_id" in lines[0]

    async def test_export_findings_csv_filter_risk(self, db_session: AsyncSession):
        service = ExportService(db_session)
        data = await service.export_findings_csv(risk_level="critical")
        lines = data.strip().split("\n")
        assert len(lines) == 2  # header + 1 finding

    async def test_get_summary_stats(self, db_session: AsyncSession):
        service = ExportService(db_session)
        stats = await service.get_summary_stats()
        assert stats["total_scans"] == 5
        assert stats["unique_packages"] == 5
        assert "risk_distribution" in stats
        assert stats["average_scan_duration"] > 0
