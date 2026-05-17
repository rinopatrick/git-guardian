"""Tests for alert service."""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from git_guardian.db.models import Base, ScanRecord
from git_guardian.services.alert_service import AlertService


@pytest_asyncio.fixture
async def db_session():
    """Create an in-memory SQLite database for testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.mark.asyncio
class TestAlertService:
    """Test alert service operations."""

    async def test_create_alert(self, db_session: AsyncSession):
        service = AlertService(db_session)
        alert = await service.create_alert(
            package_name="lodash",
            scan_id="scan-1",
            alert_type="high_risk",
            severity="warning",
            title="High risk package",
            description="lodash has high risk",
        )
        assert alert.package_name == "lodash"
        assert alert.severity == "warning"
        assert alert.is_read is False
        assert alert.is_resolved is False

    async def test_list_alerts(self, db_session: AsyncSession):
        service = AlertService(db_session)
        await service.create_alert("pkg1", "s1", "type1", "info", "Title 1", "Desc 1")
        await service.create_alert("pkg2", "s2", "type2", "warning", "Title 2", "Desc 2")
        alerts = await service.list_alerts()
        assert len(alerts) == 2

    async def test_list_alerts_filter_severity(self, db_session: AsyncSession):
        service = AlertService(db_session)
        await service.create_alert("pkg1", "s1", "type1", "info", "Title 1", "Desc 1")
        await service.create_alert("pkg2", "s2", "type2", "warning", "Title 2", "Desc 2")
        await service.create_alert("pkg3", "s3", "type3", "critical", "Title 3", "Desc 3")
        warnings = await service.list_alerts(severity="warning")
        assert len(warnings) == 1

    async def test_list_alerts_filter_read(self, db_session: AsyncSession):
        service = AlertService(db_session)
        await service.create_alert("pkg1", "s1", "type1", "info", "Title 1", "Desc 1")
        alert2 = await service.create_alert("pkg2", "s2", "type2", "info", "Title 2", "Desc 2")
        await service.mark_read(alert2.id)
        unread = await service.list_alerts(is_read=False)
        assert len(unread) == 1

    async def test_mark_read(self, db_session: AsyncSession):
        service = AlertService(db_session)
        alert = await service.create_alert("pkg", "s1", "type", "info", "Title", "Desc")
        assert alert.is_read is False
        marked = await service.mark_read(alert.id)
        assert marked is True

    async def test_mark_read_nonexistent(self, db_session: AsyncSession):
        service = AlertService(db_session)
        marked = await service.mark_read("nonexistent")
        assert marked is False

    async def test_mark_all_read(self, db_session: AsyncSession):
        service = AlertService(db_session)
        await service.create_alert("pkg1", "s1", "type1", "info", "T1", "D1")
        await service.create_alert("pkg2", "s2", "type2", "info", "T2", "D2")
        count = await service.mark_all_read()
        assert count == 2
        unread = await service.list_alerts(is_read=False)
        assert len(unread) == 0

    async def test_resolve_alert(self, db_session: AsyncSession):
        service = AlertService(db_session)
        alert = await service.create_alert("pkg", "s1", "type", "info", "Title", "Desc")
        resolved = await service.resolve_alert(alert.id)
        assert resolved is True

    async def test_resolve_nonexistent(self, db_session: AsyncSession):
        service = AlertService(db_session)
        resolved = await service.resolve_alert("nonexistent")
        assert resolved is False

    async def test_get_alert_stats(self, db_session: AsyncSession):
        service = AlertService(db_session)
        await service.create_alert("pkg1", "s1", "type1", "info", "T1", "D1")
        await service.create_alert("pkg2", "s2", "type2", "warning", "T2", "D2")
        await service.create_alert("pkg3", "s3", "type3", "critical", "T3", "D3")
        stats = await service.get_alert_stats()
        assert stats["total"] == 3
        assert stats["unread"] == 3
        assert stats["unresolved"] == 3

    async def test_get_unread_count(self, db_session: AsyncSession):
        service = AlertService(db_session)
        await service.create_alert("pkg1", "s1", "type1", "info", "T1", "D1")
        alert2 = await service.create_alert("pkg2", "s2", "type2", "info", "T2", "D2")
        await service.mark_read(alert2.id)
        count = await service.get_unread_count()
        assert count == 1

    async def test_check_scan_high_risk(self, db_session: AsyncSession):
        service = AlertService(db_session)
        findings = [
            {"rule_id": "NET-001", "title": "HTTP request", "risk_level": "medium"},
        ]
        alerts = await service.check_scan_for_alerts(
            package_name="lodash",
            scan_id="scan-1",
            risk_level="high",
            findings=findings,
        )
        assert len(alerts) >= 1
        assert any(a.alert_type == "high_risk" for a in alerts)

    async def test_check_scan_critical_finding(self, db_session: AsyncSession):
        service = AlertService(db_session)
        findings = [
            {"rule_id": "MALWARE-001", "title": "Reverse shell", "risk_level": "critical"},
        ]
        alerts = await service.check_scan_for_alerts(
            package_name="malware-pkg",
            scan_id="scan-1",
            risk_level="critical",
            findings=findings,
        )
        assert len(alerts) >= 2  # high_risk + dangerous_pattern

    async def test_check_scan_risk_increase(self, db_session: AsyncSession):
        service = AlertService(db_session)

        # Create a previous scan with low risk
        prev_scan = ScanRecord(
            package_name="lodash",
            package_version="4.17.20",
            risk_level="low",
            findings_json="[]",
            scan_duration=1.0,
        )
        db_session.add(prev_scan)
        await db_session.flush()

        # New scan with high risk
        new_scan = ScanRecord(
            package_name="lodash",
            package_version="4.17.21",
            risk_level="high",
            findings_json="[]",
            scan_duration=1.0,
        )
        db_session.add(new_scan)
        await db_session.flush()

        alerts = await service.check_scan_for_alerts(
            package_name="lodash",
            scan_id=new_scan.id,
            risk_level="high",
            findings=[],
        )
        risk_alerts = [a for a in alerts if a.alert_type == "risk_increase"]
        assert len(risk_alerts) == 1
