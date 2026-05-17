"""Tests for scheduler service."""

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from git_guardian.db.models import Base
from git_guardian.db.watchlist_models import WatchlistEntry, WatchlistStatus
from git_guardian.services.scheduler_service import SchedulerService


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
class TestSchedulerService:
    """Test scheduler service operations."""

    async def test_create_scheduled_scan(self, db_session: AsyncSession):
        service = SchedulerService(db_session)
        scheduled = await service.create_scheduled_scan(
            name="Hourly watchlist",
            scan_type="watchlist",
            interval_minutes=60,
        )
        assert scheduled.name == "Hourly watchlist"
        assert scheduled.scan_type == "watchlist"
        assert scheduled.interval_minutes == 60
        assert scheduled.is_active is True
        assert scheduled.next_run_at is not None

    async def test_create_with_packages(self, db_session: AsyncSession):
        service = SchedulerService(db_session)
        scheduled = await service.create_scheduled_scan(
            name="Batch scan",
            scan_type="batch",
            interval_minutes=30,
            packages=["lodash", "express"],
        )
        assert scheduled.packages_json is not None

    async def test_list_scheduled_scans(self, db_session: AsyncSession):
        service = SchedulerService(db_session)
        await service.create_scheduled_scan("Scan 1", "watchlist", 60)
        await service.create_scheduled_scan("Scan 2", "batch", 30)
        schedules = await service.list_scheduled_scans()
        assert len(schedules) == 2

    async def test_list_active_only(self, db_session: AsyncSession):
        service = SchedulerService(db_session)
        s1 = await service.create_scheduled_scan("Scan 1", "watchlist", 60)
        await service.create_scheduled_scan("Scan 2", "batch", 30)
        await service.toggle_schedule(s1.id, False)
        active = await service.list_scheduled_scans(active_only=True)
        assert len(active) == 1

    async def test_get_due_scans(self, db_session: AsyncSession):
        service = SchedulerService(db_session)
        # Create a scan with next_run_at in the past
        scheduled = await service.create_scheduled_scan("Past scan", "watchlist", 60)
        # Manually set next_run_at to past
        scheduled.next_run_at = datetime(2020, 1, 1, tzinfo=UTC)
        await db_session.flush()

        due = await service.get_due_scans()
        assert len(due) == 1

    async def test_mark_scan_completed(self, db_session: AsyncSession):
        service = SchedulerService(db_session)
        scheduled = await service.create_scheduled_scan("Test", "watchlist", 60)
        await db_session.commit()
        await service.mark_scan_completed(scheduled.id)
        await db_session.commit()
        await db_session.refresh(scheduled)
        assert scheduled.last_run_at is not None
        assert scheduled.run_count == 1
        assert scheduled.next_run_at.replace(tzinfo=UTC) > datetime.now(UTC)

    async def test_toggle_schedule(self, db_session: AsyncSession):
        service = SchedulerService(db_session)
        scheduled = await service.create_scheduled_scan("Test", "watchlist", 60)
        await db_session.commit()
        toggled = await service.toggle_schedule(scheduled.id, False)
        await db_session.commit()
        assert toggled is True
        await db_session.refresh(scheduled)
        assert scheduled.is_active is False

    async def test_toggle_nonexistent(self, db_session: AsyncSession):
        service = SchedulerService(db_session)
        toggled = await service.toggle_schedule("nonexistent", True)
        assert toggled is False

    async def test_delete_schedule(self, db_session: AsyncSession):
        service = SchedulerService(db_session)
        scheduled = await service.create_scheduled_scan("Test", "watchlist", 60)
        deleted = await service.delete_schedule(scheduled.id)
        assert deleted is True
        schedules = await service.list_scheduled_scans()
        assert len(schedules) == 0

    async def test_delete_nonexistent(self, db_session: AsyncSession):
        service = SchedulerService(db_session)
        deleted = await service.delete_schedule("nonexistent")
        assert deleted is False

    async def test_get_packages_watchlist(self, db_session: AsyncSession):
        service = SchedulerService(db_session)
        scheduled = await service.create_scheduled_scan("Test", "watchlist", 60)

        # Add watchlist entries
        entry = WatchlistEntry(package_name="lodash", status=WatchlistStatus.ACTIVE.value)
        db_session.add(entry)
        await db_session.flush()

        packages = await service.get_packages_for_scan(scheduled)
        assert "lodash" in packages

    async def test_get_packages_batch(self, db_session: AsyncSession):
        service = SchedulerService(db_session)
        scheduled = await service.create_scheduled_scan(
            "Test", "batch", 60, packages=["lodash", "express"]
        )
        packages = await service.get_packages_for_scan(scheduled)
        assert packages == ["lodash", "express"]

    async def test_get_packages_single(self, db_session: AsyncSession):
        service = SchedulerService(db_session)
        scheduled = await service.create_scheduled_scan(
            "Test", "single", 60, packages=["lodash"]
        )
        packages = await service.get_packages_for_scan(scheduled)
        assert packages == ["lodash"]
