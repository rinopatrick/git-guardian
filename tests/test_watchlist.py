"""Tests for watchlist service."""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from git_guardian.db.models import Base
from git_guardian.db.watchlist_models import WatchlistStatus
from git_guardian.services.watchlist_service import WatchlistService


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
class TestWatchlistService:
    """Test watchlist service operations."""

    async def test_add_package(self, db_session: AsyncSession):
        service = WatchlistService(db_session)
        entry = await service.add_package("lodash")
        assert entry.package_name == "lodash"
        assert entry.status == WatchlistStatus.ACTIVE.value

    async def test_add_package_with_notes(self, db_session: AsyncSession):
        service = WatchlistService(db_session)
        entry = await service.add_package("express", notes="Web framework")
        assert entry.notes == "Web framework"

    async def test_add_duplicate_package(self, db_session: AsyncSession):
        service = WatchlistService(db_session)
        entry1 = await service.add_package("lodash")
        entry2 = await service.add_package("lodash")
        assert entry1.id == entry2.id

    async def test_add_removed_package_reactivates(self, db_session: AsyncSession):
        service = WatchlistService(db_session)
        await service.add_package("lodash")
        await service.remove_package("lodash")
        reactivated = await service.add_package("lodash")
        assert reactivated.status == WatchlistStatus.ACTIVE.value

    async def test_remove_package(self, db_session: AsyncSession):
        service = WatchlistService(db_session)
        await service.add_package("lodash")
        removed = await service.remove_package("lodash")
        assert removed is True

    async def test_remove_nonexistent(self, db_session: AsyncSession):
        service = WatchlistService(db_session)
        removed = await service.remove_package("nonexistent")
        assert removed is False

    async def test_pause_package(self, db_session: AsyncSession):
        service = WatchlistService(db_session)
        await service.add_package("lodash")
        paused = await service.pause_package("lodash")
        assert paused is True
        entry = await service.get_entry("lodash")
        assert entry.status == WatchlistStatus.PAUSED.value

    async def test_resume_package(self, db_session: AsyncSession):
        service = WatchlistService(db_session)
        await service.add_package("lodash")
        await service.pause_package("lodash")
        resumed = await service.resume_package("lodash")
        assert resumed is True
        entry = await service.get_entry("lodash")
        assert entry.status == WatchlistStatus.ACTIVE.value

    async def test_get_entry(self, db_session: AsyncSession):
        service = WatchlistService(db_session)
        await service.add_package("lodash")
        entry = await service.get_entry("lodash")
        assert entry is not None
        assert entry.package_name == "lodash"

    async def test_get_nonexistent_entry(self, db_session: AsyncSession):
        service = WatchlistService(db_session)
        entry = await service.get_entry("nonexistent")
        assert entry is None

    async def test_list_entries(self, db_session: AsyncSession):
        service = WatchlistService(db_session)
        await service.add_package("lodash")
        await service.add_package("express")
        await service.add_package("react")
        entries = await service.list_entries()
        assert len(entries) == 3

    async def test_list_entries_excludes_removed(self, db_session: AsyncSession):
        service = WatchlistService(db_session)
        await service.add_package("lodash")
        await service.add_package("express")
        await service.remove_package("lodash")
        entries = await service.list_entries()
        assert len(entries) == 1
        assert entries[0].package_name == "express"

    async def test_get_active_packages(self, db_session: AsyncSession):
        service = WatchlistService(db_session)
        await service.add_package("lodash")
        await service.add_package("express")
        await service.pause_package("lodash")
        active = await service.get_active_packages()
        assert len(active) == 1
        assert "express" in active

    async def test_update_scan_result(self, db_session: AsyncSession):
        service = WatchlistService(db_session)
        await service.add_package("lodash")
        await service.update_scan_result("lodash", "scan-123", "high")
        entry = await service.get_entry("lodash")
        assert entry.last_scan_id == "scan-123"
        assert entry.last_risk_level == "high"
        assert entry.scan_count == 1

    async def test_get_stats(self, db_session: AsyncSession):
        service = WatchlistService(db_session)
        await service.add_package("lodash")
        await service.add_package("express")
        await service.pause_package("lodash")
        stats = await service.get_stats()
        assert stats["active"] == 1
        assert stats["paused"] == 1
        assert stats["total"] == 2
