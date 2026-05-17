"""Tests for new API routes."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from git_guardian.api.app import app
from git_guardian.api.deps import get_session
from git_guardian.db.models import Base


@pytest.fixture
def client():
    """Create test client with in-memory database."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_session():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_session] = override_get_session

    import asyncio
    loop = asyncio.new_event_loop()
    loop.run_until_complete(_init_db(engine))

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()
    loop.run_until_complete(engine.dispose())
    loop.close()


async def _init_db(engine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


class TestWatchlistAPI:
    """Test watchlist API routes."""

    def test_add_to_watchlist(self, client):
        resp = client.post("/api/watchlist", json={"package_name": "lodash"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["package_name"] == "lodash"
        assert data["status"] == "active"

    def test_list_watchlist(self, client):
        resp = client.get("/api/watchlist")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_remove_from_watchlist(self, client):
        client.post("/api/watchlist", json={"package_name": "to-remove"})
        resp = client.delete("/api/watchlist/to-remove")
        assert resp.status_code == 200
        assert resp.json()["status"] == "removed"

    def test_remove_nonexistent(self, client):
        resp = client.delete("/api/watchlist/nonexistent")
        assert resp.status_code == 404

    def test_pause_package(self, client):
        client.post("/api/watchlist", json={"package_name": "to-pause"})
        resp = client.post("/api/watchlist/to-pause/pause")
        assert resp.status_code == 200

    def test_resume_package(self, client):
        client.post("/api/watchlist", json={"package_name": "to-resume"})
        client.post("/api/watchlist/to-resume/pause")
        resp = client.post("/api/watchlist/to-resume/resume")
        assert resp.status_code == 200

    def test_watchlist_stats(self, client):
        resp = client.get("/api/watchlist/stats")
        assert resp.status_code == 200
        assert "total" in resp.json()


class TestAlertsAPI:
    """Test alerts API routes."""

    def test_list_alerts(self, client):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_alert_stats(self, client):
        resp = client.get("/api/alerts/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "unread" in data

    def test_unread_count(self, client):
        resp = client.get("/api/alerts/unread-count")
        assert resp.status_code == 200
        assert "unread" in resp.json()


class TestExportAPI:
    """Test export API routes."""

    def test_export_json(self, client):
        resp = client.get("/api/export/json")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json"

    def test_export_csv(self, client):
        resp = client.get("/api/export/csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]

    def test_export_findings_csv(self, client):
        resp = client.get("/api/export/findings/csv")
        assert resp.status_code == 200

    def test_export_summary(self, client):
        resp = client.get("/api/export/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_scans" in data


class TestTasksAPI:
    """Test tasks API routes."""

    def test_list_tasks(self, client):
        resp = client.get("/api/tasks")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_list_active_tasks(self, client):
        resp = client.get("/api/tasks/active")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_submit_scan_task(self, client):
        resp = client.post("/api/tasks/scan", json={"package_name": "lodash"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("pending", "running", "completed")

    def test_submit_batch_task(self, client):
        resp = client.post("/api/tasks/scan", json={"packages": ["lodash", "express"]})
        assert resp.status_code == 200

    def test_submit_empty_task(self, client):
        resp = client.post("/api/tasks/scan", json={})
        assert resp.status_code == 400

    def test_cleanup_tasks(self, client):
        resp = client.post("/api/tasks/cleanup")
        assert resp.status_code == 200
        assert "removed" in resp.json()


class TestCompareAPI:
    """Test compare API routes."""

    def test_compare_nonexistent(self, client):
        resp = client.post("/api/compare", json={
            "scan_id_before": "nonexistent-1",
            "scan_id_after": "nonexistent-2",
        })
        assert resp.status_code == 404

    def test_compare_latest_nonexistent(self, client):
        resp = client.get("/api/compare/nonexistent-package/latest")
        assert resp.status_code == 404


class TestDependenciesAPI:
    """Test dependencies API routes."""

    def test_scan_dependencies(self, client):
        resp = client.get("/api/dependencies/lodash?max_depth=1&max_packages=5")
        # This may fail if npm is unreachable, but should return 200 or 500
        assert resp.status_code in (200, 500)


class TestRateLimiterAPI:
    """Test rate limiter API routes."""

    def test_rate_limiter_stats(self, client):
        resp = client.get("/api/rate-limiter/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_requests" in data
        assert "bucket_size" in data


class TestSchedulerAPI:
    """Test scheduler API routes."""

    def test_list_schedules(self, client):
        resp = client.get("/api/scheduler")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_create_schedule(self, client):
        resp = client.post("/api/scheduler", json={
            "name": "Test Schedule",
            "scan_type": "watchlist",
            "interval_minutes": 60,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Test Schedule"
        assert data["is_active"] is True

    def test_delete_nonexistent_schedule(self, client):
        resp = client.delete("/api/scheduler/nonexistent")
        assert resp.status_code == 404
