"""Scheduled scanning service using APScheduler."""

import json
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from git_guardian.db.watchlist_models import ScheduledScan, WatchlistEntry, WatchlistStatus

logger = logging.getLogger(__name__)


class SchedulerService:
    """Service for managing scheduled scans."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_scheduled_scan(
        self,
        name: str,
        scan_type: str,
        interval_minutes: int = 60,
        packages: list[str] | None = None,
        enable_ai: bool = False,
    ) -> ScheduledScan:
        """Create a new scheduled scan.

        Args:
            name: Name for this scheduled scan
            scan_type: Type of scan (watchlist, batch, single)
            interval_minutes: How often to run (in minutes)
            packages: List of packages (for batch/single types)
            enable_ai: Whether to enable AI analysis

        Returns:
            Created scheduled scan
        """
        now = datetime.now(UTC)
        scheduled = ScheduledScan(
            name=name,
            scan_type=scan_type,
            packages_json=json.dumps(packages) if packages else None,
            interval_minutes=interval_minutes,
            enable_ai=enable_ai,
            is_active=True,
            next_run_at=now + timedelta(minutes=interval_minutes),
        )
        self.session.add(scheduled)
        await self.session.flush()
        return scheduled

    async def list_scheduled_scans(
        self,
        active_only: bool = False,
    ) -> list[ScheduledScan]:
        """List scheduled scans.

        Args:
            active_only: Only return active schedules

        Returns:
            List of scheduled scans
        """
        query = select(ScheduledScan).order_by(ScheduledScan.created_at)

        if active_only:
            query = query.where(ScheduledScan.is_active == True)  # noqa: E712

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_due_scans(self) -> list[ScheduledScan]:
        """Get scheduled scans that are due to run.

        Returns:
            List of due scheduled scans
        """
        now = datetime.now(UTC)
        result = await self.session.execute(
            select(ScheduledScan).where(
                ScheduledScan.is_active == True,  # noqa: E712
                ScheduledScan.next_run_at <= now,
            )
        )
        return list(result.scalars().all())

    async def mark_scan_completed(
        self,
        scheduled_id: str,
    ) -> None:
        """Mark a scheduled scan as completed and set next run time.

        Args:
            scheduled_id: ID of the scheduled scan
        """
        result = await self.session.execute(
            select(ScheduledScan).where(ScheduledScan.id == scheduled_id)
        )
        scheduled = result.scalar_one_or_none()

        if scheduled:
            now = datetime.now(UTC)
            scheduled.last_run_at = now
            scheduled.next_run_at = now + timedelta(minutes=scheduled.interval_minutes)
            scheduled.run_count += 1

    async def toggle_schedule(
        self,
        scheduled_id: str,
        is_active: bool,
    ) -> bool:
        """Enable or disable a scheduled scan.

        Args:
            scheduled_id: ID of the scheduled scan
            is_active: Whether to activate or deactivate

        Returns:
            True if updated
        """
        result = await self.session.execute(
            select(ScheduledScan).where(ScheduledScan.id == scheduled_id)
        )
        scheduled = result.scalar_one_or_none()

        if not scheduled:
            return False

        scheduled.is_active = is_active
        if is_active:
            scheduled.next_run_at = datetime.now(UTC) + timedelta(
                minutes=scheduled.interval_minutes
            )
        return True

    async def delete_schedule(self, scheduled_id: str) -> bool:
        """Delete a scheduled scan.

        Args:
            scheduled_id: ID of the scheduled scan

        Returns:
            True if deleted
        """
        result = await self.session.execute(
            select(ScheduledScan).where(ScheduledScan.id == scheduled_id)
        )
        scheduled = result.scalar_one_or_none()

        if not scheduled:
            return False

        await self.session.delete(scheduled)
        return True

    async def get_packages_for_scan(
        self,
        scheduled: ScheduledScan,
    ) -> list[str]:
        """Get the list of packages to scan for a scheduled scan.

        Args:
            scheduled: The scheduled scan configuration

        Returns:
            List of package names to scan
        """
        if scheduled.scan_type == "watchlist":
            # Get all active watchlist packages
            result = await self.session.execute(
                select(WatchlistEntry.package_name).where(
                    WatchlistEntry.status == WatchlistStatus.ACTIVE.value
                )
            )
            return [row[0] for row in result]

        elif scheduled.scan_type == "batch":
            if scheduled.packages_json:
                return json.loads(scheduled.packages_json)
            return []

        elif scheduled.scan_type == "single":
            if scheduled.packages_json:
                packages = json.loads(scheduled.packages_json)
                return packages[:1] if packages else []
            return []

        return []

    async def update_watchlist_after_scan(
        self,
        package_name: str,
        scan_id: str,
        risk_level: str,
    ) -> None:
        """Update watchlist entry after a scheduled scan.

        Args:
            package_name: Package name
            scan_id: Scan record ID
            risk_level: Risk level from scan
        """
        result = await self.session.execute(
            select(WatchlistEntry).where(WatchlistEntry.package_name == package_name)
        )
        entry = result.scalar_one_or_none()

        if entry:
            entry.last_scan_id = scan_id
            entry.last_risk_level = risk_level
            entry.last_scan_at = datetime.now(UTC)
            entry.scan_count += 1
            entry.updated_at = datetime.now(UTC)
