"""Watchlist service for managing package monitoring."""

from datetime import UTC, datetime

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from git_guardian.db.watchlist_models import WatchlistEntry, WatchlistStatus


class WatchlistService:
    """Service for managing the package watchlist."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add_package(
        self,
        package_name: str,
        notes: str | None = None,
    ) -> WatchlistEntry:
        """Add a package to the watchlist.

        Args:
            package_name: npm package name
            notes: Optional notes about why this package is watched

        Returns:
            The created or existing watchlist entry
        """
        # Check if already exists
        result = await self.session.execute(
            select(WatchlistEntry).where(WatchlistEntry.package_name == package_name)
        )
        existing = result.scalar_one_or_none()

        if existing:
            if existing.status == WatchlistStatus.REMOVED.value:
                # Reactivate
                existing.status = WatchlistStatus.ACTIVE.value
                existing.notes = notes or existing.notes
                existing.updated_at = datetime.now(UTC)
                return existing
            return existing

        entry = WatchlistEntry(
            package_name=package_name,
            notes=notes,
        )
        self.session.add(entry)
        await self.session.flush()
        return entry

    async def remove_package(self, package_name: str) -> bool:
        """Soft-remove a package from the watchlist.

        Args:
            package_name: npm package name

        Returns:
            True if removed, False if not found
        """
        result = await self.session.execute(
            select(WatchlistEntry).where(
                WatchlistEntry.package_name == package_name,
                WatchlistEntry.status != WatchlistStatus.REMOVED.value,
            )
        )
        entry = result.scalar_one_or_none()

        if not entry:
            return False

        entry.status = WatchlistStatus.REMOVED.value
        entry.updated_at = datetime.now(UTC)
        return True

    async def pause_package(self, package_name: str) -> bool:
        """Pause monitoring for a package.

        Args:
            package_name: npm package name

        Returns:
            True if paused, False if not found
        """
        result = await self.session.execute(
            select(WatchlistEntry).where(
                WatchlistEntry.package_name == package_name,
                WatchlistEntry.status == WatchlistStatus.ACTIVE.value,
            )
        )
        entry = result.scalar_one_or_none()

        if not entry:
            return False

        entry.status = WatchlistStatus.PAUSED.value
        entry.updated_at = datetime.now(UTC)
        return True

    async def resume_package(self, package_name: str) -> bool:
        """Resume monitoring for a paused package.

        Args:
            package_name: npm package name

        Returns:
            True if resumed, False if not found
        """
        result = await self.session.execute(
            select(WatchlistEntry).where(
                WatchlistEntry.package_name == package_name,
                WatchlistEntry.status == WatchlistStatus.PAUSED.value,
            )
        )
        entry = result.scalar_one_or_none()

        if not entry:
            return False

        entry.status = WatchlistStatus.ACTIVE.value
        entry.updated_at = datetime.now(UTC)
        return True

    async def get_entry(self, package_name: str) -> WatchlistEntry | None:
        """Get a watchlist entry by package name.

        Args:
            package_name: npm package name

        Returns:
            Watchlist entry or None
        """
        result = await self.session.execute(
            select(WatchlistEntry).where(WatchlistEntry.package_name == package_name)
        )
        return result.scalar_one_or_none()

    async def list_entries(
        self,
        status: WatchlistStatus | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[WatchlistEntry]:
        """List watchlist entries.

        Args:
            status: Filter by status (None for all non-removed)
            limit: Max results
            offset: Pagination offset

        Returns:
            List of watchlist entries
        """
        query = select(WatchlistEntry)

        if status:
            query = query.where(WatchlistEntry.status == status.value)
        else:
            query = query.where(
                WatchlistEntry.status != WatchlistStatus.REMOVED.value
            )

        query = query.order_by(desc(WatchlistEntry.created_at)).limit(limit).offset(offset)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_active_packages(self) -> list[str]:
        """Get list of active watchlist package names.

        Returns:
            List of package names with active status
        """
        result = await self.session.execute(
            select(WatchlistEntry.package_name).where(
                WatchlistEntry.status == WatchlistStatus.ACTIVE.value
            )
        )
        return [row[0] for row in result]

    async def update_scan_result(
        self,
        package_name: str,
        scan_id: str,
        risk_level: str,
    ) -> None:
        """Update watchlist entry after a scan.

        Args:
            package_name: npm package name
            scan_id: ID of the scan record
            risk_level: Risk level from the scan
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

    async def get_stats(self) -> dict[str, int]:
        """Get watchlist statistics.

        Returns:
            Dict with counts by status
        """
        result = await self.session.execute(
            select(
                WatchlistEntry.status,
                func.count(WatchlistEntry.id),
            ).group_by(WatchlistEntry.status)
        )
        stats = {row[0]: row[1] for row in result}
        stats["total"] = sum(stats.values())
        return stats
