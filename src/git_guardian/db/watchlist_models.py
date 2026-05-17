"""Watchlist system for monitoring npm packages."""

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from git_guardian.db.models import Base


class WatchlistStatus(StrEnum):
    """Watchlist entry status."""

    ACTIVE = "active"
    PAUSED = "paused"
    REMOVED = "removed"


class WatchlistEntry(Base):
    """A package in the watchlist."""

    __tablename__ = "watchlist"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    package_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    status: Mapped[str] = mapped_column(
        String(20),
        default=WatchlistStatus.ACTIVE.value,
        index=True,
    )
    last_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_risk_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    scan_count: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(UTC),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    def __repr__(self) -> str:
        return f"<WatchlistEntry {self.package_name} ({self.status})>"


class ScanComparison(Base):
    """Comparison between two scans of the same package."""

    __tablename__ = "scan_comparisons"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    package_name: Mapped[str] = mapped_column(String(255), index=True)
    scan_id_before: Mapped[str] = mapped_column(String(36))
    scan_id_after: Mapped[str] = mapped_column(String(36))
    risk_before: Mapped[str] = mapped_column(String(20))
    risk_after: Mapped[str] = mapped_column(String(20))
    findings_added: Mapped[int] = mapped_column(Integer, default=0)
    findings_removed: Mapped[int] = mapped_column(Integer, default=0)
    findings_unchanged: Mapped[int] = mapped_column(Integer, default=0)
    diff_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(UTC),
    )

    def __repr__(self) -> str:
        return f"<ScanComparison {self.package_name} {self.risk_before}->{self.risk_after}>"


class Alert(Base):
    """Security alert for high-risk findings."""

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    package_name: Mapped[str] = mapped_column(String(255), index=True)
    scan_id: Mapped[str] = mapped_column(String(36), index=True)
    alert_type: Mapped[str] = mapped_column(String(50), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text)
    is_read: Mapped[bool] = mapped_column(default=False)
    is_resolved: Mapped[bool] = mapped_column(default=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(UTC),
    )

    def __repr__(self) -> str:
        return f"<Alert {self.alert_type} {self.severity} for {self.package_name}>"


class ScheduledScan(Base):
    """Scheduled scan configuration."""

    __tablename__ = "scheduled_scans"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    name: Mapped[str] = mapped_column(String(255))
    scan_type: Mapped[str] = mapped_column(String(50))  # watchlist, batch, single
    packages_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    enable_ai: Mapped[bool] = mapped_column(default=False)
    is_active: Mapped[bool] = mapped_column(default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    run_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(UTC),
    )

    def __repr__(self) -> str:
        return f"<ScheduledScan {self.name} every {self.interval_minutes}min>"
