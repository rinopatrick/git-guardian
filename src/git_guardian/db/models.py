"""Database models."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for database models."""

    pass


class ScanRecord(Base):
    """Record of a package scan."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    package_name: Mapped[str] = mapped_column(String(255), index=True)
    package_version: Mapped[str] = mapped_column(String(50))
    risk_level: Mapped[str] = mapped_column(String(20), index=True)
    findings_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_analysis: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan_duration: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(UTC),
        index=True,
    )

    def __repr__(self) -> str:
        return f"<ScanRecord {self.package_name}@{self.package_version}>"
