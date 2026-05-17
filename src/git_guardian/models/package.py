"""Package data models."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    """Risk level classification."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PackageAuthor(BaseModel):
    """Package author information."""

    name: str | None = None
    email: str | None = None
    url: str | None = None


class PackageVersion(BaseModel):
    """Package version information."""

    version: str
    description: str | None = None
    author: PackageAuthor | None = None
    license: str | None = None
    dependencies: dict[str, str] = {}
    scripts: dict[str, str] = {}
    dist: dict[str, Any] = {}
    published_at: datetime | None = None


class PackageInfo(BaseModel):
    """npm package information."""

    name: str
    description: str | None = None
    latest_version: str
    versions: list[PackageVersion] = []
    author: PackageAuthor | None = None
    license: str | None = None
    repository_url: str | None = None
    homepage: str | None = None
    keywords: list[str] = []
    weekly_downloads: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None


class Finding(BaseModel):
    """A security finding."""

    rule_id: str
    title: str
    description: str
    risk_level: RiskLevel
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None
    recommendation: str | None = None


class ScanResult(BaseModel):
    """Result of scanning a package."""

    package: PackageInfo
    risk_level: RiskLevel
    findings: list[Finding] = []
    ai_analysis: str | None = None
    scan_duration_seconds: float = 0.0
    scanned_at: datetime = Field(default_factory=datetime.now)

    @property
    def finding_count(self) -> dict[RiskLevel, int]:
        """Count findings by risk level."""
        counts: dict[RiskLevel, int] = {level: 0 for level in RiskLevel}
        for finding in self.findings:
            counts[finding.risk_level] += 1
        return counts
