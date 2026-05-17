"""Export service for generating reports in JSON and CSV formats."""

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from git_guardian.db.models import ScanRecord


class ExportService:
    """Service for exporting scan data in various formats."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def export_scans_json(
        self,
        limit: int = 100,
        risk_level: str | None = None,
        package_name: str | None = None,
    ) -> str:
        """Export scans as JSON.

        Args:
            limit: Maximum number of scans to export
            risk_level: Filter by risk level
            package_name: Filter by package name

        Returns:
            JSON string
        """
        query = select(ScanRecord).order_by(desc(ScanRecord.created_at))

        if risk_level:
            query = query.where(ScanRecord.risk_level == risk_level)
        if package_name:
            query = query.where(ScanRecord.package_name == package_name)

        query = query.limit(limit)

        result = await self.session.execute(query)
        records = result.scalars().all()

        export_data = {
            "exported_at": datetime.now(UTC).isoformat(),
            "total_records": len(records),
            "filters": {
                "risk_level": risk_level,
                "package_name": package_name,
                "limit": limit,
            },
            "scans": [],
        }

        for record in records:
            findings = json.loads(record.findings_json) if record.findings_json else []
            export_data["scans"].append({
                "id": record.id,
                "package_name": record.package_name,
                "package_version": record.package_version,
                "risk_level": record.risk_level,
                "findings_count": len(findings),
                "findings": findings,
                "ai_analysis": record.ai_analysis,
                "scan_duration": record.scan_duration,
                "created_at": record.created_at.isoformat() if record.created_at else None,
            })

        return json.dumps(export_data, indent=2, default=str)

    async def export_scans_csv(
        self,
        limit: int = 100,
        risk_level: str | None = None,
        package_name: str | None = None,
    ) -> str:
        """Export scans as CSV.

        Args:
            limit: Maximum number of scans to export
            risk_level: Filter by risk level
            package_name: Filter by package name

        Returns:
            CSV string
        """
        query = select(ScanRecord).order_by(desc(ScanRecord.created_at))

        if risk_level:
            query = query.where(ScanRecord.risk_level == risk_level)
        if package_name:
            query = query.where(ScanRecord.package_name == package_name)

        query = query.limit(limit)

        result = await self.session.execute(query)
        records = result.scalars().all()

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "id",
            "package_name",
            "package_version",
            "risk_level",
            "findings_count",
            "scan_duration",
            "created_at",
        ])

        # Rows
        for record in records:
            findings = json.loads(record.findings_json) if record.findings_json else []
            writer.writerow([
                record.id,
                record.package_name,
                record.package_version,
                record.risk_level,
                len(findings),
                f"{record.scan_duration:.2f}",
                record.created_at.isoformat() if record.created_at else "",
            ])

        return output.getvalue()

    async def export_findings_csv(
        self,
        limit: int = 100,
        risk_level: str | None = None,
    ) -> str:
        """Export individual findings as CSV.

        Args:
            limit: Maximum number of scans to include
            risk_level: Filter by risk level

        Returns:
            CSV string with one row per finding
        """
        query = select(ScanRecord).order_by(desc(ScanRecord.created_at))

        if risk_level:
            query = query.where(ScanRecord.risk_level == risk_level)

        query = query.limit(limit)

        result = await self.session.execute(query)
        records = result.scalars().all()

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "scan_id",
            "package_name",
            "package_version",
            "rule_id",
            "finding_title",
            "finding_risk_level",
            "file_path",
            "line_number",
            "description",
        ])

        # Rows
        for record in records:
            findings = json.loads(record.findings_json) if record.findings_json else []
            for finding in findings:
                writer.writerow([
                    record.id,
                    record.package_name,
                    record.package_version,
                    finding.get("rule_id", ""),
                    finding.get("title", ""),
                    finding.get("risk_level", ""),
                    finding.get("file_path", ""),
                    finding.get("line_number", ""),
                    finding.get("description", ""),
                ])

        return output.getvalue()

    async def get_summary_stats(self) -> dict[str, Any]:
        """Get summary statistics for the export report.

        Returns:
            Dict with summary stats
        """
        from sqlalchemy import func

        # Total scans
        count_result = await self.session.execute(
            select(func.count(ScanRecord.id))
        )
        total_scans = count_result.scalar() or 0

        # Risk distribution
        risk_result = await self.session.execute(
            select(
                ScanRecord.risk_level,
                func.count(ScanRecord.id),
            ).group_by(ScanRecord.risk_level)
        )
        risk_distribution = {row[0]: row[1] for row in risk_result}

        # Average scan duration
        avg_result = await self.session.execute(
            select(func.avg(ScanRecord.scan_duration))
        )
        avg_duration = avg_result.scalar() or 0.0

        # Unique packages
        pkg_result = await self.session.execute(
            select(func.count(func.distinct(ScanRecord.package_name)))
        )
        unique_packages = pkg_result.scalar() or 0

        return {
            "total_scans": total_scans,
            "unique_packages": unique_packages,
            "risk_distribution": risk_distribution,
            "average_scan_duration": round(avg_duration, 2),
            "exported_at": datetime.now(UTC).isoformat(),
        }
