"""Alert service for managing security alerts."""

from datetime import UTC, datetime

from sqlalchemy import desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from git_guardian.db.models import ScanRecord
from git_guardian.db.watchlist_models import Alert


class AlertService:
    """Service for managing security alerts."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_alert(
        self,
        package_name: str,
        scan_id: str,
        alert_type: str,
        severity: str,
        title: str,
        description: str,
    ) -> Alert:
        """Create a new alert.

        Args:
            package_name: Package that triggered the alert
            scan_id: ID of the scan that triggered it
            alert_type: Type of alert (risk_change, new_finding, high_risk)
            severity: Alert severity (info, warning, critical)
            title: Alert title
            description: Alert description

        Returns:
            Created alert
        """
        alert = Alert(
            package_name=package_name,
            scan_id=scan_id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
        )
        self.session.add(alert)
        await self.session.flush()
        return alert

    async def check_scan_for_alerts(
        self,
        package_name: str,
        scan_id: str,
        risk_level: str,
        findings: list[dict],
    ) -> list[Alert]:
        """Check a scan result and generate alerts if needed.

        Args:
            package_name: Package name
            scan_id: Scan record ID
            risk_level: Risk level from scan
            findings: List of finding dicts

        Returns:
            List of created alerts
        """
        alerts = []

        # Alert on high/critical risk
        if risk_level in ("high", "critical"):
            alert = await self.create_alert(
                package_name=package_name,
                scan_id=scan_id,
                alert_type="high_risk",
                severity="critical" if risk_level == "critical" else "warning",
                title=f"High risk package: {package_name}",
                description=(
                    f"Package {package_name} has risk level {risk_level.upper()} "
                    f"with {len(findings)} findings."
                ),
            )
            alerts.append(alert)

        # Alert on specific dangerous findings
        dangerous_rules = {"MALWARE-001", "MALWARE-002", "CRYPTO-001", "CRYPTO-002"}
        for finding in findings:
            rule_id = finding.get("rule_id", "")
            if rule_id in dangerous_rules:
                alert = await self.create_alert(
                    package_name=package_name,
                    scan_id=scan_id,
                    alert_type="dangerous_pattern",
                    severity="critical",
                    title=f"Dangerous pattern in {package_name}: {finding.get('title', rule_id)}",
                    description=finding.get("description", ""),
                )
                alerts.append(alert)

        # Check for risk level change from previous scan
        prev_result = await self.session.execute(
            select(ScanRecord)
            .where(
                ScanRecord.package_name == package_name,
                ScanRecord.id != scan_id,
            )
            .order_by(desc(ScanRecord.created_at))
            .limit(1)
        )
        prev_scan = prev_result.scalar_one_or_none()

        if prev_scan and prev_scan.risk_level != risk_level:
            risk_order = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            old_val = risk_order.get(prev_scan.risk_level, 0)
            new_val = risk_order.get(risk_level, 0)

            if new_val > old_val:
                alert = await self.create_alert(
                    package_name=package_name,
                    scan_id=scan_id,
                    alert_type="risk_increase",
                    severity="warning",
                    title=f"Risk increased for {package_name}",
                    description=(
                        f"Risk level changed from {prev_scan.risk_level.upper()} "
                        f"to {risk_level.upper()}."
                    ),
                )
                alerts.append(alert)

        return alerts

    async def list_alerts(
        self,
        is_read: bool | None = None,
        is_resolved: bool | None = None,
        severity: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Alert]:
        """List alerts with optional filters.

        Args:
            is_read: Filter by read status
            is_resolved: Filter by resolved status
            severity: Filter by severity
            limit: Max results
            offset: Pagination offset

        Returns:
            List of alerts
        """
        query = select(Alert).order_by(desc(Alert.created_at))

        if is_read is not None:
            query = query.where(Alert.is_read == is_read)
        if is_resolved is not None:
            query = query.where(Alert.is_resolved == is_resolved)
        if severity:
            query = query.where(Alert.severity == severity)

        query = query.limit(limit).offset(offset)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def mark_read(self, alert_id: str) -> bool:
        """Mark an alert as read.

        Args:
            alert_id: Alert ID

        Returns:
            True if updated
        """
        result = await self.session.execute(
            select(Alert).where(Alert.id == alert_id)
        )
        alert = result.scalar_one_or_none()

        if not alert:
            return False

        alert.is_read = True
        return True

    async def mark_all_read(self) -> int:
        """Mark all alerts as read.

        Returns:
            Number of alerts updated
        """
        result = await self.session.execute(
            update(Alert)
            .where(Alert.is_read == False)  # noqa: E712
            .values(is_read=True)
        )
        return result.rowcount

    async def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert.

        Args:
            alert_id: Alert ID

        Returns:
            True if resolved
        """
        result = await self.session.execute(
            select(Alert).where(Alert.id == alert_id)
        )
        alert = result.scalar_one_or_none()

        if not alert:
            return False

        alert.is_resolved = True
        alert.resolved_at = datetime.now(UTC)
        return True

    async def get_alert_stats(self) -> dict[str, int]:
        """Get alert statistics.

        Returns:
            Dict with alert counts
        """
        # Total
        total_result = await self.session.execute(
            select(func.count(Alert.id))
        )
        total = total_result.scalar() or 0

        # Unread
        unread_result = await self.session.execute(
            select(func.count(Alert.id)).where(Alert.is_read == False)  # noqa: E712
        )
        unread = unread_result.scalar() or 0

        # Unresolved
        unresolved_result = await self.session.execute(
            select(func.count(Alert.id)).where(Alert.is_resolved == False)  # noqa: E712
        )
        unresolved = unresolved_result.scalar() or 0

        # By severity
        severity_result = await self.session.execute(
            select(
                Alert.severity,
                func.count(Alert.id),
            ).group_by(Alert.severity)
        )
        by_severity = {row[0]: row[1] for row in severity_result}

        return {
            "total": total,
            "unread": unread,
            "unresolved": unresolved,
            "by_severity": by_severity,
        }

    async def get_unread_count(self) -> int:
        """Get count of unread alerts."""
        result = await self.session.execute(
            select(func.count(Alert.id)).where(Alert.is_read == False)  # noqa: E712
        )
        return result.scalar() or 0
