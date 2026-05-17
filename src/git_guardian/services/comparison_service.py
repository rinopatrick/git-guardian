"""Scan comparison service for diffing two scan results."""

from dataclasses import dataclass, field


@dataclass
class FindingDiff:
    """A single finding diff entry."""

    rule_id: str
    title: str
    status: str  # added, removed, unchanged
    risk_level: str
    file_path: str | None = None


@dataclass
class ScanComparisonResult:
    """Result of comparing two scans."""

    package_name: str
    scan_id_before: str
    scan_id_after: str
    risk_before: str
    risk_after: str
    risk_changed: bool
    risk_direction: str  # up, down, same
    findings_added: list[FindingDiff] = field(default_factory=list)
    findings_removed: list[FindingDiff] = field(default_factory=list)
    findings_unchanged: list[FindingDiff] = field(default_factory=list)
    version_before: str | None = None
    version_after: str | None = None
    duration_before: float = 0.0
    duration_after: float = 0.0

    @property
    def total_changes(self) -> int:
        return len(self.findings_added) + len(self.findings_removed)

    def to_dict(self) -> dict:
        """Convert to dict for serialization."""
        return {
            "package_name": self.package_name,
            "scan_id_before": self.scan_id_before,
            "scan_id_after": self.scan_id_after,
            "risk_before": self.risk_before,
            "risk_after": self.risk_after,
            "risk_changed": self.risk_changed,
            "risk_direction": self.risk_direction,
            "findings_added": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "risk_level": f.risk_level,
                    "file_path": f.file_path,
                }
                for f in self.findings_added
            ],
            "findings_removed": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "risk_level": f.risk_level,
                    "file_path": f.file_path,
                }
                for f in self.findings_removed
            ],
            "findings_unchanged": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "risk_level": f.risk_level,
                    "file_path": f.file_path,
                }
                for f in self.findings_unchanged
            ],
            "version_before": self.version_before,
            "version_after": self.version_after,
            "duration_before": self.duration_before,
            "duration_after": self.duration_after,
        }


_risk_order = {
    "safe": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def compare_scans(
    scan_id_before: str,
    scan_id_after: str,
    package_name: str,
    risk_before: str,
    risk_after: str,
    findings_before: list[dict],
    findings_after: list[dict],
    version_before: str | None = None,
    version_after: str | None = None,
    duration_before: float = 0.0,
    duration_after: float = 0.0,
) -> ScanComparisonResult:
    """Compare two scan results and produce a diff.

    Args:
        scan_id_before: ID of the earlier scan
        scan_id_after: ID of the later scan
        package_name: Package name
        risk_before: Risk level of earlier scan
        risk_after: Risk level of later scan
        findings_before: Findings from earlier scan (list of dicts)
        findings_after: Findings from later scan (list of dicts)
        version_before: Version scanned before
        version_after: Version scanned after
        duration_before: Scan duration before
        duration_after: Scan duration after

    Returns:
        ScanComparisonResult with detailed diff
    """
    # Build finding keys for comparison
    def _finding_key(f: dict) -> str:
        return f"{f.get('rule_id', '')}:{f.get('file_path', '')}:{f.get('title', '')}"

    before_keys = {_finding_key(f): f for f in findings_before}
    after_keys = {_finding_key(f): f for f in findings_after}

    added = []
    removed = []
    unchanged = []

    # Find added findings
    for key, finding in after_keys.items():
        if key not in before_keys:
            added.append(FindingDiff(
                rule_id=finding.get("rule_id", ""),
                title=finding.get("title", ""),
                status="added",
                risk_level=finding.get("risk_level", "low"),
                file_path=finding.get("file_path"),
            ))
        else:
            unchanged.append(FindingDiff(
                rule_id=finding.get("rule_id", ""),
                title=finding.get("title", ""),
                status="unchanged",
                risk_level=finding.get("risk_level", "low"),
                file_path=finding.get("file_path"),
            ))

    # Find removed findings
    for key, finding in before_keys.items():
        if key not in after_keys:
            removed.append(FindingDiff(
                rule_id=finding.get("rule_id", ""),
                title=finding.get("title", ""),
                status="removed",
                risk_level=finding.get("risk_level", "low"),
                file_path=finding.get("file_path"),
            ))

    # Determine risk direction
    risk_before_val = _risk_order.get(risk_before, 0)
    risk_after_val = _risk_order.get(risk_after, 0)

    if risk_after_val > risk_before_val:
        risk_direction = "up"
    elif risk_after_val < risk_before_val:
        risk_direction = "down"
    else:
        risk_direction = "same"

    return ScanComparisonResult(
        package_name=package_name,
        scan_id_before=scan_id_before,
        scan_id_after=scan_id_after,
        risk_before=risk_before,
        risk_after=risk_after,
        risk_changed=risk_before != risk_after,
        risk_direction=risk_direction,
        findings_added=added,
        findings_removed=removed,
        findings_unchanged=unchanged,
        version_before=version_before,
        version_after=version_after,
        duration_before=duration_before,
        duration_after=duration_after,
    )
