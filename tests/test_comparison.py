"""Tests for scan comparison service."""

from git_guardian.services.comparison_service import compare_scans


class TestComparisonService:
    """Test scan comparison logic."""

    def test_identical_scans(self):
        findings = [
            {"rule_id": "NET-001", "title": "HTTP request", "risk_level": "medium", "file_path": "index.js"},
        ]
        result = compare_scans(
            scan_id_before="scan-1",
            scan_id_after="scan-2",
            package_name="lodash",
            risk_before="medium",
            risk_after="medium",
            findings_before=findings,
            findings_after=findings,
        )
        assert result.risk_changed is False
        assert result.risk_direction == "same"
        assert len(result.findings_added) == 0
        assert len(result.findings_removed) == 0
        assert len(result.findings_unchanged) == 1

    def test_findings_added(self):
        before = []
        after = [
            {"rule_id": "NET-001", "title": "HTTP request", "risk_level": "medium", "file_path": "index.js"},
        ]
        result = compare_scans(
            scan_id_before="scan-1",
            scan_id_after="scan-2",
            package_name="lodash",
            risk_before="safe",
            risk_after="medium",
            findings_before=before,
            findings_after=after,
        )
        assert result.risk_changed is True
        assert result.risk_direction == "up"
        assert len(result.findings_added) == 1
        assert len(result.findings_removed) == 0

    def test_findings_removed(self):
        before = [
            {"rule_id": "NET-001", "title": "HTTP request", "risk_level": "medium", "file_path": "index.js"},
        ]
        after = []
        result = compare_scans(
            scan_id_before="scan-1",
            scan_id_after="scan-2",
            package_name="lodash",
            risk_before="medium",
            risk_after="safe",
            findings_before=before,
            findings_after=after,
        )
        assert result.risk_changed is True
        assert result.risk_direction == "down"
        assert len(result.findings_added) == 0
        assert len(result.findings_removed) == 1

    def test_mixed_changes(self):
        before = [
            {"rule_id": "NET-001", "title": "HTTP request", "risk_level": "medium", "file_path": "index.js"},
            {"rule_id": "FS-001", "title": "File write", "risk_level": "medium", "file_path": "lib.js"},
        ]
        after = [
            {"rule_id": "NET-001", "title": "HTTP request", "risk_level": "medium", "file_path": "index.js"},
            {"rule_id": "EXEC-001", "title": "Process exec", "risk_level": "high", "file_path": "cmd.js"},
        ]
        result = compare_scans(
            scan_id_before="scan-1",
            scan_id_after="scan-2",
            package_name="test-pkg",
            risk_before="medium",
            risk_after="high",
            findings_before=before,
            findings_after=after,
        )
        assert result.risk_changed is True
        assert result.risk_direction == "up"
        assert len(result.findings_added) == 1
        assert len(result.findings_removed) == 1
        assert len(result.findings_unchanged) == 1
        assert result.findings_added[0].rule_id == "EXEC-001"
        assert result.findings_removed[0].rule_id == "FS-001"

    def test_risk_downgrade(self):
        result = compare_scans(
            scan_id_before="scan-1",
            scan_id_after="scan-2",
            package_name="test-pkg",
            risk_before="high",
            risk_after="low",
            findings_before=[],
            findings_after=[],
        )
        assert result.risk_changed is True
        assert result.risk_direction == "down"

    def test_to_dict(self):
        result = compare_scans(
            scan_id_before="scan-1",
            scan_id_after="scan-2",
            package_name="lodash",
            risk_before="safe",
            risk_after="safe",
            findings_before=[],
            findings_after=[],
        )
        d = result.to_dict()
        assert d["package_name"] == "lodash"
        assert d["risk_changed"] is False
        assert isinstance(d["findings_added"], list)

    def test_version_tracking(self):
        result = compare_scans(
            scan_id_before="scan-1",
            scan_id_after="scan-2",
            package_name="lodash",
            risk_before="safe",
            risk_after="safe",
            findings_before=[],
            findings_after=[],
            version_before="4.17.20",
            version_after="4.17.21",
        )
        assert result.version_before == "4.17.20"
        assert result.version_after == "4.17.21"

    def test_total_changes(self):
        before = [
            {"rule_id": "A", "title": "A", "risk_level": "low", "file_path": "a.js"},
        ]
        after = [
            {"rule_id": "B", "title": "B", "risk_level": "low", "file_path": "b.js"},
        ]
        result = compare_scans(
            scan_id_before="scan-1",
            scan_id_after="scan-2",
            package_name="test",
            risk_before="low",
            risk_after="low",
            findings_before=before,
            findings_after=after,
        )
        assert result.total_changes == 2  # 1 added + 1 removed
