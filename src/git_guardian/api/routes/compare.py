"""Scan comparison API routes."""

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from git_guardian.api.deps import get_session
from git_guardian.db.models import ScanRecord
from git_guardian.services.comparison_service import compare_scans

router = APIRouter(prefix="/compare", tags=["compare"])


class CompareRequest(BaseModel):
    """Request to compare two scans."""

    scan_id_before: str
    scan_id_after: str


class CompareResponse(BaseModel):
    """Comparison response."""

    package_name: str
    scan_id_before: str
    scan_id_after: str
    risk_before: str
    risk_after: str
    risk_changed: bool
    risk_direction: str
    findings_added: list[dict]
    findings_removed: list[dict]
    findings_unchanged: list[dict]
    version_before: str | None
    version_after: str | None


@router.post("", response_model=CompareResponse)
async def compare_two_scans(
    request: CompareRequest,
    session: AsyncSession = Depends(get_session),
) -> CompareResponse:
    """Compare two scan results."""
    # Fetch both scans
    before_result = await session.execute(
        select(ScanRecord).where(ScanRecord.id == request.scan_id_before)
    )
    before = before_result.scalar_one_or_none()

    after_result = await session.execute(
        select(ScanRecord).where(ScanRecord.id == request.scan_id_after)
    )
    after = after_result.scalar_one_or_none()

    if not before:
        raise HTTPException(status_code=404, detail=f"Scan {request.scan_id_before} not found")
    if not after:
        raise HTTPException(status_code=404, detail=f"Scan {request.scan_id_after} not found")

    if before.package_name != after.package_name:
        raise HTTPException(
            status_code=400,
            detail="Cannot compare scans of different packages",
        )

    findings_before = json.loads(before.findings_json) if before.findings_json else []
    findings_after = json.loads(after.findings_json) if after.findings_json else []

    result = compare_scans(
        scan_id_before=before.id,
        scan_id_after=after.id,
        package_name=before.package_name,
        risk_before=before.risk_level,
        risk_after=after.risk_level,
        findings_before=findings_before,
        findings_after=findings_after,
        version_before=before.package_version,
        version_after=after.package_version,
        duration_before=before.scan_duration,
        duration_after=after.scan_duration,
    )

    return CompareResponse(
        package_name=result.package_name,
        scan_id_before=result.scan_id_before,
        scan_id_after=result.scan_id_after,
        risk_before=result.risk_before,
        risk_after=result.risk_after,
        risk_changed=result.risk_changed,
        risk_direction=result.risk_direction,
        findings_added=[
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "risk_level": f.risk_level,
                "file_path": f.file_path,
            }
            for f in result.findings_added
        ],
        findings_removed=[
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "risk_level": f.risk_level,
                "file_path": f.file_path,
            }
            for f in result.findings_removed
        ],
        findings_unchanged=[
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "risk_level": f.risk_level,
                "file_path": f.file_path,
            }
            for f in result.findings_unchanged
        ],
        version_before=result.version_before,
        version_after=result.version_after,
    )


@router.get("/{package_name}/latest")
async def compare_latest_scans(
    package_name: str,
    session: AsyncSession = Depends(get_session),
) -> CompareResponse:
    """Compare the two most recent scans of a package."""
    result = await session.execute(
        select(ScanRecord)
        .where(ScanRecord.package_name == package_name)
        .order_by(desc(ScanRecord.created_at))
        .limit(2)
    )
    records = list(result.scalars().all())

    if len(records) < 2:
        raise HTTPException(
            status_code=404,
            detail=f"Need at least 2 scans of {package_name} to compare",
        )

    after = records[0]
    before = records[1]

    findings_before = json.loads(before.findings_json) if before.findings_json else []
    findings_after = json.loads(after.findings_json) if after.findings_json else []

    comp = compare_scans(
        scan_id_before=before.id,
        scan_id_after=after.id,
        package_name=package_name,
        risk_before=before.risk_level,
        risk_after=after.risk_level,
        findings_before=findings_before,
        findings_after=findings_after,
        version_before=before.package_version,
        version_after=after.package_version,
        duration_before=before.scan_duration,
        duration_after=after.scan_duration,
    )

    return CompareResponse(
        package_name=comp.package_name,
        scan_id_before=comp.scan_id_before,
        scan_id_after=comp.scan_id_after,
        risk_before=comp.risk_before,
        risk_after=comp.risk_after,
        risk_changed=comp.risk_changed,
        risk_direction=comp.risk_direction,
        findings_added=[
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "risk_level": f.risk_level,
                "file_path": f.file_path,
            }
            for f in comp.findings_added
        ],
        findings_removed=[
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "risk_level": f.risk_level,
                "file_path": f.file_path,
            }
            for f in comp.findings_removed
        ],
        findings_unchanged=[
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "risk_level": f.risk_level,
                "file_path": f.file_path,
            }
            for f in comp.findings_unchanged
        ],
        version_before=comp.version_before,
        version_after=comp.version_after,
    )
