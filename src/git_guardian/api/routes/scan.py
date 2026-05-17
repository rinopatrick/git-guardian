"""Scan API routes."""

import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from git_guardian.api.deps import get_session
from git_guardian.db.models import ScanRecord
from git_guardian.scanner.service import ScanService

router = APIRouter(prefix="/scan", tags=["scan"])


class ScanRequest(BaseModel):
    """Scan request model."""

    package_name: str
    version: str | None = None
    deep: bool = False


class ScanResponse(BaseModel):
    """Scan response model."""

    id: str
    package_name: str
    package_version: str
    risk_level: str
    findings: list[dict]
    ai_analysis: str | None
    scan_duration: float
    created_at: str


@router.post("", response_model=ScanResponse)
async def scan_package(
    request: ScanRequest,
    session: AsyncSession = Depends(get_session),
) -> ScanResponse:
    """Scan an npm package for security issues."""
    try:
        with ScanService(enable_ai=request.deep) as service:
            result = service.scan_package(request.package_name, request.version)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Save to database
    record = ScanRecord(
        package_name=request.package_name,
        package_version=result.package.latest_version,
        risk_level=result.risk_level.value,
        findings_json=json.dumps([f.model_dump() for f in result.findings]),
        ai_analysis=result.ai_analysis,
        scan_duration=result.scan_duration_seconds,
    )
    session.add(record)
    await session.flush()

    return ScanResponse(
        id=record.id,
        package_name=request.package_name,
        package_version=result.package.latest_version,
        risk_level=result.risk_level.value,
        findings=[f.model_dump() for f in result.findings],
        ai_analysis=result.ai_analysis,
        scan_duration=result.scan_duration_seconds,
        created_at=datetime.now(UTC).isoformat(),
    )


@router.get("", response_model=list[ScanResponse])
async def list_scans(
    limit: int = 50,
    offset: int = 0,
    session: AsyncSession = Depends(get_session),
) -> list[ScanResponse]:
    """List scan history."""
    result = await session.execute(
        select(ScanRecord)
        .order_by(desc(ScanRecord.created_at))
        .limit(limit)
        .offset(offset)
    )
    records = result.scalars().all()

    return [
        ScanResponse(
            id=r.id,
            package_name=r.package_name,
            package_version=r.package_version,
            risk_level=r.risk_level,
            findings=json.loads(r.findings_json) if r.findings_json else [],
            ai_analysis=r.ai_analysis,
            scan_duration=r.scan_duration,
            created_at=r.created_at.isoformat() if r.created_at else "",
        )
        for r in records
    ]


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    session: AsyncSession = Depends(get_session),
) -> ScanResponse:
    """Get scan details by ID."""
    result = await session.execute(
        select(ScanRecord).where(ScanRecord.id == scan_id)
    )
    record = result.scalar_one_or_none()

    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResponse(
        id=record.id,
        package_name=record.package_name,
        package_version=record.package_version,
        risk_level=record.risk_level,
        findings=json.loads(record.findings_json) if record.findings_json else [],
        ai_analysis=record.ai_analysis,
        scan_duration=record.scan_duration,
        created_at=record.created_at.isoformat() if record.created_at else "",
    )
