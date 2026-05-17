"""Scan API routes."""

import json
import time
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from git_guardian.api.deps import get_session
from git_guardian.db.models import ScanRecord
from git_guardian.models.package import RiskLevel, ScanResult
from git_guardian.scanner.ai_analyzer import AICodeAnalyzer
from git_guardian.scanner.npm import NpmRegistryClient
from git_guardian.scanner.patterns import PatternDetector
from git_guardian.scanner.typosquat import TyposquatDetector

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
    start_time = time.time()

    # Initialize components
    npm_client = NpmRegistryClient()
    pattern_detector = PatternDetector()
    typosquat_detector = TyposquatDetector(npm_client.get_popular_packages())
    ai_analyzer = AICodeAnalyzer(enabled=request.deep)

    try:
        # Fetch package info
        package_info = npm_client.get_package(request.package_name)

        # Check typosquat
        typosquat_findings = typosquat_detector.scan_package_name(request.package_name)

        # Fetch and scan files
        files = npm_client.get_package_files(request.package_name, request.version)

        # Pattern detection
        pattern_findings = pattern_detector.scan_package(files)

        # Combine findings
        all_findings = typosquat_findings + pattern_findings

        # AI analysis (if enabled)
        ai_finding = None
        if request.deep:
            ai_finding = ai_analyzer.analyze_package(package_info, files, all_findings)
            if ai_finding:
                all_findings.append(ai_finding)

        # Determine overall risk level
        if not all_findings:
            risk_level = RiskLevel.SAFE
        else:
            risk_order = [
                RiskLevel.CRITICAL,
                RiskLevel.HIGH,
                RiskLevel.MEDIUM,
                RiskLevel.LOW,
                RiskLevel.SAFE,
            ]
            risk_level = RiskLevel.SAFE
            for level in risk_order:
                if any(f.risk_level == level for f in all_findings):
                    risk_level = level
                    break

        scan_duration = time.time() - start_time

        # Build result
        result = ScanResult(
            package=package_info,
            risk_level=risk_level,
            findings=all_findings,
            ai_analysis=ai_finding.description if ai_finding else None,
            scan_duration_seconds=scan_duration,
        )

        # Save to database
        record = ScanRecord(
            package_name=request.package_name,
            package_version=package_info.latest_version,
            risk_level=risk_level.value,
            findings_json=json.dumps([f.model_dump() for f in all_findings]),
            ai_analysis=result.ai_analysis,
            scan_duration=scan_duration,
        )
        session.add(record)
        await session.flush()

        return ScanResponse(
            id=record.id,
            package_name=request.package_name,
            package_version=package_info.latest_version,
            risk_level=risk_level.value,
            findings=[f.model_dump() for f in all_findings],
            ai_analysis=result.ai_analysis,
            scan_duration=scan_duration,
            created_at=datetime.utcnow().isoformat(),
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        npm_client.close()


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
