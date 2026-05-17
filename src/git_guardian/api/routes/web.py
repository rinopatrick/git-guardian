"""Web UI routes."""

import json
import time
from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from git_guardian.api.app import templates
from git_guardian.api.deps import get_session
from git_guardian.db.models import ScanRecord
from git_guardian.models.package import RiskLevel, ScanResult
from git_guardian.scanner.ai_analyzer import AICodeAnalyzer
from git_guardian.scanner.npm import NpmRegistryClient
from git_guardian.scanner.patterns import PatternDetector
from git_guardian.scanner.typosquat import TyposquatDetector

router = APIRouter(tags=["web"])


def _risk_color(level: str) -> str:
    """Get CSS class for risk level."""
    colors = {
        "safe": "text-green-600 bg-green-100",
        "low": "text-yellow-600 bg-yellow-100",
        "medium": "text-orange-600 bg-orange-100",
        "high": "text-red-600 bg-red-100",
        "critical": "text-red-800 bg-red-200",
    }
    return colors.get(level, "text-gray-600 bg-gray-100")


@router.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Home page."""
    return templates.TemplateResponse(
        name="index.html",
        request=request,
        context={"title": "Git Guardian"},
    )


@router.post("/scan", response_class=HTMLResponse)
async def scan_form(
    request: Request,
    package_name: str = Form(...),
    deep: bool = Form(False),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    """Scan package from form submission."""
    start_time = time.time()

    # Initialize components
    npm_client = NpmRegistryClient()
    pattern_detector = PatternDetector()
    typosquat_detector = TyposquatDetector(npm_client.get_popular_packages())
    ai_analyzer = AICodeAnalyzer(enabled=deep)

    try:
        # Fetch package info
        package_info = npm_client.get_package(package_name)

        # Check typosquat
        typosquat_findings = typosquat_detector.scan_package_name(package_name)

        # Fetch and scan files
        files = npm_client.get_package_files(package_name)

        # Pattern detection
        pattern_findings = pattern_detector.scan_package(files)

        # Combine findings
        all_findings = typosquat_findings + pattern_findings

        # AI analysis (if enabled)
        ai_finding = None
        if deep:
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

        # Save to database
        record = ScanRecord(
            package_name=package_name,
            package_version=package_info.latest_version,
            risk_level=risk_level.value,
            findings_json=json.dumps([f.model_dump() for f in all_findings]),
            ai_analysis=ai_finding.description if ai_finding else None,
            scan_duration=scan_duration,
        )
        session.add(record)
        await session.flush()

        return templates.TemplateResponse(
            name="scan.html",
            request=request,
            context={
                "title": f"Scan: {package_name}",
                "package": package_info,
                "risk_level": risk_level.value,
                "risk_color": _risk_color(risk_level.value),
                "findings": all_findings,
                "ai_analysis": ai_finding.description if ai_finding else None,
                "scan_duration": scan_duration,
                "scan_id": record.id,
            },
        )

    except Exception as e:
        return templates.TemplateResponse(
            name="index.html",
            request=request,
            context={
                "title": "Git Guardian",
                "error": str(e),
            },
        )
    finally:
        npm_client.close()


@router.get("/history", response_class=HTMLResponse)
async def history(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    """Scan history page."""
    # Get total count
    count_result = await session.execute(select(func.count(ScanRecord.id)))
    total_scans = count_result.scalar() or 0

    # Get risk level distribution
    risk_dist_result = await session.execute(
        select(ScanRecord.risk_level, func.count(ScanRecord.id))
        .group_by(ScanRecord.risk_level)
    )
    risk_distribution = {row[0]: row[1] for row in risk_dist_result}

    # Get recent scans
    result = await session.execute(
        select(ScanRecord)
        .order_by(desc(ScanRecord.created_at))
        .limit(50)
    )
    records = result.scalars().all()

    return templates.TemplateResponse(
        name="history.html",
        request=request,
        context={
            "title": "Scan History",
            "scans": records,
            "total_scans": total_scans,
            "risk_distribution": risk_distribution,
            "risk_color": _risk_color,
        },
    )


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_detail(
    request: Request,
    scan_id: str,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    """Scan detail page."""
    result = await session.execute(
        select(ScanRecord).where(ScanRecord.id == scan_id)
    )
    record = result.scalar_one_or_none()

    if not record:
        return templates.TemplateResponse(
            name="index.html",
            request=request,
            context={
                "title": "Not Found",
                "error": "Scan not found",
            },
        )

    findings = json.loads(record.findings_json) if record.findings_json else []

    return templates.TemplateResponse(
        name="scan.html",
        request=request,
        context={
            "title": f"Scan: {record.package_name}",
            "package_name": record.package_name,
            "package_version": record.package_version,
            "risk_level": record.risk_level,
            "risk_color": _risk_color(record.risk_level),
            "findings": findings,
            "ai_analysis": record.ai_analysis,
            "scan_duration": record.scan_duration,
            "scan_id": record.id,
        },
    )
