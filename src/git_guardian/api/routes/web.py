"""Web UI routes."""

import json

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from git_guardian.api.app import templates
from git_guardian.api.deps import get_session
from git_guardian.db.models import ScanRecord
from git_guardian.scanner.service import ScanService

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
    try:
        with ScanService(enable_ai=deep) as service:
            result = service.scan_package(package_name)

        # Save to database
        record = ScanRecord(
            package_name=package_name,
            package_version=result.package.latest_version,
            risk_level=result.risk_level.value,
            findings_json=json.dumps([f.model_dump() for f in result.findings]),
            ai_analysis=result.ai_analysis,
            scan_duration=result.scan_duration_seconds,
        )
        session.add(record)
        await session.flush()

        return templates.TemplateResponse(
            name="scan.html",
            request=request,
            context={
                "title": f"Scan: {package_name}",
                "package": result.package,
                "risk_level": result.risk_level.value,
                "risk_color": _risk_color(result.risk_level.value),
                "findings": result.findings,
                "ai_analysis": result.ai_analysis,
                "scan_duration": result.scan_duration_seconds,
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
