"""Export API routes."""

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from git_guardian.api.deps import get_session
from git_guardian.services.export_service import ExportService

router = APIRouter(prefix="/export", tags=["export"])


@router.get("/json")
async def export_json(
    limit: int = Query(100, ge=1, le=1000),
    risk_level: str | None = None,
    package_name: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Export scans as JSON."""
    service = ExportService(session)
    json_data = await service.export_scans_json(
        limit=limit,
        risk_level=risk_level,
        package_name=package_name,
    )
    return Response(
        content=json_data,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=scans.json"},
    )


@router.get("/csv")
async def export_csv(
    limit: int = Query(100, ge=1, le=1000),
    risk_level: str | None = None,
    package_name: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> PlainTextResponse:
    """Export scans as CSV."""
    service = ExportService(session)
    csv_data = await service.export_scans_csv(
        limit=limit,
        risk_level=risk_level,
        package_name=package_name,
    )
    return PlainTextResponse(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=scans.csv"},
    )


@router.get("/findings/csv")
async def export_findings_csv(
    limit: int = Query(100, ge=1, le=1000),
    risk_level: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> PlainTextResponse:
    """Export individual findings as CSV."""
    service = ExportService(session)
    csv_data = await service.export_findings_csv(
        limit=limit,
        risk_level=risk_level,
    )
    return PlainTextResponse(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings.csv"},
    )


@router.get("/summary")
async def export_summary(
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Get export summary statistics."""
    service = ExportService(session)
    return await service.get_summary_stats()
