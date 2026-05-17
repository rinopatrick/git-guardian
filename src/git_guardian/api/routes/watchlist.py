"""Watchlist API routes."""


from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from git_guardian.api.deps import get_session
from git_guardian.services.watchlist_service import WatchlistService

router = APIRouter(prefix="/watchlist", tags=["watchlist"])


class WatchlistAddRequest(BaseModel):
    """Request to add a package to watchlist."""

    package_name: str
    notes: str | None = None


class WatchlistEntryResponse(BaseModel):
    """Watchlist entry response."""

    id: str
    package_name: str
    status: str
    last_scan_id: str | None
    last_risk_level: str | None
    last_scan_at: str | None
    scan_count: int
    notes: str | None
    created_at: str


@router.post("", response_model=WatchlistEntryResponse)
async def add_to_watchlist(
    request: WatchlistAddRequest,
    session: AsyncSession = Depends(get_session),
) -> WatchlistEntryResponse:
    """Add a package to the watchlist."""
    service = WatchlistService(session)
    entry = await service.add_package(request.package_name, request.notes)

    return WatchlistEntryResponse(
        id=entry.id,
        package_name=entry.package_name,
        status=entry.status,
        last_scan_id=entry.last_scan_id,
        last_risk_level=entry.last_risk_level,
        last_scan_at=entry.last_scan_at.isoformat() if entry.last_scan_at else None,
        scan_count=entry.scan_count,
        notes=entry.notes,
        created_at=entry.created_at.isoformat() if entry.created_at else "",
    )


@router.get("", response_model=list[WatchlistEntryResponse])
async def list_watchlist(
    limit: int = 100,
    offset: int = 0,
    session: AsyncSession = Depends(get_session),
) -> list[WatchlistEntryResponse]:
    """List watchlist entries."""
    service = WatchlistService(session)
    entries = await service.list_entries(limit=limit, offset=offset)

    return [
        WatchlistEntryResponse(
            id=e.id,
            package_name=e.package_name,
            status=e.status,
            last_scan_id=e.last_scan_id,
            last_risk_level=e.last_risk_level,
            last_scan_at=e.last_scan_at.isoformat() if e.last_scan_at else None,
            scan_count=e.scan_count,
            notes=e.notes,
            created_at=e.created_at.isoformat() if e.created_at else "",
        )
        for e in entries
    ]


@router.delete("/{package_name}")
async def remove_from_watchlist(
    package_name: str,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Remove a package from the watchlist."""
    service = WatchlistService(session)
    removed = await service.remove_package(package_name)

    if not removed:
        raise HTTPException(status_code=404, detail="Package not in watchlist")

    return {"status": "removed", "package_name": package_name}


@router.post("/{package_name}/pause")
async def pause_watchlist(
    package_name: str,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Pause monitoring for a package."""
    service = WatchlistService(session)
    paused = await service.pause_package(package_name)

    if not paused:
        raise HTTPException(status_code=404, detail="Package not found or not active")

    return {"status": "paused", "package_name": package_name}


@router.post("/{package_name}/resume")
async def resume_watchlist(
    package_name: str,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Resume monitoring for a paused package."""
    service = WatchlistService(session)
    resumed = await service.resume_package(package_name)

    if not resumed:
        raise HTTPException(status_code=404, detail="Package not found or not paused")

    return {"status": "resumed", "package_name": package_name}


@router.get("/stats")
async def watchlist_stats(
    session: AsyncSession = Depends(get_session),
) -> dict[str, int]:
    """Get watchlist statistics."""
    service = WatchlistService(session)
    return await service.get_stats()
