"""Scheduler API routes."""


from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from git_guardian.api.deps import get_session
from git_guardian.services.scheduler_service import SchedulerService

router = APIRouter(prefix="/scheduler", tags=["scheduler"])


class ScheduleCreateRequest(BaseModel):
    """Request to create a scheduled scan."""

    name: str
    scan_type: str  # watchlist, batch, single
    interval_minutes: int = 60
    packages: list[str] | None = None
    enable_ai: bool = False


class ScheduleResponse(BaseModel):
    """Scheduled scan response."""

    id: str
    name: str
    scan_type: str
    interval_minutes: int
    is_active: bool
    last_run_at: str | None
    next_run_at: str | None
    run_count: int
    created_at: str


@router.post("", response_model=ScheduleResponse)
async def create_schedule(
    request: ScheduleCreateRequest,
    session: AsyncSession = Depends(get_session),
) -> ScheduleResponse:
    """Create a new scheduled scan."""
    service = SchedulerService(session)
    scheduled = await service.create_scheduled_scan(
        name=request.name,
        scan_type=request.scan_type,
        interval_minutes=request.interval_minutes,
        packages=request.packages,
        enable_ai=request.enable_ai,
    )

    return ScheduleResponse(
        id=scheduled.id,
        name=scheduled.name,
        scan_type=scheduled.scan_type,
        interval_minutes=scheduled.interval_minutes,
        is_active=scheduled.is_active,
        last_run_at=scheduled.last_run_at.isoformat() if scheduled.last_run_at else None,
        next_run_at=scheduled.next_run_at.isoformat() if scheduled.next_run_at else None,
        run_count=scheduled.run_count,
        created_at=scheduled.created_at.isoformat() if scheduled.created_at else "",
    )


@router.get("", response_model=list[ScheduleResponse])
async def list_schedules(
    active_only: bool = False,
    session: AsyncSession = Depends(get_session),
) -> list[ScheduleResponse]:
    """List scheduled scans."""
    service = SchedulerService(session)
    schedules = await service.list_scheduled_scans(active_only=active_only)

    return [
        ScheduleResponse(
            id=s.id,
            name=s.name,
            scan_type=s.scan_type,
            interval_minutes=s.interval_minutes,
            is_active=s.is_active,
            last_run_at=s.last_run_at.isoformat() if s.last_run_at else None,
            next_run_at=s.next_run_at.isoformat() if s.next_run_at else None,
            run_count=s.run_count,
            created_at=s.created_at.isoformat() if s.created_at else "",
        )
        for s in schedules
    ]


@router.post("/{schedule_id}/toggle")
async def toggle_schedule(
    schedule_id: str,
    is_active: bool,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Enable or disable a scheduled scan."""
    service = SchedulerService(session)
    toggled = await service.toggle_schedule(schedule_id, is_active)

    if not toggled:
        raise HTTPException(status_code=404, detail="Schedule not found")

    return {
        "status": "activated" if is_active else "deactivated",
        "id": schedule_id,
    }


@router.delete("/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Delete a scheduled scan."""
    service = SchedulerService(session)
    deleted = await service.delete_schedule(schedule_id)

    if not deleted:
        raise HTTPException(status_code=404, detail="Schedule not found")

    return {"status": "deleted", "id": schedule_id}
