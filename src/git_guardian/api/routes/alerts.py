"""Alert API routes."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from git_guardian.api.deps import get_session
from git_guardian.services.alert_service import AlertService

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertResponse(BaseModel):
    """Alert response model."""

    id: str
    package_name: str
    scan_id: str
    alert_type: str
    severity: str
    title: str
    description: str
    is_read: bool
    is_resolved: bool
    resolved_at: str | None
    created_at: str


@router.get("", response_model=list[AlertResponse])
async def list_alerts(
    is_read: bool | None = None,
    is_resolved: bool | None = None,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
    session: AsyncSession = Depends(get_session),
) -> list[AlertResponse]:
    """List alerts with optional filters."""
    service = AlertService(session)
    alerts = await service.list_alerts(
        is_read=is_read,
        is_resolved=is_resolved,
        severity=severity,
        limit=limit,
        offset=offset,
    )

    return [
        AlertResponse(
            id=a.id,
            package_name=a.package_name,
            scan_id=a.scan_id,
            alert_type=a.alert_type,
            severity=a.severity,
            title=a.title,
            description=a.description,
            is_read=a.is_read,
            is_resolved=a.is_resolved,
            resolved_at=a.resolved_at.isoformat() if a.resolved_at else None,
            created_at=a.created_at.isoformat() if a.created_at else "",
        )
        for a in alerts
    ]


@router.post("/{alert_id}/read")
async def mark_alert_read(
    alert_id: str,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Mark an alert as read."""
    service = AlertService(session)
    marked = await service.mark_read(alert_id)

    if not marked:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {"status": "read", "id": alert_id}


@router.post("/read-all")
async def mark_all_read(
    session: AsyncSession = Depends(get_session),
) -> dict[str, int]:
    """Mark all alerts as read."""
    service = AlertService(session)
    count = await service.mark_all_read()
    return {"marked": count}


@router.post("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Resolve an alert."""
    service = AlertService(session)
    resolved = await service.resolve_alert(alert_id)

    if not resolved:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {"status": "resolved", "id": alert_id}


@router.get("/stats")
async def alert_stats(
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Get alert statistics."""
    service = AlertService(session)
    return await service.get_alert_stats()


@router.get("/unread-count")
async def unread_count(
    session: AsyncSession = Depends(get_session),
) -> dict[str, int]:
    """Get count of unread alerts."""
    service = AlertService(session)
    count = await service.get_unread_count()
    return {"unread": count}
