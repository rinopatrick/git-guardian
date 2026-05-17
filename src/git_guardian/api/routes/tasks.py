"""Background task API routes."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from git_guardian.workers.task_manager import get_task_manager

router = APIRouter(prefix="/tasks", tags=["tasks"])


class TaskSubmitRequest(BaseModel):
    """Request to submit a background task."""

    package_name: str | None = None
    packages: list[str] | None = None
    enable_ai: bool = False


class TaskResponse(BaseModel):
    """Task response model."""

    id: str
    task_type: str
    status: str
    package_name: str | None
    packages: list[str]
    progress: int
    total: int
    progress_percent: float
    result: dict | None
    error: str | None
    elapsed_seconds: float | None
    created_at: str
    started_at: str | None
    completed_at: str | None


@router.post("/scan", response_model=TaskResponse)
async def submit_scan_task(
    request: TaskSubmitRequest,
) -> TaskResponse:
    """Submit a background scan task."""
    manager = get_task_manager()

    if request.packages:
        task = manager.submit_batch_scan(request.packages, request.enable_ai)
    elif request.package_name:
        task = manager.submit_scan(request.package_name, request.enable_ai)
    else:
        raise HTTPException(
            status_code=400,
            detail="Either package_name or packages must be provided",
        )

    return _task_to_response(task)


@router.get("", response_model=list[TaskResponse])
async def list_tasks() -> list[TaskResponse]:
    """List all background tasks."""
    manager = get_task_manager()
    tasks = manager.get_all_tasks()
    return [_task_to_response(t) for t in tasks]


@router.get("/active", response_model=list[TaskResponse])
async def list_active_tasks() -> list[TaskResponse]:
    """List active (pending/running) tasks."""
    manager = get_task_manager()
    tasks = manager.get_active_tasks()
    return [_task_to_response(t) for t in tasks]


@router.get("/{task_id}", response_model=TaskResponse)
async def get_task(task_id: str) -> TaskResponse:
    """Get a specific task by ID."""
    manager = get_task_manager()
    task = manager.get_task(task_id)

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return _task_to_response(task)


@router.post("/{task_id}/cancel")
async def cancel_task(task_id: str) -> dict[str, str]:
    """Cancel a pending task."""
    manager = get_task_manager()
    cancelled = manager.cancel_task(task_id)

    if not cancelled:
        raise HTTPException(
            status_code=400,
            detail="Task not found or not in pending state",
        )

    return {"status": "cancelled", "id": task_id}


@router.post("/cleanup")
async def cleanup_tasks(max_age_hours: int = 24) -> dict[str, int]:
    """Clean up old completed tasks."""
    manager = get_task_manager()
    removed = manager.cleanup(max_age_hours)
    return {"removed": removed}


def _task_to_response(task) -> TaskResponse:
    """Convert a BackgroundTask to a TaskResponse."""
    return TaskResponse(
        id=task.id,
        task_type=task.task_type.value,
        status=task.status.value,
        package_name=task.package_name,
        packages=task.packages,
        progress=task.progress,
        total=task.total,
        progress_percent=task.progress_percent,
        result=task.result,
        error=task.error,
        elapsed_seconds=task.elapsed_seconds,
        created_at=task.created_at.isoformat(),
        started_at=task.started_at.isoformat() if task.started_at else None,
        completed_at=task.completed_at.isoformat() if task.completed_at else None,
    )
