"""Background task worker system using ThreadPoolExecutor.

No Redis/Celery needed — uses Python's built-in threading with SQLite persistence.
"""

import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TaskStatus(StrEnum):
    """Background task status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskType(StrEnum):
    """Types of background tasks."""

    SINGLE_SCAN = "single_scan"
    BATCH_SCAN = "batch_scan"
    WATCHLIST_SCAN = "watchlist_scan"
    DEPENDENCY_SCAN = "dependency_scan"


class BackgroundTask(BaseModel):
    """A background task record."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_type: TaskType
    status: TaskStatus = TaskStatus.PENDING
    package_name: str | None = None
    packages: list[str] = []
    progress: int = 0
    total: int = 0
    result: dict[str, Any] | None = None
    error: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    completed_at: datetime | None = None

    @property
    def elapsed_seconds(self) -> float | None:
        if self.started_at is None:
            return None
        end = self.completed_at or datetime.now(UTC)
        return (end - self.started_at).total_seconds()

    @property
    def progress_percent(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.progress / self.total) * 100


class TaskManager:
    """Manages background scanning tasks."""

    def __init__(self, max_workers: int = 4) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._tasks: dict[str, BackgroundTask] = {}
        self._futures: dict[str, Future] = {}
        self._lock = threading.Lock()

    def submit_scan(
        self,
        package_name: str,
        enable_ai: bool = False,
    ) -> BackgroundTask:
        """Submit a single package scan as a background task."""
        task = BackgroundTask(
            task_type=TaskType.SINGLE_SCAN,
            package_name=package_name,
            total=1,
        )
        with self._lock:
            self._tasks[task.id] = task

        future = self._executor.submit(
            self._run_single_scan, task.id, package_name, enable_ai
        )
        self._futures[task.id] = future
        return task

    def submit_batch_scan(
        self,
        packages: list[str],
        enable_ai: bool = False,
    ) -> BackgroundTask:
        """Submit a batch scan of multiple packages."""
        task = BackgroundTask(
            task_type=TaskType.BATCH_SCAN,
            packages=packages,
            total=len(packages),
        )
        with self._lock:
            self._tasks[task.id] = task

        future = self._executor.submit(
            self._run_batch_scan, task.id, packages, enable_ai
        )
        self._futures[task.id] = future
        return task

    def submit_watchlist_scan(
        self,
        packages: list[str],
        enable_ai: bool = False,
    ) -> BackgroundTask:
        """Submit a watchlist rescan."""
        task = BackgroundTask(
            task_type=TaskType.WATCHLIST_SCAN,
            packages=packages,
            total=len(packages),
        )
        with self._lock:
            self._tasks[task.id] = task

        future = self._executor.submit(
            self._run_batch_scan, task.id, packages, enable_ai
        )
        self._futures[task.id] = future
        return task

    def get_task(self, task_id: str) -> BackgroundTask | None:
        """Get a task by ID."""
        with self._lock:
            return self._tasks.get(task_id)

    def get_all_tasks(self) -> list[BackgroundTask]:
        """Get all tasks, newest first."""
        with self._lock:
            tasks = sorted(
                self._tasks.values(),
                key=lambda t: t.created_at,
                reverse=True,
            )
            return list(tasks)

    def get_active_tasks(self) -> list[BackgroundTask]:
        """Get tasks that are pending or running."""
        with self._lock:
            return [
                t
                for t in self._tasks.values()
                if t.status in (TaskStatus.PENDING, TaskStatus.RUNNING)
            ]

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending task."""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task or task.status != TaskStatus.PENDING:
                return False
            task.status = TaskStatus.CANCELLED
            future = self._futures.get(task_id)
            if future:
                future.cancel()
            return True

    def cleanup(self, max_age_hours: int = 24) -> int:
        """Remove completed tasks older than max_age_hours."""
        cutoff = datetime.now(UTC).timestamp() - (max_age_hours * 3600)
        removed = 0
        with self._lock:
            to_remove = []
            for task_id, task in self._tasks.items():
                if task.status in (
                    TaskStatus.COMPLETED,
                    TaskStatus.FAILED,
                    TaskStatus.CANCELLED,
                ):
                    created = task.created_at.timestamp()
                    if created < cutoff:
                        to_remove.append(task_id)
            for task_id in to_remove:
                del self._tasks[task_id]
                self._futures.pop(task_id, None)
                removed += 1
        return removed

    def shutdown(self, wait: bool = True) -> None:
        """Shutdown the executor."""
        self._executor.shutdown(wait=wait)

    def _run_single_scan(
        self,
        task_id: str,
        package_name: str,
        enable_ai: bool,
    ) -> None:
        """Execute a single package scan."""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task or task.status == TaskStatus.CANCELLED:
                return
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now(UTC)

        try:
            from git_guardian.scanner.service import ScanService

            with ScanService(enable_ai=enable_ai) as service:
                result = service.scan_package(package_name)

            with self._lock:
                task = self._tasks.get(task_id)
                if task and task.status != TaskStatus.CANCELLED:
                    task.status = TaskStatus.COMPLETED
                    task.progress = 1
                    task.completed_at = datetime.now(UTC)
                    task.result = {
                        "package_name": result.package.name,
                        "version": result.package.latest_version,
                        "risk_level": result.risk_level.value,
                        "findings_count": len(result.findings),
                        "findings": [f.model_dump() for f in result.findings],
                        "ai_analysis": result.ai_analysis,
                        "scan_duration": result.scan_duration_seconds,
                    }
        except Exception as e:
            with self._lock:
                task = self._tasks.get(task_id)
                if task and task.status != TaskStatus.CANCELLED:
                    task.status = TaskStatus.FAILED
                    task.completed_at = datetime.now(UTC)
                    task.error = str(e)

    def _run_batch_scan(
        self,
        task_id: str,
        packages: list[str],
        enable_ai: bool,
    ) -> None:
        """Execute a batch scan of multiple packages."""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task or task.status == TaskStatus.CANCELLED:
                return
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now(UTC)

        results = []
        errors = []

        try:
            from git_guardian.scanner.service import ScanService

            with ScanService(enable_ai=enable_ai) as service:
                for i, pkg_name in enumerate(packages):
                    # Check if cancelled
                    with self._lock:
                        task = self._tasks.get(task_id)
                        if task and task.status == TaskStatus.CANCELLED:
                            return

                    try:
                        result = service.scan_package(pkg_name)
                        results.append({
                            "package_name": result.package.name,
                            "version": result.package.latest_version,
                            "risk_level": result.risk_level.value,
                            "findings_count": len(result.findings),
                            "findings": [f.model_dump() for f in result.findings],
                            "ai_analysis": result.ai_analysis,
                            "scan_duration": result.scan_duration_seconds,
                        })
                    except Exception as e:
                        errors.append({"package_name": pkg_name, "error": str(e)})

                    # Update progress
                    with self._lock:
                        task = self._tasks.get(task_id)
                        if task:
                            task.progress = i + 1

            with self._lock:
                task = self._tasks.get(task_id)
                if task and task.status != TaskStatus.CANCELLED:
                    task.status = TaskStatus.COMPLETED
                    task.completed_at = datetime.now(UTC)
                    task.result = {
                        "total": len(packages),
                        "successful": len(results),
                        "failed": len(errors),
                        "results": results,
                        "errors": errors,
                    }
        except Exception as e:
            with self._lock:
                task = self._tasks.get(task_id)
                if task and task.status != TaskStatus.CANCELLED:
                    task.status = TaskStatus.FAILED
                    task.completed_at = datetime.now(UTC)
                    task.error = str(e)


# Global task manager instance
_task_manager: TaskManager | None = None
_manager_lock = threading.Lock()


def get_task_manager() -> TaskManager:
    """Get the global task manager instance."""
    global _task_manager
    with _manager_lock:
        if _task_manager is None:
            _task_manager = TaskManager()
        return _task_manager
