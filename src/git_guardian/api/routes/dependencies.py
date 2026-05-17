"""Dependency scanning API routes."""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from git_guardian.services.dependency_scanner import DependencyScanner

router = APIRouter(prefix="/dependencies", tags=["dependencies"])


class DependencyScanRequest(BaseModel):
    """Request to scan dependencies."""

    package_name: str
    version: str | None = None
    max_depth: int = 3
    max_packages: int = 50


class DependencyScanResponse(BaseModel):
    """Dependency scan response."""

    root_package: str
    root_version: str
    total_packages: int
    total_findings: int
    packages_with_findings: int
    max_depth_reached: int
    scan_duration_seconds: float
    graph: dict


@router.post("/scan", response_model=DependencyScanResponse)
async def scan_dependencies(
    request: DependencyScanRequest,
) -> DependencyScanResponse:
    """Scan a package and its transitive dependencies."""
    try:
        with DependencyScanner(
            max_depth=request.max_depth,
            max_packages=request.max_packages,
        ) as scanner:
            result = scanner.scan_dependencies(
                request.package_name,
                request.version,
            )

        return DependencyScanResponse(
            root_package=result.root_package,
            root_version=result.root_version,
            total_packages=result.total_packages,
            total_findings=result.total_findings,
            packages_with_findings=result.packages_with_findings,
            max_depth_reached=result.max_depth_reached,
            scan_duration_seconds=result.scan_duration_seconds,
            graph=result.graph.to_dict(),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{package_name}", response_model=DependencyScanResponse)
async def scan_package_dependencies(
    package_name: str,
    max_depth: int = Query(3, ge=1, le=5),
    max_packages: int = Query(50, ge=1, le=200),
) -> DependencyScanResponse:
    """Scan dependencies of a package (GET endpoint)."""
    try:
        with DependencyScanner(
            max_depth=max_depth,
            max_packages=max_packages,
        ) as scanner:
            result = scanner.scan_dependencies(package_name)

        return DependencyScanResponse(
            root_package=result.root_package,
            root_version=result.root_version,
            total_packages=result.total_packages,
            total_findings=result.total_findings,
            packages_with_findings=result.packages_with_findings,
            max_depth_reached=result.max_depth_reached,
            scan_duration_seconds=result.scan_duration_seconds,
            graph=result.graph.to_dict(),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
