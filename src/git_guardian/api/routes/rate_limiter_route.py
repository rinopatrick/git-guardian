"""Rate limiter status API route."""

from fastapi import APIRouter

from git_guardian.scanner.rate_limiter import get_npm_rate_limiter

router = APIRouter(prefix="/rate-limiter", tags=["rate-limiter"])


@router.get("/stats")
async def rate_limiter_stats() -> dict:
    """Get rate limiter statistics."""
    limiter = get_npm_rate_limiter()
    return limiter.get_stats()
