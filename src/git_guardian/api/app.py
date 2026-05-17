"""FastAPI application."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from git_guardian.db.database import close_db, init_db

# Template directory
TEMPLATE_DIR = Path(__file__).parent.parent / "web" / "templates"
STATIC_DIR = Path(__file__).parent.parent / "web" / "static"

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler."""
    # Startup
    await init_db()
    yield
    # Shutdown
    await close_db()


app = FastAPI(
    title="Git Guardian",
    description="AI-powered supply chain security scanner for npm packages",
    version="0.1.0",
    lifespan=lifespan,
)

# Mount static files
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Import and include routes  # noqa: E402
from git_guardian.api.routes.alerts import router as alerts_router  # noqa: E402
from git_guardian.api.routes.compare import router as compare_router  # noqa: E402
from git_guardian.api.routes.dependencies import router as dependencies_router  # noqa: E402
from git_guardian.api.routes.export import router as export_router  # noqa: E402
from git_guardian.api.routes.rate_limiter_route import router as rate_limiter_router  # noqa: E402
from git_guardian.api.routes.scan import router as scan_router  # noqa: E402
from git_guardian.api.routes.scheduler import router as scheduler_router  # noqa: E402
from git_guardian.api.routes.tasks import router as tasks_router  # noqa: E402
from git_guardian.api.routes.watchlist import router as watchlist_router  # noqa: E402
from git_guardian.api.routes.web import router as web_router  # noqa: E402
from git_guardian.github.bot import router as github_router  # noqa: E402

app.include_router(scan_router, prefix="/api")
app.include_router(web_router)
app.include_router(github_router)
app.include_router(watchlist_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(export_router, prefix="/api")
app.include_router(compare_router, prefix="/api")
app.include_router(dependencies_router, prefix="/api")
app.include_router(tasks_router, prefix="/api")
app.include_router(scheduler_router, prefix="/api")
app.include_router(rate_limiter_router, prefix="/api")
