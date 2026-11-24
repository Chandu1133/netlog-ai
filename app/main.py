"""FastAPI application entrypoint and configuration."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.health import router as health_router
from app.api.incidents import router as incidents_router
from app.api.logs import router as logs_router
from app.config import get_settings

STATIC_DIR = Path(__file__).resolve().parent / "static"


def configure_logging(level_name: str) -> None:
    """Configure root structured logging for the application."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Handle startup and shutdown lifecycle hooks."""
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = logging.getLogger(__name__)
    logger.info(
        "Starting %s (env=%s, llm_provider=%s)",
        settings.app_name,
        settings.app_env,
        settings.llm_provider,
    )
    yield
    logger.info("Shutting down %s", settings.app_name)


def create_app() -> FastAPI:
    """Construct and configure the FastAPI application."""
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        description=(
            "AI-powered network and server log analyzer with rule-based and ML anomaly "
            "detection plus structured incident summarization."
        ),
        lifespan=lifespan,
    )

    app.include_router(health_router)
    app.include_router(logs_router)
    app.include_router(incidents_router)

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @app.get("/", include_in_schema=False)
        def serve_dashboard() -> FileResponse:
            """Serve the NetLog AI single-page dashboard."""
            return FileResponse(STATIC_DIR / "index.html")

    return app


app = create_app()
