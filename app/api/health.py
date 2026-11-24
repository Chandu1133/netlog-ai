"""Health check endpoint verifying service and database availability."""

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import check_db_connection, get_db
from app.schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health_check(
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> HealthResponse:
    """Return service health and database connectivity status."""
    db_ok = check_db_connection(db)
    if not db_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return HealthResponse(
        status="ok" if db_ok else "degraded",
        database="connected" if db_ok else "disconnected",
        llm_provider=settings.llm_provider,
    )
