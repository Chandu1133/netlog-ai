"""API routes for incidents, anomalies, stats, and on-demand analysis."""

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import require_api_key
from app.config import Settings, get_settings
from app.database import get_db
from app.schemas import (
    AnalyzeResponse,
    IncidentDetailOut,
    IncidentOut,
    PaginatedAnomaliesResponse,
    PaginatedIncidentsResponse,
    SeverityLevel,
    StatsResponse,
)
from app.services.incidents import (
    compute_stats,
    get_incident_by_id,
    list_anomalies,
    list_incidents,
    run_analysis_from_db,
)

router = APIRouter(tags=["incidents"])


class IncidentStatusUpdate(BaseModel):
    """Request body for updating an incident's workflow status."""

    status: Literal["open", "acknowledged", "resolved"]


@router.get("/incidents", response_model=PaginatedIncidentsResponse)
def get_incidents(
    severity: SeverityLevel | None = Query(default=None),
    host: str | None = Query(default=None),
    service: str | None = Query(default=None),
    incident_status: Literal["open", "acknowledged", "resolved"] | None = Query(
        default=None, alias="status"
    ),
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> PaginatedIncidentsResponse:
    """List AI-summarized incidents with pagination and severity/time/host filtering."""
    return list_incidents(
        db=db,
        severity=severity,
        host=host,
        service=service,
        status_filter=incident_status,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )


@router.get("/incidents/{incident_id}", response_model=IncidentDetailOut)
def get_incident_detail(
    incident_id: int,
    db: Session = Depends(get_db),
) -> IncidentDetailOut:
    """Retrieve a single incident along with all linked anomaly records."""
    incident = get_incident_by_id(db, incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found.",
        )
    return IncidentDetailOut.model_validate(incident)


@router.patch(
    "/incidents/{incident_id}/status",
    response_model=IncidentOut,
    dependencies=[Depends(require_api_key)],
)
def update_incident_status(
    incident_id: int,
    body: IncidentStatusUpdate,
    db: Session = Depends(get_db),
) -> IncidentOut:
    """Update incident workflow status (requires X-API-Key)."""
    incident = get_incident_by_id(db, incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found.",
        )
    incident.status = body.status
    db.commit()
    db.refresh(incident)
    return IncidentOut.model_validate(incident)


@router.get("/anomalies", response_model=PaginatedAnomaliesResponse)
def get_anomalies(
    severity: SeverityLevel | None = Query(default=None),
    anomaly_type: str | None = Query(default=None),
    host: str | None = Query(default=None),
    service: str | None = Query(default=None),
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> PaginatedAnomaliesResponse:
    """List detected anomalies with pagination and filtering."""
    return list_anomalies(
        db=db,
        severity=severity,
        anomaly_type=anomaly_type,
        host=host,
        service=service,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=StatsResponse)
def get_stats(
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    host: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> StatsResponse:
    """Return aggregate operational counts and per-minute chart time-series."""
    return compute_stats(db=db, start_time=start_time, end_time=end_time, host=host)


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    dependencies=[Depends(require_api_key)],
)
def trigger_analysis(
    since: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AnalyzeResponse:
    """Run anomaly detection and AI incident summarization over persisted logs."""
    return run_analysis_from_db(db=db, settings=settings, since=since)
