"""Log ingestion endpoints supporting file uploads (.log/.txt) and JSON batches."""

import logging
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import enforce_upload_rate_limit, require_api_key
from app.config import Settings, get_settings
from app.database import get_db
from app.schemas import IngestionResponse, LogBatchRequest, NormalizedLogRecord
from app.services.incidents import analyze_records_and_persist
from app.services.ingestion import ingest_json_batch, ingest_raw_log_text

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/logs", tags=["logs"])

ALLOWED_EXTENSIONS = {".log", ".txt"}


@router.post(
    "/upload",
    response_model=IngestionResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key), Depends(enforce_upload_rate_limit)],
)
async def upload_log_file(
    file: UploadFile = File(...),
    log_format: Literal["auto", "syslog", "nginx"] = Query(default="auto"),
    run_analysis: bool = Query(default=True),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> IngestionResponse:
    """Ingest a .log or .txt file in syslog or nginx access-log format."""
    filename = file.filename or ""
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '{ext}'. Allowed: .log, .txt",
        )

    raw_bytes = await file.read(settings.max_upload_size_bytes + 1)
    if len(raw_bytes) > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=(
                f"Upload exceeds maximum allowed size of {settings.max_upload_size_bytes} bytes."
            ),
        )
    if not raw_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded log file is empty.",
        )

    content = raw_bytes.decode("utf-8", errors="replace")
    response, entries = ingest_raw_log_text(db, content, format_hint=log_format)

    if run_analysis and entries:
        records = [
            NormalizedLogRecord(
                timestamp=e.timestamp,
                host=e.host,
                source_ip=e.source_ip,
                service=e.service,
                level=e.level,  # type: ignore[arg-type]
                status_code=e.status_code,
                latency_ms=e.latency_ms,
                message=e.message,
                log_format=e.log_format,
            )
            for e in entries
        ]
        anomalies, incidents = analyze_records_and_persist(db, records, settings=settings)
        response.anomalies_detected = len(anomalies)
        response.incidents_created = len(incidents)

    return response


@router.post(
    "",
    response_model=IngestionResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
)
def ingest_logs_json(
    payload: LogBatchRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> IngestionResponse:
    """Ingest a batch of pre-normalized JSON log records."""
    response, _entries = ingest_json_batch(db, payload.logs)
    if payload.run_analysis and payload.logs:
        anomalies, incidents = analyze_records_and_persist(db, payload.logs, settings=settings)
        response.anomalies_detected = len(anomalies)
        response.incidents_created = len(incidents)
    return response
