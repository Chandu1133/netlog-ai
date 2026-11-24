"""Log ingestion service handling parsing, normalization, and batch persistence."""

import logging
from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models import LogEntry
from app.parsers import parse_raw_lines
from app.schemas import IngestionResponse, NormalizedLogRecord

logger = logging.getLogger(__name__)


def _to_naive_utc(dt: datetime) -> datetime:
    if dt.tzinfo is not None:
        return dt.astimezone(UTC).replace(tzinfo=None)
    return dt


def persist_log_records(db: Session, records: Iterable[NormalizedLogRecord]) -> list[LogEntry]:
    """Persist normalized log records using parameterized SQLAlchemy ORM inserts."""
    entries = [
        LogEntry(
            timestamp=_to_naive_utc(rec.timestamp),
            host=rec.host,
            source_ip=rec.source_ip,
            service=rec.service,
            level=rec.level,
            status_code=rec.status_code,
            latency_ms=rec.latency_ms,
            message=rec.message,
            log_format=rec.log_format,
        )
        for rec in records
    ]
    if not entries:
        return []

    db.add_all(entries)
    db.commit()
    logger.info("Persisted %d normalized log entries", len(entries))
    return entries


def ingest_raw_log_text(
    db: Session,
    content: str,
    format_hint: str = "auto",
) -> tuple[IngestionResponse, list[LogEntry]]:
    """Parse raw log text, store valid entries, and return ingestion summary plus ORM rows."""
    parse_result = parse_raw_lines(content.splitlines(), format_hint=format_hint)
    entries = persist_log_records(db, parse_result.records)

    logger.info(
        "Ingested raw log payload: ingested=%d bad=%d total=%d format=%s",
        len(entries),
        parse_result.bad_line_count,
        parse_result.total_lines,
        parse_result.format_detected,
    )

    response = IngestionResponse(
        ingested_count=len(entries),
        bad_line_count=parse_result.bad_line_count,
        total_lines=parse_result.total_lines,
        format_detected=parse_result.format_detected,
        bad_line_samples=parse_result.bad_line_samples,
    )
    return response, entries


def ingest_json_batch(
    db: Session,
    records: list[NormalizedLogRecord],
) -> tuple[IngestionResponse, list[LogEntry]]:
    """Persist a validated JSON batch of normalized log records."""
    entries = persist_log_records(db, records)
    response = IngestionResponse(
        ingested_count=len(entries),
        bad_line_count=0,
        total_lines=len(records),
        format_detected="json",
        bad_line_samples=[],
    )
    return response, entries
