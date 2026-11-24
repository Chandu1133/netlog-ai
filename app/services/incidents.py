"""Incident grouping, AI summarization persistence, and query/statistics services."""

import logging
import time
from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import datetime, timedelta

import numpy as np
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.config import Settings
from app.detectors import DetectedAnomaly, run_all_detectors
from app.detectors.base import floor_to_minute
from app.llm import BaseLLMClient, get_llm_client, summarize_anomalies
from app.models import Anomaly, Incident, LogEntry
from app.schemas import (
    AnalyzeResponse,
    AnomalyOut,
    IncidentOut,
    NormalizedLogRecord,
    PaginatedAnomaliesResponse,
    PaginatedIncidentsResponse,
    SeverityLevel,
    StatsResponse,
    TimeSeriesPoint,
)
from app.services.redaction import redact_evidence, redact_lines

logger = logging.getLogger(__name__)

_SEVERITY_RANK: dict[str, int] = {"low": 1, "medium": 2, "high": 3}


def _highest_severity(anomalies: Sequence[DetectedAnomaly]) -> SeverityLevel:
    best = max(anomalies, key=lambda a: _SEVERITY_RANK.get(a.severity, 1))
    return best.severity


def group_anomalies_into_incidents(
    anomalies: Sequence[DetectedAnomaly],
    merge_gap_minutes: int = 2,
) -> list[list[DetectedAnomaly]]:
    """Group overlapping or nearby anomalies on the same (host, service) into incidents."""
    if not anomalies:
        return []

    ordered = sorted(anomalies, key=lambda a: (a.host or "", a.service or "", a.window_start))
    groups: list[list[DetectedAnomaly]] = []
    gap = timedelta(minutes=merge_gap_minutes)

    for anomaly in ordered:
        placed = False
        for group in groups:
            ref = group[-1]
            same_target = (ref.host == anomaly.host) and (ref.service == anomaly.service)
            group_end = max(a.window_end for a in group)
            if same_target and anomaly.window_start <= group_end + gap:
                group.append(anomaly)
                placed = True
                break
        if not placed:
            groups.append([anomaly])

    return sorted(groups, key=lambda g: min(a.window_start for a in g))


def analyze_records_and_persist(
    db: Session,
    records: Sequence[NormalizedLogRecord],
    settings: Settings,
    llm_client: BaseLLMClient | None = None,
) -> tuple[list[Anomaly], list[Incident]]:
    """Run anomaly detectors on normalized records, summarize via LLM, and persist results."""
    if not records:
        return [], []

    detected = run_all_detectors(records, settings=settings)
    if not detected:
        return [], []

    client = llm_client or get_llm_client(settings)
    groups = group_anomalies_into_incidents(detected)

    created_anomalies: list[Anomaly] = []
    created_incidents: list[Incident] = []

    for group in groups:
        new_group = [a for a in group if not _anomaly_exists(db, a)]
        if not new_group:
            continue

        summary, used_fallback, redacted_ev = summarize_anomalies(new_group, client)
        win_start = min(a.window_start for a in new_group)
        win_end = max(a.window_end for a in new_group)

        incident = Incident(
            title=summary.title,
            summary=summary.summary,
            likely_root_cause=summary.likely_root_cause,
            suggested_fix=summary.suggested_fix,
            confidence=summary.confidence,
            severity=_highest_severity(new_group),
            status="open",
            host=new_group[0].host,
            service=new_group[0].service,
            window_start=win_start,
            window_end=win_end,
            llm_provider=client.provider_name,
            used_fallback=used_fallback,
            evidence=redacted_ev,
        )
        db.add(incident)
        db.flush()

        for item in new_group:
            anomaly_row = Anomaly(
                anomaly_type=item.anomaly_type,
                detector=item.detector,
                severity=item.severity,
                window_start=item.window_start,
                window_end=item.window_end,
                host=item.host,
                service=item.service,
                score=item.score,
                evidence=redact_evidence(item.evidence),
                sample_lines=redact_lines(item.sample_lines, max_lines=5),
                incident_id=incident.id,
            )
            db.add(anomaly_row)
            created_anomalies.append(anomaly_row)

        created_incidents.append(incident)

    if created_incidents or created_anomalies:
        db.commit()
        for inc in created_incidents:
            db.refresh(inc)
        logger.info(
            "Analysis persisted %d anomalies across %d incidents",
            len(created_anomalies),
            len(created_incidents),
        )

    return created_anomalies, created_incidents


def _anomaly_exists(db: Session, anomaly: DetectedAnomaly) -> bool:
    stmt = (
        select(Anomaly.id)
        .where(
            Anomaly.anomaly_type == anomaly.anomaly_type,
            Anomaly.host == anomaly.host,
            Anomaly.service == anomaly.service,
            Anomaly.window_start == anomaly.window_start,
            Anomaly.window_end == anomaly.window_end,
        )
        .limit(1)
    )
    return db.scalar(stmt) is not None


def run_analysis_from_db(
    db: Session,
    settings: Settings,
    since: datetime | None = None,
    llm_client: BaseLLMClient | None = None,
) -> AnalyzeResponse:
    """Load stored logs from the database and run anomaly detection plus AI summarization."""
    t0 = time.perf_counter()
    stmt = select(LogEntry).order_by(LogEntry.timestamp.asc())
    if since is not None:
        stmt = stmt.where(LogEntry.timestamp >= since)

    rows = db.scalars(stmt).all()
    records = [
        NormalizedLogRecord(
            timestamp=row.timestamp,
            host=row.host,
            source_ip=row.source_ip,
            service=row.service,
            level=row.level,  # type: ignore[arg-type]
            status_code=row.status_code,
            latency_ms=row.latency_ms,
            message=row.message,
            log_format=row.log_format,
        )
        for row in rows
    ]

    anomalies, incidents = analyze_records_and_persist(
        db=db,
        records=records,
        settings=settings,
        llm_client=llm_client,
    )
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return AnalyzeResponse(
        logs_analyzed=len(records),
        anomalies_detected=len(anomalies),
        incidents_created=len(incidents),
        duration_ms=elapsed_ms,
    )


def list_incidents(
    db: Session,
    severity: str | None = None,
    host: str | None = None,
    service: str | None = None,
    status_filter: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = 20,
    offset: int = 0,
) -> PaginatedIncidentsResponse:
    """Return a paginated, filtered list of incidents ordered newest first."""
    base_stmt = select(Incident)
    count_stmt = select(func.count(Incident.id))

    filters = []
    if severity:
        filters.append(Incident.severity == severity)
    if host:
        filters.append(Incident.host == host)
    if service:
        filters.append(Incident.service == service)
    if status_filter:
        filters.append(Incident.status == status_filter)
    if start_time:
        filters.append(Incident.window_end >= start_time)
    if end_time:
        filters.append(Incident.window_start <= end_time)

    for condition in filters:
        base_stmt = base_stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = int(db.scalar(count_stmt) or 0)
    rows = db.scalars(
        base_stmt.order_by(Incident.window_start.desc(), Incident.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()

    return PaginatedIncidentsResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[IncidentOut.model_validate(r) for r in rows],
    )


def get_incident_by_id(db: Session, incident_id: int) -> Incident | None:
    """Fetch a single incident with its linked anomalies."""
    stmt = (
        select(Incident).options(selectinload(Incident.anomalies)).where(Incident.id == incident_id)
    )
    return db.scalar(stmt)


def list_anomalies(
    db: Session,
    severity: str | None = None,
    anomaly_type: str | None = None,
    host: str | None = None,
    service: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = 50,
    offset: int = 0,
) -> PaginatedAnomaliesResponse:
    """Return a paginated, filtered list of detected anomalies ordered newest first."""
    base_stmt = select(Anomaly)
    count_stmt = select(func.count(Anomaly.id))

    filters = []
    if severity:
        filters.append(Anomaly.severity == severity)
    if anomaly_type:
        filters.append(Anomaly.anomaly_type == anomaly_type)
    if host:
        filters.append(Anomaly.host == host)
    if service:
        filters.append(Anomaly.service == service)
    if start_time:
        filters.append(Anomaly.window_end >= start_time)
    if end_time:
        filters.append(Anomaly.window_start <= end_time)

    for condition in filters:
        base_stmt = base_stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = int(db.scalar(count_stmt) or 0)
    rows = db.scalars(
        base_stmt.order_by(Anomaly.window_start.desc(), Anomaly.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()

    return PaginatedAnomaliesResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[AnomalyOut.model_validate(r) for r in rows],
    )


def compute_stats(
    db: Session,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    host: str | None = None,
) -> StatsResponse:
    """Compute aggregate log/anomaly/incident metrics and per-minute dashboard time-series."""
    log_stmt = select(LogEntry)
    anom_stmt = select(Anomaly)
    inc_stmt = select(Incident)

    if start_time:
        log_stmt = log_stmt.where(LogEntry.timestamp >= start_time)
        anom_stmt = anom_stmt.where(Anomaly.window_end >= start_time)
        inc_stmt = inc_stmt.where(Incident.window_end >= start_time)
    if end_time:
        log_stmt = log_stmt.where(LogEntry.timestamp <= end_time)
        anom_stmt = anom_stmt.where(Anomaly.window_start <= end_time)
        inc_stmt = inc_stmt.where(Incident.window_start <= end_time)
    if host:
        log_stmt = log_stmt.where(LogEntry.host == host)
        anom_stmt = anom_stmt.where(Anomaly.host == host)
        inc_stmt = inc_stmt.where(Incident.host == host)

    logs = db.scalars(log_stmt.order_by(LogEntry.timestamp.asc())).all()
    anomalies = db.scalars(anom_stmt).all()
    incidents = db.scalars(inc_stmt).all()

    incidents_by_severity = {"high": 0, "medium": 0, "low": 0}
    for inc in incidents:
        incidents_by_severity[inc.severity] = incidents_by_severity.get(inc.severity, 0) + 1

    anomalies_by_type = dict(Counter(a.anomaly_type for a in anomalies))
    host_counts = Counter(log.host for log in logs)
    top_hosts = [{"host": h, "log_count": c} for h, c in host_counts.most_common(10)]

    by_minute: dict[datetime, list[LogEntry]] = defaultdict(list)
    for log in logs:
        by_minute[floor_to_minute(log.timestamp)].append(log)

    timeseries: list[TimeSeriesPoint] = []
    for minute in sorted(by_minute.keys()):
        bucket = by_minute[minute]
        req_count = len(bucket)
        err_count = sum(
            1
            for item in bucket
            if item.level in {"ERROR", "CRITICAL"}
            or (item.status_code is not None and item.status_code >= 500)
        )
        latencies = [item.latency_ms for item in bucket if item.latency_ms is not None]
        if latencies:
            arr = np.asarray(latencies, dtype=float)
            mean_lat: float | None = round(float(np.mean(arr)), 2)
            p95_lat: float | None = round(float(np.percentile(arr, 95)), 2)
        else:
            mean_lat = None
            p95_lat = None

        minute_end = minute + timedelta(minutes=1)
        anomaly_hits = sum(
            1 for a in anomalies if a.window_start < minute_end and a.window_end >= minute
        )

        timeseries.append(
            TimeSeriesPoint(
                timestamp=minute,
                request_count=req_count,
                error_count=err_count,
                error_rate=round(err_count / req_count, 4) if req_count else 0.0,
                mean_latency_ms=mean_lat,
                p95_latency_ms=p95_lat,
                anomaly_count=anomaly_hits,
            )
        )

    return StatsResponse(
        total_logs=len(logs),
        total_anomalies=len(anomalies),
        total_incidents=len(incidents),
        incidents_by_severity=incidents_by_severity,
        anomalies_by_type=anomalies_by_type,
        top_hosts=top_hosts,
        timeseries=timeseries,
    )
