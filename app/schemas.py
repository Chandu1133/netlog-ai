"""Pydantic v2 request and response schemas."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SeverityLevel = Literal["low", "medium", "high"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class HealthResponse(BaseModel):
    """Service health status payload."""

    status: Literal["ok", "degraded"]
    database: Literal["connected", "disconnected"]
    llm_provider: str
    version: str = "1.0.0"


class NormalizedLogRecord(BaseModel):
    """Canonical normalized log structure across all supported formats."""

    timestamp: datetime
    host: str = Field(min_length=1, max_length=255)
    source_ip: str | None = Field(default=None, max_length=64)
    service: str = Field(min_length=1, max_length=128)
    level: LogLevel = "INFO"
    status_code: int | None = Field(default=None, ge=100, le=599)
    latency_ms: float | None = Field(default=None, ge=0.0)
    message: str = Field(min_length=1, max_length=4096)
    log_format: str = Field(default="json", max_length=32)


class LogBatchRequest(BaseModel):
    """JSON batch ingestion payload for POST /logs."""

    logs: list[NormalizedLogRecord] = Field(min_length=1, max_length=10000)
    run_analysis: bool = Field(
        default=True,
        description="Run anomaly detection and incident summarization after ingest.",
    )


class IngestionResponse(BaseModel):
    """Summary of a log ingestion operation."""

    ingested_count: int
    bad_line_count: int
    total_lines: int
    format_detected: str
    anomalies_detected: int = 0
    incidents_created: int = 0
    bad_line_samples: list[str] = Field(default_factory=list)


class AnomalyOut(BaseModel):
    """Serialized anomaly record."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    anomaly_type: str
    detector: str
    severity: SeverityLevel
    window_start: datetime
    window_end: datetime
    host: str | None = None
    service: str | None = None
    score: float | None = None
    evidence: dict[str, Any]
    sample_lines: list[str]
    incident_id: int | None = None
    created_at: datetime


class IncidentSummaryLLM(BaseModel):
    """Validated structured JSON output expected from the LLM layer."""

    title: str = Field(min_length=3, max_length=255)
    summary: str = Field(min_length=10, max_length=2000)
    likely_root_cause: str = Field(min_length=5, max_length=1500)
    suggested_fix: str = Field(min_length=5, max_length=1500)
    confidence: float = Field(ge=0.0, le=1.0)


class IncidentOut(BaseModel):
    """Serialized incident list item."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    summary: str
    likely_root_cause: str
    suggested_fix: str
    confidence: float
    severity: SeverityLevel
    status: str
    host: str | None = None
    service: str | None = None
    window_start: datetime
    window_end: datetime
    llm_provider: str
    used_fallback: bool
    evidence: dict[str, Any]
    created_at: datetime


class IncidentDetailOut(IncidentOut):
    """Detailed incident response including linked anomalies."""

    anomalies: list[AnomalyOut] = Field(default_factory=list)


class PaginatedIncidentsResponse(BaseModel):
    """Paginated list of incidents."""

    total: int
    limit: int
    offset: int
    items: list[IncidentOut]


class PaginatedAnomaliesResponse(BaseModel):
    """Paginated list of anomalies."""

    total: int
    limit: int
    offset: int
    items: list[AnomalyOut]


class TimeSeriesPoint(BaseModel):
    """Per-minute metric point for dashboard charts."""

    timestamp: datetime
    request_count: int
    error_count: int
    error_rate: float
    mean_latency_ms: float | None = None
    p95_latency_ms: float | None = None
    anomaly_count: int = 0


class StatsResponse(BaseModel):
    """Aggregate operational statistics and time-series data."""

    total_logs: int
    total_anomalies: int
    total_incidents: int
    incidents_by_severity: dict[str, int]
    anomalies_by_type: dict[str, int]
    top_hosts: list[dict[str, Any]]
    timeseries: list[TimeSeriesPoint]


class AnalyzeResponse(BaseModel):
    """Result of an explicit anomaly detection + incident summarization run."""

    logs_analyzed: int
    anomalies_detected: int
    incidents_created: int
    duration_ms: float
