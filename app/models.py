"""SQLAlchemy ORM models for logs, anomalies, and incidents."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utc_now() -> datetime:
    """Return current UTC datetime without tzinfo for consistent DB storage."""
    return datetime.now(UTC).replace(tzinfo=None)


class LogEntry(Base):
    """Normalized network/server log event."""

    __tablename__ = "log_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    service: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    level: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    log_format: Mapped[str] = mapped_column(String(32), nullable=False, default="json")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utc_now)

    __table_args__ = (
        Index("ix_log_entries_ts_host_service", "timestamp", "host", "service"),
        Index("ix_log_entries_ts_status", "timestamp", "status_code"),
    )


class Incident(Base):
    """AI-summarized operational incident grouping one or more anomalies."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    likely_root_cause: Mapped[str] = mapped_column(Text, nullable=False)
    suggested_fix: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open", index=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    service: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    window_end: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    llm_provider: Mapped[str] = mapped_column(String(64), nullable=False, default="mock")
    used_fallback: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utc_now)

    anomalies: Mapped[list["Anomaly"]] = relationship(
        "Anomaly",
        back_populates="incident",
        cascade="all, delete-orphan",
    )


class Anomaly(Base):
    """Detected rule-based or ML-based anomaly over a time window."""

    __tablename__ = "anomalies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    anomaly_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    detector: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    window_end: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    service: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    sample_lines: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    incident_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utc_now)

    incident: Mapped[Incident | None] = relationship("Incident", back_populates="anomalies")

    __table_args__ = (Index("ix_anomalies_severity_window", "severity", "window_start"),)
