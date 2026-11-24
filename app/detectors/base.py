"""Base detector interface and anomaly data model."""

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.schemas import NormalizedLogRecord, SeverityLevel


@dataclass
class DetectedAnomaly:
    """In-memory representation of an anomaly detected over a log window."""

    anomaly_type: str
    detector: str
    severity: SeverityLevel
    window_start: datetime
    window_end: datetime
    host: str | None
    service: str | None
    score: float | None
    evidence: dict[str, Any] = field(default_factory=dict)
    sample_lines: list[str] = field(default_factory=list)


class BaseDetector(ABC):
    """Abstract base class for rule-based and ML-based anomaly detectors."""

    name: str = "base_detector"

    @abstractmethod
    def detect(self, records: Sequence[NormalizedLogRecord]) -> list[DetectedAnomaly]:
        """Analyze normalized log records and return detected anomalies."""


def floor_to_minute(dt: datetime) -> datetime:
    """Truncate a datetime to the start of its minute."""
    return dt.replace(second=0, microsecond=0)


def floor_to_window(dt: datetime, window_minutes: int) -> datetime:
    """Truncate a datetime to a fixed N-minute bucket boundary."""
    minute_bucket = (dt.minute // window_minutes) * window_minutes
    return dt.replace(minute=minute_bucket, second=0, microsecond=0)
