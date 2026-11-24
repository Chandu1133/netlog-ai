"""Detector suite orchestration."""

from collections.abc import Sequence

from app.config import Settings, get_settings
from app.detectors.base import BaseDetector, DetectedAnomaly
from app.detectors.ml import IsolationForestDetector
from app.detectors.rules import (
    FailedLoginSpikeDetector,
    Http5xxSpikeDetector,
    RepeatedErrorDetector,
)
from app.schemas import NormalizedLogRecord


def build_detectors(settings: Settings | None = None) -> list[BaseDetector]:
    """Instantiate all configured rule-based and ML-based anomaly detectors."""
    cfg = settings or get_settings()
    return [
        FailedLoginSpikeDetector(
            threshold=cfg.rule_failed_login_threshold,
            window_minutes=cfg.rule_failed_login_window_minutes,
        ),
        Http5xxSpikeDetector(
            rate_threshold=cfg.rule_http_5xx_rate_threshold,
            min_requests=cfg.rule_http_5xx_min_requests,
        ),
        RepeatedErrorDetector(
            threshold=cfg.rule_repeated_error_threshold,
            window_minutes=cfg.rule_repeated_error_window_minutes,
        ),
        IsolationForestDetector(
            contamination=cfg.ml_contamination,
            min_baseline_minutes=cfg.ml_min_baseline_minutes,
            baseline_fraction=cfg.ml_baseline_fraction,
            random_state=cfg.ml_random_state,
        ),
    ]


def run_all_detectors(
    records: Sequence[NormalizedLogRecord],
    settings: Settings | None = None,
) -> list[DetectedAnomaly]:
    """Execute every configured detector over records and return sorted anomalies."""
    anomalies: list[DetectedAnomaly] = []
    for detector in build_detectors(settings):
        anomalies.extend(detector.detect(records))
    return sorted(anomalies, key=lambda a: (a.window_start, a.anomaly_type))


__all__ = [
    "BaseDetector",
    "DetectedAnomaly",
    "FailedLoginSpikeDetector",
    "Http5xxSpikeDetector",
    "IsolationForestDetector",
    "RepeatedErrorDetector",
    "build_detectors",
    "run_all_detectors",
]
