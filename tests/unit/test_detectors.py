"""Unit tests for every rule-based and ML anomaly detector."""

from datetime import datetime, timedelta

from app.detectors import (
    FailedLoginSpikeDetector,
    Http5xxSpikeDetector,
    IsolationForestDetector,
    RepeatedErrorDetector,
    run_all_detectors,
)
from app.schemas import NormalizedLogRecord


def _make_record(
    ts: datetime,
    host: str = "web-01",
    source_ip: str | None = "192.0.2.10",
    service: str = "nginx",
    level: str = "INFO",
    status_code: int | None = 200,
    latency_ms: float | None = 35.0,
    message: str = "GET /api/items HTTP/1.1 -> HTTP 200",
    log_format: str = "nginx",
) -> NormalizedLogRecord:
    return NormalizedLogRecord(
        timestamp=ts,
        host=host,
        source_ip=source_ip,
        service=service,
        level=level,  # type: ignore[arg-type]
        status_code=status_code,
        latency_ms=latency_ms,
        message=message,
        log_format=log_format,
    )


def test_failed_login_spike_detector_positive_and_negative() -> None:
    """FailedLoginSpikeDetector catches brute-force bursts and ignores low-volume noise."""
    base = datetime(2026, 11, 24, 14, 0, 0)
    records: list[NormalizedLogRecord] = []

    # 22 failed logins from one attacker IP -> high severity
    for i in range(22):
        records.append(
            _make_record(
                ts=base + timedelta(seconds=i * 5),
                host="auth-01",
                source_ip="203.0.113.99",
                service="sshd",
                level="ERROR",
                status_code=None,
                latency_ms=None,
                message=f"Failed password for invalid user admin{i} from 203.0.113.99 port 50000",
                log_format="syslog",
            )
        )
    # 3 failed logins from normal user -> below threshold
    for i in range(3):
        records.append(
            _make_record(
                ts=base + timedelta(seconds=i * 10),
                host="auth-01",
                source_ip="198.51.100.12",
                service="sshd",
                level="ERROR",
                status_code=None,
                latency_ms=None,
                message="Failed password for bob from 198.51.100.12 port 40000",
                log_format="syslog",
            )
        )

    detector = FailedLoginSpikeDetector(threshold=8, window_minutes=5)
    anomalies = detector.detect(records)

    assert len(anomalies) == 1
    anomaly = anomalies[0]
    assert anomaly.anomaly_type == "failed_login_spike"
    assert anomaly.severity == "high"
    assert anomaly.host == "auth-01"
    assert anomaly.evidence["source_ip"] == "203.0.113.99"
    assert anomaly.evidence["failed_attempts"] == 22


def test_http_5xx_spike_detector_merges_consecutive_minutes() -> None:
    """Http5xxSpikeDetector catches sustained 5xx bursts and merges contiguous minutes."""
    base = datetime(2026, 11, 24, 14, 0, 0)
    records: list[NormalizedLogRecord] = []

    # Minutes 0..4: healthy traffic (20 req/min, 0% 5xx)
    for minute in range(5):
        for i in range(20):
            records.append(
                _make_record(
                    ts=base + timedelta(minutes=minute, seconds=i * 2),
                    status_code=200,
                    level="INFO",
                )
            )

    # Minutes 5..6: 50% 502/503 errors
    for minute in (5, 6):
        for i in range(20):
            is_err = i < 10
            records.append(
                _make_record(
                    ts=base + timedelta(minutes=minute, seconds=i * 2),
                    status_code=502 if is_err else 200,
                    level="ERROR" if is_err else "INFO",
                    message=(
                        "POST /api/pay -> HTTP 502" if is_err else "GET /api/health -> HTTP 200"
                    ),
                )
            )

    detector = Http5xxSpikeDetector(rate_threshold=0.15, min_requests=10)
    anomalies = detector.detect(records)

    assert len(anomalies) == 1
    anomaly = anomalies[0]
    assert anomaly.anomaly_type == "http_5xx_spike"
    assert anomaly.severity == "high"
    assert anomaly.evidence["error_5xx_count"] == 20
    assert anomaly.evidence["error_5xx_rate"] == 0.5


def test_repeated_error_detector_canonicalizes_dynamic_tokens() -> None:
    """RepeatedErrorDetector groups identical error templates with different IDs/numbers."""
    base = datetime(2026, 11, 24, 14, 10, 0)
    records = [
        _make_record(
            ts=base + timedelta(seconds=i * 8),
            host="app-02",
            service="billing-worker",
            level="ERROR",
            status_code=None,
            latency_ms=None,
            message=f"Database connection pool exhausted while processing job {1000 + i}",
            log_format="syslog",
        )
        for i in range(15)
    ]

    detector = RepeatedErrorDetector(threshold=10, window_minutes=5)
    anomalies = detector.detect(records)

    assert len(anomalies) == 1
    anomaly = anomalies[0]
    assert anomaly.anomaly_type == "repeated_error"
    assert anomaly.host == "app-02"
    assert anomaly.service == "billing-worker"
    assert anomaly.evidence["error_count"] == 15
    assert "<NUM>" in anomaly.evidence["canonical_message"]


def test_isolation_forest_detects_latency_degradation_without_baseline_false_positives() -> None:
    """IsolationForestDetector fits on baseline minutes and catches latency degradation."""
    base = datetime(2026, 11, 24, 10, 0, 0)
    records: list[NormalizedLogRecord] = []

    # 30 baseline minutes + 15 normal eval minutes: ~30 req/min, latency 30-55ms, 0% errors
    for minute in range(45):
        for i in range(25):
            latency = 35.0 + ((minute * 7 + i * 3) % 20)
            records.append(
                _make_record(
                    ts=base + timedelta(minutes=minute, seconds=i * 2),
                    host="edge-01",
                    service="api-gateway",
                    status_code=200,
                    latency_ms=latency,
                )
            )

    # Minutes 45..48: severe latency degradation (500-950ms)
    for minute in range(45, 49):
        for i in range(25):
            latency = 550.0 + (i * 15.0)
            records.append(
                _make_record(
                    ts=base + timedelta(minutes=minute, seconds=i * 2),
                    host="edge-01",
                    service="api-gateway",
                    status_code=200,
                    latency_ms=latency,
                    message=f"GET /api/search -> HTTP 200 [{latency:.1f}ms]",
                )
            )

    # Minutes 49..55: recovery back to normal
    for minute in range(49, 55):
        for i in range(25):
            latency = 35.0 + ((minute * 5 + i) % 18)
            records.append(
                _make_record(
                    ts=base + timedelta(minutes=minute, seconds=i * 2),
                    host="edge-01",
                    service="api-gateway",
                    status_code=200,
                    latency_ms=latency,
                )
            )

    detector = IsolationForestDetector(
        contamination=0.05,
        min_baseline_minutes=15,
        baseline_fraction=0.5,
        random_state=42,
    )
    anomalies = detector.detect(records)

    assert len(anomalies) == 1
    anomaly = anomalies[0]
    assert anomaly.anomaly_type == "ml_traffic_anomaly"
    assert anomaly.host == "edge-01"
    assert anomaly.service == "api-gateway"
    assert "latency_degradation" in anomaly.evidence["primary_drivers"]
    assert anomaly.evidence["peak_p95_latency_ms"] > 700.0
    assert anomaly.window_start == base + timedelta(minutes=45)


def test_isolation_forest_no_false_positives_on_steady_traffic() -> None:
    """IsolationForestDetector emits zero anomalies on steady baseline-like traffic."""
    base = datetime(2026, 11, 24, 9, 0, 0)
    records = [
        _make_record(
            ts=base + timedelta(minutes=m, seconds=i * 2),
            host="edge-02",
            service="catalog",
            status_code=200,
            latency_ms=40.0 + ((m + i) % 10),
        )
        for m in range(30)
        for i in range(20)
    ]

    detector = IsolationForestDetector(min_baseline_minutes=10, baseline_fraction=0.5)
    assert detector.detect(records) == []


def test_run_all_detectors_combines_results() -> None:
    """run_all_detectors executes both rule and ML detectors cleanly."""
    base = datetime(2026, 11, 24, 11, 0, 0)
    records = [
        _make_record(
            ts=base + timedelta(seconds=i * 3),
            host="auth-01",
            source_ip="203.0.113.5",
            service="sshd",
            level="ERROR",
            status_code=None,
            latency_ms=None,
            message="Failed password for root from 203.0.113.5 port 22",
            log_format="syslog",
        )
        for i in range(12)
    ]
    anomalies = run_all_detectors(records)
    assert any(a.anomaly_type == "failed_login_spike" for a in anomalies)
