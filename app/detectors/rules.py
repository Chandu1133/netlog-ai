"""Rule-based anomaly detectors for auth spikes, HTTP 5xx spikes, and repeated errors."""

import re
from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import datetime, timedelta

from app.detectors.base import BaseDetector, DetectedAnomaly, floor_to_minute, floor_to_window
from app.schemas import NormalizedLogRecord, SeverityLevel

_AUTH_FAIL_KEYWORDS = (
    "failed password",
    "authentication failure",
    "invalid user",
    "failed publickey",
    "login failed",
    "bad password",
)

_IP_TOKEN_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_UUID_TOKEN_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_NUM_TOKEN_RE = re.compile(r"\b\d+(?:\.\d+)?\b")


def is_auth_failure(record: NormalizedLogRecord) -> bool:
    """Return True if a log record represents an authentication failure event."""
    lower = record.message.lower()
    if any(kw in lower for kw in _AUTH_FAIL_KEYWORDS):
        return True
    return record.status_code == 401 and record.service in {"auth", "sshd", "login", "iam"}


def canonicalize_error_message(message: str) -> str:
    """Replace variable tokens (IPs, UUIDs, numbers) so identical error templates group cleanly."""
    cleaned = _UUID_TOKEN_RE.sub("<UUID>", message)
    cleaned = _IP_TOKEN_RE.sub("<IP>", cleaned)
    cleaned = _NUM_TOKEN_RE.sub("<NUM>", cleaned)
    return " ".join(cleaned.split())[:180]


class FailedLoginSpikeDetector(BaseDetector):
    """Detect bursts of authentication failures from a single source IP within a time window."""

    name = "rule:failed_login_spike"

    def __init__(self, threshold: int = 8, window_minutes: int = 5) -> None:
        self.threshold = threshold
        self.window_minutes = window_minutes

    def detect(self, records: Sequence[NormalizedLogRecord]) -> list[DetectedAnomaly]:
        """Return failed-login spike anomalies grouped by source IP and host."""
        buckets: dict[tuple[str, str, datetime], list[NormalizedLogRecord]] = defaultdict(list)

        for rec in records:
            if not is_auth_failure(rec):
                continue
            src_ip = rec.source_ip or "unknown"
            bucket_ts = floor_to_window(rec.timestamp, self.window_minutes)
            buckets[(src_ip, rec.host, bucket_ts)].append(rec)

        flagged_by_key: dict[tuple[str, str], list[tuple[datetime, list[NormalizedLogRecord]]]] = (
            defaultdict(list)
        )
        for (src_ip, host, bucket_ts), items in sorted(buckets.items(), key=lambda x: x[0][2]):
            if len(items) >= self.threshold:
                flagged_by_key[(src_ip, host)].append((bucket_ts, items))

        anomalies: list[DetectedAnomaly] = []
        window_delta = timedelta(minutes=self.window_minutes)

        for (src_ip, host), bucket_list in flagged_by_key.items():
            merged_groups = _merge_contiguous_buckets(bucket_list, window_delta)
            for group_records in merged_groups:
                count = len(group_records)
                services = sorted({r.service for r in group_records})
                win_start = min(r.timestamp for r in group_records)
                win_end = max(r.timestamp for r in group_records)
                if win_end == win_start:
                    win_end = win_start + timedelta(seconds=1)

                severity: SeverityLevel = (
                    "high"
                    if count >= max(20, int(self.threshold * 2.5))
                    else "medium" if count >= int(self.threshold * 1.5) else "low"
                )
                anomalies.append(
                    DetectedAnomaly(
                        anomaly_type="failed_login_spike",
                        detector=self.name,
                        severity=severity,
                        window_start=win_start,
                        window_end=win_end,
                        host=host,
                        service=services[0] if services else "sshd",
                        score=round(count / self.threshold, 3),
                        evidence={
                            "source_ip": src_ip,
                            "failed_attempts": count,
                            "threshold": self.threshold,
                            "window_minutes": self.window_minutes,
                            "services": services,
                        },
                        sample_lines=[r.message for r in group_records[:5]],
                    )
                )

        return sorted(anomalies, key=lambda a: a.window_start)


class Http5xxSpikeDetector(BaseDetector):
    """Detect per-minute HTTP 5xx error-rate spikes per host and service."""

    name = "rule:http_5xx_spike"

    def __init__(self, rate_threshold: float = 0.15, min_requests: int = 10) -> None:
        self.rate_threshold = rate_threshold
        self.min_requests = min_requests

    def detect(self, records: Sequence[NormalizedLogRecord]) -> list[DetectedAnomaly]:
        """Return HTTP 5xx spike anomalies merged across consecutive anomalous minutes."""
        buckets: dict[tuple[str, str, datetime], list[NormalizedLogRecord]] = defaultdict(list)

        for rec in records:
            if rec.status_code is None:
                continue
            minute_ts = floor_to_minute(rec.timestamp)
            buckets[(rec.host, rec.service, minute_ts)].append(rec)

        flagged_by_target: dict[
            tuple[str, str], list[tuple[datetime, list[NormalizedLogRecord]]]
        ] = defaultdict(list)
        for (host, service, minute_ts), items in sorted(buckets.items(), key=lambda x: x[0][2]):
            total = len(items)
            if total < self.min_requests:
                continue
            err_5xx = [r for r in items if r.status_code is not None and r.status_code >= 500]
            rate = len(err_5xx) / total
            if rate >= self.rate_threshold:
                flagged_by_target[(host, service)].append((minute_ts, items))

        anomalies: list[DetectedAnomaly] = []
        one_minute = timedelta(minutes=1)

        for (host, service), bucket_list in flagged_by_target.items():
            merged_groups = _merge_contiguous_buckets(bucket_list, one_minute)
            for group_records in merged_groups:
                total = len(group_records)
                err_records = [
                    r for r in group_records if r.status_code is not None and r.status_code >= 500
                ]
                err_count = len(err_records)
                rate = err_count / total if total else 0.0
                status_counts = Counter(str(r.status_code) for r in err_records)

                win_start = min(r.timestamp for r in group_records)
                win_end = max(r.timestamp for r in group_records)
                if win_end == win_start:
                    win_end = win_start + timedelta(seconds=1)

                severity: SeverityLevel = (
                    "high"
                    if rate >= 0.40 or err_count >= 50
                    else "medium" if rate >= 0.25 or err_count >= 20 else "low"
                )
                anomalies.append(
                    DetectedAnomaly(
                        anomaly_type="http_5xx_spike",
                        detector=self.name,
                        severity=severity,
                        window_start=win_start,
                        window_end=win_end,
                        host=host,
                        service=service,
                        score=round(rate, 4),
                        evidence={
                            "total_requests": total,
                            "error_5xx_count": err_count,
                            "error_5xx_rate": round(rate, 4),
                            "threshold_rate": self.rate_threshold,
                            "status_breakdown": dict(status_counts),
                        },
                        sample_lines=[r.message for r in err_records[:5]],
                    )
                )

        return sorted(anomalies, key=lambda a: a.window_start)


class RepeatedErrorDetector(BaseDetector):
    """Detect bursts of repeated identical error messages from a host/service."""

    name = "rule:repeated_error"

    def __init__(self, threshold: int = 10, window_minutes: int = 5) -> None:
        self.threshold = threshold
        self.window_minutes = window_minutes

    def detect(self, records: Sequence[NormalizedLogRecord]) -> list[DetectedAnomaly]:
        """Return repeated-error anomalies excluding auth bursts and HTTP access 5xx."""
        buckets: dict[tuple[str, str, str, datetime], list[NormalizedLogRecord]] = defaultdict(list)

        for rec in records:
            if rec.level not in {"ERROR", "CRITICAL"}:
                continue
            if is_auth_failure(rec):
                continue
            if rec.log_format == "nginx" and rec.status_code is not None and rec.status_code >= 500:
                continue
            canonical = canonicalize_error_message(rec.message)
            bucket_ts = floor_to_window(rec.timestamp, self.window_minutes)
            buckets[(rec.host, rec.service, canonical, bucket_ts)].append(rec)

        flagged: dict[tuple[str, str, str], list[tuple[datetime, list[NormalizedLogRecord]]]] = (
            defaultdict(list)
        )
        for (host, service, canonical, bucket_ts), items in sorted(
            buckets.items(), key=lambda x: x[0][3]
        ):
            if len(items) >= self.threshold:
                flagged[(host, service, canonical)].append((bucket_ts, items))

        anomalies: list[DetectedAnomaly] = []
        window_delta = timedelta(minutes=self.window_minutes)

        for (host, service, canonical), bucket_list in flagged.items():
            merged_groups = _merge_contiguous_buckets(bucket_list, window_delta)
            for group_records in merged_groups:
                count = len(group_records)
                win_start = min(r.timestamp for r in group_records)
                win_end = max(r.timestamp for r in group_records)
                if win_end == win_start:
                    win_end = win_start + timedelta(seconds=1)

                severity: SeverityLevel = (
                    "high"
                    if count >= self.threshold * 3
                    else "medium" if count >= self.threshold * 2 else "low"
                )
                anomalies.append(
                    DetectedAnomaly(
                        anomaly_type="repeated_error",
                        detector=self.name,
                        severity=severity,
                        window_start=win_start,
                        window_end=win_end,
                        host=host,
                        service=service,
                        score=round(count / self.threshold, 3),
                        evidence={
                            "error_count": count,
                            "threshold": self.threshold,
                            "window_minutes": self.window_minutes,
                            "canonical_message": canonical,
                        },
                        sample_lines=[r.message for r in group_records[:5]],
                    )
                )

        return sorted(anomalies, key=lambda a: a.window_start)


def _merge_contiguous_buckets(
    bucket_list: list[tuple[datetime, list[NormalizedLogRecord]]],
    step: timedelta,
) -> list[list[NormalizedLogRecord]]:
    """Merge consecutive anomalous time buckets into contiguous incident bursts."""
    if not bucket_list:
        return []

    ordered = sorted(bucket_list, key=lambda item: item[0])
    merged: list[list[NormalizedLogRecord]] = []
    current_end, current_records = ordered[0][0], list(ordered[0][1])

    for bucket_ts, records in ordered[1:]:
        if bucket_ts <= current_end + step:
            current_records.extend(records)
            current_end = bucket_ts
        else:
            merged.append(current_records)
            current_end = bucket_ts
            current_records = list(records)

    merged.append(current_records)
    return merged
