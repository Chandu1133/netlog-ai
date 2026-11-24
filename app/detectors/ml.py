"""IsolationForest ML anomaly detector operating on per-minute traffic features."""

import logging
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.detectors.base import BaseDetector, DetectedAnomaly, floor_to_minute
from app.schemas import NormalizedLogRecord, SeverityLevel

logger = logging.getLogger(__name__)


@dataclass
class MinuteFeatureRow:
    """Aggregated operational telemetry for a single minute bucket."""

    minute: datetime
    request_count: int
    error_rate: float
    mean_latency_ms: float
    p95_latency_ms: float
    records: list[NormalizedLogRecord]

    def to_vector(self) -> list[float]:
        """Convert feature fields to a numeric vector for IsolationForest."""
        return [
            float(self.request_count),
            float(self.error_rate),
            float(self.mean_latency_ms),
            float(self.p95_latency_ms),
        ]


def extract_minute_features(records: Sequence[NormalizedLogRecord]) -> list[MinuteFeatureRow]:
    """Aggregate normalized log records into sorted per-minute feature vectors."""
    by_minute: dict[datetime, list[NormalizedLogRecord]] = defaultdict(list)
    for rec in records:
        by_minute[floor_to_minute(rec.timestamp)].append(rec)

    rows: list[MinuteFeatureRow] = []
    for minute in sorted(by_minute.keys()):
        bucket = by_minute[minute]
        total = len(bucket)
        errors = sum(
            1
            for r in bucket
            if r.level in {"ERROR", "CRITICAL"}
            or (r.status_code is not None and r.status_code >= 500)
        )
        latencies = [r.latency_ms for r in bucket if r.latency_ms is not None]
        if latencies:
            arr = np.asarray(latencies, dtype=float)
            mean_lat = float(np.mean(arr))
            p95_lat = float(np.percentile(arr, 95))
        else:
            mean_lat = 0.0
            p95_lat = 0.0

        rows.append(
            MinuteFeatureRow(
                minute=minute,
                request_count=total,
                error_rate=errors / total if total else 0.0,
                mean_latency_ms=mean_lat,
                p95_latency_ms=p95_lat,
                records=bucket,
            )
        )
    return rows


class IsolationForestDetector(BaseDetector):
    """Fit an IsolationForest on a baseline window of per-minute features to flag anomalies."""

    name = "ml:isolation_forest"

    def __init__(
        self,
        contamination: float = 0.05,
        min_baseline_minutes: int = 10,
        baseline_fraction: float = 0.5,
        random_state: int = 42,
    ) -> None:
        self.contamination = contamination
        self.min_baseline_minutes = min_baseline_minutes
        self.baseline_fraction = baseline_fraction
        self.random_state = random_state

    def detect(
        self,
        records: Sequence[NormalizedLogRecord],
        baseline_records: Sequence[NormalizedLogRecord] | None = None,
    ) -> list[DetectedAnomaly]:
        """Run per-(host, service) IsolationForest detection over per-minute telemetry."""
        grouped: dict[tuple[str, str], list[NormalizedLogRecord]] = defaultdict(list)
        for rec in records:
            # Focus ML telemetry modeling on logs with latency or HTTP status metrics
            if rec.latency_ms is not None or rec.status_code is not None:
                grouped[(rec.host, rec.service)].append(rec)

        baseline_grouped: dict[tuple[str, str], list[NormalizedLogRecord]] = defaultdict(list)
        if baseline_records is not None:
            for rec in baseline_records:
                if rec.latency_ms is not None or rec.status_code is not None:
                    baseline_grouped[(rec.host, rec.service)].append(rec)

        anomalies: list[DetectedAnomaly] = []
        for (host, service), target_records in grouped.items():
            target_baseline = baseline_grouped.get((host, service)) if baseline_records else None
            anomalies.extend(
                self._detect_for_target(
                    host=host,
                    service=service,
                    records=target_records,
                    explicit_baseline=target_baseline,
                )
            )

        return sorted(anomalies, key=lambda a: a.window_start)

    def _detect_for_target(
        self,
        host: str,
        service: str,
        records: Sequence[NormalizedLogRecord],
        explicit_baseline: Sequence[NormalizedLogRecord] | None = None,
    ) -> list[DetectedAnomaly]:
        rows = extract_minute_features(records)
        if explicit_baseline is not None:
            baseline_rows = extract_minute_features(explicit_baseline)
            eval_rows = rows
        else:
            if len(rows) < self.min_baseline_minutes + 2:
                logger.debug(
                    "Skipping ML detector for %s/%s: only %d minute buckets",
                    host,
                    service,
                    len(rows),
                )
                return []
            split_idx = max(
                self.min_baseline_minutes,
                int(len(rows) * self.baseline_fraction),
            )
            split_idx = min(split_idx, len(rows) - 1)
            baseline_rows = rows[:split_idx]
            eval_rows = rows[split_idx:]

        if len(baseline_rows) < self.min_baseline_minutes or not eval_rows:
            return []

        x_base = np.asarray([r.to_vector() for r in baseline_rows], dtype=float)
        x_eval = np.asarray([r.to_vector() for r in eval_rows], dtype=float)

        scaler = StandardScaler()
        x_base_scaled = scaler.fit_transform(x_base)
        x_eval_scaled = scaler.transform(x_eval)

        model = IsolationForest(
            n_estimators=150,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        model.fit(x_base_scaled)

        eval_scores = model.decision_function(x_eval_scaled)

        # Baseline summary statistics for operational deviation guard & rich evidence
        base_req_med = float(np.median(x_base[:, 0]))
        base_err_med = float(np.median(x_base[:, 1]))
        base_mean_lat_med = float(np.median(x_base[:, 2]))
        base_p95_lat_med = float(np.median(x_base[:, 3]))

        flagged: list[tuple[MinuteFeatureRow, float, list[str]]] = []
        for row, score in zip(eval_rows, eval_scores, strict=True):
            drivers = self._identify_drivers(
                row=row,
                base_req_med=base_req_med,
                base_err_med=base_err_med,
                base_mean_lat_med=base_mean_lat_med,
                base_p95_lat_med=base_p95_lat_med,
            )
            # In IsolationForest, out-of-range points on small clean baselines can saturate
            # right at decision_function == 0.0 (same boundary leaf as baseline extremes).
            if score <= 0.005 and drivers:
                flagged.append((row, float(score), drivers))

        if not flagged:
            return []

        merged = _merge_flagged_minutes(flagged)
        anomalies: list[DetectedAnomaly] = []

        for cluster in merged:
            cluster_rows = [item[0] for item in cluster]
            cluster_scores = [item[1] for item in cluster]
            all_drivers = sorted({d for item in cluster for d in item[2]})

            win_start = cluster_rows[0].minute
            win_end = cluster_rows[-1].minute + timedelta(minutes=1)
            min_score = min(cluster_scores)

            peak_p95 = max(r.p95_latency_ms for r in cluster_rows)
            peak_mean_lat = max(r.mean_latency_ms for r in cluster_rows)
            peak_err = max(r.error_rate for r in cluster_rows)
            peak_req = max(r.request_count for r in cluster_rows)

            latency_ratio = peak_p95 / max(base_p95_lat_med, 1.0)
            severity: SeverityLevel = (
                "high"
                if min_score < -0.14 or latency_ratio >= 4.0 or peak_err >= 0.35
                else (
                    "medium"
                    if min_score < -0.07 or latency_ratio >= 2.5 or peak_err >= 0.20
                    else "low"
                )
            )

            sample_records = sorted(
                (rec for row in cluster_rows for rec in row.records),
                key=lambda r: (r.latency_ms or 0.0, r.status_code or 0),
                reverse=True,
            )[:5]

            anomalies.append(
                DetectedAnomaly(
                    anomaly_type="ml_traffic_anomaly",
                    detector=self.name,
                    severity=severity,
                    window_start=win_start,
                    window_end=win_end,
                    host=host,
                    service=service,
                    score=round(min_score, 4),
                    evidence={
                        "primary_drivers": all_drivers,
                        "anomalous_minutes": len(cluster_rows),
                        "min_isolation_score": round(min_score, 4),
                        "peak_request_count": peak_req,
                        "peak_error_rate": round(peak_err, 4),
                        "peak_mean_latency_ms": round(peak_mean_lat, 2),
                        "peak_p95_latency_ms": round(peak_p95, 2),
                        "baseline_request_count": round(base_req_med, 2),
                        "baseline_error_rate": round(base_err_med, 4),
                        "baseline_mean_latency_ms": round(base_mean_lat_med, 2),
                        "baseline_p95_latency_ms": round(base_p95_lat_med, 2),
                        "baseline_minutes_used": len(baseline_rows),
                    },
                    sample_lines=[r.message for r in sample_records],
                )
            )

        return anomalies

    @staticmethod
    def _identify_drivers(
        row: MinuteFeatureRow,
        base_req_med: float,
        base_err_med: float,
        base_mean_lat_med: float,
        base_p95_lat_med: float,
    ) -> list[str]:
        drivers: list[str] = []
        if row.p95_latency_ms > max(base_p95_lat_med * 2.0, base_p95_lat_med + 75.0) or (
            row.mean_latency_ms > max(base_mean_lat_med * 2.0, base_mean_lat_med + 50.0)
        ):
            drivers.append("latency_degradation")
        if row.error_rate > max(base_err_med * 3.0, base_err_med + 0.08):
            drivers.append("error_rate_spike")
        if row.request_count > max(base_req_med * 2.2, base_req_med + 20):
            drivers.append("traffic_volume_spike")
        return drivers


def _merge_flagged_minutes(
    flagged: list[tuple[MinuteFeatureRow, float, list[str]]],
) -> list[list[tuple[MinuteFeatureRow, float, list[str]]]]:
    """Merge consecutive anomalous minutes (allowing a 1-minute gap) into coherent bursts."""
    ordered = sorted(flagged, key=lambda item: item[0].minute)
    clusters: list[list[tuple[MinuteFeatureRow, float, list[str]]]] = []
    current = [ordered[0]]

    for item in ordered[1:]:
        prev_min = current[-1][0].minute
        if item[0].minute <= prev_min + timedelta(minutes=2):
            current.append(item)
        else:
            clusters.append(current)
            current = [item]

    clusters.append(current)
    return clusters
