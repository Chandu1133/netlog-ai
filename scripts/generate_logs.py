"""Synthetic syslog and nginx log generator with labeled ground-truth anomalies."""

import argparse
import json
import logging
import random
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class GroundTruthIncident:
    """Single injected anomaly event recorded in ground truth for evaluation."""

    id: str
    anomaly_type: str
    expected_types: list[str]
    host: str
    service: str
    window_start: str
    window_end: str
    description: str


def generate_dataset(
    output_dir: Path,
    duration_minutes: int = 90,
    seed: int = 42,
    start_time: datetime | None = None,
) -> tuple[Path, Path]:
    """Generate realistic mixed syslog + nginx logs with injected anomalies and ground truth.

    Returns paths to (combined_log_path, ground_truth_json_path).
    """
    rng = random.Random(seed)
    output_dir.mkdir(parents=True, exist_ok=True)
    base = start_time or datetime(2026, 11, 24, 12, 0, 0)

    timed_lines: list[tuple[datetime, str]] = []
    ground_truth: list[GroundTruthIncident] = []

    normal_paths = [
        "/api/v1/orders",
        "/api/v1/products",
        "/api/v1/users/profile",
        "/api/v1/search",
        "/healthz",
    ]
    normal_ips = [f"10.20.{i // 20}.{10 + (i % 20)}" for i in range(60)]

    # 1. Baseline & background traffic across all minutes
    for minute in range(duration_minutes):
        minute_dt = base + timedelta(minutes=minute)

        # edge-01 / nginx: ~28 req/min steady baseline (latency 25-65ms)
        req_count_1 = rng.randint(25, 31)
        for _ in range(req_count_1):
            ts = minute_dt + timedelta(seconds=rng.randint(0, 59))
            ip = rng.choice(normal_ips)
            path = rng.choice(normal_paths)
            status_code = 404 if rng.random() < 0.02 else 200
            rt_sec = round(rng.uniform(0.025, 0.065), 4)
            ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
            timed_lines.append(
                (
                    ts,
                    f'{ip} - - [{ts_str}] "GET {path} HTTP/1.1" {status_code} '
                    f'{rng.randint(180, 4096)} "-" "Mozilla/5.0" '
                    f"rt={rt_sec} host=edge-01 service=nginx",
                )
            )

        # edge-02 / payments-api: ~22 req/min steady baseline (latency 35-85ms)
        req_count_2 = rng.randint(19, 25)
        for _ in range(req_count_2):
            ts = minute_dt + timedelta(seconds=rng.randint(0, 59))
            ip = rng.choice(normal_ips)
            status_code = 201 if rng.random() < 0.7 else 200
            rt_sec = round(rng.uniform(0.035, 0.085), 4)
            ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
            timed_lines.append(
                (
                    ts,
                    f'{ip} - - [{ts_str}] "POST /api/v1/payments HTTP/1.1" {status_code} '
                    f'{rng.randint(256, 1500)} "-" "PaySDK/2.1" '
                    f"rt={rt_sec} host=edge-02 service=payments-api",
                )
            )

        # auth-01 / sshd: routine accepted logins + occasional single typo
        for _ in range(rng.randint(2, 4)):
            ts = minute_dt + timedelta(seconds=rng.randint(0, 59))
            ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
            ip = rng.choice(normal_ips)
            port = rng.randint(30000, 60000)
            timed_lines.append(
                (
                    ts,
                    f"{ts_iso} auth-01 sshd[{rng.randint(1000, 9999)}]: "
                    f"Accepted publickey for deploy from {ip} port {port} ssh2",
                )
            )
        if minute % 9 == 0:
            ts = minute_dt + timedelta(seconds=15)
            ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
            timed_lines.append(
                (
                    ts,
                    f"{ts_iso} auth-01 sshd[4102]: "
                    "Failed password for ops from 10.20.0.15 port 44122 ssh2",
                )
            )

        # app-01 / billing-worker: routine INFO heartbeats
        for _ in range(3):
            ts = minute_dt + timedelta(seconds=rng.randint(0, 59))
            ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
            timed_lines.append(
                (
                    ts,
                    f"{ts_iso} app-01 billing-worker[812]: "
                    f"Processed invoice batch #{rng.randint(10000, 99999)} successfully",
                )
            )

    # 2. Inject ground-truth anomalies (placed after baseline window when duration allows)
    offset = max(15, int(duration_minutes * 0.5))

    def _clamp_minute(delta_from_offset: int) -> int:
        return min(duration_minutes - 3, offset + delta_from_offset)

    # Anomaly 1: SSH brute-force burst #1 on auth-01
    m1 = _clamp_minute(1)
    w1_start = base + timedelta(minutes=m1)
    w1_end = w1_start + timedelta(minutes=2)
    for i in range(30):
        ts = w1_start + timedelta(seconds=i * 3)
        ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        timed_lines.append(
            (
                ts,
                f"{ts_iso} auth-01 sshd[5001]: Failed password for invalid user admin "
                f"from 203.0.113.88 port {51000 + i} ssh2",
            )
        )
    ground_truth.append(
        GroundTruthIncident(
            id="gt-1-brute-force-1",
            anomaly_type="failed_login_spike",
            expected_types=["failed_login_spike"],
            host="auth-01",
            service="sshd",
            window_start=w1_start.isoformat(),
            window_end=w1_end.isoformat(),
            description="30 failed SSH logins from 203.0.113.88 within 2 minutes",
        )
    )

    # Anomaly 2: HTTP 5xx outage on edge-01 / nginx
    m2 = _clamp_minute(8)
    w2_start = base + timedelta(minutes=m2)
    w2_end = w2_start + timedelta(minutes=3)
    for m_off in range(3):
        for i in range(24):
            ts = w2_start + timedelta(minutes=m_off, seconds=i * 2)
            ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
            status_code = rng.choice([502, 503, 504])
            rt_sec = round(rng.uniform(0.35, 0.95), 4)
            timed_lines.append(
                (
                    ts,
                    f'198.51.100.{10 + (i % 10)} - - [{ts_str}] "POST /api/v1/checkout HTTP/1.1" '
                    f'{status_code} 512 "-" "Mozilla/5.0" '
                    f"rt={rt_sec} host=edge-01 service=nginx",
                )
            )
    ground_truth.append(
        GroundTruthIncident(
            id="gt-2-http-5xx-nginx",
            anomaly_type="http_5xx_spike",
            expected_types=["http_5xx_spike", "ml_traffic_anomaly"],
            host="edge-01",
            service="nginx",
            window_start=w2_start.isoformat(),
            window_end=w2_end.isoformat(),
            description="Sustained HTTP 502/503/504 outage on edge-01/nginx",
        )
    )

    # Anomaly 3: Pure latency degradation (HTTP 200, high latency) on edge-01 / nginx (ML target)
    m3 = _clamp_minute(16)
    w3_start = base + timedelta(minutes=m3)
    w3_end = w3_start + timedelta(minutes=4)
    for m_off in range(4):
        for i in range(24):
            ts = w3_start + timedelta(minutes=m_off, seconds=i * 2)
            ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
            rt_sec = round(rng.uniform(0.55, 1.25), 4)
            timed_lines.append(
                (
                    ts,
                    f'192.0.2.{20 + (i % 15)} - - [{ts_str}] "GET /api/v1/search HTTP/1.1" '
                    f'200 2048 "-" "Mozilla/5.0" '
                    f"rt={rt_sec} host=edge-01 service=nginx",
                )
            )
    ground_truth.append(
        GroundTruthIncident(
            id="gt-3-latency-degradation",
            anomaly_type="ml_traffic_anomaly",
            expected_types=["ml_traffic_anomaly"],
            host="edge-01",
            service="nginx",
            window_start=w3_start.isoformat(),
            window_end=w3_end.isoformat(),
            description="Severe latency degradation (550-1250ms p95) with HTTP 200s on edge-01",
        )
    )

    # Anomaly 4: Repeated application error burst on app-01 / billing-worker
    m4 = _clamp_minute(24)
    w4_start = base + timedelta(minutes=m4)
    w4_end = w4_start + timedelta(minutes=2)
    for i in range(26):
        ts = w4_start + timedelta(seconds=i * 4)
        ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        timed_lines.append(
            (
                ts,
                f"{ts_iso} app-01 billing-worker[812]: "
                f"ERROR Database connection pool exhausted while executing txn {70000 + i}",
            )
        )
    ground_truth.append(
        GroundTruthIncident(
            id="gt-4-repeated-error",
            anomaly_type="repeated_error",
            expected_types=["repeated_error"],
            host="app-01",
            service="billing-worker",
            window_start=w4_start.isoformat(),
            window_end=w4_end.isoformat(),
            description="26 repeated DB connection pool exhaustion errors on app-01",
        )
    )

    # Anomaly 5: Second SSH brute-force burst from another IP on auth-01
    m5 = _clamp_minute(31)
    w5_start = base + timedelta(minutes=m5)
    w5_end = w5_start + timedelta(minutes=2)
    for i in range(20):
        ts = w5_start + timedelta(seconds=i * 4)
        ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        timed_lines.append(
            (
                ts,
                f"{ts_iso} auth-01 sshd[6100]: Failed password for root "
                f"from 198.51.100.77 port {42000 + i} ssh2",
            )
        )
    ground_truth.append(
        GroundTruthIncident(
            id="gt-5-brute-force-2",
            anomaly_type="failed_login_spike",
            expected_types=["failed_login_spike"],
            host="auth-01",
            service="sshd",
            window_start=w5_start.isoformat(),
            window_end=w5_end.isoformat(),
            description="20 failed SSH root login attempts from 198.51.100.77",
        )
    )

    # Anomaly 6: HTTP 5xx + latency spike on edge-02 / payments-api
    m6 = _clamp_minute(38)
    w6_start = base + timedelta(minutes=m6)
    w6_end = w6_start + timedelta(minutes=3)
    for m_off in range(3):
        for i in range(20):
            ts = w6_start + timedelta(minutes=m_off, seconds=i * 2)
            ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
            status_code = rng.choice([500, 503])
            rt_sec = round(rng.uniform(0.45, 1.1), 4)
            timed_lines.append(
                (
                    ts,
                    f'203.0.113.{30 + (i % 8)} - - [{ts_str}] "POST /api/v1/payments HTTP/1.1" '
                    f'{status_code} 320 "-" "PaySDK/2.1" '
                    f"rt={rt_sec} host=edge-02 service=payments-api",
                )
            )
    ground_truth.append(
        GroundTruthIncident(
            id="gt-6-http-5xx-payments",
            anomaly_type="http_5xx_spike",
            expected_types=["http_5xx_spike", "ml_traffic_anomaly"],
            host="edge-02",
            service="payments-api",
            window_start=w6_start.isoformat(),
            window_end=w6_end.isoformat(),
            description="HTTP 500/503 outage on edge-02/payments-api",
        )
    )

    # 3. Sprinkle 20 intentionally malformed lines to verify resilient bad-line handling
    bad_line_count = 20
    for i in range(bad_line_count):
        ts = base + timedelta(minutes=rng.randint(0, duration_minutes - 1), seconds=30)
        timed_lines.append((ts, f"CORRUPT_LOG_FRAGMENT_{i} ### unparseable payload"))

    timed_lines.sort(key=lambda pair: pair[0])

    log_path = output_dir / "synthetic_server.log"
    gt_path = output_dir / "ground_truth.json"

    log_path.write_text("\n".join(line for _, line in timed_lines) + "\n", encoding="utf-8")
    gt_payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "seed": seed,
        "duration_minutes": duration_minutes,
        "total_lines": len(timed_lines),
        "expected_bad_lines": bad_line_count,
        "anomalies": [asdict(item) for item in ground_truth],
    }
    gt_path.write_text(json.dumps(gt_payload, indent=2), encoding="utf-8")

    logger.info(
        "Generated %d log lines (%d intentional bad lines, %d ground-truth incidents) -> %s",
        len(timed_lines),
        bad_line_count,
        len(ground_truth),
        log_path,
    )
    return log_path, gt_path


def main() -> None:
    """CLI entrypoint for synthetic log dataset generation."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    parser = argparse.ArgumentParser(description="Generate synthetic logs with ground truth.")
    parser.add_argument("--output-dir", type=Path, default=Path("data"))
    parser.add_argument("--duration-minutes", type=int, default=90)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    generate_dataset(
        output_dir=args.output_dir,
        duration_minutes=args.duration_minutes,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
