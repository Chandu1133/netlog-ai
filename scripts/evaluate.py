"""Benchmark and accuracy evaluation script for NetLog AI detection & summarization."""

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure repository root is importable when invoked as `python scripts/evaluate.py`
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.config import Settings  # noqa: E402
from app.database import Base  # noqa: E402
from app.detectors import run_all_detectors  # noqa: E402
from app.llm import MockLLMClient, summarize_anomalies  # noqa: E402
from app.parsers import parse_raw_lines  # noqa: E402
from app.services.incidents import group_anomalies_into_incidents  # noqa: E402
from app.services.ingestion import ingest_raw_log_text  # noqa: E402
from scripts.generate_logs import generate_dataset  # noqa: E402

logger = logging.getLogger(__name__)


@dataclass
class EvaluationMetrics:
    """Measured accuracy and performance metrics from a real evaluation run."""

    total_lines: int
    valid_lines: int
    bad_lines_detected: int
    expected_bad_lines: int
    parse_throughput_lps: float
    db_ingest_throughput_lps: float
    ground_truth_count: int
    predicted_incident_count: int
    raw_anomaly_count: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    avg_detection_latency_ms: float
    avg_summary_latency_ms: float
    avg_total_pipeline_latency_ms: float
    per_incident_summary_latency_ms: float
    benchmark_runs: int
    detector_breakdown: dict[str, int]
    matched_details: list[dict[str, Any]]


def _windows_overlap(
    start_a: datetime,
    end_a: datetime,
    start_b: datetime,
    end_b: datetime,
    tolerance_minutes: int = 2,
) -> bool:
    pad = timedelta(minutes=tolerance_minutes)
    return (start_a <= end_b + pad) and (end_a + pad >= start_b)


def evaluate_dataset(
    log_path: Path,
    ground_truth_path: Path,
    benchmark_runs: int = 5,
) -> EvaluationMetrics:
    """Run parsing, DB ingestion, detection, and LLM summarization and compare with ground truth."""
    raw_text = log_path.read_text(encoding="utf-8")
    gt_data = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    gt_events: list[dict[str, Any]] = gt_data["anomalies"]
    expected_bad = int(gt_data.get("expected_bad_lines", 0))

    settings = Settings(app_env="eval", llm_provider="mock", api_key="eval-key")
    llm_client = MockLLMClient()

    # 1. Measure parsing throughput
    parse_times: list[float] = []
    parse_result = None
    for _ in range(benchmark_runs):
        t0 = time.perf_counter()
        parse_result = parse_raw_lines(raw_text.splitlines(), format_hint="auto")
        parse_times.append(time.perf_counter() - t0)

    assert parse_result is not None
    avg_parse_sec = sum(parse_times) / len(parse_times)
    parse_lps = parse_result.total_lines / avg_parse_sec if avg_parse_sec > 0 else 0.0

    # 2. Measure full ingestion (parse + SQLAlchemy ORM persistence) throughput
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    t_ingest_0 = time.perf_counter()
    with session_factory() as db:
        ingest_resp, _ = ingest_raw_log_text(db, raw_text, format_hint="auto")
    db_ingest_sec = time.perf_counter() - t_ingest_0
    db_ingest_lps = ingest_resp.total_lines / db_ingest_sec if db_ingest_sec > 0 else 0.0
    engine.dispose()

    # 3. Measure detection + incident grouping + LLM summarization across benchmark_runs
    detect_times_ms: list[float] = []
    summary_times_ms: list[float] = []
    anomalies = []
    groups = []

    for _ in range(benchmark_runs):
        t_det_0 = time.perf_counter()
        anomalies = run_all_detectors(parse_result.records, settings=settings)
        groups = group_anomalies_into_incidents(anomalies)
        detect_times_ms.append((time.perf_counter() - t_det_0) * 1000.0)

        t_sum_0 = time.perf_counter()
        for group in groups:
            summarize_anomalies(group, llm_client)
        summary_times_ms.append((time.perf_counter() - t_sum_0) * 1000.0)

    avg_detect_ms = sum(detect_times_ms) / len(detect_times_ms)
    avg_summary_ms = sum(summary_times_ms) / len(summary_times_ms)
    avg_total_ms = avg_detect_ms + avg_summary_ms
    per_inc_summary_ms = avg_summary_ms / len(groups) if groups else 0.0

    # 4. Score predicted grouped incidents against ground truth (1-to-1 matching)
    matched_gt_ids: set[str] = set()
    matched_details: list[dict[str, Any]] = []
    tp = 0
    fp = 0

    for idx, group in enumerate(groups, start=1):
        pred_host = group[0].host
        pred_service = group[0].service
        pred_start = min(a.window_start for a in group)
        pred_end = max(a.window_end for a in group)
        pred_types = sorted({a.anomaly_type for a in group})

        matched_gt = None
        for gt in gt_events:
            if gt["id"] in matched_gt_ids:
                continue
            gt_start = datetime.fromisoformat(gt["window_start"])
            gt_end = datetime.fromisoformat(gt["window_end"])
            expected_types = set(gt.get("expected_types", [gt["anomaly_type"]]))

            if (
                pred_host == gt["host"]
                and pred_service == gt["service"]
                and bool(set(pred_types) & expected_types)
                and _windows_overlap(pred_start, pred_end, gt_start, gt_end)
            ):
                matched_gt = gt
                break

        if matched_gt is not None:
            matched_gt_ids.add(matched_gt["id"])
            tp += 1
            matched_details.append(
                {
                    "predicted_incident": idx,
                    "status": "TP",
                    "ground_truth_id": matched_gt["id"],
                    "host": pred_host,
                    "service": pred_service,
                    "detected_types": pred_types,
                    "window": f"{pred_start.isoformat()} -> {pred_end.isoformat()}",
                }
            )
        else:
            fp += 1
            matched_details.append(
                {
                    "predicted_incident": idx,
                    "status": "FP",
                    "ground_truth_id": None,
                    "host": pred_host,
                    "service": pred_service,
                    "detected_types": pred_types,
                    "window": f"{pred_start.isoformat()} -> {pred_end.isoformat()}",
                }
            )

    fn = len(gt_events) - tp
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    detector_breakdown: dict[str, int] = {}
    for anom in anomalies:
        detector_breakdown[anom.anomaly_type] = detector_breakdown.get(anom.anomaly_type, 0) + 1

    return EvaluationMetrics(
        total_lines=parse_result.total_lines,
        valid_lines=len(parse_result.records),
        bad_lines_detected=parse_result.bad_line_count,
        expected_bad_lines=expected_bad,
        parse_throughput_lps=round(parse_lps, 1),
        db_ingest_throughput_lps=round(db_ingest_lps, 1),
        ground_truth_count=len(gt_events),
        predicted_incident_count=len(groups),
        raw_anomaly_count=len(anomalies),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        avg_detection_latency_ms=round(avg_detect_ms, 2),
        avg_summary_latency_ms=round(avg_summary_ms, 2),
        avg_total_pipeline_latency_ms=round(avg_total_ms, 2),
        per_incident_summary_latency_ms=round(per_inc_summary_ms, 2),
        benchmark_runs=benchmark_runs,
        detector_breakdown=detector_breakdown,
        matched_details=matched_details,
    )


def render_results_markdown(metrics: EvaluationMetrics) -> str:
    """Format measured evaluation metrics as a clean Markdown report."""
    breakdown_rows = "\n".join(
        f"| `{atype}` | {count} |" for atype, count in sorted(metrics.detector_breakdown.items())
    )
    detail_rows = "\n".join(
        f"| #{d['predicted_incident']} | **{d['status']}** | "
        f"`{d['ground_truth_id'] or '-'}` | `{d['host']}/{d['service']}` | "
        f"`{', '.join(d['detected_types'])}` | `{d['window']}` |"
        for d in metrics.matched_details
    )

    parse_lps = f"{metrics.parse_throughput_lps:,.1f} lines/sec"
    ingest_lps = f"{metrics.db_ingest_throughput_lps:,.1f} lines/sec"
    det_ms = f"{metrics.avg_detection_latency_ms:.2f} ms"
    sum_ms = f"{metrics.avg_summary_latency_ms:.2f} ms"
    per_inc_ms = f"{metrics.per_incident_summary_latency_ms:.2f} ms"
    tot_ms = f"{metrics.avg_total_pipeline_latency_ms:.2f} ms"
    eval_cmd = (
        "python scripts/evaluate.py --log-file data/synthetic_server.log "
        "--ground-truth data/ground_truth.json --results-file docs/RESULTS.md"
    )
    match_header = (
        "| Predicted | Match | Ground Truth ID | Target (`host/service`) "
        "| Triggered Detectors | Detected Window |"
    )

    return f"""# NetLog AI — Evaluation & Benchmark Results

All numbers below were measured directly by running `python scripts/evaluate.py` against the
synthetic multi-host dataset generated by `scripts/generate_logs.py` (averaged over
{metrics.benchmark_runs} runs with `MockLLMClient` and SQLAlchemy ORM persistence).

## Detection Accuracy (Incident-Level vs. Ground Truth)

| Metric | Measured Value |
| --- | ---: |
| Ground-Truth Injected Incidents | {metrics.ground_truth_count} |
| Predicted Incidents (Grouped) | {metrics.predicted_incident_count} |
| Raw Detector Signals | {metrics.raw_anomaly_count} |
| True Positives (TP) | {metrics.true_positives} |
| False Positives (FP) | {metrics.false_positives} |
| False Negatives (FN) | {metrics.false_negatives} |
| **Precision** | **{metrics.precision:.4f} ({metrics.precision * 100:.1f}%)** |
| **Recall** | **{metrics.recall:.4f} ({metrics.recall * 100:.1f}%)** |
| **F1 Score** | **{metrics.f1_score:.4f} ({metrics.f1_score * 100:.1f}%)** |

## Ingestion & Pipeline Performance

| Benchmark Metric | Measured Value |
| --- | ---: |
| Total Log Lines Processed | {metrics.total_lines:,} |
| Valid Normalized Lines | {metrics.valid_lines:,} |
| Malformed Lines Caught & Reported | {metrics.bad_lines_detected} / {metrics.expected_bad_lines} |
| **Parsing & Normalization Throughput** | **{parse_lps}** |
| **End-to-End Ingestion Throughput (Parse + DB Write)** | **{ingest_lps}** |
| Average Detection Latency (Rules + IsolationForest) | {det_ms} |
| Average AI Summarization Latency (all incidents, MockLLM) | {sum_ms} |
| Average Summary Latency per Incident | {per_inc_ms} |
| **Average Detection + Summary Total Latency** | **{tot_ms}** |

## Raw Signals by Anomaly Type

| Anomaly Type | Signals Detected |
| --- | ---: |
{breakdown_rows}

## Incident Matching Details

{match_header}
| --- | --- | --- | --- | --- | --- |
{detail_rows}

## How to Reproduce

```bash
python scripts/generate_logs.py --output-dir data --duration-minutes 90 --seed 42
{eval_cmd}
```
"""


def main() -> None:
    """CLI entrypoint to generate (if missing), evaluate, and write docs/RESULTS.md."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    parser = argparse.ArgumentParser(description="Evaluate NetLog AI detection and performance.")
    parser.add_argument("--log-file", type=Path, default=Path("data/synthetic_server.log"))
    parser.add_argument("--ground-truth", type=Path, default=Path("data/ground_truth.json"))
    parser.add_argument("--results-file", type=Path, default=Path("docs/RESULTS.md"))
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()

    if not args.log_file.exists() or not args.ground_truth.exists():
        logger.info("Dataset not found; generating fresh synthetic logs...")
        generate_dataset(output_dir=args.log_file.parent)

    metrics = evaluate_dataset(
        log_path=args.log_file,
        ground_truth_path=args.ground_truth,
        benchmark_runs=args.runs,
    )

    args.results_file.parent.mkdir(parents=True, exist_ok=True)
    args.results_file.write_text(render_results_markdown(metrics), encoding="utf-8")

    logger.info(
        "Evaluation complete: Precision=%.4f Recall=%.4f F1=%.4f | Parse=%.1f lines/s | "
        "Ingest=%.1f lines/s | Detect+Summary=%.2f ms",
        metrics.precision,
        metrics.recall,
        metrics.f1_score,
        metrics.parse_throughput_lps,
        metrics.db_ingest_throughput_lps,
        metrics.avg_total_pipeline_latency_ms,
    )


if __name__ == "__main__":
    main()
