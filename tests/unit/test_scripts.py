"""Unit tests for the synthetic log generator and evaluation harness."""

from pathlib import Path

from scripts.evaluate import evaluate_dataset, render_results_markdown
from scripts.generate_logs import generate_dataset


def test_generate_and_evaluate_pipeline(tmp_path: Path) -> None:
    """Synthetic generator + evaluator runs end-to-end and achieves strong F1."""
    log_path, gt_path = generate_dataset(output_dir=tmp_path, duration_minutes=60, seed=7)
    assert log_path.exists()
    assert gt_path.exists()

    metrics = evaluate_dataset(log_path=log_path, ground_truth_path=gt_path, benchmark_runs=1)
    assert metrics.total_lines > 1000
    assert metrics.bad_lines_detected == metrics.expected_bad_lines
    assert metrics.f1_score >= 0.8
    assert metrics.parse_throughput_lps > 0
    assert metrics.db_ingest_throughput_lps > 0

    markdown = render_results_markdown(metrics)
    assert "Precision" in markdown
    assert "Recall" in markdown
    assert "F1 Score" in markdown
