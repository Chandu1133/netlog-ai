"""Compact prompt builders and deterministic template fallback for incident summaries."""

import json
from collections.abc import Sequence
from typing import Any

from app.detectors.base import DetectedAnomaly
from app.schemas import IncidentSummaryLLM

SYSTEM_PROMPT = (
    "You are a senior Site Reliability Engineer analyzing network and server anomalies. "
    "Return ONLY a single JSON object with exact keys: "
    '"title" (string), "summary" (string), "likely_root_cause" (string), '
    '"suggested_fix" (string), and "confidence" (float between 0.0 and 1.0). '
    "Do not include markdown prose outside JSON. Base conclusions strictly on provided evidence."
)


def build_incident_prompt(
    anomalies: Sequence[DetectedAnomaly],
    redacted_evidence: dict[str, Any],
    redacted_samples: list[str],
) -> str:
    """Build a compact, token-efficient prompt from aggregated evidence and redacted samples."""
    anomaly_overview = [
        {
            "type": a.anomaly_type,
            "detector": a.detector,
            "severity": a.severity,
            "host": a.host,
            "service": a.service,
            "window_start": a.window_start.isoformat(),
            "window_end": a.window_end.isoformat(),
            "score": a.score,
        }
        for a in anomalies
    ]
    payload = {
        "anomalies": anomaly_overview,
        "aggregated_evidence": redacted_evidence,
        "redacted_sample_lines": redacted_samples[:5],
    }
    return (
        "Analyze the following aggregated incident telemetry and return the required JSON schema:\n"
        + json.dumps(payload, separators=(",", ":"), default=str)
    )


def build_retry_prompt(original_user_prompt: str, invalid_response: str, error_detail: str) -> str:
    """Build a corrective prompt for a single retry after invalid JSON or schema failure."""
    return (
        f"{original_user_prompt}\n\n"
        f"Your previous output was invalid ({error_detail}). "
        f"Previous snippet: {invalid_response[:300]}\n"
        "Respond again with ONLY valid JSON containing keys: "
        "title, summary, likely_root_cause, suggested_fix, confidence."
    )


def build_template_fallback(
    anomalies: Sequence[DetectedAnomaly],
    redacted_evidence: dict[str, Any],
) -> IncidentSummaryLLM:
    """Produce a deterministic plain-English SRE summary if the LLM fails."""
    primary = anomalies[0]
    host = primary.host or "unknown-host"
    service = primary.service or "unknown-service"
    types = sorted({a.anomaly_type for a in anomalies})

    if "failed_login_spike" in types:
        attempts = redacted_evidence.get("failed_attempts", "multiple")
        masked_ip = redacted_evidence.get("source_ip", "masked-ip")
        return IncidentSummaryLLM(
            title=f"SSH/Auth Brute-Force Spike on {host} ({service})",
            summary=(
                f"Detected {attempts} failed authentication attempts targeting {service} on "
                f"{host} from {masked_ip} between {primary.window_start.isoformat()} and "
                f"{primary.window_end.isoformat()}."
            ),
            likely_root_cause=(
                "Automated credential stuffing or SSH brute-force attack originating from "
                f"subnet {masked_ip}."
            ),
            suggested_fix=(
                "Block or rate-limit the offending IP via fail2ban/firewall, verify no "
                "successful logins occurred, and enforce key-based authentication with MFA."
            ),
            confidence=0.72,
        )

    if "http_5xx_spike" in types:
        err_count = redacted_evidence.get("error_5xx_count", "elevated")
        rate = redacted_evidence.get("error_5xx_rate", 0.0)
        rate_pct = f"{float(rate) * 100:.1f}%" if isinstance(rate, int | float) else str(rate)
        return IncidentSummaryLLM(
            title=f"HTTP 5xx Error Spike on {host} ({service})",
            summary=(
                f"Observed {err_count} HTTP 5xx responses ({rate_pct} error rate) on "
                f"{service} ({host}) from {primary.window_start.isoformat()} to "
                f"{primary.window_end.isoformat()}."
            ),
            likely_root_cause=(
                "Upstream application crash, gateway timeout, or backend resource exhaustion "
                "causing reverse proxy 5xx responses."
            ),
            suggested_fix=(
                "Inspect upstream service health and logs, check recent deployments for rollback, "
                "and verify database/downstream connection pool saturation."
            ),
            confidence=0.74,
        )

    if "repeated_error" in types:
        count = redacted_evidence.get("error_count", "repeated")
        canonical = redacted_evidence.get("canonical_message", "application error")
        return IncidentSummaryLLM(
            title=f"Repeated Error Burst on {host} ({service})",
            summary=(
                f"Detected {count} occurrences of recurring error '{canonical}' on {service} "
                f"({host}) between {primary.window_start.isoformat()} and "
                f"{primary.window_end.isoformat()}."
            ),
            likely_root_cause=(
                "Persistent dependency failure, exhausted connection pool, or unhandled "
                "exception loop in the service."
            ),
            suggested_fix=(
                "Review service stack traces around the incident window, check dependency "
                "connectivity and pool limits, and restart or roll back unhealthy instances."
            ),
            confidence=0.70,
        )

    drivers = redacted_evidence.get("primary_drivers", ["telemetry_shift"])
    p95 = redacted_evidence.get("peak_p95_latency_ms")
    base_p95 = redacted_evidence.get("baseline_p95_latency_ms")
    lat_note = (
        f" Peak p95 latency reached {p95}ms vs {base_p95}ms baseline."
        if p95 is not None and base_p95 is not None
        else ""
    )
    return IncidentSummaryLLM(
        title=f"Anomalous Service Telemetry on {host} ({service})",
        summary=(
            f"IsolationForest detected anomalous per-minute behavior ({', '.join(drivers)}) "
            f"on {service} ({host}) from {primary.window_start.isoformat()} to "
            f"{primary.window_end.isoformat()}.{lat_note}"
        ),
        likely_root_cause=(
            "Backend latency regression, slow database queries, CPU/memory contention, or "
            "sudden traffic surge."
        ),
        suggested_fix=(
            "Check slow query logs, CPU/memory utilization, and upstream response times; "
            "scale replicas or enable circuit breaking if load-induced."
        ),
        confidence=0.68,
    )
