"""Deterministic MockLLM client allowing full operation and tests with zero API key."""

import json
from typing import Any

from app.llm.base import BaseLLMClient


class MockLLMClient(BaseLLMClient):
    """Local mock LLM returning realistic structured incident JSON from prompt evidence."""

    provider_name = "mock"

    def generate_json(self, system_prompt: str, user_prompt: str) -> str:
        """Parse embedded telemetry JSON from user_prompt and emit structured incident JSON."""
        del system_prompt
        payload = self._extract_payload(user_prompt)
        anomalies = payload.get("anomalies", [])
        evidence = payload.get("aggregated_evidence", {})

        primary = anomalies[0] if anomalies else {}
        anomaly_types = {a.get("type", "") for a in anomalies}
        host = primary.get("host") or "unknown-host"
        service = primary.get("service") or "unknown-service"
        severity = primary.get("severity") or "medium"

        if "failed_login_spike" in anomaly_types:
            attempts = evidence.get("failed_attempts", 10)
            masked_ip = evidence.get("source_ip", "masked-subnet")
            result = {
                "title": f"Brute-Force Authentication Spike Targeting {host}/{service}",
                "summary": (
                    f"{service} on {host} recorded {attempts} failed login attempts from "
                    f"{masked_ip} within a short burst window, exceeding the security threshold "
                    f"(severity: {severity})."
                ),
                "likely_root_cause": (
                    f"Automated SSH/authentication brute-force or credential-stuffing probe "
                    f"originating from {masked_ip}."
                ),
                "suggested_fix": (
                    "Add an immediate firewall/fail2ban block for the offending source, audit "
                    "auth logs for any accepted sessions, and disable password authentication "
                    "in favor of SSH keys."
                ),
                "confidence": 0.92,
            }
        elif "http_5xx_spike" in anomaly_types:
            err_count = evidence.get("error_5xx_count", 0)
            rate = float(evidence.get("error_5xx_rate", 0.0)) * 100.0
            statuses = evidence.get("status_breakdown", {})
            result = {
                "title": f"Elevated HTTP 5xx Error Rate on {host}/{service}",
                "summary": (
                    f"{service} on {host} experienced an HTTP 5xx spike with {err_count} server "
                    f"errors ({rate:.1f}% of requests; status breakdown: {statuses})."
                ),
                "likely_root_cause": (
                    "Upstream backend unavailability, gateway timeout, or bad deployment causing "
                    "reverse-proxy 502/503/504 responses."
                ),
                "suggested_fix": (
                    "Verify upstream worker health and container restarts, inspect recent "
                    "rollouts for immediate rollback, and check upstream connection pool limits."
                ),
                "confidence": 0.89,
            }
        elif "repeated_error" in anomaly_types:
            count = evidence.get("error_count", 0)
            canonical = evidence.get("canonical_message", "repeated error")
            result = {
                "title": f"Recurring Error Flood in {service} on {host}",
                "summary": (
                    f"{service} on {host} emitted {count} matching error events matching "
                    f"'{canonical}' within the detection window."
                ),
                "likely_root_cause": (
                    "Persistent downstream dependency outage, connection pool exhaustion, or "
                    "tight retry loop on a failing code path."
                ),
                "suggested_fix": (
                    "Inspect the failing dependency and pool metrics, add exponential backoff "
                    "with jitter to retries, and restart stuck worker processes if needed."
                ),
                "confidence": 0.86,
            }
        else:
            drivers = evidence.get("primary_drivers", ["latency_degradation"])
            peak_p95 = evidence.get("peak_p95_latency_ms", 0.0)
            base_p95 = evidence.get("baseline_p95_latency_ms", 0.0)
            result = {
                "title": f"ML-Detected Telemetry Degradation on {host}/{service}",
                "summary": (
                    f"IsolationForest flagged abnormal per-minute traffic behavior on {service} "
                    f"({host}) driven by {', '.join(drivers)}. Peak p95 latency hit "
                    f"{peak_p95}ms compared to a {base_p95}ms baseline."
                ),
                "likely_root_cause": (
                    "Database lock contention, downstream service slowdown, or resource "
                    "saturation under elevated request load."
                ),
                "suggested_fix": (
                    "Profile slow endpoints and DB queries during the anomaly window, verify "
                    "CPU/memory headroom, and autoscale or shed non-critical load."
                ),
                "confidence": 0.84,
            }

        return json.dumps(result)

    @staticmethod
    def _extract_payload(user_prompt: str) -> dict[str, Any]:
        start = user_prompt.find("{")
        if start == -1:
            return {}
        try:
            # Find matching JSON object even if retry text follows
            decoder = json.JSONDecoder()
            obj, _ = decoder.raw_decode(user_prompt[start:])
            return obj if isinstance(obj, dict) else {}
        except json.JSONDecodeError:
            return {}
