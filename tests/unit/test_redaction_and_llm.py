"""Unit tests for log redaction, MockLLM, structured output validation, retry, and fallback."""

import json
from datetime import datetime, timedelta

import pytest

from app.config import Settings
from app.detectors.base import DetectedAnomaly
from app.llm import (
    BaseLLMClient,
    LLMClientError,
    MockLLMClient,
    OpenAICompatibleLLMClient,
    get_llm_client,
    summarize_anomalies,
)
from app.services.redaction import redact_evidence, redact_lines, redact_text


def _sample_anomaly(
    anomaly_type: str = "failed_login_spike",
    evidence: dict | None = None,
    sample_lines: list[str] | None = None,
) -> DetectedAnomaly:
    start = datetime(2026, 11, 24, 14, 0, 0)
    return DetectedAnomaly(
        anomaly_type=anomaly_type,
        detector=f"rule:{anomaly_type}",
        severity="high",
        window_start=start,
        window_end=start + timedelta(minutes=2),
        host="auth-01",
        service="sshd",
        score=2.5,
        evidence=evidence
        or {
            "source_ip": "203.0.113.45",
            "failed_attempts": 25,
            "threshold": 8,
        },
        sample_lines=sample_lines
        or [
            "Failed password for alice@example.com from 203.0.113.45 "
            "Authorization: Bearer superSecretToken123456"
        ],
    )


def test_redaction_masks_ips_emails_tokens_and_secrets() -> None:
    """redact_text partially masks IPs and removes emails, JWTs, bearer tokens, and secrets."""
    raw = (
        "User alice.smith@corp.example failed login from 203.0.113.45 "
        "with Bearer abcdef1234567890 password=myPassword99 "
        "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123456 "
        "key=sk-proj1234567890abcdef"
    )
    redacted = redact_text(raw)

    assert "alice.smith@corp.example" not in redacted
    assert "[REDACTED_EMAIL]" in redacted
    assert "203.0.113.45" not in redacted
    assert "203.0.xxx.xxx" in redacted
    assert "abcdef1234567890" not in redacted
    assert "myPassword99" not in redacted
    assert "eyJhbGciOiJIUzI1NiJ9" not in redacted
    assert "sk-proj1234567890abcdef" not in redacted


def test_redact_lines_and_evidence() -> None:
    """redact_lines caps count and redact_evidence masks nested fields."""
    lines = [f"Error from 198.51.100.{i} user=u{i}@test.io" for i in range(10)]
    redacted = redact_lines(lines, max_lines=5)
    assert len(redacted) == 5
    assert all("198.51.xxx.xxx" in line and "[REDACTED_EMAIL]" in line for line in redacted)

    ev = redact_evidence({"source_ip": "192.0.2.88", "nested": {"email": "ops@company.org"}})
    assert ev["source_ip"] == "192.0.xxx.xxx"
    assert ev["nested"]["email"] == "[REDACTED_EMAIL]"


def test_summarize_with_mock_llm_never_sends_unredacted_pii() -> None:
    """summarize_anomalies redacts prompts before invoking the LLM and validates output."""
    captured_prompts: list[str] = []

    class SpyMockLLM(MockLLMClient):
        def generate_json(self, system_prompt: str, user_prompt: str) -> str:
            captured_prompts.append(user_prompt)
            return super().generate_json(system_prompt, user_prompt)

    anomaly = _sample_anomaly()
    summary, used_fallback, redacted_ev = summarize_anomalies([anomaly], SpyMockLLM())

    assert not used_fallback
    assert summary.confidence > 0.5
    assert "auth-01" in summary.title or "auth-01" in summary.summary
    assert redacted_ev["source_ip"] == "203.0.xxx.xxx"

    assert len(captured_prompts) == 1
    sent = captured_prompts[0]
    assert "203.0.113.45" not in sent
    assert "alice@example.com" not in sent
    assert "superSecretToken123456" not in sent
    assert "203.0.xxx.xxx" in sent


def test_summarize_retries_once_on_invalid_json() -> None:
    """summarize_anomalies retries once on invalid JSON and succeeds if retry is valid."""

    class FlakyLLM(BaseLLMClient):
        provider_name = "flaky"

        def __init__(self) -> None:
            self.calls = 0

        def generate_json(self, system_prompt: str, user_prompt: str) -> str:
            del system_prompt, user_prompt
            self.calls += 1
            if self.calls == 1:
                return "NOT VALID JSON AT ALL"
            return json.dumps(
                {
                    "title": "Recovered HTTP 5xx Incident",
                    "summary": "Upstream service returned elevated 502 responses for 2 minutes.",
                    "likely_root_cause": "Upstream worker crash after bad config reload.",
                    "suggested_fix": "Roll back config and verify upstream health checks.",
                    "confidence": 0.88,
                }
            )

    llm = FlakyLLM()
    anomaly = _sample_anomaly(
        anomaly_type="http_5xx_spike",
        evidence={"error_5xx_count": 40, "error_5xx_rate": 0.45},
    )
    summary, used_fallback, _ = summarize_anomalies([anomaly], llm)

    assert llm.calls == 2
    assert not used_fallback
    assert summary.title == "Recovered HTTP 5xx Incident"
    assert summary.confidence == pytest.approx(0.88)


def test_summarize_falls_back_after_two_invalid_outputs() -> None:
    """summarize_anomalies falls back to deterministic template after two invalid responses."""

    class BrokenJSONLLM(BaseLLMClient):
        provider_name = "broken"

        def __init__(self) -> None:
            self.calls = 0

        def generate_json(self, system_prompt: str, user_prompt: str) -> str:
            del system_prompt, user_prompt
            self.calls += 1
            return '{"title": "x"}'  # Missing required fields

    llm = BrokenJSONLLM()
    anomaly = _sample_anomaly(
        anomaly_type="repeated_error",
        evidence={"error_count": 24, "canonical_message": "DB pool exhausted"},
    )
    summary, used_fallback, _ = summarize_anomalies([anomaly], llm)

    assert llm.calls == 2
    assert used_fallback
    assert "Repeated Error" in summary.title
    assert 0.0 <= summary.confidence <= 1.0


def test_summarize_falls_back_on_llm_client_error() -> None:
    """summarize_anomalies falls back immediately when the provider raises LLMClientError."""

    class FailingLLM(BaseLLMClient):
        provider_name = "failing"

        def generate_json(self, system_prompt: str, user_prompt: str) -> str:
            del system_prompt, user_prompt
            raise LLMClientError("upstream 503")

    anomaly = _sample_anomaly(
        anomaly_type="ml_traffic_anomaly",
        evidence={
            "primary_drivers": ["latency_degradation"],
            "peak_p95_latency_ms": 920.0,
            "baseline_p95_latency_ms": 65.0,
        },
    )
    summary, used_fallback, _ = summarize_anomalies([anomaly], FailingLLM())

    assert used_fallback
    assert "920.0ms" in summary.summary


def test_llm_factory_and_openai_missing_key() -> None:
    """get_llm_client returns MockLLM or OpenAICompatibleLLMClient based on config."""
    mock_client = get_llm_client(Settings(llm_provider="mock"))
    assert isinstance(mock_client, MockLLMClient)

    openai_client = get_llm_client(Settings(llm_provider="openai", llm_api_key=""))
    assert isinstance(openai_client, OpenAICompatibleLLMClient)
    with pytest.raises(LLMClientError):
        openai_client.generate_json("sys", "user")
