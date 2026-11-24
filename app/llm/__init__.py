"""LLM factory and validated incident summarization pipeline with retry and fallback."""

import logging
import re
from collections.abc import Sequence
from typing import Any

from pydantic import ValidationError

from app.config import Settings, get_settings
from app.detectors.base import DetectedAnomaly
from app.llm.base import BaseLLMClient, LLMClientError
from app.llm.mock import MockLLMClient
from app.llm.openai_client import OpenAICompatibleLLMClient
from app.llm.prompts import (
    SYSTEM_PROMPT,
    build_incident_prompt,
    build_retry_prompt,
    build_template_fallback,
)
from app.schemas import IncidentSummaryLLM
from app.services.redaction import redact_evidence, redact_lines

logger = logging.getLogger(__name__)

_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


def get_llm_client(settings: Settings | None = None) -> BaseLLMClient:
    """Instantiate the configured LLM provider from environment settings."""
    cfg = settings or get_settings()
    provider = cfg.llm_provider.strip().lower()
    if provider == "mock":
        return MockLLMClient()
    if provider in {"openai", "openai_compatible"}:
        return OpenAICompatibleLLMClient(
            api_key=cfg.llm_api_key,
            base_url=cfg.llm_base_url,
            model=cfg.llm_model,
            timeout_seconds=cfg.llm_timeout_seconds,
        )
    logger.warning("Unknown LLM_PROVIDER '%s'; defaulting to MockLLMClient", cfg.llm_provider)
    return MockLLMClient()


def _strip_markdown_fences(raw_text: str) -> str:
    return _CODE_FENCE_RE.sub("", raw_text.strip()).strip()


def merge_anomaly_evidence(anomalies: Sequence[DetectedAnomaly]) -> dict[str, Any]:
    """Merge evidence dicts from grouped anomalies into one compact dictionary."""
    merged: dict[str, Any] = {}
    for anomaly in anomalies:
        for key, value in anomaly.evidence.items():
            if key not in merged:
                merged[key] = value
    merged["anomaly_types"] = sorted({a.anomaly_type for a in anomalies})
    merged["anomaly_count"] = len(anomalies)
    return merged


def summarize_anomalies(
    anomalies: Sequence[DetectedAnomaly],
    llm_client: BaseLLMClient,
) -> tuple[IncidentSummaryLLM, bool, dict[str, Any]]:
    """Summarize grouped anomalies using redacted evidence, validating output with one retry.

    Returns (summary, used_fallback, redacted_evidence).
    """
    if not anomalies:
        raise ValueError("Cannot summarize an empty anomaly list.")

    raw_evidence = merge_anomaly_evidence(anomalies)
    redacted_ev = redact_evidence(raw_evidence)
    raw_samples = [line for a in anomalies for line in a.sample_lines]
    redacted_samples = redact_lines(raw_samples, max_lines=5)

    user_prompt = build_incident_prompt(
        anomalies=anomalies,
        redacted_evidence=redacted_ev,
        redacted_samples=redacted_samples,
    )

    last_error = ""
    last_raw = ""

    for attempt in range(2):
        prompt_to_send = (
            user_prompt if attempt == 0 else build_retry_prompt(user_prompt, last_raw, last_error)
        )
        try:
            raw_output = llm_client.generate_json(SYSTEM_PROMPT, prompt_to_send)
        except LLMClientError as exc:
            logger.warning(
                "LLM call failed on attempt %d (%s); falling back to template summary",
                attempt + 1,
                exc,
            )
            return build_template_fallback(anomalies, redacted_ev), True, redacted_ev

        cleaned = _strip_markdown_fences(raw_output)
        try:
            validated = IncidentSummaryLLM.model_validate_json(cleaned)
            return validated, False, redacted_ev
        except ValidationError as exc:
            last_raw = raw_output
            last_error = str(exc.errors()[0]["msg"]) if exc.errors() else str(exc)
            logger.warning(
                "LLM output failed schema validation on attempt %d: %s",
                attempt + 1,
                last_error,
            )

    logger.warning("LLM output remained invalid after retry; using deterministic template fallback")
    return build_template_fallback(anomalies, redacted_ev), True, redacted_ev


__all__ = [
    "BaseLLMClient",
    "LLMClientError",
    "MockLLMClient",
    "OpenAICompatibleLLMClient",
    "get_llm_client",
    "summarize_anomalies",
]
