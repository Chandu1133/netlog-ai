"""Redaction utilities ensuring raw secrets, emails, tokens, and full IPs never reach an LLM."""

import re
from collections.abc import Sequence
from typing import Any

_IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_IPV6_RE = re.compile(r"\b([0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_BEARER_RE = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
_API_KEY_PREFIX_RE = re.compile(r"\b(?:sk|pk|rk|ghp|xox[baprs])-[A-Za-z0-9_-]{10,}\b")
_SECRET_KV_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|auth[_-]?token)"
    r"(\s*[=:]\s*)([^\s,;\"']+)"
)


def _mask_ipv4(match: re.Match[str]) -> str:
    octets = [int(match.group(i)) for i in range(1, 5)]
    if all(0 <= o <= 255 for o in octets):
        return f"{octets[0]}.{octets[1]}.xxx.xxx"
    return match.group(0)


def _mask_ipv6(match: re.Match[str]) -> str:
    parts = match.group(0).split(":")
    if len(parts) >= 2:
        return f"{parts[0]}:{parts[1]}:xxxx:xxxx"
    return "xxxx::xxxx"


def redact_text(text: str) -> str:
    """Partially mask IP addresses and fully redact emails, JWTs, bearer tokens, and secrets."""
    redacted = _JWT_RE.sub("[REDACTED_TOKEN]", text)
    redacted = _BEARER_RE.sub(r"\1[REDACTED_TOKEN]", redacted)
    redacted = _API_KEY_PREFIX_RE.sub("[REDACTED_TOKEN]", redacted)
    redacted = _SECRET_KV_RE.sub(r"\1\2[REDACTED_SECRET]", redacted)
    redacted = _EMAIL_RE.sub("[REDACTED_EMAIL]", redacted)
    redacted = _IPV4_RE.sub(_mask_ipv4, redacted)
    redacted = _IPV6_RE.sub(_mask_ipv6, redacted)
    return redacted


def redact_lines(lines: Sequence[str], max_lines: int = 5, max_chars: int = 300) -> list[str]:
    """Return a bounded list of redacted, truncated sample log lines."""
    return [redact_text(line)[:max_chars] for line in list(lines)[:max_lines]]


def redact_evidence(data: Any) -> Any:
    """Recursively redact sensitive strings inside structured evidence dictionaries."""
    if isinstance(data, str):
        return redact_text(data)
    if isinstance(data, list):
        return [redact_evidence(item) for item in data]
    if isinstance(data, dict):
        return {str(k): redact_evidence(v) for k, v in data.items()}
    return data
