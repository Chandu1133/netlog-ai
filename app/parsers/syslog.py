"""Parser for BSD (RFC 3164) and ISO-timestamp (RFC 5424-style) syslog lines."""

import re
from datetime import UTC, datetime

from app.parsers.base import BaseParser
from app.schemas import LogLevel, NormalizedLogRecord

# Matches optional <PRI> followed by either ISO-8601 timestamp or BSD "Mon DD HH:MM:SS"
_ISO_SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?:\d+\s+)?"
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>[A-Za-z0-9._-]+)\s+"
    r"(?P<service>[A-Za-z0-9._/@-]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

_BSD_SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[A-Za-z0-9._-]+)\s+"
    r"(?P<service>[A-Za-z0-9._/@-]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

_IP_RE = re.compile(r"(?:from|rhost=|client=|src=|ip=)?\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b")
_STATUS_RE = re.compile(r"\bstatus(?:_code)?[=:]\s*(?P<status>[1-5]\d{2})\b", re.IGNORECASE)
_LATENCY_MS_RE = re.compile(
    r"\b(?:latency_ms|latency|duration_ms)[=:]\s*(?P<val>\d+(?:\.\d+)?)\s*(?:ms)?\b",
    re.IGNORECASE,
)

_PRIORITY_TO_LEVEL: dict[int, LogLevel] = {
    0: "CRITICAL",
    1: "CRITICAL",
    2: "CRITICAL",
    3: "ERROR",
    4: "WARNING",
    5: "INFO",
    6: "INFO",
    7: "DEBUG",
}


class SyslogParser(BaseParser):
    """Parse RFC 3164 and RFC 5424-style syslog lines into normalized log records."""

    format_name = "syslog"

    def __init__(self, default_year: int | None = None) -> None:
        self._default_year = default_year or datetime.now(UTC).year

    def can_parse(self, line: str) -> bool:
        """Return True if the line matches RFC 3164 or ISO syslog syntax."""
        stripped = line.strip()
        return bool(_ISO_SYSLOG_RE.match(stripped) or _BSD_SYSLOG_RE.match(stripped))

    def parse_line(self, line: str) -> NormalizedLogRecord | None:
        """Parse one syslog line into a NormalizedLogRecord, or return None on failure."""
        stripped = line.strip()
        if not stripped:
            return None

        match = _ISO_SYSLOG_RE.match(stripped)
        if match:
            timestamp = self._parse_iso_timestamp(match.group("ts"))
        else:
            match = _BSD_SYSLOG_RE.match(stripped)
            if not match:
                return None
            timestamp = self._parse_bsd_timestamp(match.group("ts"))

        if timestamp is None:
            return None

        pri_str = match.group("pri")
        host = match.group("host")
        service = match.group("service")
        message = match.group("message").strip()

        level = self._infer_level(pri_str, message)
        source_ip = self._extract_ip(message)
        status_code = self._extract_status_code(message)
        latency_ms = self._extract_latency_ms(message)

        return NormalizedLogRecord(
            timestamp=timestamp,
            host=host,
            source_ip=source_ip,
            service=service,
            level=level,
            status_code=status_code,
            latency_ms=latency_ms,
            message=message,
            log_format=self.format_name,
        )

    @staticmethod
    def _parse_iso_timestamp(raw_ts: str) -> datetime | None:
        normalized = raw_ts.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if dt.tzinfo is not None:
            dt = dt.astimezone(UTC).replace(tzinfo=None)
        return dt

    def _parse_bsd_timestamp(self, raw_ts: str) -> datetime | None:
        compact = " ".join(raw_ts.split())
        try:
            dt = datetime.strptime(f"{self._default_year} {compact}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        return dt

    @staticmethod
    def _infer_level(pri_str: str | None, message: str) -> LogLevel:
        if pri_str is not None:
            severity = int(pri_str) % 8
            return _PRIORITY_TO_LEVEL.get(severity, "INFO")

        lower = message.lower()
        if any(token in lower for token in ("critical", "fatal", "panic", "emerg", "alert")):
            return "CRITICAL"
        if any(
            token in lower
            for token in (
                "error",
                "failed password",
                "authentication failure",
                "invalid user",
                "exception",
                "connection refused",
                "timeout",
                "timed out",
                "out of memory",
                "oom-killer",
                "denied",
            )
        ):
            return "ERROR"
        if any(token in lower for token in ("warn", "warning", "retry", "degraded")):
            return "WARNING"
        if "debug" in lower:
            return "DEBUG"
        return "INFO"

    @staticmethod
    def _extract_ip(message: str) -> str | None:
        match = _IP_RE.search(message)
        if not match:
            return None
        ip_str = match.group("ip")
        octets = ip_str.split(".")
        if all(0 <= int(part) <= 255 for part in octets):
            return ip_str
        return None

    @staticmethod
    def _extract_status_code(message: str) -> int | None:
        match = _STATUS_RE.search(message)
        return int(match.group("status")) if match else None

    @staticmethod
    def _extract_latency_ms(message: str) -> float | None:
        match = _LATENCY_MS_RE.search(message)
        return float(match.group("val")) if match else None
