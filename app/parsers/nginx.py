"""Parser for Nginx combined and extended access log lines."""

import re
from datetime import UTC, datetime

from app.parsers.base import BaseParser
from app.schemas import LogLevel, NormalizedLogRecord

_NGINX_RE = re.compile(
    r"^(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<bytes>\d+|-)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
    r"(?P<extra>.*)$"
)

_KV_RT_RE = re.compile(r"\b(?:rt|request_time)=(?P<sec>\d+(?:\.\d+)?)\b")
_KV_LATENCY_MS_RE = re.compile(r"\blatency_ms=(?P<ms>\d+(?:\.\d+)?)\b")
_KV_HOST_RE = re.compile(r"\b(?:host|server)=(?P<host>[A-Za-z0-9._-]+)\b")
_KV_SERVICE_RE = re.compile(r"\b(?:service|upstream)=(?P<service>[A-Za-z0-9._-]+)\b")
_TRAILING_FLOAT_RE = re.compile(r"^\s*(?P<sec>\d+(?:\.\d+)?)\s*$")


class NginxParser(BaseParser):
    """Parse Nginx combined and extended access log lines."""

    format_name = "nginx"

    def __init__(self, default_host: str = "nginx-edge", default_service: str = "nginx") -> None:
        self._default_host = default_host
        self._default_service = default_service

    def can_parse(self, line: str) -> bool:
        """Return True if the line matches Nginx access log syntax."""
        return bool(_NGINX_RE.match(line.strip()))

    def parse_line(self, line: str) -> NormalizedLogRecord | None:
        """Parse one Nginx access log line into a NormalizedLogRecord, or None if invalid."""
        stripped = line.strip()
        if not stripped:
            return None

        match = _NGINX_RE.match(stripped)
        if not match:
            return None

        timestamp = self._parse_nginx_timestamp(match.group("ts"))
        if timestamp is None:
            return None

        source_ip = match.group("ip")
        status_code = int(match.group("status"))
        if status_code < 100 or status_code > 599:
            return None

        request_str = match.group("request") or "-"
        bytes_sent = match.group("bytes")
        extra = (match.group("extra") or "").strip()

        host = self._extract_host(extra) or self._default_host
        service = self._extract_service(extra) or self._default_service
        latency_ms = self._extract_latency_ms(extra)
        level = self._status_to_level(status_code)

        message = f"{request_str} -> HTTP {status_code} ({bytes_sent}B)"
        if latency_ms is not None:
            message = f"{message} [{latency_ms:.1f}ms]"

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
    def _parse_nginx_timestamp(raw_ts: str) -> datetime | None:
        try:
            dt = datetime.strptime(raw_ts, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                return datetime.strptime(raw_ts, "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                return None
        return dt.astimezone(UTC).replace(tzinfo=None)

    @staticmethod
    def _status_to_level(status_code: int) -> LogLevel:
        if status_code >= 500:
            return "ERROR"
        if status_code >= 400:
            return "WARNING"
        return "INFO"

    @staticmethod
    def _extract_host(extra: str) -> str | None:
        match = _KV_HOST_RE.search(extra)
        return match.group("host") if match else None

    @staticmethod
    def _extract_service(extra: str) -> str | None:
        match = _KV_SERVICE_RE.search(extra)
        return match.group("service") if match else None

    @staticmethod
    def _extract_latency_ms(extra: str) -> float | None:
        if not extra:
            return None
        ms_match = _KV_LATENCY_MS_RE.search(extra)
        if ms_match:
            return round(float(ms_match.group("ms")), 3)
        rt_match = _KV_RT_RE.search(extra)
        if rt_match:
            return round(float(rt_match.group("sec")) * 1000.0, 3)
        trailing = _TRAILING_FLOAT_RE.match(extra)
        if trailing:
            return round(float(trailing.group("sec")) * 1000.0, 3)
        return None
