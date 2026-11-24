"""Parser registry and auto-detection helpers."""

from collections.abc import Iterable

from app.parsers.base import BaseParser, ParseResult
from app.parsers.nginx import NginxParser
from app.parsers.syslog import SyslogParser


def get_parser(format_name: str) -> BaseParser:
    """Return a parser instance by explicit format name."""
    normalized = format_name.strip().lower()
    if normalized == "syslog":
        return SyslogParser()
    if normalized == "nginx":
        return NginxParser()
    raise ValueError(f"Unsupported log format: {format_name}")


def parse_raw_lines(
    lines: Iterable[str],
    format_hint: str = "auto",
    max_bad_samples: int = 10,
) -> ParseResult:
    """Parse raw log lines using an explicit format or per-line auto-detection."""
    hint = format_hint.strip().lower()
    if hint in {"syslog", "nginx"}:
        return get_parser(hint).parse_lines(lines, max_bad_samples=max_bad_samples)
    if hint != "auto":
        raise ValueError(f"Unsupported format hint: {format_hint}")

    parsers: list[BaseParser] = [NginxParser(), SyslogParser()]
    result = ParseResult(format_detected="auto")
    formats_seen: set[str] = set()

    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped:
            continue
        result.total_lines += 1
        parsed = None
        for parser in parsers:
            if parser.can_parse(stripped):
                parsed = parser.parse_line(stripped)
                if parsed is not None:
                    formats_seen.add(parser.format_name)
                    break
        if parsed is None:
            result.bad_line_count += 1
            if len(result.bad_line_samples) < max_bad_samples:
                result.bad_line_samples.append(stripped[:200])
        else:
            result.records.append(parsed)

    if len(formats_seen) == 1:
        result.format_detected = next(iter(formats_seen))
    elif len(formats_seen) > 1:
        result.format_detected = "mixed"
    else:
        result.format_detected = "unknown"

    return result


__all__ = [
    "BaseParser",
    "NginxParser",
    "ParseResult",
    "SyslogParser",
    "get_parser",
    "parse_raw_lines",
]
