"""Unit tests for syslog, nginx, and auto-detecting log parsers."""

from datetime import datetime

import pytest

from app.parsers import NginxParser, SyslogParser, get_parser, parse_raw_lines


def test_syslog_parser_bsd_format() -> None:
    """SyslogParser normalizes RFC 3164 BSD syslog entries including source IP and level."""
    parser = SyslogParser(default_year=2026)
    line = (
        "Nov 24 14:22:01 auth-01 sshd[4821]: "
        "Failed password for invalid user admin from 203.0.113.45 port 54321 ssh2"
    )
    assert parser.can_parse(line)
    record = parser.parse_line(line)
    assert record is not None
    assert record.timestamp == datetime(2026, 11, 24, 14, 22, 1)
    assert record.host == "auth-01"
    assert record.service == "sshd"
    assert record.source_ip == "203.0.113.45"
    assert record.level == "ERROR"
    assert record.log_format == "syslog"
    assert "Failed password" in record.message


def test_syslog_parser_iso_with_priority_and_metrics() -> None:
    """SyslogParser parses ISO-8601 syslog with RFC priority, status_code, and latency_ms."""
    parser = SyslogParser()
    line = (
        "<131>2026-11-24T15:10:05Z api-02 gateway[901]: "
        "Upstream timeout client=198.51.100.22 status=504 latency_ms=2450.5"
    )
    record = parser.parse_line(line)
    assert record is not None
    assert record.timestamp == datetime(2026, 11, 24, 15, 10, 5)
    assert record.host == "api-02"
    assert record.service == "gateway"
    assert record.source_ip == "198.51.100.22"
    assert record.level == "ERROR"
    assert record.status_code == 504
    assert record.latency_ms == pytest.approx(2450.5)


def test_syslog_parser_rejects_malformed_lines() -> None:
    """Malformed syslog lines return None and never raise."""
    parser = SyslogParser()
    assert parser.parse_line("") is None
    assert parser.parse_line("not a valid syslog line at all") is None
    assert parser.parse_line("Foo 99 99:99:99 host svc: bad date") is None


def test_nginx_parser_standard_and_extended() -> None:
    """NginxParser extracts IP, timestamp, status, level, host, service, and latency."""
    parser = NginxParser()
    line = (
        '192.0.2.10 - - [24/Nov/2026:14:22:01 +0000] "POST /api/checkout HTTP/1.1" '
        '502 552 "-" "curl/8.4" rt=0.842 host=edge-01 service=checkout-api'
    )
    assert parser.can_parse(line)
    record = parser.parse_line(line)
    assert record is not None
    assert record.timestamp == datetime(2026, 11, 24, 14, 22, 1)
    assert record.source_ip == "192.0.2.10"
    assert record.host == "edge-01"
    assert record.service == "checkout-api"
    assert record.status_code == 502
    assert record.level == "ERROR"
    assert record.latency_ms == pytest.approx(842.0)
    assert "POST /api/checkout" in record.message


def test_nginx_parser_trailing_float_and_4xx_level() -> None:
    """NginxParser handles trailing request_time float and maps 4xx to WARNING."""
    parser = NginxParser()
    line = (
        '198.51.100.8 - - [24/Nov/2026:14:25:10 +0000] "GET /secret HTTP/1.1" '
        '404 128 "-" "Mozilla/5.0" 0.035'
    )
    record = parser.parse_line(line)
    assert record is not None
    assert record.status_code == 404
    assert record.level == "WARNING"
    assert record.latency_ms == pytest.approx(35.0)
    assert record.host == "nginx-edge"
    assert record.service == "nginx"


def test_auto_detect_mixed_and_bad_lines() -> None:
    """parse_raw_lines handles mixed syslog + nginx plus bad lines without crashing."""
    lines = [
        '192.0.2.1 - - [24/Nov/2026:14:00:00 +0000] "GET /health HTTP/1.1" 200 12 "-" "probe" 0.01',
        "2026-11-24T14:00:01Z web-01 sshd[123]: Accepted publickey for ops from 10.0.0.5 port 22",
        "COMPLETELY GARBAGE LINE %%%%",
        "",
        "ANOTHER BROKEN LINE",
    ]
    result = parse_raw_lines(lines, format_hint="auto")
    assert result.total_lines == 4
    assert len(result.records) == 2
    assert result.bad_line_count == 2
    assert result.format_detected == "mixed"
    assert len(result.bad_line_samples) == 2


def test_get_parser_invalid_raises() -> None:
    """get_parser raises ValueError for unsupported format names."""
    with pytest.raises(ValueError):
        get_parser("apache_xml")
    with pytest.raises(ValueError):
        parse_raw_lines(["abc"], format_hint="unknown_fmt")
