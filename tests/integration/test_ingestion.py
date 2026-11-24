"""Integration tests for log ingestion endpoints, auth, upload limits, and rate limiting."""

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import LogEntry


def test_upload_logs_requires_api_key(client: TestClient) -> None:
    """POST /logs/upload rejects requests without valid X-API-Key."""
    response = client.post(
        "/logs/upload",
        files={"file": ("app.log", b"2026-11-24T12:00:00Z h1 svc: hello\n", "text/plain")},
    )
    assert response.status_code == 401

    bad_key = client.post(
        "/logs/upload",
        headers={"X-API-Key": "wrong-key"},
        files={"file": ("app.log", b"2026-11-24T12:00:00Z h1 svc: hello\n", "text/plain")},
    )
    assert bad_key.status_code == 401


def test_upload_log_file_counts_bad_lines(
    client: TestClient,
    auth_headers: dict[str, str],
    db_session: Session,
) -> None:
    """POST /logs/upload parses valid syslog/nginx lines and reports bad lines without failing."""
    nginx_line = (
        '192.0.2.15 - - [24/Nov/2026:12:00:01 +0000] "GET /api/v1/items HTTP/1.1" '
        '200 512 "-" "curl" rt=0.045 host=edge-01'
    )
    syslog_line = (
        "2026-11-24T12:00:02Z auth-01 sshd[101]: "
        "Failed password for root from 203.0.113.9 port 2222 ssh2"
    )
    payload = "\n".join([nginx_line, syslog_line, "MALFORMED GARBAGE LINE"]).encode("utf-8")

    response = client.post(
        "/logs/upload",
        headers=auth_headers,
        params={"run_analysis": "false"},
        files={"file": ("server.log", payload, "text/plain")},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["ingested_count"] == 2
    assert body["bad_line_count"] == 1
    assert body["total_lines"] == 3
    assert body["format_detected"] == "mixed"
    assert len(body["bad_line_samples"]) == 1

    count = db_session.scalar(select(func.count(LogEntry.id)))
    assert count == 2


def test_upload_rejects_bad_extension_and_oversized_file(
    client: TestClient,
    auth_headers: dict[str, str],
    test_settings: Settings,
) -> None:
    """POST /logs/upload validates file extension and enforces MAX_UPLOAD_SIZE_BYTES."""
    bad_ext = client.post(
        "/logs/upload",
        headers=auth_headers,
        files={"file": ("archive.zip", b"dummy", "application/zip")},
    )
    assert bad_ext.status_code == 400

    oversized = b"x" * (test_settings.max_upload_size_bytes + 5)
    too_big = client.post(
        "/logs/upload",
        headers=auth_headers,
        files={"file": ("huge.log", oversized, "text/plain")},
    )
    assert too_big.status_code == 413


def test_json_batch_ingestion(
    client: TestClient,
    auth_headers: dict[str, str],
    db_session: Session,
) -> None:
    """POST /logs ingests a validated JSON batch of normalized log records."""
    batch = {
        "run_analysis": False,
        "logs": [
            {
                "timestamp": "2026-11-24T12:10:00Z",
                "host": "web-01",
                "source_ip": "198.51.100.14",
                "service": "nginx",
                "level": "ERROR",
                "status_code": 503,
                "latency_ms": 620.5,
                "message": "GET /api/pay -> HTTP 503",
            }
        ],
    }
    response = client.post("/logs", headers=auth_headers, json=batch)
    assert response.status_code == 201
    body = response.json()
    assert body["ingested_count"] == 1
    assert body["format_detected"] == "json"

    stored = db_session.scalars(select(LogEntry)).all()
    assert len(stored) == 1
    assert stored[0].status_code == 503
    assert stored[0].host == "web-01"


def test_upload_rate_limit(
    client: TestClient,
    auth_headers: dict[str, str],
    test_settings: Settings,
) -> None:
    """POST /logs/upload returns 429 when rate limit is exceeded."""
    test_settings.upload_rate_limit_requests = 2
    sample = b"2026-11-24T12:00:00Z host1 svc[1]: ok\n"

    r1 = client.post(
        "/logs/upload",
        headers=auth_headers,
        params={"run_analysis": "false"},
        files={"file": ("a.log", sample, "text/plain")},
    )
    r2 = client.post(
        "/logs/upload",
        headers=auth_headers,
        params={"run_analysis": "false"},
        files={"file": ("b.log", sample, "text/plain")},
    )
    r3 = client.post(
        "/logs/upload",
        headers=auth_headers,
        params={"run_analysis": "false"},
        files={"file": ("c.log", sample, "text/plain")},
    )
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers
