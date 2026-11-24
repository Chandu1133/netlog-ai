"""Integration tests for incidents, anomalies, stats, analysis, filtering, pagination, and auth."""

from datetime import datetime, timedelta

from fastapi.testclient import TestClient


def _build_mixed_attack_and_outage_log() -> bytes:
    """Build a realistic multi-incident log payload triggering auth and 5xx anomalies."""
    lines: list[str] = []
    base = datetime(2026, 11, 24, 15, 0, 0)

    # 1. Brute-force SSH login burst on auth-01 (22 attempts -> high severity)
    for i in range(22):
        ts = (base + timedelta(seconds=i * 4)).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines.append(
            f"{ts} auth-01 sshd[3100]: Failed password for invalid user admin "
            f"from 203.0.113.77 port {50000 + i} ssh2"
        )

    # 2. Nginx 5xx outage on edge-01 (15 requests in one minute, 9 are 502 -> 60% 5xx)
    for i in range(15):
        ts = (base + timedelta(minutes=3, seconds=i * 3)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        status_code = 502 if i < 9 else 200
        rt = 0.85 if i < 9 else 0.04
        lines.append(
            f'192.0.2.50 - - [{ts}] "POST /api/payments HTTP/1.1" {status_code} 412 '
            f'"-" "curl/8.4" rt={rt} host=edge-01 service=payments-api'
        )

    return ("\n".join(lines) + "\n").encode("utf-8")


def test_end_to_end_ingest_detect_summarize_and_query(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    """Uploading logs with run_analysis=true creates redacted anomalies and AI incidents."""
    payload = _build_mixed_attack_and_outage_log()

    upload_resp = client.post(
        "/logs/upload",
        headers=auth_headers,
        params={"run_analysis": "true"},
        files={"file": ("mixed.log", payload, "text/plain")},
    )
    assert upload_resp.status_code == 201
    ingest_data = upload_resp.json()
    assert ingest_data["ingested_count"] == 37
    assert ingest_data["anomalies_detected"] >= 2
    assert ingest_data["incidents_created"] >= 2

    # GET /incidents with pagination and filtering
    inc_resp = client.get("/incidents", params={"limit": 1, "offset": 0})
    assert inc_resp.status_code == 200
    inc_page = inc_resp.json()
    assert inc_page["total"] >= 2
    assert len(inc_page["items"]) == 1

    # Filter by host
    host_resp = client.get("/incidents", params={"host": "auth-01", "severity": "high"})
    assert host_resp.status_code == 200
    host_items = host_resp.json()["items"]
    assert len(host_items) == 1
    auth_incident = host_items[0]
    assert auth_incident["llm_provider"] == "mock"
    assert auth_incident["used_fallback"] is False
    # Full IP must be redacted in stored evidence
    assert "203.0.113.77" not in str(auth_incident["evidence"])
    assert "203.0.xxx.xxx" in str(auth_incident["evidence"])

    # GET /incidents/{id}
    detail_resp = client.get(f"/incidents/{auth_incident['id']}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["id"] == auth_incident["id"]
    assert len(detail["anomalies"]) >= 1
    assert detail["anomalies"][0]["anomaly_type"] == "failed_login_spike"

    # 404 for unknown incident
    assert client.get("/incidents/999999").status_code == 404

    # GET /anomalies filtered by type
    anom_resp = client.get("/anomalies", params={"anomaly_type": "http_5xx_spike"})
    assert anom_resp.status_code == 200
    anom_body = anom_resp.json()
    assert anom_body["total"] == 1
    assert anom_body["items"][0]["host"] == "edge-01"

    # GET /stats
    stats_resp = client.get("/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_logs"] == 37
    assert stats["total_anomalies"] >= 2
    assert stats["total_incidents"] >= 2
    assert stats["incidents_by_severity"]["high"] >= 2
    assert len(stats["timeseries"]) >= 2
    assert any(pt["anomaly_count"] > 0 for pt in stats["timeseries"])


def test_write_endpoints_require_api_key_and_status_update_works(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    """POST /analyze and PATCH /incidents/{id}/status require X-API-Key."""
    assert client.post("/analyze").status_code == 401

    # Upload without immediate analysis, then trigger /analyze explicitly
    payload = _build_mixed_attack_and_outage_log()
    client.post(
        "/logs/upload",
        headers=auth_headers,
        params={"run_analysis": "false"},
        files={"file": ("deferred.log", payload, "text/plain")},
    )

    analyze_resp = client.post("/analyze", headers=auth_headers)
    assert analyze_resp.status_code == 200
    analyze_body = analyze_resp.json()
    assert analyze_body["logs_analyzed"] == 37
    assert analyze_body["incidents_created"] >= 2

    # Running /analyze again should deduplicate and create 0 duplicate incidents
    rerun_resp = client.post("/analyze", headers=auth_headers)
    assert rerun_resp.status_code == 200
    assert rerun_resp.json()["incidents_created"] == 0

    inc_id = client.get("/incidents").json()["items"][0]["id"]
    assert (
        client.patch(f"/incidents/{inc_id}/status", json={"status": "resolved"}).status_code == 401
    )

    patch_resp = client.patch(
        f"/incidents/{inc_id}/status",
        headers=auth_headers,
        json={"status": "acknowledged"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "acknowledged"


def test_openapi_docs_available(client: TestClient) -> None:
    """OpenAPI JSON schema and Swagger UI /docs are served properly."""
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200
