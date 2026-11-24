"""Integration tests for the single-page HTML/JS dashboard served at /."""

from fastapi.testclient import TestClient


def test_dashboard_root_and_static_assets(client: TestClient) -> None:
    """GET / serves the dashboard HTML and /static serves JS and CSS assets."""
    index = client.get("/")
    assert index.status_code == 200
    assert "text/html" in index.headers["content-type"]
    assert "NetLog AI" in index.text
    assert "telemetryChart" in index.text
    assert "/static/app.js" in index.text

    js = client.get("/static/app.js")
    assert js.status_code == 200
    assert "REFRESH_INTERVAL_MS = 30000" in js.text

    css = client.get("/static/styles.css")
    assert css.status_code == 200
    assert ".kpi-grid" in css.text
