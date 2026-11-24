"""Integration tests for health endpoint and Alembic migration sanity."""

from pathlib import Path

from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect

from alembic import command


def test_health_ok(client: TestClient) -> None:
    """GET /health returns 200 and connected database status."""
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["database"] == "connected"
    assert payload["llm_provider"] == "mock"


def test_alembic_upgrade_and_downgrade(tmp_path: Path, monkeypatch) -> None:
    """Alembic migrations cleanly create and drop all core tables."""
    db_file = tmp_path / "migration_test.db"
    db_url = f"sqlite:///{db_file.as_posix()}"
    monkeypatch.setenv("DATABASE_URL", db_url)

    from app.config import get_settings

    get_settings.cache_clear()
    try:
        project_root = Path(__file__).resolve().parents[2]
        alembic_cfg = Config(str(project_root / "alembic.ini"))
        alembic_cfg.set_main_option("script_location", str(project_root / "alembic"))

        command.upgrade(alembic_cfg, "head")

        engine = create_engine(db_url)
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        assert {"log_entries", "incidents", "anomalies"}.issubset(tables)
        engine.dispose()

        command.downgrade(alembic_cfg, "base")

        engine = create_engine(db_url)
        inspector = inspect(engine)
        tables_after = set(inspector.get_table_names())
        assert "log_entries" not in tables_after
        assert "incidents" not in tables_after
        assert "anomalies" not in tables_after
        engine.dispose()
    finally:
        get_settings.cache_clear()
