"""Shared pytest fixtures for NetLog AI unit and integration tests."""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import upload_rate_limiter
from app.config import Settings, get_settings
from app.database import Base, get_db
from app.main import create_app

TEST_API_KEY = "test-secret-api-key"


@pytest.fixture
def test_settings() -> Settings:
    """Return isolated Settings configured for tests with MockLLM."""
    return Settings(
        app_env="test",
        database_url="sqlite:///:memory:",
        api_key=TEST_API_KEY,
        llm_provider="mock",
        max_upload_size_bytes=1024 * 1024,
        upload_rate_limit_requests=100,
        upload_rate_limit_window_seconds=60,
    )


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    """Provide an isolated in-memory SQLite database session per test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture
def client(db_session: Session, test_settings: Settings) -> Generator[TestClient, None, None]:
    """Return a FastAPI TestClient wired to the test database and settings."""
    app = create_app()

    def override_get_db() -> Generator[Session, None, None]:
        yield db_session

    def override_get_settings() -> Settings:
        return test_settings

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = override_get_settings

    upload_rate_limiter.reset()
    with TestClient(app) as test_client:
        yield test_client
    upload_rate_limiter.reset()


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Valid write-endpoint authentication headers for tests."""
    return {"X-API-Key": TEST_API_KEY}
