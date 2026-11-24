"""Application configuration loaded strictly from environment variables."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for NetLog AI."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = Field(default="NetLog AI")
    app_env: str = Field(default="development")
    log_level: str = Field(default="INFO")

    database_url: str = Field(default="sqlite:///./netlog_ai.db")

    api_key: str = Field(default="")
    max_upload_size_bytes: int = Field(default=10 * 1024 * 1024, ge=1024)
    upload_rate_limit_requests: int = Field(default=30, ge=1)
    upload_rate_limit_window_seconds: int = Field(default=60, ge=1)

    llm_provider: str = Field(default="mock")
    llm_api_key: str = Field(default="")
    llm_base_url: str = Field(default="https://api.openai.com/v1")
    llm_model: str = Field(default="gpt-4o-mini")
    llm_timeout_seconds: float = Field(default=20.0, gt=0)

    rule_failed_login_threshold: int = Field(default=8, ge=2)
    rule_failed_login_window_minutes: int = Field(default=5, ge=1)
    rule_http_5xx_rate_threshold: float = Field(default=0.15, gt=0.0, le=1.0)
    rule_http_5xx_min_requests: int = Field(default=10, ge=1)
    rule_repeated_error_threshold: int = Field(default=10, ge=2)
    rule_repeated_error_window_minutes: int = Field(default=5, ge=1)

    ml_contamination: float = Field(default=0.05, gt=0.0, lt=0.5)
    ml_min_baseline_minutes: int = Field(default=10, ge=3)
    ml_baseline_fraction: float = Field(default=0.5, gt=0.1, lt=0.95)
    ml_random_state: int = Field(default=42)


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings loaded from environment variables."""
    return Settings()
