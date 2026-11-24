"""SQLAlchemy 2.0 database engine, session factory, and health helpers."""

import logging
from collections.abc import Generator
from typing import Any

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Base declarative class for all ORM models."""


def create_db_engine(database_url: str) -> Engine:
    """Create a configured SQLAlchemy engine for MySQL or SQLite."""
    connect_args: dict[str, Any] = {}
    engine_kwargs: dict[str, Any] = {"pool_pre_ping": True}

    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        engine_kwargs["connect_args"] = connect_args
    else:
        engine_kwargs["pool_recycle"] = 3600

    return create_engine(database_url, **engine_kwargs)


_settings = get_settings()
engine: Engine = create_db_engine(_settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, class_=Session)


def get_db() -> Generator[Session, None, None]:
    """Yield a database session and ensure it is closed after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_connection(db: Session) -> bool:
    """Execute a lightweight query to verify database connectivity."""
    try:
        db.execute(text("SELECT 1"))
        return True
    except Exception:
        logger.exception("Database connectivity check failed")
        return False
