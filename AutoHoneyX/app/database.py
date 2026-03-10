"""Database connection and session management

This module attempts to connect to the configured database (Postgres in
production). If a connection cannot be established (for example, the
Postgres host is not reachable inside a Docker container), it will
automatically fall back to a local SQLite database so the application can
still start in development/test environments.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import OperationalError
from contextlib import contextmanager
import logging

from app.config import config, BASE_DIR

logger = logging.getLogger(__name__)


# Helper to create an engine for a URL with sensible args for SQLite vs others
def _make_engine(db_url: str):
    if db_url.startswith("sqlite"):
        return create_engine(db_url, connect_args={"check_same_thread": False}, echo=False)
    return create_engine(db_url, pool_pre_ping=True, pool_size=10, max_overflow=20, echo=False)


# Try to create engine for configured DATABASE_URL and validate connection.
# If the database is unreachable (OperationalError), fall back to SQLite.
try:
    engine = _make_engine(config.DATABASE_URL)
    # test connection immediately so failures are detected early
    try:
        with engine.connect() as conn:
            pass
    except OperationalError:
        raise
except OperationalError:
    logger.warning("Could not connect to configured database. Falling back to SQLite.")
    fallback_path = BASE_DIR / "autohoneyx_fallback.db"
    fallback_url = f"sqlite:///{fallback_path}"
    engine = _make_engine(fallback_url)
    # update runtime config so other modules can see the effective DB URL
    try:
        config.DATABASE_URL = fallback_url
    except Exception:
        # config may be an object; attempt best-effort assignment
        pass


# Create session factory with expire_on_commit=False to prevent detached instance errors
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, expire_on_commit=False)

# Base class for models
Base = declarative_base()


def get_db() -> Session:
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_session():
    """Context manager for database session"""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db():
    """Initialize database tables"""
    global engine, SessionLocal
    try:
        Base.metadata.create_all(bind=engine)
    except OperationalError:
        logger.exception("Database operation failed during init_db; attempting fallback to SQLite.")
        fallback_path = BASE_DIR / "autohoneyx_fallback.db"
        fallback_url = f"sqlite:///{fallback_path}"
        new_engine = _make_engine(fallback_url)
        engine = new_engine
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, expire_on_commit=False)
        Base.metadata.create_all(bind=engine)

