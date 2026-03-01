"""
SQLAlchemy database engine, session factory, and base class.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from config import settings

# Render (and other cloud providers) issue postgres:// URLs; SQLAlchemy needs postgresql://
_db_url = settings.database_url
if _db_url.startswith("postgres://"):
    _db_url = _db_url.replace("postgres://", "postgresql://", 1)

# Strip channel_binding param — not supported by psycopg2
if "channel_binding" in _db_url:
    from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
    _parsed = urlparse(_db_url)
    _qs = {k: v for k, v in parse_qs(_parsed.query).items() if k != "channel_binding"}
    _db_url = urlunparse(_parsed._replace(query=urlencode(_qs, doseq=True)))

# check_same_thread is SQLite-only
_connect_args = {"check_same_thread": False} if _db_url.startswith("sqlite") else {}

engine = create_engine(
    _db_url,
    connect_args=_connect_args,
    echo=settings.debug,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency: yield a DB session, close it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables (called at startup)."""
    from database import models  # noqa: F401 — registers models with Base
    Base.metadata.create_all(bind=engine)
