"""DB engine/session + init. SQLite default (demo), Postgres via DATABASE_URL (scale).

Postgres: DATABASE_URL=postgresql+psycopg://netsentry:netsentry@db:5432/netsentry
Needs: pip install -r requirements.txt (psycopg[binary] included).
SQLite file is dev-only; compose mounts nothing for pg (data in pgdata volume).
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base


def _database_url() -> str:
    return os.getenv("DATABASE_URL", "sqlite:///./netsentry.db")


def _make_engine():
    url = _database_url()
    if url.startswith("sqlite"):
        return create_engine(url, connect_args={"check_same_thread": False})
    # Postgres / others: pool + pre-ping for dropped connections, no check_same_thread
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=10)


DATABASE_URL = _database_url()
engine = _make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_session():
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()
