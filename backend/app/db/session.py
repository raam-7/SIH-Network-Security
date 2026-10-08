import os
from collections.abc import Generator
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _load_database_url(env_file: Path = PROJECT_ROOT / ".env") -> str:
    load_dotenv(env_file)
    return os.getenv("DATABASE_URL", "postgresql+psycopg://postgres:postgres@localhost:5432/sih_security")


DATABASE_URL = _load_database_url()
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_session() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
