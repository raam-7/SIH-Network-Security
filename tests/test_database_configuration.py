from pathlib import Path

from backend.app.db.session import _load_database_url


def test_database_url_loads_from_local_env_file(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("DATABASE_URL=sqlite:///local-test.db\n", encoding="utf-8")

    assert _load_database_url(env_file) == "sqlite:///local-test.db"


def test_process_database_url_takes_precedence_over_env_file(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///process.db")
    env_file = tmp_path / ".env"
    env_file.write_text("DATABASE_URL=sqlite:///file.db\n", encoding="utf-8")

    assert _load_database_url(env_file) == "sqlite:///process.db"
