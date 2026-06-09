from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker
import os

DB_PATH = os.environ.get("VAULTSCAN_DB", os.path.join(os.path.dirname(__file__), "..", "vaultscan.db"))
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def run_lightweight_migrations() -> None:
    """Add columns that newer code expects, preserving existing rows.

    SQLAlchemy's create_all never ALTERs existing tables, so new columns on
    already-created tables must be added explicitly. Idempotent and safe.
    """
    expected = {
        "scans": [
            ("mode", "VARCHAR DEFAULT 'safe'"),
            ("risk_score", "INTEGER DEFAULT 0"),
            ("risk_grade", "VARCHAR DEFAULT ''"),
            ("tags", "VARCHAR DEFAULT ''"),
            ("notes", "TEXT DEFAULT ''"),
        ],
        "findings": [
            ("cvss", "FLOAT DEFAULT 0.0"),
            ("owasp", "VARCHAR DEFAULT ''"),
            ("cwe", "VARCHAR DEFAULT ''"),
            ("confidence", "VARCHAR DEFAULT ''"),
        ],
    }
    insp = inspect(engine)
    existing_tables = insp.get_table_names()
    with engine.begin() as conn:
        for table, columns in expected.items():
            if table not in existing_tables:
                continue
            present = {c["name"] for c in insp.get_columns(table)}
            for name, ddl in columns:
                if name not in present:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
