"""SQLite storage layer for the signature registry."""

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(os.environ.get("REGISTRY_DB_PATH", Path(__file__).parent / "signatures.db"))

# Columns added after the initial release; migrated in on existing databases.
_EXTRA_COLUMNS = {
    "name": "TEXT",
    "email": "TEXT",
    "components_verified": "INTEGER",
    "summary_json": "TEXT",
}

_SELECT_COLS = (
    "hash, signed_at, public_key, signature, registered_at, "
    "name, email, components_verified, summary_json"
)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    """Create the signatures table if needed and migrate in newer columns."""
    conn = _connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT NOT NULL,
            signed_at TEXT NOT NULL,
            public_key TEXT,
            signature TEXT NOT NULL,
            registered_at TEXT NOT NULL,
            name TEXT,
            email TEXT,
            components_verified INTEGER,
            summary_json TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hash ON signatures (hash)")

    # Migrate older databases that predate the metadata columns.
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(signatures)")}
    for col, col_type in _EXTRA_COLUMNS.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE signatures ADD COLUMN {col} {col_type}")

    conn.commit()
    conn.close()


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Convert a DB row into the dict shape the API serves."""
    summary = None
    if row["summary_json"]:
        try:
            summary = json.loads(row["summary_json"])
        except (json.JSONDecodeError, TypeError):
            summary = None
    verified = row["components_verified"]
    return {
        "hash": row["hash"],
        "signed_at": row["signed_at"],
        "public_key": row["public_key"],
        "signature": row["signature"],
        "registered_at": row["registered_at"],
        "name": row["name"],
        "email": row["email"],
        "components_verified": None if verified is None else bool(verified),
        "summary": summary,
    }


def insert_signature(
    signed_at: str,
    public_key: str | None,
    hash_val: str,
    signature: str,
    name: str | None = None,
    email: str | None = None,
    components_verified: bool | None = None,
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Insert a signature record and return it with the server-side timestamp."""
    conn = _connect()
    registered_at = datetime.now(timezone.utc).isoformat()
    summary_json = json.dumps(summary) if summary is not None else None
    verified_int = None if components_verified is None else int(components_verified)
    conn.execute(
        "INSERT INTO signatures "
        "(hash, signed_at, public_key, signature, registered_at, "
        "name, email, components_verified, summary_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            hash_val,
            signed_at,
            public_key,
            signature,
            registered_at,
            name,
            email,
            verified_int,
            summary_json,
        ),
    )
    conn.commit()
    conn.close()
    return {
        "signed_at": signed_at,
        "public_key": public_key,
        "hash": hash_val,
        "signature": signature,
        "registered_at": registered_at,
        "name": name,
        "email": email,
        "components_verified": components_verified,
        "summary": summary,
    }


def get_by_hash(hash_val: str) -> list[dict[str, Any]]:
    """Return all signature records matching the given hash."""
    conn = _connect()
    rows = conn.execute(
        f"SELECT {_SELECT_COLS} "
        "FROM signatures WHERE hash = ? ORDER BY registered_at DESC",
        (hash_val,),
    ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def get_recent(limit: int = 20, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
    """Return recent signatures with pagination."""
    conn = _connect()
    total = conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
    rows = conn.execute(
        f"SELECT {_SELECT_COLS} "
        "FROM signatures ORDER BY registered_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows], total
