"""SQLite storage layer for the signature registry."""

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(os.environ.get("REGISTRY_DB_PATH", Path(__file__).parent / "signatures.db"))


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    """Create the signatures table if it doesn't exist."""
    conn = _connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT NOT NULL,
            signed_at TEXT NOT NULL,
            public_key TEXT,
            signature TEXT NOT NULL,
            registered_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hash ON signatures (hash)")
    conn.commit()
    conn.close()


def insert_signature(
    signed_at: str,
    public_key: str | None,
    hash_val: str,
    signature: str,
) -> dict[str, Any]:
    """Insert a signature record and return it with the server-side timestamp."""
    conn = _connect()
    registered_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO signatures (hash, signed_at, public_key, signature, registered_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (hash_val, signed_at, public_key, signature, registered_at),
    )
    conn.commit()
    conn.close()
    return {
        "signed_at": signed_at,
        "public_key": public_key,
        "hash": hash_val,
        "signature": signature,
        "registered_at": registered_at,
    }


def get_by_hash(hash_val: str) -> list[dict[str, Any]]:
    """Return all signature records matching the given hash."""
    conn = _connect()
    rows = conn.execute(
        "SELECT hash, signed_at, public_key, signature, registered_at "
        "FROM signatures WHERE hash = ? ORDER BY registered_at DESC",
        (hash_val,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent(limit: int = 20, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
    """Return recent signatures with pagination."""
    conn = _connect()
    total = conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
    rows = conn.execute(
        "SELECT hash, signed_at, public_key, signature, registered_at "
        "FROM signatures ORDER BY registered_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows], total
