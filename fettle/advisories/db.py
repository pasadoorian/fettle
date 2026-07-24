"""SQLite cache for advisory data — ``~/.cache/fettle/advisories.db``.

A rebuildable CACHE (PLAN.md §19.8): if it's wiped or the schema version changes,
the next refresh repopulates it; nothing authoritative lives only here. ``sqlite3``
is Python stdlib, so this keeps fettle's zero-runtime-dependency core intact.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

SCHEMA_VERSION = 2


def db_path(ctx) -> Path:
    home = getattr(ctx, "user_home", None) or Path.home()
    return Path(home) / ".cache/fettle/advisories.db"


def connect(path) -> sqlite3.Connection:
    """Open (creating dirs), enable WAL, and ensure the schema. On a schema-version
    mismatch the tables are dropped and rebuilt (it's a cache — safe to discard)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL")
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    ver = conn.execute("PRAGMA user_version").fetchone()[0]
    if ver == SCHEMA_VERSION:
        return
    conn.executescript(
        "DROP TABLE IF EXISTS advisories; DROP TABLE IF EXISTS meta;"
        "CREATE TABLE advisories(source TEXT, group_id TEXT, package TEXT,"
        " status TEXT, severity TEXT, affected TEXT, fixed TEXT, cves TEXT,"
        " advisory_id TEXT, url TEXT, dclass TEXT);"
        "CREATE INDEX idx_adv_src_pkg ON advisories(source, package);"
        "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);")
    conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    conn.commit()


# columns returned by all_rows (everything but the source filter), in order.
_COLS = ("group_id", "package", "status", "severity", "affected", "fixed",
         "cves", "advisory_id", "url", "dclass")


def replace_source(conn: sqlite3.Connection, source: str, rows, *, now=None) -> None:
    """Replace all rows for ``source`` in one transaction; stamp its update time.
    Each row is ``(source, group_id, package, status, severity, affected, fixed,
    cves, advisory_id, url, dclass)`` — ``dclass`` is the distro class tag used for
    filtering (Arch status / Debian urgency|nodsa)."""
    with conn:
        conn.execute("DELETE FROM advisories WHERE source=?", (source,))
        conn.executemany(
            "INSERT INTO advisories(source,group_id,package,status,severity,affected,"
            "fixed,cves,advisory_id,url,dclass) VALUES(?,?,?,?,?,?,?,?,?,?,?)", rows)
        conn.execute("INSERT OR REPLACE INTO meta VALUES(?,?)",
                     (f"updated_{source}", str(int(now if now is not None else time.time()))))


def last_updated(conn: sqlite3.Connection, source: str) -> int | None:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (f"updated_{source}",)).fetchone()
    return int(row[0]) if row and row[0] else None


def all_rows(conn: sqlite3.Connection, source: str) -> list[tuple]:
    """Every advisory row for ``source`` (the table is small — a few thousand rows —
    so we filter against installed packages in Python, dodging SQLite's parameter
    limit on huge ``IN`` lists)."""
    return conn.execute(
        f"SELECT {','.join(_COLS)} FROM advisories WHERE source=?", (source,)).fetchall()
