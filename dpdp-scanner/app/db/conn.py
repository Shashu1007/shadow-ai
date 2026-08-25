"""SQLite connection + schema bootstrap + migrations."""
import logging
import sqlite3
from pathlib import Path
from contextlib import contextmanager

from app.db.migrations import run_migrations

APP_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = APP_DIR / "data" / "scanner.db"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

logger = logging.getLogger("db.conn")

# SQLite's default "database is locked" behavior is to fail immediately.
# Under gunicorn with >1 worker (Dockerfile runs --workers 2) plus a
# concurrent cron scan writing to the same file, that turns an ordinary
# momentary write overlap into a 500 the user actually sees. busy_timeout
# makes SQLite itself retry internally for up to this many ms before giving
# up; WAL mode (below) additionally lets readers and a writer proceed
# concurrently instead of blocking each other outright.
BUSY_TIMEOUT_MS = 5000


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=BUSY_TIMEOUT_MS / 1000)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    return conn


def init_db() -> None:
    """Create tables if they don't exist, then bring an existing DB's schema
    up to date via run_migrations(). Safe to call on every startup — this is
    the ONE place both `run_scan.py` and `app.web` bootstrap the DB from, so
    a schema change only has to be written once (see app/db/migrations.py)."""
    conn = get_connection()
    try:
        with open(SCHEMA_PATH, "r") as f:
            conn.executescript(f.read())
        conn.commit()
        run_migrations(conn)
    finally:
        conn.close()


def health_check() -> tuple[bool, str]:
    """Used by /healthz and the ops self-check. Returns (ok, detail)."""
    try:
        conn = get_connection()
        try:
            conn.execute("SELECT 1").fetchone()
            return True, "ok"
        finally:
            conn.close()
    except Exception as e:
        return False, str(e)


@contextmanager
def db_cursor():
    """Context manager yielding a cursor, committing on success, closing
    always, rolling back on any exception so a failed write never leaves a
    half-applied transaction sitting on the connection.

    Note on lock contention: a @contextmanager generator can only yield once
    per `with` use, so retrying the caller's own statements from inside this
    function isn't structurally possible (and isn't needed) — `busy_timeout`
    set in get_connection() already makes SQLite itself wait and retry
    internally (up to BUSY_TIMEOUT_MS) before raising "database is locked",
    which is what actually absorbs the concurrent-writer case (gunicorn's 2
    workers, or a dashboard click landing mid-cron-scan)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
