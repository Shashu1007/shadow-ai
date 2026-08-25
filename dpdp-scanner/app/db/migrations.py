"""
Lightweight versioned schema migrations.

Why this exists: `schema.sql` only ever runs `CREATE TABLE IF NOT EXISTS`, so
it can add brand-new tables safely but can NEVER add a column to a table that
already exists on a live/deployed DB (including the pre-populated demo
`data/scanner.db` shipped in this repo, and any pilot client's production
volume). Without a migration mechanism, every future schema change would
require either a manual `ALTER TABLE` on each deployment (easy to forget, no
record of what's been applied) or wiping the DB (loses the audit trail —
unacceptable, the audit trail is itself a sellable feature per the spec).

Each migration is a small Python function, not a raw .sql file, so it can use
PRAGMA table_info() to check "do I need to do anything?" before acting —
that makes every migration safe to run again even if `schema_migrations`
somehow lost track of what applied (belt-and-suspenders, not just an
optimization). Migrations run in id order, once each, tracked in the
`schema_migrations` table created below. New migrations: add a new
(id, description, fn) tuple to MIGRATIONS — never edit or remove an existing
entry, that's what makes this safe across every already-deployed DB.
"""
from __future__ import annotations

import logging
import sqlite3

logger = logging.getLogger("db.migrations")


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == column for r in rows)


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


# --- individual migrations ---

def _m0001_scan_error_tracking(conn: sqlite3.Connection) -> None:
    """scans.error_message — lets a failed scan record WHY it failed instead of
    either crashing the whole process or silently looking like a normal scan."""
    if not _column_exists(conn, "scans", "error_message"):
        conn.execute("ALTER TABLE scans ADD COLUMN error_message TEXT")


def _m0002_alert_delivery_tracking(conn: sqlite3.Connection) -> None:
    """alerts.delivery_status / delivery_error — separate from `status`
    (open/handled, which is about whether a HUMAN has acted on the alert).
    delivery_status is about whether the message actually reached the
    provider (sim | sent | failed), which matters once real Twilio/WhatsApp
    sending is wired in and can itself fail (bad number, provider outage)."""
    if not _column_exists(conn, "alerts", "delivery_status"):
        conn.execute("ALTER TABLE alerts ADD COLUMN delivery_status TEXT NOT NULL DEFAULT 'unknown'")
    if not _column_exists(conn, "alerts", "delivery_error"):
        conn.execute("ALTER TABLE alerts ADD COLUMN delivery_error TEXT")


def _m0003_client_active_flag(conn: sqlite3.Connection) -> None:
    """clients.active — lets a churned/paused client be excluded from
    `run_scan.py --all` without deleting their history (audit trail must
    survive a client leaving)."""
    if not _column_exists(conn, "clients", "active"):
        conn.execute("ALTER TABLE clients ADD COLUMN active INTEGER NOT NULL DEFAULT 1")


def _m0004_scan_indexes(conn: sqlite3.Connection) -> None:
    """Composite index for the 'find latest scan per client' and 'find last N
    days of scans' queries that both the orchestrator and the ops self-check
    (see app/ops.py) run frequently."""
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_client_scanned ON scans(client_id, scanned_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)")


def _m0005_client_alert_threshold(conn: sqlite3.Connection) -> None:
    """clients.min_alert_severity — per-client override so a noisy/low-value
    finding type doesn't have to be a global config change; defaults to
    'medium' which matches today's hardcoded ALERTABLE_SEVERITIES behavior."""
    if not _column_exists(conn, "clients", "min_alert_severity"):
        conn.execute("ALTER TABLE clients ADD COLUMN min_alert_severity TEXT NOT NULL DEFAULT 'medium'")


def _m0006_operators_table(conn: sqlite3.Connection) -> None:
    """Real multi-operator accounts, replacing the single shared
    DASHBOARD_USERNAME/PASSWORD credential. The env vars now only seed the
    FIRST operator on a brand-new DB (see app/auth.py:seed_operator_from_env)
    — after that, operators are managed via the DB (dashboard /operators
    page or scripts/manage_operators.py), same pattern as clients."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS operators (
               id            INTEGER PRIMARY KEY AUTOINCREMENT,
               username      TEXT NOT NULL UNIQUE,
               password_hash TEXT NOT NULL,
               active        INTEGER NOT NULL DEFAULT 1,
               created_at    TEXT NOT NULL DEFAULT (datetime('now'))
           )"""
    )


def _m0007_client_portal_access(conn: sqlite3.Connection) -> None:
    """clients.portal_password_hash — enables the client-facing portal
    (separate from the operator dashboard) for a given client. NULL means
    "no portal access set up yet," not "locked out" — a client created by
    an operator (not via public signup) simply has no portal login until
    one is set. Login identifier is the client's own (already-unique)
    domain — see app/portal.py for why that's an acceptable MVP tradeoff."""
    if not _column_exists(conn, "clients", "portal_password_hash"):
        conn.execute("ALTER TABLE clients ADD COLUMN portal_password_hash TEXT")


def _m0008_draft_decision_audit(conn: sqlite3.Connection) -> None:
    """drafts.decided_at/decided_by — records who approved/rejected a
    drafted notice paragraph or inventory row and when, once the client
    portal makes that a real action instead of dead code. NULL means still
    pending (status stays 'draft')."""
    if not _column_exists(conn, "drafts", "decided_at"):
        conn.execute("ALTER TABLE drafts ADD COLUMN decided_at TEXT")
    if not _column_exists(conn, "drafts", "decided_by"):
        conn.execute("ALTER TABLE drafts ADD COLUMN decided_by TEXT")  # 'client' | 'operator'


MIGRATIONS: list[tuple[str, str, callable]] = [
    ("0001", "scans.error_message for failed-scan tracking", _m0001_scan_error_tracking),
    ("0002", "alerts delivery_status/delivery_error", _m0002_alert_delivery_tracking),
    ("0003", "clients.active soft-disable flag", _m0003_client_active_flag),
    ("0004", "scan lookup indexes", _m0004_scan_indexes),
    ("0005", "clients.min_alert_severity override", _m0005_client_alert_threshold),
    ("0006", "operators table for multi-operator dashboard accounts", _m0006_operators_table),
    ("0007", "clients.portal_password_hash for client portal access", _m0007_client_portal_access),
    ("0008", "drafts.decided_at/decided_by audit trail", _m0008_draft_decision_audit),
]


def run_migrations(conn: sqlite3.Connection) -> list[str]:
    """Apply every migration not yet recorded as applied. Returns the ids
    actually applied this call (empty list = DB was already up to date)."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS schema_migrations (
               id TEXT PRIMARY KEY,
               description TEXT NOT NULL,
               applied_at TEXT NOT NULL DEFAULT (datetime('now'))
           )"""
    )
    already = {r[0] for r in conn.execute("SELECT id FROM schema_migrations").fetchall()}

    applied_now = []
    for mig_id, description, fn in MIGRATIONS:
        if mig_id in already:
            continue
        try:
            fn(conn)
            conn.execute(
                "INSERT INTO schema_migrations (id, description) VALUES (?, ?)",
                (mig_id, description),
            )
            conn.commit()
            applied_now.append(mig_id)
            logger.info("Applied migration %s: %s", mig_id, description)
        except Exception:
            conn.rollback()
            logger.exception("Migration %s (%s) failed — leaving DB as-is, will retry next startup", mig_id, description)
            raise
    return applied_now
