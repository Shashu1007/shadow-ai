"""Thin data-access layer over SQLite. Keeps SQL out of the orchestrator/dashboard."""
from __future__ import annotations

import json
from app.db.conn import db_cursor, get_connection


# --- clients ---

def create_client(domain: str, whatsapp_number: str | None = None, plan_tier: str = "trial",
                   portal_password_hash: str | None = None) -> int:
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO clients (domain, whatsapp_number, plan_tier, portal_password_hash) VALUES (?, ?, ?, ?)",
            (domain, whatsapp_number, plan_tier, portal_password_hash),
        )
        return cur.lastrowid


def set_client_portal_password(client_id: int, password_hash: str | None) -> None:
    """password_hash=None revokes portal access entirely without touching
    any other client data — used by the operator dashboard's "revoke portal
    access" action."""
    with db_cursor() as cur:
        cur.execute("UPDATE clients SET portal_password_hash = ? WHERE id = ?", (password_hash, client_id))


def get_client_by_domain(domain: str) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM clients WHERE domain = ?", (domain,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_client(client_id: int) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_clients() -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM clients ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_or_create_client(domain: str, whatsapp_number: str | None = None) -> dict:
    existing = get_client_by_domain(domain)
    if existing:
        return existing
    cid = create_client(domain, whatsapp_number)
    return get_client(cid)


def list_active_clients() -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM clients WHERE active = 1 ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def set_client_active(client_id: int, active: bool) -> None:
    with db_cursor() as cur:
        cur.execute("UPDATE clients SET active = ? WHERE id = ?", (1 if active else 0, client_id))


# --- scans ---

def create_scan(client_id: int, page_count: int, raw_findings: dict, status: str = "completed",
                 error_message: str | None = None) -> int:
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO scans (client_id, page_count, status, raw_findings_json, error_message) VALUES (?, ?, ?, ?, ?)",
            (client_id, page_count, status, json.dumps(raw_findings), error_message),
        )
        return cur.lastrowid


def mark_scan_failed(scan_id: int, error_message: str) -> None:
    with db_cursor() as cur:
        cur.execute("UPDATE scans SET status = 'failed', error_message = ? WHERE id = ?", (error_message, scan_id))


def list_recent_scan_failures(client_id: int, limit: int = 5) -> list[dict]:
    """Most recent scans for a client, newest first — used by the ops
    self-check (app/ops.py) to spot a client whose last N scans all failed."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM scans WHERE client_id = ? ORDER BY id DESC LIMIT ?", (client_id, limit)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_latest_scan(client_id: int, before_scan_id: int | None = None) -> dict | None:
    conn = get_connection()
    try:
        if before_scan_id:
            row = conn.execute(
                "SELECT * FROM scans WHERE client_id = ? AND id < ? ORDER BY id DESC LIMIT 1",
                (client_id, before_scan_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM scans WHERE client_id = ? ORDER BY id DESC LIMIT 1",
                (client_id,),
            ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_scans(client_id: int) -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM scans WHERE client_id = ? ORDER BY id DESC", (client_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# --- findings ---

def bulk_insert_findings(scan_id: int, findings: list[dict]) -> None:
    with db_cursor() as cur:
        for f in findings:
            cur.execute(
                """INSERT INTO findings
                   (scan_id, page_url, type, detail, detail_hash, data_category,
                    third_party_domain, dpdp_relevance, confidence, raw_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id, f["url"], f["type"], f["detail"], f["detail_hash"],
                    f.get("data_category"), f.get("third_party_domain"),
                    f.get("dpdp_relevance"), f.get("confidence", "medium"),
                    json.dumps(f),
                ),
            )


def get_findings_for_scan(scan_id: int) -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# --- review queue ---

def enqueue_review(finding_id: int, client_id: int) -> None:
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO review_queue (finding_id, client_id) VALUES (?, ?)",
            (finding_id, client_id),
        )


def list_review_queue(status: str = "pending") -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT rq.*, f.detail, f.type, f.page_url, c.domain
               FROM review_queue rq
               JOIN findings f ON f.id = rq.finding_id
               JOIN clients c ON c.id = rq.client_id
               WHERE rq.status = ?
               ORDER BY rq.created_at DESC""",
            (status,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# --- diffs ---

def create_diff(client_id: int, prev_scan_id: int | None, curr_scan_id: int,
                 new: list, changed: list, removed: list, severity: str) -> int:
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO diffs (client_id, prev_scan_id, curr_scan_id, new_json, changed_json, removed_json, severity)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (client_id, prev_scan_id, curr_scan_id, json.dumps(new), json.dumps(changed), json.dumps(removed), severity),
        )
        return cur.lastrowid


def list_diffs(client_id: int) -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM diffs WHERE client_id = ? ORDER BY id DESC", (client_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_diff(diff_id: int) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM diffs WHERE id = ?", (diff_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# --- alerts ---

def create_alert(client_id: int, diff_id: int, severity: str, message: str, channel: str = "whatsapp_sim",
                  delivery_status: str = "unknown", delivery_error: str | None = None) -> int:
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO alerts (client_id, diff_id, severity, channel, message, delivery_status, delivery_error)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (client_id, diff_id, severity, channel, message, delivery_status, delivery_error),
        )
        return cur.lastrowid


def list_alerts(client_id: int | None = None, status: str | None = None) -> list[dict]:
    conn = get_connection()
    try:
        q = "SELECT alerts.*, clients.domain FROM alerts JOIN clients ON clients.id = alerts.client_id WHERE 1=1"
        params = []
        if client_id:
            q += " AND client_id = ?"
            params.append(client_id)
        if status:
            q += " AND status = ?"
            params.append(status)
        q += " ORDER BY alerts.created_at DESC"
        rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def mark_alert_handled(alert_id: int) -> None:
    with db_cursor() as cur:
        cur.execute("UPDATE alerts SET status = 'handled' WHERE id = ?", (alert_id,))


# --- drafts ---

def create_draft(client_id: int, finding_id: int, kind: str, content: str) -> int:
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO drafts (client_id, finding_id, kind, content) VALUES (?, ?, ?, ?)",
            (client_id, finding_id, kind, content),
        )
        return cur.lastrowid


def list_drafts(client_id: int, status: str = "draft") -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM drafts WHERE client_id = ? AND status = ? ORDER BY created_at DESC",
            (client_id, status),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def set_draft_status(draft_id: int, status: str) -> None:
    with db_cursor() as cur:
        cur.execute("UPDATE drafts SET status = ? WHERE id = ?", (status, draft_id))


def get_draft(draft_id: int) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM drafts WHERE id = ?", (draft_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_all_drafts(client_id: int) -> list[dict]:
    """Every draft regardless of status — the portal's own drafts view
    shows a client their full decision history, not just what's pending."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM drafts WHERE client_id = ? ORDER BY created_at DESC", (client_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def decide_draft(draft_id: int, status: str, decided_by: str) -> None:
    """status: 'approved' | 'rejected'. decided_by: 'client' | 'operator' —
    who made the call, for the audit trail (app/db/migrations.py 0008).
    This never publishes anything anywhere; it only records that someone
    with the right access reviewed and signed off in this system — see the
    portal template copy, which says this explicitly."""
    with db_cursor() as cur:
        cur.execute(
            "UPDATE drafts SET status = ?, decided_at = datetime('now'), decided_by = ? WHERE id = ?",
            (status, decided_by, draft_id),
        )


# --- operators (dashboard accounts) ---

def create_operator(username: str, password_hash: str, active: bool = True) -> int:
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO operators (username, password_hash, active) VALUES (?, ?, ?)",
            (username, password_hash, 1 if active else 0),
        )
        return cur.lastrowid


def get_operator_by_username(username: str) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM operators WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_operators() -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM operators ORDER BY created_at ASC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def count_operators() -> int:
    conn = get_connection()
    try:
        return conn.execute("SELECT COUNT(*) FROM operators").fetchone()[0]
    finally:
        conn.close()


def count_active_operators() -> int:
    conn = get_connection()
    try:
        return conn.execute("SELECT COUNT(*) FROM operators WHERE active = 1").fetchone()[0]
    finally:
        conn.close()


def set_operator_active(operator_id: int, active: bool) -> None:
    with db_cursor() as cur:
        cur.execute("UPDATE operators SET active = ? WHERE id = ?", (1 if active else 0, operator_id))


def set_operator_password(operator_id: int, password_hash: str) -> None:
    with db_cursor() as cur:
        cur.execute("UPDATE operators SET password_hash = ? WHERE id = ?", (password_hash, operator_id))
