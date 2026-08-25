"""
Client-facing portal — separate, session-based login for the client
themselves (not an operator), scoped strictly to their own data.

Why this is a separate auth system from app/auth.py's operator Basic Auth
(see that module's docstring): a client is not an operator and must never
share that credential space — an operator's password grants access to
every client's findings; a client's portal password must only ever unlock
their own single client_id. Session-based (Flask's signed cookie session,
not Basic Auth) is the right shape here specifically because it needs a
real logout and a login *page* a client can be sent a link to, rather than
a browser-cached credential prompt.

Security model, stated explicitly:
  - Login identifier is the client's own domain (already unique — see
    clients.domain UNIQUE) + a password an operator sets and relays to them
    (see app/web.py:set_client_portal_password) — there's no email/SMS
    integration to do this via a "forgot password" flow yet, so a client
    locked out has to ask their operator to reset it, same as they would
    for the initial password.
  - Every route below re-derives client_id from `session["portal_client_id"]`
    — set only by a successful login in this module — and NEVER from a
    URL parameter or form field. That's what prevents one client's portal
    session from reading or acting on another client's data (IDOR): there
    is no code path where a request supplies which client it wants to see.
  - Login is rate-limited per source IP (see app/ratelimit.py) — a public,
    unauthenticated POST endpoint that checks a password is exactly the
    kind of thing that gets credential-stuffed otherwise.
  - CSRF: enforced centrally in app/auth.py's before_request hook, which
    applies to every unsafe-method request regardless of which auth system
    guards the route — portal POSTs are covered by the same mechanism as
    operator POSTs.
  - Approving/rejecting a draft is a REAL, audited action (see
    app/db/migrations.py 0008 — decided_at/decided_by) but explicitly does
    NOT publish or send anything anywhere. The copy on every relevant page
    says this outright — see DEMO.md/ONBOARDING.md's characterization of
    drafts as "auto-generated, never auto-published." A client's approval
    only records that a human at the client company signed off *in this
    system*; it is not a substitute for the client actually publishing an
    updated privacy notice or however they choose to act on it.
"""
from __future__ import annotations

import functools
import json
import logging

from flask import Blueprint, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from app import ratelimit, repository as repo

logger = logging.getLogger("portal")

portal_bp = Blueprint("portal", __name__, url_prefix="/portal")

LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 10
LOGIN_RATE_LIMIT_WINDOW_SECONDS = 60


def _current_client() -> dict | None:
    """The logged-in client for this session, or None. Also self-heals a
    session left pointing at a client whose portal access was since
    revoked or who was deleted — never trust a stale session over live DB
    state for something that gates data access."""
    client_id = session.get("portal_client_id")
    if not client_id:
        return None
    client = repo.get_client(client_id)
    if not client or not client.get("portal_password_hash"):
        session.pop("portal_client_id", None)
        return None
    return client


def _require_login(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        client = _current_client()
        if not client:
            return redirect(url_for("portal.login"))
        return view(client, *args, **kwargs)
    return wrapped


@portal_bp.route("/login", methods=["GET", "POST"])
def login():
    if _current_client():
        return redirect(url_for("portal.dashboard"))

    error = None
    if request.method == "POST":
        rl_key = f"portal_login:{request.remote_addr}"
        if not ratelimit.allow(rl_key, LOGIN_RATE_LIMIT_MAX_ATTEMPTS, LOGIN_RATE_LIMIT_WINDOW_SECONDS):
            error = "Too many attempts. Wait a minute and try again."
            return render_template("portal_login.html", error=error), 429

        domain = request.form.get("domain", "").strip().lower()
        password = request.form.get("password", "").strip()
        client = repo.get_client_by_domain(domain) if domain else None

        # Constant-shape check regardless of whether the domain exists, so
        # "no such client" vs "wrong password" isn't distinguishable by an
        # attacker probing for registered domains via response differences.
        stored_hash = client["portal_password_hash"] if client else None
        valid = bool(stored_hash) and check_password_hash(stored_hash, password)

        if not client or not stored_hash or not valid:
            error = "Incorrect domain or password."
            logger.info("Failed portal login attempt for domain=%r from %s", domain, request.remote_addr)
            return render_template("portal_login.html", error=error, domain=domain), 401

        session.clear()
        session["portal_client_id"] = client["id"]
        return redirect(url_for("portal.dashboard"))

    return render_template("portal_login.html", error=error)


@portal_bp.route("/logout", methods=["POST"])
def logout():
    session.pop("portal_client_id", None)
    return redirect(url_for("portal.login"))


@portal_bp.route("/")
@_require_login
def dashboard(client: dict):
    scans = repo.list_scans(client["id"])
    diffs = repo.list_diffs(client["id"])
    pending_drafts = [d for d in repo.list_all_drafts(client["id"]) if d["status"] == "draft"]
    return render_template(
        "portal_dashboard.html",
        client=client, scans=scans, diffs=diffs, pending_draft_count=len(pending_drafts),
    )


@portal_bp.route("/scans/<int:scan_id>")
@_require_login
def scan_detail(client: dict, scan_id: int):
    scan = next((s for s in repo.list_scans(client["id"]) if s["id"] == scan_id), None)
    if not scan:
        # Deliberately a redirect to their own dashboard, not a 404 that
        # would confirm/deny whether a given scan_id exists for *someone*.
        return redirect(url_for("portal.dashboard"))
    findings = repo.get_findings_for_scan(scan_id)
    return render_template("portal_scan_detail.html", client=client, scan=scan, findings=findings)


@portal_bp.route("/diffs/<int:diff_id>")
@_require_login
def diff_detail(client: dict, diff_id: int):
    diff = repo.get_diff(diff_id)
    if not diff or diff["client_id"] != client["id"]:
        return redirect(url_for("portal.dashboard"))
    return render_template(
        "portal_diff_detail.html",
        client=client, diff=diff,
        new=json.loads(diff["new_json"]),
        changed=json.loads(diff["changed_json"]),
        removed=json.loads(diff["removed_json"]),
    )


@portal_bp.route("/drafts")
@_require_login
def drafts(client: dict):
    all_drafts = repo.list_all_drafts(client["id"])
    return render_template("portal_drafts.html", client=client, drafts=all_drafts)


@portal_bp.route("/drafts/<int:draft_id>/decide", methods=["POST"])
@_require_login
def decide_draft(client: dict, draft_id: int):
    draft = repo.get_draft(draft_id)
    # The IDOR check that matters: this client_id came from the session,
    # never from the request, so there is nothing an attacker can put in
    # the form to act on a draft that isn't theirs.
    if not draft or draft["client_id"] != client["id"]:
        return redirect(url_for("portal.drafts"))
    if draft["status"] != "draft":
        # Already decided — no take-backs through this route (the audit
        # trail should read as a single decision, not a flip-flop); an
        # operator can still change it from the dashboard if truly needed.
        return redirect(url_for("portal.drafts"))

    decision = request.form.get("decision")
    if decision not in ("approved", "rejected"):
        return redirect(url_for("portal.drafts"))

    repo.decide_draft(draft_id, decision, decided_by="client")
    return redirect(url_for("portal.drafts"))
