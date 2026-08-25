"""Minimal server-rendered dashboard — Flask + Jinja2, no JS framework needed for MVP."""
from __future__ import annotations

import json
import logging
import os
import re

from flask import Flask, render_template, redirect, url_for, request, abort, session

from werkzeug.security import generate_password_hash

from app import config
from app import ratelimit
from app import repository as repo
from app import auth
from app.portal import portal_bp
from app.db.conn import init_db, health_check
from app.ops import check_fleet_health

logger = logging.getLogger("web")

app = Flask(__name__)

# Required for the client portal's session cookie (Flask signs it with this
# — see app/portal.py; the operator dashboard's own auth stays Basic Auth
# and doesn't use sessions at all). Falls back to a random per-process
# value like auth.py's CSRF secret does: portal sessions just get
# invalidated on restart rather than failing to start, which is the right
# tradeoff for an MVP deploy with no secret-management infra yet. Set
# SECRET_KEY in production so a restart/redeploy doesn't log every client
# portal session out.
app.secret_key = os.environ.get("SECRET_KEY", "").strip() or os.urandom(32).hex()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=config.SESSION_COOKIE_SECURE,
)

app.register_blueprint(portal_bp)

# Run at import time, not just inside `if __name__ == "__main__"` — a WSGI
# server like gunicorn imports this module and reads `app` directly, it never
# executes the __main__ block. Without this, `schema.sql` never runs under
# gunicorn and every route 500s on a missing table. init_db() is idempotent
# (CREATE TABLE IF NOT EXISTS + migrations tracked in schema_migrations), so
# this is safe to also leave in create_app().
init_db()

# Seeds the first operator from DASHBOARD_PASSWORD/_HASH if none exist yet
# — must run after init_db() (the operators table has to exist) and before
# auth.register() so the very first request already sees it. A no-op on
# every startup after the first operator exists — see app/auth.py.
auth.seed_operator_from_env()

# Auth (HTTP Basic, per-operator accounts) + CSRF enforcement on every
# POST/PUT/PATCH/DELETE. See app/auth.py for why this exists and how it
# degrades (loudly, not silently) when no operator accounts exist.
auth.register(app)


@app.after_request
def _security_headers(resp):
    # Defense-in-depth headers appropriate for a small server-rendered
    # dashboard with no third-party embeds and no JS framework.
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
    return resp


@app.errorhandler(404)
def _not_found(e):
    return render_template("error.html", code=404, message="Not found."), 404


@app.errorhandler(403)
def _forbidden(e):
    return render_template("error.html", code=403, message=str(e.description) if hasattr(e, "description") else "Forbidden."), 403


@app.errorhandler(500)
def _server_error(e):
    # Never leak a stack trace / exception text to the client — that's
    # exactly the kind of internal detail (file paths, SQL, library
    # versions) an attacker uses to find the next hole. Full detail still
    # goes to the server log via Flask's own exception logging.
    logger.exception("Unhandled exception on %s %s", request.method, request.path)
    return render_template("error.html", code=500, message="Something went wrong. It's been logged."), 500


DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")
# Loose but real E.164-ish check — good enough to catch fat-fingered input
# without rejecting legitimate international numbers.
WHATSAPP_RE = re.compile(r"^\+?[1-9]\d{6,14}$")


@app.route("/healthz")
def healthz():
    """Unauthenticated liveness/readiness check for Fly/Railway health
    checks and uptime monitors — checks the DB is actually reachable, not
    just that the process is up (a stuck/corrupt DB file should fail this)."""
    ok, detail = health_check()
    return {"status": "ok" if ok else "error", "db": detail}, (200 if ok else 503)


@app.template_filter("fmt_findings")
def fmt_findings(entries_json: str) -> list[dict]:
    try:
        return json.loads(entries_json)
    except Exception:
        return []


@app.route("/")
def index():
    clients = repo.list_clients()
    summary = []
    for c in clients:
        scans = repo.list_scans(c["id"])
        latest_diff = repo.list_diffs(c["id"])
        alerts = repo.list_alerts(client_id=c["id"], status="open")
        summary.append({
            "client": c,
            "scan_count": len(scans),
            "last_scan": scans[0] if scans else None,
            "last_severity": latest_diff[0]["severity"] if latest_diff else None,
            "open_alerts": len(alerts),
        })
    health_issues = check_fleet_health()
    return render_template("index.html", summary=summary, health_issues=health_issues)


@app.route("/ops/health")
def ops_health():
    """JSON view of the fleet self-check — same data as the dashboard
    banner, machine-readable for an external uptime monitor to poll."""
    issues = check_fleet_health()
    return {"ok": len(issues) == 0, "issue_count": len(issues), "issues": issues}


@app.route("/clients/<int:client_id>")
def client_detail(client_id: int):
    client = repo.get_client(client_id)
    if not client:
        abort(404)
    scans = repo.list_scans(client_id)
    diffs = repo.list_diffs(client_id)
    alerts = repo.list_alerts(client_id=client_id)
    drafts = repo.list_drafts(client_id)
    return render_template(
        "client_detail.html",
        client=client, scans=scans, diffs=diffs, alerts=alerts, drafts=drafts,
    )


@app.route("/clients/<int:client_id>/scans/<int:scan_id>")
def scan_detail(client_id: int, scan_id: int):
    client = repo.get_client(client_id)
    if not client:
        abort(404)
    findings = repo.get_findings_for_scan(scan_id)
    return render_template("scan_detail.html", client=client, scan_id=scan_id, findings=findings)


@app.route("/clients/<int:client_id>/diffs/<int:diff_id>")
def diff_detail(client_id: int, diff_id: int):
    client = repo.get_client(client_id)
    diff = repo.get_diff(diff_id)
    if not client or not diff:
        abort(404)
    return render_template(
        "diff_detail.html",
        client=client, diff=diff,
        new=json.loads(diff["new_json"]),
        changed=json.loads(diff["changed_json"]),
        removed=json.loads(diff["removed_json"]),
    )


@app.route("/alerts")
def alerts_list():
    status = request.args.get("status")
    alerts = repo.list_alerts(status=status)
    return render_template("alerts.html", alerts=alerts, status=status)


@app.route("/alerts/<int:alert_id>/handle", methods=["POST"])
def handle_alert(alert_id: int):
    repo.mark_alert_handled(alert_id)
    return redirect(request.referrer or url_for("alerts_list"))


@app.route("/review-queue")
def review_queue():
    items = repo.list_review_queue(status="pending")
    return render_template("review_queue.html", items=items)


@app.route("/clients/<int:client_id>/drafts")
def drafts_list(client_id: int):
    client = repo.get_client(client_id)
    if not client:
        abort(404)
    drafts = repo.list_drafts(client_id)
    return render_template("drafts.html", client=client, drafts=drafts)


@app.route("/clients/new", methods=["GET", "POST"])
def new_client():
    if request.method == "POST":
        raw_domain = request.form.get("domain", "").strip().lower()
        # Accept a pasted full URL too ("https://example.com/") without
        # forcing the operator to strip it themselves.
        domain = re.sub(r"^https?://", "", raw_domain).split("/")[0].strip()
        whatsapp = request.form.get("whatsapp", "").strip() or None

        if not domain or not DOMAIN_RE.match(domain):
            return render_template("new_client.html", error="Enter a valid domain, e.g. example.com", domain=raw_domain, whatsapp=whatsapp), 400
        if whatsapp and not WHATSAPP_RE.match(whatsapp.replace(" ", "")):
            return render_template("new_client.html", error="WhatsApp number doesn't look valid — use E.164 format, e.g. +919999999999", domain=domain, whatsapp=whatsapp), 400

        client = repo.get_or_create_client(domain, whatsapp)
        return redirect(url_for("client_detail", client_id=client["id"]))
    return render_template("new_client.html")


SIGNUP_RATE_LIMIT_MAX_ATTEMPTS = 5
SIGNUP_RATE_LIMIT_WINDOW_SECONDS = 600  # 10 minutes — signup is a rarer action than login, so a tighter window is fine


@app.route("/signup", methods=["GET", "POST"])
def public_signup():
    """Public, unauthenticated self-serve trial signup — no payment, no
    email verification (there's no email integration in this MVP at all).
    Creates a `plan_tier='trial'` client with portal access already set up,
    logs them straight into the client portal — but does NOT trigger a
    scan. Scanning is still an operator action (run_scan.py, or a future
    dashboard button): a public form is by definition reachable by anyone,
    including someone probing what domains this scanner will crawl, and the
    SSRF guard in app/agents/crawler.py only blocks private/internal
    targets, not "some public site the visitor doesn't own." Keeping the
    first crawl an explicit operator step is the approval gate for that —
    see the "operator manually approves/upgrades" scope decided for this
    feature. The new client shows up immediately in the operator dashboard
    with zero scans, which IS the pending-approval queue."""
    error = None
    if request.method == "POST":
        rl_key = f"signup:{request.remote_addr}"
        if not ratelimit.allow(rl_key, SIGNUP_RATE_LIMIT_MAX_ATTEMPTS, SIGNUP_RATE_LIMIT_WINDOW_SECONDS):
            return render_template("signup.html", error="Too many signup attempts from this connection. Wait a few minutes and try again."), 429

        raw_domain = request.form.get("domain", "").strip().lower()
        domain = re.sub(r"^https?://", "", raw_domain).split("/")[0].strip()
        whatsapp = request.form.get("whatsapp", "").strip() or None
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm_password", "").strip()

        if not domain or not DOMAIN_RE.match(domain):
            error = "Enter a valid domain, e.g. example.com"
        elif whatsapp and not WHATSAPP_RE.match(whatsapp.replace(" ", "")):
            error = "WhatsApp number doesn't look valid — use E.164 format, e.g. +919999999999"
        elif len(password) < auth.MIN_PASSWORD_LENGTH:
            error = f"Password must be at least {auth.MIN_PASSWORD_LENGTH} characters."
        elif password != confirm:
            error = "Passwords don't match."
        elif repo.get_client_by_domain(domain):
            # Deliberately vague — "already registered, contact us" rather
            # than anything that would let a signup attempt be used to
            # take over or probe an existing client's account.
            error = "This domain is already registered. If this is your business and you've lost access, contact your account operator."

        if error:
            return render_template("signup.html", error=error, domain=raw_domain, whatsapp=whatsapp), 400

        client_id = repo.create_client(domain, whatsapp, plan_tier="trial", portal_password_hash=generate_password_hash(password))
        logger.info("New self-serve signup: domain=%r client_id=%s", domain, client_id)
        session.clear()
        session["portal_client_id"] = client_id
        return redirect(url_for("portal.dashboard"))

    return render_template("signup.html", error=error)


@app.route("/clients/<int:client_id>/toggle-active", methods=["POST"])
def toggle_client_active(client_id: int):
    """Soft-disable a churned/paused client so `run_scan.py --all` skips
    them, without touching their scan/finding/alert history."""
    client = repo.get_client(client_id)
    if not client:
        abort(404)
    repo.set_client_active(client_id, not client["active"])
    return redirect(url_for("client_detail", client_id=client_id))


@app.route("/clients/<int:client_id>/portal-password", methods=["POST"])
def set_client_portal_password(client_id: int):
    """Operator-set portal password for this client (see app/portal.py) —
    there's no email integration to send it automatically, so the operator
    sets it here and relays it to the client themselves (WhatsApp, a call,
    however they're already in touch). Empty submission revokes access."""
    client = repo.get_client(client_id)
    if not client:
        abort(404)
    password = request.form.get("portal_password", "").strip()
    if not password:
        repo.set_client_portal_password(client_id, None)
        return redirect(url_for("client_detail", client_id=client_id))
    if len(password) < auth.MIN_PASSWORD_LENGTH:
        scans = repo.list_scans(client_id)
        diffs = repo.list_diffs(client_id)
        alerts = repo.list_alerts(client_id=client_id)
        drafts = repo.list_drafts(client_id)
        return render_template(
            "client_detail.html", client=client, scans=scans, diffs=diffs, alerts=alerts, drafts=drafts,
            portal_password_error=f"Portal password must be at least {auth.MIN_PASSWORD_LENGTH} characters.",
        ), 400
    repo.set_client_portal_password(client_id, generate_password_hash(password))
    return redirect(url_for("client_detail", client_id=client_id))


@app.route("/operators")
def operators_list():
    operators = repo.list_operators()
    return render_template("operators.html", operators=operators)


@app.route("/operators/new", methods=["POST"])
def new_operator():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    error = None
    if not username:
        error = "Username is required."
    elif repo.get_operator_by_username(username):
        error = f"An operator named {username!r} already exists."
    elif len(password) < auth.MIN_PASSWORD_LENGTH:
        error = f"Password must be at least {auth.MIN_PASSWORD_LENGTH} characters."

    if error:
        return render_template("operators.html", operators=repo.list_operators(), error=error), 400

    repo.create_operator(username, generate_password_hash(password))
    return redirect(url_for("operators_list"))


@app.route("/operators/<int:operator_id>/toggle-active", methods=["POST"])
def toggle_operator_active(operator_id: int):
    operators = repo.list_operators()
    operator = next((o for o in operators if o["id"] == operator_id), None)
    if not operator:
        abort(404)
    active_count = sum(1 for o in operators if o["active"])
    if operator["active"] and active_count <= 1:
        # Never let the last active operator lock everyone (including
        # themselves) out — deactivate a second operator first, or add one.
        return render_template(
            "operators.html", operators=operators,
            error="Can't deactivate the last active operator — add or activate another one first.",
        ), 400
    repo.set_operator_active(operator_id, not operator["active"])
    return redirect(url_for("operators_list"))


def create_app():
    init_db()
    return app


if __name__ == "__main__":
    import os

    create_app()
    # DEBUG defaults OFF. Werkzeug's debug mode exposes an interactive
    # in-browser Python console on unhandled exceptions — fine on localhost,
    # a remote code execution hole if it's ever reachable from the internet.
    # Set FLASK_DEBUG=1 explicitly for local development only, never in
    # production hosting.
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=debug)
