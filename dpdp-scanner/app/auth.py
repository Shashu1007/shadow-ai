"""
Operator dashboard auth + CSRF.

The DEPLOY.md that shipped with the original MVP flagged, correctly, that
the dashboard had no authentication at all. A follow-up hardening pass
added a single shared HTTP Basic credential (env-configured). This version
replaces that with real multi-operator accounts stored in the `operators`
table (see app/db/migrations.py 0006) — one shared password doesn't hold up
once more than one or two people who fully trust each other need access:
there's no way to revoke just one person's access, no record of who did
what, and rotating the password locks everyone out at once.

Design:
  - Still HTTP Basic Auth, not a session-based login — this is the
    *operator* dashboard specifically; simplest thing that supports "give
    Priya her own login, revoke Raj's without touching anyone else's."
    (The client-facing portal in app/portal.py is a different, separate
    login system with its own session-based auth — clients aren't
    operators and shouldn't share this credential space at all.)
  - DASHBOARD_USERNAME/DASHBOARD_PASSWORD (or DASHBOARD_PASSWORD_HASH) env
    vars now ONLY seed the first operator, once, on a brand-new database
    (see seed_operator_from_env, called from app/web.py right after
    init_db()). After that, operators are managed via the DB — the
    dashboard's /operators page, or scripts/manage_operators.py for
    headless bootstrapping. This mirrors how clients themselves are
    managed (env vars/CLI to bootstrap, then the DB is the source of truth).
  - If there are zero operators in the DB (nothing seeded, none added),
    auth is OFF — but loudly: a warning logs on startup and a banner
    renders on every page. This check is now a live DB query, not a
    fixed-at-import-time boolean, since an operator can be added after the
    process starts (from the dashboard or the CLI script) without a restart.
  - CSRF: Basic Auth credentials are cached per-origin by the browser and
    attached automatically to same-origin requests regardless of which page
    triggered them — so a malicious third-party page can still submit a POST
    to this dashboard and have the browser attach valid credentials. Every
    state-changing route therefore needs a CSRF token, checked here. The
    same CSRF check also covers the client portal's own POSTs (login,
    draft approve/reject) — one mechanism, two auth systems.
"""
from __future__ import annotations

import logging
import os
import time

from flask import request, Response, abort
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import check_password_hash, generate_password_hash

from app import repository as repo

logger = logging.getLogger("auth")

# Seed-only env vars — see module docstring. Read once; only used the very
# first time this process finds zero operators in the DB.
_SEED_USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin").strip() or "admin"
_SEED_PASSWORD_HASH_ENV = os.environ.get("DASHBOARD_PASSWORD_HASH", "").strip()
_SEED_PASSWORD_PLAIN_ENV = os.environ.get("DASHBOARD_PASSWORD", "").strip()

MIN_PASSWORD_LENGTH = 8

# CSRF token secret. Falls back to a random per-process secret, which is
# fine (tokens just stop validating across a restart, forcing a page
# refresh) — it never needs to be the same across processes/deploys.
_CSRF_SECRET = os.environ.get("SECRET_KEY", "").strip() or os.urandom(32).hex()
_csrf_serializer = URLSafeTimedSerializer(_CSRF_SECRET, salt="dpdp-scanner-csrf")
CSRF_TOKEN_MAX_AGE_SECONDS = 4 * 3600  # 4 hours — long enough for a working session, short enough to matter


def seed_operator_from_env() -> None:
    """Creates the first operator from DASHBOARD_PASSWORD/_HASH if the
    operators table is still empty. Call once, at startup, after init_db()
    has run migrations (the operators table must exist first). A no-op on
    every subsequent startup once at least one operator exists — env vars
    never overwrite or reset an existing operator's password, so rotating
    DASHBOARD_PASSWORD after the fact does nothing; use /operators or
    scripts/manage_operators.py to change a password instead."""
    if repo.count_operators() > 0:
        return

    if _SEED_PASSWORD_HASH_ENV:
        pw_hash = _SEED_PASSWORD_HASH_ENV
    elif _SEED_PASSWORD_PLAIN_ENV:
        pw_hash = generate_password_hash(_SEED_PASSWORD_PLAIN_ENV)
    else:
        logger.warning(
            "DASHBOARD AUTH IS DISABLED — no operators exist yet and neither "
            "DASHBOARD_PASSWORD nor DASHBOARD_PASSWORD_HASH is set to seed one. "
            "Anyone with the URL can see every client's findings, alerts, and "
            "drafts. Set one of those two env vars before this is reachable by "
            "anyone but you, or add an operator via scripts/manage_operators.py. "
            "See DEPLOY.md."
        )
        return

    repo.create_operator(_SEED_USERNAME, pw_hash)
    logger.info("Seeded initial operator %r from DASHBOARD_PASSWORD env var", _SEED_USERNAME)


def any_active_operators() -> bool:
    return repo.count_active_operators() > 0


def check_auth() -> bool:
    """True if auth is off (no operators at all), or the request carries
    valid Basic Auth credentials for an active operator."""
    if not any_active_operators():
        return True
    authz = request.authorization
    if not authz or not authz.username or not authz.password:
        return False
    operator = repo.get_operator_by_username(authz.username)
    if not operator or not operator["active"]:
        return False
    # constant-time-safe: check_password_hash uses hmac.compare_digest internally
    return check_password_hash(operator["password_hash"], authz.password)


def auth_challenge() -> Response:
    return Response(
        "Authentication required.", 401,
        {"WWW-Authenticate": 'Basic realm="DPDP Drift Scanner"'},
    )


def generate_csrf_token() -> str:
    return _csrf_serializer.dumps({"t": time.time()})


def validate_csrf_token(token: str | None) -> bool:
    if not token:
        return False
    try:
        _csrf_serializer.loads(token, max_age=CSRF_TOKEN_MAX_AGE_SECONDS)
        return True
    except (BadSignature, SignatureExpired):
        return False


UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Paths exempt from OPERATOR Basic-Auth — the client portal has its own,
# separate session-based login (see app/portal.py) and enforces it itself
# via a route decorator; a client must never need an operator credential.
# /signup is the public self-serve signup form (app/web.py) — by definition
# reachable by someone who doesn't have an operator credential yet. CSRF is
# still enforced centrally below regardless of this exemption.
_OPERATOR_AUTH_EXEMPT_PREFIXES = ("/portal", "/healthz", "/signup")


def register(app):
    """Wire auth + CSRF enforcement into a Flask app via before_request, plus
    a `csrf_token()`/`auth_enabled()` Jinja global so templates can embed
    the hidden field and the "auth is off" warning banner."""

    @app.before_request
    def _enforce_auth_and_csrf():
        exempt = any(request.path == p or request.path.startswith(p + "/") for p in _OPERATOR_AUTH_EXEMPT_PREFIXES)
        if not exempt:
            if not check_auth():
                return auth_challenge()
        if request.method in UNSAFE_METHODS:
            token = request.form.get("csrf_token")
            if not validate_csrf_token(token):
                logger.warning("Rejected %s %s: missing/invalid CSRF token", request.method, request.path)
                abort(403, description="Invalid or missing CSRF token. Please reload the page and try again.")
        return None

    app.jinja_env.globals["csrf_token"] = generate_csrf_token
    # Callable, not a fixed value — an operator can be added after startup
    # (dashboard or CLI) without a restart, so this has to reflect live DB
    # state on every render, not a boolean computed once at import time.
    app.jinja_env.globals["auth_enabled"] = any_active_operators
