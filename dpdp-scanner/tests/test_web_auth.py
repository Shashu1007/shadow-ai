"""
Tests for dashboard auth + CSRF (app/auth.py, wired into app/web.py).

Uses Flask's test client against a throwaway SQLite file — no live server,
no browser. Each test function sets env vars and DB_PATH *before* importing
app.web: DASHBOARD_USERNAME/PASSWORD/_HASH are seed-only values now (see
app/auth.py:seed_operator_from_env, called at app.web import time, right
after init_db()) — they create the first row in the `operators` table on a
brand-new DB, they aren't checked directly on every request. We run each
scenario against its own fresh DB file and force a fresh reimport of the
whole app.* namespace so that seeding re-runs against the new env/DB
instead of a previous test's already-seeded operator leaking through.
"""
import base64
import importlib
import os
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _fresh_app(db_path: str, **env):
    """Reimport app.auth and app.web with a clean env so module-level auth
    config (which reads os.environ at import time) reflects `env`."""
    for var in ("DASHBOARD_USERNAME", "DASHBOARD_PASSWORD", "DASHBOARD_PASSWORD_HASH", "SECRET_KEY"):
        os.environ.pop(var, None)
    os.environ.update(env)

    # `from app import auth` (used in app/web.py) resolves via getattr() on
    # the already-imported `app` package object BEFORE it ever consults
    # sys.modules — so popping just "app.auth" isn't enough, the stale
    # module stays reachable as the `app` package's cached `auth` attribute.
    # The only reliable way to force every app.* module (and everything that
    # did `from app.x import y`) to rebind fresh is to drop the entire `app`
    # namespace and let it re-import from scratch.
    for mod in list(sys.modules):
        if mod == "app" or mod.startswith("app."):
            sys.modules.pop(mod, None)

    import app.db.conn as conn_mod
    conn_mod.DB_PATH = Path(db_path)
    import app.web as webmod
    return webmod.app


def _tmp_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)  # let init_db create it fresh
    return path


def test_no_password_set_auth_disabled_but_healthz_and_pages_work():
    app = _fresh_app(_tmp_db())
    client = app.test_client()
    assert client.get("/").status_code == 200
    assert client.get("/healthz").status_code == 200


def test_password_set_blocks_unauthenticated_requests():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="correct-horse-battery-staple")
    client = app.test_client()
    assert client.get("/").status_code == 401
    # healthz stays open even with auth on — platform health checks don't send creds
    assert client.get("/healthz").status_code == 200


def test_correct_credentials_allowed_wrong_credentials_rejected():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="correct-horse-battery-staple")
    client = app.test_client()
    good = {"Authorization": "Basic " + base64.b64encode(b"admin:correct-horse-battery-staple").decode()}
    bad = {"Authorization": "Basic " + base64.b64encode(b"admin:wrong").decode()}
    assert client.get("/", headers=good).status_code == 200
    assert client.get("/", headers=bad).status_code == 401


def test_custom_username_honored():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="pw", DASHBOARD_USERNAME="ops")
    client = app.test_client()
    wrong_user = {"Authorization": "Basic " + base64.b64encode(b"admin:pw").decode()}
    right_user = {"Authorization": "Basic " + base64.b64encode(b"ops:pw").decode()}
    assert client.get("/", headers=wrong_user).status_code == 401
    assert client.get("/", headers=right_user).status_code == 200


def test_post_without_csrf_token_rejected():
    app = _fresh_app(_tmp_db())
    client = app.test_client()
    resp = client.post("/clients/new", data={"domain": "example.com"})
    assert resp.status_code == 403


def test_post_with_valid_csrf_token_succeeds():
    app = _fresh_app(_tmp_db())
    client = app.test_client()
    form_resp = client.get("/clients/new")
    token = re.search(rb'name="csrf_token" value="([^"]+)"', form_resp.data).group(1).decode()
    resp = client.post("/clients/new", data={"domain": "example.com", "csrf_token": token})
    assert resp.status_code == 302
    assert resp.headers["Location"].startswith("/clients/")


def test_invalid_domain_rejected_with_400():
    app = _fresh_app(_tmp_db())
    client = app.test_client()
    form_resp = client.get("/clients/new")
    token = re.search(rb'name="csrf_token" value="([^"]+)"', form_resp.data).group(1).decode()
    resp = client.post("/clients/new", data={"domain": "not a domain!!", "csrf_token": token})
    assert resp.status_code == 400


def test_pasted_full_url_normalized_to_bare_domain():
    app = _fresh_app(_tmp_db())
    client = app.test_client()
    form_resp = client.get("/clients/new")
    token = re.search(rb'name="csrf_token" value="([^"]+)"', form_resp.data).group(1).decode()
    resp = client.post("/clients/new", data={"domain": "https://example.com/pricing", "csrf_token": token})
    assert resp.status_code == 302
    # confirm the stored client is the bare domain, not the full pasted URL
    detail = client.get(resp.headers["Location"])
    assert b"example.com" in detail.data
    assert b"/pricing" not in detail.data


def test_unhandled_exception_returns_generic_500_not_a_traceback():
    app = _fresh_app(_tmp_db())
    app.testing = False  # keep Flask's error handler path instead of re-raising for pytest

    @app.route("/_boom")
    def _boom():
        raise RuntimeError("some internal detail that must not leak: /etc/passwd")

    client = app.test_client()
    resp = client.get("/_boom")
    assert resp.status_code == 500
    assert b"/etc/passwd" not in resp.data
    assert b"RuntimeError" not in resp.data


if __name__ == "__main__":
    import inspect
    mod = sys.modules[__name__]
    tests = [f for name, f in inspect.getmembers(mod) if name.startswith("test_")]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"FAIL {t.__name__}: {e!r}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
