"""
Tests for public self-serve trial signup (app/web.py:public_signup) — no
payment, operator-approved first scan. Same fresh-reimport pattern as
tests/test_web_auth.py.
"""
import os
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _fresh_app(db_path: str, **env):
    for var in ("DASHBOARD_USERNAME", "DASHBOARD_PASSWORD", "DASHBOARD_PASSWORD_HASH", "SECRET_KEY"):
        os.environ.pop(var, None)
    os.environ.update(env)
    for mod in list(sys.modules):
        if mod == "app" or mod.startswith("app."):
            sys.modules.pop(mod, None)
    import app.db.conn as conn_mod
    conn_mod.DB_PATH = Path(db_path)
    import app.ratelimit as ratelimit_mod
    ratelimit_mod.reset_for_tests()
    import app.web as webmod
    return webmod.app


def _tmp_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    return path


def _csrf(client, get_path="/signup") -> str:
    resp = client.get(get_path)
    return re.search(rb'name="csrf_token" value="([^"]+)"', resp.data).group(1).decode()


def test_signup_page_reachable_without_any_operator_credential():
    # No DASHBOARD_PASSWORD set at all here, so operators COULD exist from a
    # prior run in a shared DB — use a totally fresh DB to prove /signup
    # itself never demands Basic Auth regardless.
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    resp = client.get("/signup")
    assert resp.status_code == 200
    assert b"WWW-Authenticate" not in str(resp.headers).encode()


def test_successful_signup_creates_client_and_logs_into_portal():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    token = _csrf(client)
    resp = client.post("/signup", data={
        "csrf_token": token, "domain": "newtrial.example", "whatsapp": "+919999999999",
        "password": "trial-secret-1", "confirm_password": "trial-secret-1",
    })
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/portal/")

    dash = client.get("/portal/")
    assert dash.status_code == 200
    assert b"newtrial.example" in dash.data

    import app.repository as repo
    created = repo.get_client_by_domain("newtrial.example")
    assert created is not None
    assert created["plan_tier"] == "trial"
    assert created["portal_password_hash"] is not None
    # signup must not itself trigger a scan — that stays an operator action
    assert repo.list_scans(created["id"]) == []


def test_duplicate_domain_rejected_not_silently_reused():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    token = _csrf(client)
    client.post("/signup", data={
        "csrf_token": token, "domain": "taken.example", "password": "first-secret-1", "confirm_password": "first-secret-1",
    })

    token2 = _csrf(client)
    resp = client.post("/signup", data={
        "csrf_token": token2, "domain": "taken.example", "password": "second-secret-2", "confirm_password": "second-secret-2",
    })
    assert resp.status_code == 400
    assert b"already registered" in resp.data

    # the original portal password must be unchanged/unusable by the second attempt
    import app.repository as repo
    from werkzeug.security import check_password_hash
    client_row = repo.get_client_by_domain("taken.example")
    assert check_password_hash(client_row["portal_password_hash"], "first-secret-1")
    assert not check_password_hash(client_row["portal_password_hash"], "second-secret-2")


def test_mismatched_passwords_rejected():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    token = _csrf(client)
    resp = client.post("/signup", data={
        "csrf_token": token, "domain": "mismatch.example", "password": "one-secret-1", "confirm_password": "two-secret-2",
    })
    assert resp.status_code == 400


def test_short_password_rejected():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    token = _csrf(client)
    resp = client.post("/signup", data={
        "csrf_token": token, "domain": "shortpw.example", "password": "short", "confirm_password": "short",
    })
    assert resp.status_code == 400


def test_invalid_domain_rejected():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    token = _csrf(client)
    resp = client.post("/signup", data={
        "csrf_token": token, "domain": "not a domain!!", "password": "valid-secret-1", "confirm_password": "valid-secret-1",
    })
    assert resp.status_code == 400


def test_signup_rate_limited_after_repeated_attempts():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    last_status = None
    for i in range(8):
        token = _csrf(client)
        resp = client.post("/signup", data={
            "csrf_token": token, "domain": f"ratelimit{i}.example",
            "password": "valid-secret-1", "confirm_password": "valid-secret-1",
        })
        last_status = resp.status_code
    assert last_status == 429


def test_signup_without_csrf_token_rejected():
    app = _fresh_app(_tmp_db())
    client = app.test_client()
    resp = client.post("/signup", data={"domain": "acme.example", "password": "x", "confirm_password": "x"})
    assert resp.status_code == 403


def test_new_signup_visible_to_operator_dashboard_immediately():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    token = _csrf(client)
    client.post("/signup", data={
        "csrf_token": token, "domain": "visible.example", "password": "valid-secret-1", "confirm_password": "valid-secret-1",
    })

    import base64
    admin = {"Authorization": "Basic " + base64.b64encode(b"admin:admin-pw").decode()}
    resp = client.get("/", headers=admin)
    assert resp.status_code == 200
    assert b"visible.example" in resp.data


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
