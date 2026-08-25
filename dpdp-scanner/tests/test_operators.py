"""
Tests for real multi-operator dashboard accounts (app/auth.py DB-backed
auth, app/web.py /operators routes, app/db/migrations.py 0006).

Same fresh-reimport pattern as tests/test_web_auth.py — see that file's
docstring for why the whole app.* namespace has to be dropped, not just
leaf modules, to force config to re-read from a clean env/DB per test.
"""
import base64
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
    import app.web as webmod
    return webmod.app


def _tmp_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    return path


def _basic(username: str, password: str) -> dict:
    return {"Authorization": "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()}


def _csrf(client, get_path="/clients/new", headers=None) -> str:
    resp = client.get(get_path, headers=headers or {})
    return re.search(rb'name="csrf_token" value="([^"]+)"', resp.data).group(1).decode()


def test_second_operator_can_be_added_and_login_independently():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    admin = _basic("admin", "admin-pw")

    token = _csrf(client, "/operators", headers=admin)
    resp = client.post(
        "/operators/new",
        data={"csrf_token": token, "username": "priya", "password": "priya-secret"},
        headers=admin,
    )
    assert resp.status_code == 302

    priya = _basic("priya", "priya-secret")
    assert client.get("/", headers=priya).status_code == 200
    # admin's own creds still work — adding a second operator doesn't revoke the first
    assert client.get("/", headers=admin).status_code == 200


def test_wrong_password_for_second_operator_rejected():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    admin = _basic("admin", "admin-pw")
    token = _csrf(client, "/operators", headers=admin)
    client.post("/operators/new", data={"csrf_token": token, "username": "priya", "password": "priya-secret"}, headers=admin)

    bad = _basic("priya", "wrong-password")
    assert client.get("/", headers=bad).status_code == 401


def test_deactivated_operator_loses_access_others_unaffected():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    admin = _basic("admin", "admin-pw")
    token = _csrf(client, "/operators", headers=admin)
    client.post("/operators/new", data={"csrf_token": token, "username": "raj", "password": "raj-secret"}, headers=admin)

    import app.repository as repo
    raj = repo.get_operator_by_username("raj")

    token2 = _csrf(client, "/operators", headers=admin)
    resp = client.post(f"/operators/{raj['id']}/toggle-active", data={"csrf_token": token2}, headers=admin)
    assert resp.status_code == 302

    raj_creds = _basic("raj", "raj-secret")
    assert client.get("/", headers=raj_creds).status_code == 401
    # admin, untouched, still works
    assert client.get("/", headers=admin).status_code == 200


def test_cannot_deactivate_last_active_operator():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    admin = _basic("admin", "admin-pw")

    import app.repository as repo
    only_op = repo.get_operator_by_username("admin")
    token = _csrf(client, "/operators", headers=admin)
    resp = client.post(f"/operators/{only_op['id']}/toggle-active", data={"csrf_token": token}, headers=admin)
    assert resp.status_code == 400
    # still active — the refusal must actually have prevented it, not just returned 400
    assert repo.get_operator_by_username("admin")["active"] == 1
    assert client.get("/", headers=admin).status_code == 200


def test_duplicate_username_rejected():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    admin = _basic("admin", "admin-pw")
    token = _csrf(client, "/operators", headers=admin)
    resp = client.post("/operators/new", data={"csrf_token": token, "username": "admin", "password": "another-secret"}, headers=admin)
    assert resp.status_code == 400
    assert b"already exists" in resp.data


def test_short_password_rejected_on_add():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    admin = _basic("admin", "admin-pw")
    token = _csrf(client, "/operators", headers=admin)
    resp = client.post("/operators/new", data={"csrf_token": token, "username": "newop", "password": "short"}, headers=admin)
    assert resp.status_code == 400


def test_env_password_only_seeds_first_operator_does_not_reset_on_restart():
    db_path = _tmp_db()
    app1 = _fresh_app(db_path, DASHBOARD_PASSWORD="first-password")
    client1 = app1.test_client()
    assert client1.get("/", headers=_basic("admin", "first-password")).status_code == 200

    # "restart" with a different DASHBOARD_PASSWORD — must NOT silently change
    # the already-seeded operator's password (that would let anyone who
    # controls the env at redeploy time reset every operator's credentials).
    app2 = _fresh_app(db_path, DASHBOARD_PASSWORD="second-password")
    client2 = app2.test_client()
    assert client2.get("/", headers=_basic("admin", "first-password")).status_code == 200
    assert client2.get("/", headers=_basic("admin", "second-password")).status_code == 401


def test_portal_password_set_and_revoke():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    admin = _basic("admin", "admin-pw")

    token = _csrf(client, "/clients/new", headers=admin)
    resp = client.post("/clients/new", data={"domain": "example.com", "csrf_token": token}, headers=admin)
    client_id = int(resp.headers["Location"].rstrip("/").rsplit("/", 1)[-1])

    import app.repository as repo
    assert repo.get_client(client_id)["portal_password_hash"] is None

    token2 = _csrf(client, f"/clients/{client_id}", headers=admin)
    resp = client.post(
        f"/clients/{client_id}/portal-password",
        data={"csrf_token": token2, "portal_password": "client-secret-pw"},
        headers=admin,
    )
    assert resp.status_code == 302
    assert repo.get_client(client_id)["portal_password_hash"] is not None

    # blank submission revokes access
    token3 = _csrf(client, f"/clients/{client_id}", headers=admin)
    resp = client.post(
        f"/clients/{client_id}/portal-password",
        data={"csrf_token": token3, "portal_password": ""},
        headers=admin,
    )
    assert resp.status_code == 302
    assert repo.get_client(client_id)["portal_password_hash"] is None


def test_short_portal_password_rejected():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    client = app.test_client()
    admin = _basic("admin", "admin-pw")
    token = _csrf(client, "/clients/new", headers=admin)
    resp = client.post("/clients/new", data={"domain": "example.com", "csrf_token": token}, headers=admin)
    client_id = int(resp.headers["Location"].rstrip("/").rsplit("/", 1)[-1])

    token2 = _csrf(client, f"/clients/{client_id}", headers=admin)
    resp = client.post(
        f"/clients/{client_id}/portal-password",
        data={"csrf_token": token2, "portal_password": "short"},
        headers=admin,
    )
    assert resp.status_code == 400


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
