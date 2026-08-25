"""
Tests for the client-facing portal (app/portal.py): session login scoped to
one client, read-only views, and draft approve/reject as a real, audited,
IDOR-safe action. Same fresh-reimport pattern as tests/test_web_auth.py.
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
    import app.ratelimit as ratelimit_mod
    ratelimit_mod.reset_for_tests()
    import app.web as webmod
    return webmod.app


def _tmp_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    return path


def _basic(username: str, password: str) -> dict:
    return {"Authorization": "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()}


def _csrf(client, get_path, headers=None) -> str:
    resp = client.get(get_path, headers=headers or {})
    return re.search(rb'name="csrf_token" value="([^"]+)"', resp.data).group(1).decode()


def _make_client_with_portal_password(app, admin_headers, test_client, domain="acme.example", password="portal-secret-1"):
    """Creates a client via the operator dashboard and sets its portal
    password, returning the client_id."""
    token = _csrf(test_client, "/clients/new", headers=admin_headers)
    resp = test_client.post("/clients/new", data={"domain": domain, "csrf_token": token}, headers=admin_headers)
    client_id = int(resp.headers["Location"].rstrip("/").rsplit("/", 1)[-1])

    token2 = _csrf(test_client, f"/clients/{client_id}", headers=admin_headers)
    test_client.post(
        f"/clients/{client_id}/portal-password",
        data={"csrf_token": token2, "portal_password": password},
        headers=admin_headers,
    )
    return client_id


def _seed_draft(client_id: int) -> int:
    """Creates a scan + finding + draft directly via the repository, since
    only the orchestrator normally produces these — tests need one to exist
    to exercise approve/reject."""
    import app.repository as repo
    scan_id = repo.create_scan(client_id, page_count=1, raw_findings={})
    repo.bulk_insert_findings(scan_id, [{
        "url": "https://acme.example/signup", "type": "form_field", "detail": "input name=email",
        "detail_hash": "h1", "data_category": "contact", "dpdp_relevance": "notice", "confidence": "high",
    }])
    finding_id = repo.get_findings_for_scan(scan_id)[0]["id"]
    return repo.create_draft(client_id, finding_id, "notice_paragraph", "We collect your email address for account signup.")


def test_login_page_loads_without_auth():
    app = _fresh_app(_tmp_db())
    client = app.test_client()
    assert client.get("/portal/login").status_code == 200


def test_dashboard_redirects_to_login_when_not_authenticated():
    app = _fresh_app(_tmp_db())
    client = app.test_client()
    resp = client.get("/portal/")
    assert resp.status_code == 302
    assert "/portal/login" in resp.headers["Location"]


def test_successful_login_reaches_dashboard_scoped_to_that_client():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    test_client = app.test_client()
    admin = _basic("admin", "admin-pw")
    _make_client_with_portal_password(app, admin, test_client, domain="acme.example", password="portal-secret-1")

    token = _csrf(test_client, "/portal/login")
    resp = test_client.post("/portal/login", data={"csrf_token": token, "domain": "acme.example", "password": "portal-secret-1"})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/portal/")

    dash = test_client.get("/portal/")
    assert dash.status_code == 200
    assert b"acme.example" in dash.data


def test_wrong_password_rejected():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    test_client = app.test_client()
    admin = _basic("admin", "admin-pw")
    _make_client_with_portal_password(app, admin, test_client, domain="acme.example", password="portal-secret-1")

    token = _csrf(test_client, "/portal/login")
    resp = test_client.post("/portal/login", data={"csrf_token": token, "domain": "acme.example", "password": "wrong"})
    assert resp.status_code == 401
    assert test_client.get("/portal/").status_code == 302  # still not logged in


def test_nonexistent_domain_rejected_same_as_wrong_password():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    test_client = app.test_client()
    token = _csrf(test_client, "/portal/login")
    resp = test_client.post("/portal/login", data={"csrf_token": token, "domain": "no-such-client.example", "password": "whatever"})
    assert resp.status_code == 401
    assert b"Incorrect domain or password" in resp.data


def test_client_with_no_portal_password_set_cannot_log_in():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    test_client = app.test_client()
    admin = _basic("admin", "admin-pw")
    token = _csrf(test_client, "/clients/new", headers=admin)
    test_client.post("/clients/new", data={"domain": "nopassword.example", "csrf_token": token}, headers=admin)

    token2 = _csrf(test_client, "/portal/login")
    resp = test_client.post("/portal/login", data={"csrf_token": token2, "domain": "nopassword.example", "password": "anything"})
    assert resp.status_code == 401


def test_login_rate_limited_after_repeated_failures():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    test_client = app.test_client()
    admin = _basic("admin", "admin-pw")
    _make_client_with_portal_password(app, admin, test_client, domain="acme.example", password="portal-secret-1")

    last_status = None
    for _ in range(15):
        token = _csrf(test_client, "/portal/login")
        resp = test_client.post("/portal/login", data={"csrf_token": token, "domain": "acme.example", "password": "wrong"})
        last_status = resp.status_code
    assert last_status == 429


def test_logout_clears_session():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    test_client = app.test_client()
    admin = _basic("admin", "admin-pw")
    _make_client_with_portal_password(app, admin, test_client, domain="acme.example", password="portal-secret-1")

    token = _csrf(test_client, "/portal/login")
    test_client.post("/portal/login", data={"csrf_token": token, "domain": "acme.example", "password": "portal-secret-1"})
    assert test_client.get("/portal/").status_code == 200

    token2 = _csrf(test_client, "/portal/")
    resp = test_client.post("/portal/logout", data={"csrf_token": token2})
    assert resp.status_code == 302
    assert test_client.get("/portal/").status_code == 302


def test_client_a_cannot_see_or_act_on_client_bs_draft():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    test_client = app.test_client()
    admin = _basic("admin", "admin-pw")

    client_a_id = _make_client_with_portal_password(app, admin, test_client, domain="a.example", password="a-secret-pw")
    client_b_id = _make_client_with_portal_password(app, admin, test_client, domain="b.example", password="b-secret-pw")
    draft_b_id = _seed_draft(client_b_id)

    # Log in as client A
    token = _csrf(test_client, "/portal/login")
    test_client.post("/portal/login", data={"csrf_token": token, "domain": "a.example", "password": "a-secret-pw"})

    # A's drafts view must not show B's draft content
    drafts_resp = test_client.get("/portal/drafts")
    assert b"email address for account signup" not in drafts_resp.data

    # A attempting to decide B's draft_id directly must not succeed
    token2 = _csrf(test_client, "/portal/drafts")
    test_client.post(f"/portal/drafts/{draft_b_id}/decide", data={"csrf_token": token2, "decision": "approved"})

    import app.repository as repo
    still_pending = repo.get_draft(draft_b_id)
    assert still_pending["status"] == "draft"
    assert still_pending["decided_by"] is None


def test_client_can_approve_own_draft_and_it_is_audited():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    test_client = app.test_client()
    admin = _basic("admin", "admin-pw")
    client_id = _make_client_with_portal_password(app, admin, test_client, domain="acme.example", password="portal-secret-1")
    draft_id = _seed_draft(client_id)

    token = _csrf(test_client, "/portal/login")
    test_client.post("/portal/login", data={"csrf_token": token, "domain": "acme.example", "password": "portal-secret-1"})

    token2 = _csrf(test_client, "/portal/drafts")
    resp = test_client.post(f"/portal/drafts/{draft_id}/decide", data={"csrf_token": token2, "decision": "approved"})
    assert resp.status_code == 302

    import app.repository as repo
    decided = repo.get_draft(draft_id)
    assert decided["status"] == "approved"
    assert decided["decided_by"] == "client"
    assert decided["decided_at"] is not None


def test_cannot_redecide_an_already_decided_draft():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    test_client = app.test_client()
    admin = _basic("admin", "admin-pw")
    client_id = _make_client_with_portal_password(app, admin, test_client, domain="acme.example", password="portal-secret-1")
    draft_id = _seed_draft(client_id)

    token = _csrf(test_client, "/portal/login")
    test_client.post("/portal/login", data={"csrf_token": token, "domain": "acme.example", "password": "portal-secret-1"})

    token2 = _csrf(test_client, "/portal/drafts")
    test_client.post(f"/portal/drafts/{draft_id}/decide", data={"csrf_token": token2, "decision": "approved"})

    token3 = _csrf(test_client, "/portal/drafts")
    test_client.post(f"/portal/drafts/{draft_id}/decide", data={"csrf_token": token3, "decision": "rejected"})

    import app.repository as repo
    still_approved = repo.get_draft(draft_id)
    assert still_approved["status"] == "approved"  # the second (rejected) call must not have overwritten it


def test_portal_post_without_csrf_token_rejected():
    app = _fresh_app(_tmp_db())
    test_client = app.test_client()
    resp = test_client.post("/portal/login", data={"domain": "acme.example", "password": "x"})
    assert resp.status_code == 403


def test_revoking_portal_password_logs_out_effectively():
    app = _fresh_app(_tmp_db(), DASHBOARD_PASSWORD="admin-pw")
    test_client = app.test_client()
    admin = _basic("admin", "admin-pw")
    client_id = _make_client_with_portal_password(app, admin, test_client, domain="acme.example", password="portal-secret-1")

    token = _csrf(test_client, "/portal/login")
    test_client.post("/portal/login", data={"csrf_token": token, "domain": "acme.example", "password": "portal-secret-1"})
    assert test_client.get("/portal/").status_code == 200

    # Operator revokes access (blank password submission)
    token2 = _csrf(test_client, f"/clients/{client_id}", headers=admin)
    test_client.post(f"/clients/{client_id}/portal-password", data={"csrf_token": token2, "portal_password": ""}, headers=admin)

    # The client's existing session must no longer grant access
    assert test_client.get("/portal/").status_code == 302


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
