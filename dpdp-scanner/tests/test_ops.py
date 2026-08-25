"""
Tests for the ops self-check (app/ops.py) — distinct from /healthz, this is
what's supposed to catch "the process is fine but the scanner silently
stopped doing its job" (stale clients, a client whose last few scans all
failed, an active client that was never scanned at all).
"""
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _fresh_env():
    for mod in list(sys.modules):
        if mod == "app" or mod.startswith("app."):
            sys.modules.pop(mod, None)
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    import app.db.conn as conn_mod
    conn_mod.DB_PATH = Path(path)
    conn_mod.init_db()
    import app.repository as repo
    import app.ops as ops
    return repo, ops, path


def _set_scanned_at(db_path: str, scan_id: int, when: datetime) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("UPDATE scans SET scanned_at = ? WHERE id = ?", (when.strftime("%Y-%m-%d %H:%M:%S"), scan_id))
        conn.commit()
    finally:
        conn.close()


def test_never_scanned_active_client_flagged():
    repo, ops, path = _fresh_env()
    repo.create_client("never-scanned.example")
    issues = ops.check_fleet_health()
    assert any(i["kind"] == "never_scanned" and i["domain"] == "never-scanned.example" for i in issues)


def test_recently_scanned_healthy_client_not_flagged():
    repo, ops, path = _fresh_env()
    client = repo.get_or_create_client("healthy.example")
    scan_id = repo.create_scan(client["id"], page_count=3, raw_findings={}, status="completed")
    _set_scanned_at(path, scan_id, datetime.now(timezone.utc))
    issues = ops.check_fleet_health()
    assert not any(i["domain"] == "healthy.example" for i in issues)


def test_stale_client_flagged():
    repo, ops, path = _fresh_env()
    client = repo.get_or_create_client("stale.example")
    scan_id = repo.create_scan(client["id"], page_count=3, raw_findings={}, status="completed")
    old = datetime.now(timezone.utc) - timedelta(days=ops.STALE_SCAN_THRESHOLD_DAYS + 5)
    _set_scanned_at(path, scan_id, old)
    issues = ops.check_fleet_health()
    stale = [i for i in issues if i["domain"] == "stale.example" and i["kind"] == "stale"]
    assert len(stale) == 1


def test_consecutive_failures_flagged():
    repo, ops, path = _fresh_env()
    client = repo.get_or_create_client("flaky.example")
    for _ in range(ops.CONSECUTIVE_FAILURE_WINDOW):
        scan_id = repo.create_scan(client["id"], page_count=0, raw_findings={}, status="failed", error_message="site down")
        _set_scanned_at(path, scan_id, datetime.now(timezone.utc))
    issues = ops.check_fleet_health()
    failures = [i for i in issues if i["domain"] == "flaky.example" and i["kind"] == "consecutive_failures"]
    assert len(failures) == 1
    assert "site down" in failures[0]["detail"]


def test_one_failure_among_successes_not_flagged_as_consecutive():
    repo, ops, path = _fresh_env()
    client = repo.get_or_create_client("mostly-fine.example")
    s1 = repo.create_scan(client["id"], page_count=3, raw_findings={}, status="completed")
    _set_scanned_at(path, s1, datetime.now(timezone.utc) - timedelta(days=2))
    s2 = repo.create_scan(client["id"], page_count=0, raw_findings={}, status="failed", error_message="blip")
    _set_scanned_at(path, s2, datetime.now(timezone.utc) - timedelta(days=1))
    s3 = repo.create_scan(client["id"], page_count=3, raw_findings={}, status="completed")
    _set_scanned_at(path, s3, datetime.now(timezone.utc))
    issues = ops.check_fleet_health()
    assert not any(i["domain"] == "mostly-fine.example" for i in issues)


def test_paused_client_excluded_from_check():
    repo, ops, path = _fresh_env()
    client = repo.get_or_create_client("paused.example")
    repo.set_client_active(client["id"], False)
    issues = ops.check_fleet_health()
    assert not any(i["domain"] == "paused.example" for i in issues)


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
        except AssertionError as e:
            print(f"FAIL {t.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR {t.__name__}: {e!r}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
