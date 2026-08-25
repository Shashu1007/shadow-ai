"""Tests for scripts/backup_db.py — the SQLite hot-backup + retention script."""
import importlib.util
import sqlite3
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def _load_backup_module(db_path: Path):
    """scripts/backup_db.py isn't a package member (it's a standalone CLI
    script), and it reads app.db.conn.DB_PATH at import time — so point
    DB_PATH at a throwaway DB before importing it, same pattern as the
    other test files' _fresh_env helpers."""
    for mod in list(sys.modules):
        if mod == "app" or mod.startswith("app.") or mod == "backup_db":
            sys.modules.pop(mod, None)
    import app.db.conn as conn_mod
    conn_mod.DB_PATH = db_path
    conn_mod.init_db()

    spec = importlib.util.spec_from_file_location("backup_db", REPO_ROOT / "scripts" / "backup_db.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_backup_copies_data_correctly():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db_path = tmp / "scanner.db"
        backup_mod = _load_backup_module(db_path)

        import app.repository as repo
        repo.create_client("backup-test.example")

        dest_dir = tmp / "backups"
        backup_path = backup_mod.backup_once(dest_dir)

        assert backup_path.exists()
        conn = sqlite3.connect(backup_path)
        try:
            row = conn.execute("SELECT domain FROM clients WHERE domain = 'backup-test.example'").fetchone()
            assert row is not None, "backed-up DB must contain the same data as the source"
        finally:
            conn.close()


def test_backup_missing_db_raises_cleanly():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db_path = tmp / "does-not-exist.db"
        backup_mod = _load_backup_module(db_path)
        # init_db() in _load_backup_module already created it — delete it
        # again to actually exercise the "no DB yet" path.
        db_path.unlink()

        raised = False
        try:
            backup_mod.backup_once(tmp / "backups")
        except FileNotFoundError:
            raised = True
        assert raised


def test_prune_keeps_only_most_recent_n():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db_path = tmp / "scanner.db"
        backup_mod = _load_backup_module(db_path)
        dest_dir = tmp / "backups"
        dest_dir.mkdir()

        # Create 5 fake backup files with distinct, sortable names.
        for i in range(5):
            (dest_dir / f"scanner-2026010{i}T000000Z.db").write_text("fake")

        removed = backup_mod.prune_old_backups(dest_dir, keep=2)
        remaining = sorted(p.name for p in dest_dir.glob("scanner-*.db"))
        assert len(remaining) == 2
        assert remaining == ["scanner-20260103T000000Z.db", "scanner-20260104T000000Z.db"], \
            "must keep the most recent, not an arbitrary 2"
        assert len(removed) == 3


def test_prune_keep_zero_means_keep_all():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db_path = tmp / "scanner.db"
        backup_mod = _load_backup_module(db_path)
        dest_dir = tmp / "backups"
        dest_dir.mkdir()
        for i in range(3):
            (dest_dir / f"scanner-2026010{i}T000000Z.db").write_text("fake")

        removed = backup_mod.prune_old_backups(dest_dir, keep=0)
        assert removed == []
        assert len(list(dest_dir.glob("scanner-*.db"))) == 3


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
