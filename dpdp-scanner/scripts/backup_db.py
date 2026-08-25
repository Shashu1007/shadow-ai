#!/usr/bin/env python3
"""
Hot-backs-up the SQLite database to a timestamped file, safely, even while
the dashboard/a scan is actively writing to it.

Why this exists: the DEPLOY.md that shipped with the original MVP relies
entirely on the hosting platform's own volume for durability (Fly/Railway
persistent volumes) — real, but a single point of failure: a volume can
still be deleted, corrupted, or lost with an account issue, and neither
platform's "the volume survives redeploys" claim is a backup strategy on
its own. This script is the missing piece: a real, independent copy.

Uses SQLite's own online backup API (`sqlite3.Connection.backup()`), NOT a
plain file copy — copying the .db file directly while WAL mode is active
(see app/db/conn.py) can grab an inconsistent snapshot if a write is
in-flight; the backup API is what SQLite itself provides specifically to
avoid that.

Usage:
    python3 scripts/backup_db.py                  # writes to data/backups/
    python3 scripts/backup_db.py --out /some/dir   # custom destination
    python3 scripts/backup_db.py --keep 14         # prune older than N backups (default 14)

Wire this into cron (daily is reasonable) and, for real off-host durability,
point the destination at a mounted/synced object-storage path — see
DEPLOY.md's backup section for the recommended approach (litestream) for
continuous, off-host replication instead of periodic snapshots like this one.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.conn import DB_PATH  # noqa: E402


def backup_once(dest_dir: Path) -> Path:
    if not DB_PATH.exists():
        raise FileNotFoundError(f"No database at {DB_PATH} — nothing to back up yet.")

    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest_path = dest_dir / f"scanner-{stamp}.db"

    source = sqlite3.connect(DB_PATH)
    dest = sqlite3.connect(dest_path)
    try:
        source.backup(dest)
    finally:
        dest.close()
        source.close()

    return dest_path


def prune_old_backups(dest_dir: Path, keep: int) -> list[Path]:
    backups = sorted(dest_dir.glob("scanner-*.db"))
    to_remove = backups[:-keep] if keep > 0 and len(backups) > keep else []
    for p in to_remove:
        p.unlink()
    return to_remove


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=str(DB_PATH.parent / "backups"), help="Backup destination directory")
    parser.add_argument("--keep", type=int, default=14, help="Number of most-recent backups to retain (0 = keep all)")
    args = parser.parse_args()

    dest_dir = Path(args.out)
    try:
        dest_path = backup_once(dest_dir)
    except FileNotFoundError as e:
        print(str(e))
        return 1

    size_kb = dest_path.stat().st_size / 1024
    print(f"Backed up {DB_PATH} -> {dest_path} ({size_kb:.1f} KB)")

    removed = prune_old_backups(dest_dir, args.keep)
    if removed:
        print(f"Pruned {len(removed)} older backup(s), keeping the most recent {args.keep}.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
