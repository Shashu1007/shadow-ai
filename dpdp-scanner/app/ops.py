"""
Ops self-check — answers "is the scanner itself healthy?" as distinct from
"/healthz", which only answers "is the process up and can it reach its own
DB?". A client whose site has been unreachable for three scans running, or
who hasn't been scanned at all in two weeks because a cron job silently
stopped firing, will pass /healthz every single time — the process is fine,
the DB is fine, nothing crashed. This is the check that's actually meant to
catch that class of "technically running, not doing its job" failure.

Meant to be run on its own schedule (daily is plenty — see
`python -m app.ops` / DEPLOY.md), separate from the weekly scan cron.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TypedDict

from app import repository as repo
from app.config import STALE_SCAN_THRESHOLD_DAYS, CONSECUTIVE_FAILURE_WINDOW


class HealthIssue(TypedDict):
    client_id: int
    domain: str
    kind: str  # "stale" | "consecutive_failures" | "never_scanned"
    detail: str


def _parse_ts(ts: str) -> datetime:
    # SQLite's datetime('now') default produces "YYYY-MM-DD HH:MM:SS" (UTC,
    # naive). Treat it as UTC explicitly rather than relying on the local
    # server timezone matching, which would silently be wrong on a host set
    # to IST or anything else.
    dt = datetime.fromisoformat(ts.replace("Z", ""))
    return dt.replace(tzinfo=timezone.utc)


def check_fleet_health() -> list[HealthIssue]:
    """Runs the self-check across every active client. Returns a list of
    issues — empty means everything looks healthy."""
    issues: list[HealthIssue] = []
    now = datetime.now(timezone.utc)

    for client in repo.list_active_clients():
        recent = repo.list_recent_scan_failures(client["id"], limit=CONSECUTIVE_FAILURE_WINDOW)

        if not recent:
            issues.append(HealthIssue(
                client_id=client["id"], domain=client["domain"], kind="never_scanned",
                detail="Client is active but has never been scanned.",
            ))
            continue

        last_scan = recent[0]
        age_days = (now - _parse_ts(last_scan["scanned_at"])).days
        if age_days > STALE_SCAN_THRESHOLD_DAYS:
            issues.append(HealthIssue(
                client_id=client["id"], domain=client["domain"], kind="stale",
                detail=f"Last scan was {age_days} days ago (threshold: {STALE_SCAN_THRESHOLD_DAYS}). "
                       f"Check the cron/scheduled job is still firing.",
            ))

        if len(recent) >= CONSECUTIVE_FAILURE_WINDOW and all(s["status"] == "failed" for s in recent):
            issues.append(HealthIssue(
                client_id=client["id"], domain=client["domain"], kind="consecutive_failures",
                detail=f"The last {len(recent)} scans all failed. Last error: {last_scan.get('error_message')!r}",
            ))

    return issues


def _main() -> int:
    from app.db.conn import init_db
    from app.logging_setup import setup_logging
    setup_logging()
    init_db()

    issues = check_fleet_health()
    if not issues:
        print("Fleet health: OK — no stale or consistently-failing clients.")
        return 0

    print(f"Fleet health: {len(issues)} issue(s) found:\n")
    for issue in issues:
        print(f"  [{issue['kind']}] {issue['domain']} (client_id={issue['client_id']}): {issue['detail']}")
    return 1


if __name__ == "__main__":
    import sys
    sys.exit(_main())
