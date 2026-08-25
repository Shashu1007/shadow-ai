#!/usr/bin/env python3
"""
CLI entry point to run a scan for one client, or every active client.

Usage:
    python run_scan.py --domain example.com [--whatsapp +919999999999] [--start-url http://localhost:8899/]
    python run_scan.py --all   # scan every active (non-paused) client already in the DB

For real weekly scans, schedule this with cron, e.g.:
    0 6 * * 1  cd /path/to/dpdp-scanner && python3 run_scan.py --all >> logs/scan.log 2>&1

--all is what makes a real weekly cron job viable with more than one client:
each client's scan is isolated (see app/orchestrator.py's module docstring)
so client #4's site being down doesn't stop #5 and #6 from being scanned,
and the run always exits 0 unless something more fundamental broke (DB
unreachable) — a handful of failed individual scans is reported, not a
crashed cron job. Check the exit code AND the printed summary either way;
"exit 0" only means the run completed, not that every client succeeded.
"""
import argparse
import logging
import sys

from app.db.conn import init_db
from app import repository as repo
from app.logging_setup import setup_logging
from app.orchestrator import run_scan_for_client


def _print_summary(result: dict) -> None:
    if not result.get("success", True):
        print(f"Client:        {result['domain']} (id={result['client_id']})")
        print(f"Scan ID:       {result['scan_id']}  *** FAILED ***")
        print(f"Error:         {result['error']}")
        print()
        return

    print(f"Client:        {result['domain']} (id={result['client_id']})")
    print(f"Scan ID:       {result['scan_id']}{'  (first scan — baseline only, alerts suppressed)' if result['is_first_scan'] else ''}")
    print(f"Pages crawled: {result['page_count']}")
    print(f"Findings:      {result['finding_count']}")
    print(f"Diff severity: {result['severity'].upper()}")
    print(f"  new: {result['new_count']}  changed: {result['changed_count']}  removed: {result['removed_count']}")
    print(f"Alerts sent:   {len(result['alerts_sent'])}")
    for a in result["alerts_sent"]:
        print(f"  [{a['severity'].upper()}] {a['message'].splitlines()[1] if len(a['message'].splitlines()) > 1 else a['message']}")
    print(f"Drafts created: {result['drafts_created']}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Run a DPDP drift scan for one client, or every active client.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--domain", help="Client domain, e.g. example.com")
    group.add_argument("--all", action="store_true", help="Scan every active (non-paused) client already registered")
    parser.add_argument("--whatsapp", default=None, help="Client WhatsApp number for alerts (only used with --domain)")
    parser.add_argument(
        "--start-url", default=None,
        help="Override crawl entry URL (defaults to https://<domain>/). Useful for local test fixtures. Only used with --domain.",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    setup_logging(verbose=args.verbose)
    logger = logging.getLogger("run_scan")

    init_db()

    print("\n=== Scan summary ===")

    if args.domain:
        result = run_scan_for_client(args.domain, whatsapp_number=args.whatsapp, start_url=args.start_url)
        _print_summary(result)
        return 0 if result.get("success", True) else 1

    # --all: one client's failure must not stop the rest, and must not
    # abort the run — see module docstring.
    clients = repo.list_active_clients()
    if not clients:
        print("No active clients registered. Add one from the dashboard or with --domain first.")
        return 0

    failures = 0
    for c in clients:
        try:
            result = run_scan_for_client(c["domain"], whatsapp_number=c.get("whatsapp_number"))
        except Exception as e:
            # Belt-and-suspenders: run_scan_for_client already isolates
            # ordinary scan failures internally (returns success=False
            # instead of raising) — this only catches something more
            # fundamental (e.g. the DB itself becoming unreachable
            # mid-run), which still shouldn't take out the rest of the fleet.
            logger.exception("Unexpected error scanning client %s (id=%s) — continuing with the rest", c["domain"], c["id"])
            print(f"Client:        {c['domain']} (id={c['id']})  *** UNEXPECTED FAILURE ***")
            print(f"Error:         {e}\n")
            failures += 1
            continue

        _print_summary(result)
        if not result.get("success", True):
            failures += 1

    print(f"=== {len(clients)} client(s) scanned, {failures} failure(s) ===")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
