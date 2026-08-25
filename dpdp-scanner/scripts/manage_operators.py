#!/usr/bin/env python3
"""
Headless operator-account management for the dashboard's multi-operator
auth (see app/auth.py, app/db/migrations.py 0006).

Why this exists: the dashboard's own /operators page (app/web.py) needs at
least one working operator account to log in and reach it in the first
place. DASHBOARD_PASSWORD/_HASH env vars seed exactly one, on first startup
only — after that, adding, deactivating, or repassword-ing an operator
either happens through /operators (once you can log in) or here, e.g. when
you're bootstrapping a fresh deploy over SSH/a one-off shell and want a
second operator before ever loading the dashboard, or you're locked out and
need to reactivate/reset from the box directly.

Usage:
    python3 scripts/manage_operators.py add <username>              # prompts for password
    python3 scripts/manage_operators.py add <username> --password P # non-interactive (CI/scripts)
    python3 scripts/manage_operators.py list
    python3 scripts/manage_operators.py deactivate <username>
    python3 scripts/manage_operators.py reactivate <username>
    python3 scripts/manage_operators.py set-password <username>              # prompts
    python3 scripts/manage_operators.py set-password <username> --password P

--password is provided for scripted bootstrapping (e.g. a deploy step) —
prefer the interactive prompt (via getpass, never echoed, never in shell
history) whenever a human is actually running this.
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from werkzeug.security import generate_password_hash  # noqa: E402

from app.db.conn import init_db  # noqa: E402
from app import repository as repo  # noqa: E402
from app import auth  # noqa: E402


def _read_password(cli_password: str | None) -> str:
    if cli_password:
        return cli_password
    pw1 = getpass.getpass("Password: ")
    pw2 = getpass.getpass("Confirm password: ")
    if pw1 != pw2:
        print("Passwords don't match.", file=sys.stderr)
        sys.exit(1)
    return pw1


def cmd_add(args: argparse.Namespace) -> int:
    if repo.get_operator_by_username(args.username):
        print(f"An operator named {args.username!r} already exists. Use set-password to change their password.", file=sys.stderr)
        return 1
    password = _read_password(args.password)
    if len(password) < auth.MIN_PASSWORD_LENGTH:
        print(f"Password must be at least {auth.MIN_PASSWORD_LENGTH} characters.", file=sys.stderr)
        return 1
    repo.create_operator(args.username, generate_password_hash(password))
    print(f"Added operator {args.username!r}.")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    operators = repo.list_operators()
    if not operators:
        print("No operators yet — the dashboard has no auth. Run 'add' to create the first one.")
        return 0
    for o in operators:
        status = "active" if o["active"] else "deactivated"
        print(f"  {o['username']:<20} {status:<12} added {o['created_at']}")
    return 0


def _require_operator(username: str) -> dict | None:
    operator = repo.get_operator_by_username(username)
    if not operator:
        print(f"No operator named {username!r}.", file=sys.stderr)
    return operator


def cmd_deactivate(args: argparse.Namespace) -> int:
    operator = _require_operator(args.username)
    if not operator:
        return 1
    if operator["active"] and repo.count_active_operators() <= 1:
        print("Refusing to deactivate the last active operator — that would disable dashboard auth entirely. Add or reactivate another operator first.", file=sys.stderr)
        return 1
    repo.set_operator_active(operator["id"], False)
    print(f"Deactivated {args.username!r}.")
    return 0


def cmd_reactivate(args: argparse.Namespace) -> int:
    operator = _require_operator(args.username)
    if not operator:
        return 1
    repo.set_operator_active(operator["id"], True)
    print(f"Reactivated {args.username!r}.")
    return 0


def cmd_set_password(args: argparse.Namespace) -> int:
    operator = _require_operator(args.username)
    if not operator:
        return 1
    password = _read_password(args.password)
    if len(password) < auth.MIN_PASSWORD_LENGTH:
        print(f"Password must be at least {auth.MIN_PASSWORD_LENGTH} characters.", file=sys.stderr)
        return 1
    repo.set_operator_password(operator["id"], generate_password_hash(password))
    print(f"Updated password for {args.username!r}.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="Create a new operator")
    p_add.add_argument("username")
    p_add.add_argument("--password", default=None, help="Non-interactive (scripts/CI only)")
    p_add.set_defaults(func=cmd_add)

    p_list = sub.add_parser("list", help="List all operators")
    p_list.set_defaults(func=cmd_list)

    p_deact = sub.add_parser("deactivate", help="Deactivate an operator (can't deactivate the last active one)")
    p_deact.add_argument("username")
    p_deact.set_defaults(func=cmd_deactivate)

    p_react = sub.add_parser("reactivate", help="Reactivate a deactivated operator")
    p_react.add_argument("username")
    p_react.set_defaults(func=cmd_reactivate)

    p_setpw = sub.add_parser("set-password", help="Reset an operator's password")
    p_setpw.add_argument("username")
    p_setpw.add_argument("--password", default=None, help="Non-interactive (scripts/CI only)")
    p_setpw.set_defaults(func=cmd_set_password)

    args = parser.parse_args()
    init_db()  # idempotent — ensures the operators table exists before we touch it
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
