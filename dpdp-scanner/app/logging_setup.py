"""
Shared logging configuration for both entry points (run_scan.py and the
Flask dashboard). Previously run_scan.py called logging.basicConfig()
directly and app.web relied on Flask's own default handler — meaning a
production deploy had no single place to turn on file rotation or hook up
error tracking. Centralizing it here means both entry points get the same
behavior from the same env vars.

Defaults to stdout-only logging (the 12-factor-app way — correct for
Fly/Railway, which both capture stdout directly), with optional rotating
file output for anyone running this via plain cron on a VM instead
(matches the README's original `>> logs/scan.log` pattern, now with
rotation instead of an ever-growing file).
"""
from __future__ import annotations

import logging
import logging.handlers
import sys

from app.config import (
    LOG_LEVEL, LOG_FILE, LOG_FILE_MAX_BYTES, LOG_FILE_BACKUP_COUNT, SENTRY_DSN,
)

_configured = False


def setup_logging(verbose: bool = False) -> None:
    global _configured
    if _configured:
        return
    _configured = True

    level = logging.DEBUG if verbose else getattr(logging, LOG_LEVEL, logging.INFO)
    fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if LOG_FILE:
        handlers.append(
            logging.handlers.RotatingFileHandler(
                LOG_FILE, maxBytes=LOG_FILE_MAX_BYTES, backupCount=LOG_FILE_BACKUP_COUNT,
            )
        )

    logging.basicConfig(level=level, format=fmt, handlers=handlers, force=True)

    _setup_sentry()


def _setup_sentry() -> None:
    """Optional error tracking. Only activates if SENTRY_DSN is set AND the
    sentry-sdk package is installed — neither is required for this project
    to run, so a missing package degrades to a logged warning, not a crash."""
    if not SENTRY_DSN:
        return
    try:
        import sentry_sdk
        sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=0.0)
        logging.getLogger("logging_setup").info("Sentry error tracking enabled")
    except ImportError:
        logging.getLogger("logging_setup").warning(
            "SENTRY_DSN is set but the 'sentry-sdk' package isn't installed — "
            "add it to requirements.txt to enable error tracking. Continuing without it."
        )
    except Exception:
        logging.getLogger("logging_setup").exception("Failed to initialize Sentry — continuing without it")
