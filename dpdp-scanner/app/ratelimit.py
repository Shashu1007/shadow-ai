"""
Minimal in-memory sliding-window rate limiter for unauthenticated,
publicly-reachable POST endpoints — the client portal login and the public
self-serve signup form. There's no Redis or other shared store in this
deploy, and pulling one in purely for MVP-scale traffic (a handful of pilot
clients) would be over-engineering the wrong problem before there's a real
one. This is intentionally simple: process-local, in-memory, and it resets
on restart/redeploy.

Known limitation, stated plainly rather than glossed over: this does NOT
coordinate across multiple worker processes or dynos — if the app runs with
more than one gunicorn worker (see Dockerfile) or scales past a single
instance, each process enforces its own independent limit, so the
*effective* limit is (per-process limit) x (worker count). That's an
acceptable gap for a single-instance pilot deployment (see DEPLOY.md) but
not a real defense at scale — swap for Redis-backed limiting (e.g.
Flask-Limiter with a redis storage backend) before that matters.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

_lock = threading.Lock()
_hits: dict[str, deque] = defaultdict(deque)


def allow(key: str, max_attempts: int, window_seconds: int) -> bool:
    """True and records a hit if `key` is still under `max_attempts` within
    the trailing `window_seconds`; False (and does NOT record a hit) if the
    limit is already reached."""
    now = time.time()
    with _lock:
        dq = _hits[key]
        while dq and dq[0] <= now - window_seconds:
            dq.popleft()
        if len(dq) >= max_attempts:
            return False
        dq.append(now)
        return True


def reset_for_tests() -> None:
    """Test-only: clear all tracked state so scenarios don't bleed into
    each other across test functions sharing this process."""
    with _lock:
        _hits.clear()
