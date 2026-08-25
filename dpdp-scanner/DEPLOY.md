# Deploying the DPDP Drift Scanner

Two ready-to-use paths: **Fly.io** (cheapest to start) or **Railway**
(less CLI/Docker fiddling, built-in cron). Both use the same `Dockerfile`.

Either way, do this first:

```bash
# From the project root, sanity-check the image builds before pushing to a platform
docker build -t dpdp-scanner .
docker run --rm -p 5000:5000 dpdp-scanner
# visit http://localhost:5000 — you should see the (empty, or demo) client list
```

If you don't have Docker installed locally, skip straight to `fly deploy` /
Railway's GitHub-connected deploy — both build the image on their own
servers, you don't need Docker on your machine.

---

## Option A: Fly.io

Best if minimizing cost matters most. Free allowance covers a small
always-on-when-used app (`auto_stop_machines = "suspend"` in `fly.toml`
means it sleeps between visits and wakes on the next request, so idle time
costs ~nothing).

```bash
# 1. Install flyctl: https://fly.io/docs/flyctl/install/
fly auth login

# 2. Rename the app in fly.toml first — "dpdp-drift-scanner" needs to be
#    globally unique across all of Fly, it will not be free.

# 3. Create the app (skip its Dockerfile-detection prompt, we already have one)
fly launch --no-deploy

# 4. Create a persistent volume for the SQLite DB — WITHOUT this, every
#    redeploy wipes your entire scan history and client list.
fly volumes create dpdp_data --size 1 --region bom   # match fly.toml's primary_region

# 5. Set secrets (never commit these — fly.toml is version-controlled)
fly secrets set DASHBOARD_PASSWORD=change-me-to-something-real   # seeds the FIRST operator — do this before anyone else gets the URL
fly secrets set SECRET_KEY=$(python3 -c "import os; print(os.urandom(32).hex())")  # signs CSRF tokens AND client portal sessions — set this, see note below
fly secrets set GEMINI_API_KEY=your-key-here   # optional — omit to keep using the mock classifier
# See .env.example for the rest (TWILIO_*, SENTRY_DSN, SESSION_COOKIE_SECURE, ...) — all optional.

# 6. Deploy
fly deploy

# 7. Open it
fly open
```

**Weekly scan scheduling on Fly:** Fly doesn't have a dead-simple built-in
cron the way Railway does. `.github/workflows/weekly-scan.yml` is a ready
GitHub Actions workflow that wakes your Fly machine and runs `run_scan.py`
inside it on a weekly schedule — set the `FLY_API_TOKEN` repo secret (from
`fly auth token`) and edit the client list in that file. See the comments in
`fly.toml` and the workflow file for the details and a fallback if you'd
rather keep the machine always-on instead (`min_machines_running = 1`,
simpler, small extra cost).

---

## Option B: Railway

Best if you'd rather not touch a CLI much and want cron handled for you.

1. Push this project to a GitHub repo.
2. In Railway: **New Project → Deploy from GitHub repo** → pick the repo.
   Railway detects `railway.json` and the `Dockerfile` automatically.
3. **Add a persistent volume**: in the service's Settings → Volumes, mount
   one at `/app/data` (same reasoning as Fly — without it, SQLite resets on
   every redeploy).
4. **Set environment variables** in the service's Variables tab: at minimum
   `DASHBOARD_PASSWORD` (seeds the first operator — do this before anyone
   else gets the URL) and `SECRET_KEY` (signs CSRF tokens and client portal
   sessions — a random redeploy-stable value, e.g.
   `python3 -c "import os; print(os.urandom(32).hex())"`); optionally
   `GEMINI_API_KEY`, `TWILIO_ACCOUNT_SID`/`TWILIO_AUTH_TOKEN`/
   `TWILIO_WHATSAPP_FROM`, `SENTRY_DSN`, `SESSION_COOKIE_SECURE=1` (once
   served over HTTPS) — see `.env.example` for the full list.
5. **Weekly scan job** — Railway's cron is a per-service setting, not a
   config-file field (their schema for this changes across versions, so
   this is safest done in the dashboard rather than guessed at in JSON
   here): create a **second service** in the same project from the same
   repo/image, set its **Cron Schedule** (Settings → Cron Schedule, e.g.
   `0 6 * * 1` for Monday 06:00 UTC) and its **Start Command** to
   `python run_scan.py --all` — one call scans every active client already
   registered in this deployment's own database, so onboarding a new client
   never means touching this service's config.
6. **Daily health check** (optional but recommended) — a **third service**,
   same repo/image, **Cron Schedule** e.g. `0 7 * * *`, **Start Command**
   `python -m app.ops`. Exits non-zero if any client is stale or
   consistently failing — Railway surfaces a failed run in that service's
   deploy history either way.
7. Railway assigns a public URL automatically under the main
   (non-cron) service's Settings → Networking → Generate Domain.

---

## After first deploy, either platform

- Visit the dashboard URL — your browser will prompt for the first
  operator's `DASHBOARD_USERNAME` (default `admin`) / `DASHBOARD_PASSWORD`
  you set above, then confirm the client list loads (empty, unless you kept
  the demo `data/scanner.db` — see README; a fresh volume starts empty).
- Add a second operator from `/operators` if more than one person needs
  dashboard access — don't share the seeded credential between people.
- Add a client via the "+ Add Client" page, or from the CLI:
  `python run_scan.py --domain <client-domain> --whatsapp <number>` run
  through the platform's shell/SSH into the running container. Or point a
  prospective client at `/signup` to self-register (see README's "Client
  portal + self-serve signup") — either way, run their first scan yourself
  before telling them anything (see ONBOARDING.md).
- Confirm the scheduled scan job actually fires once (Fly: check the GitHub
  Actions run log; Railway: check the cron service's deploy logs) before
  trusting it unattended for a real client.

## Security note before this goes in front of any client

- `FLASK_DEBUG` must stay unset/`0` in production — see the comment in
  `app/web.py`. Neither `fly.toml` nor `railway.json` set it, which is
  correct; don't add it as an env var on either platform.
- **Set `DASHBOARD_PASSWORD` before anyone but you can reach the URL.**
  Dashboard auth (HTTP Basic, per-operator accounts, see `app/auth.py`) is
  now built in, but it's off by default until an operator exists — leaving
  it off is loud, not silent (a warning banner renders on every page and a
  warning logs on startup), but it's still on you to actually set it:
  `fly secrets set DASHBOARD_PASSWORD=...` / Railway's Variables tab. This
  only seeds the *first* operator — add more via `/operators` or
  `scripts/manage_operators.py`. See `.env.example` for the rest
  (`DASHBOARD_USERNAME`, `DASHBOARD_PASSWORD_HASH` as an alternative to a
  plaintext password).
- **Set `SECRET_KEY` too.** It signs both CSRF tokens and the client
  portal's session cookie (`app/portal.py`). Without it, a random value is
  generated per-process — CSRF tokens and every client's portal login both
  get silently invalidated on every restart/redeploy, which is confusing in
  production even though it isn't a security hole on its own.
- Every state-changing dashboard/portal/signup action (adding a client,
  marking an alert handled, a client approving a draft) is CSRF-protected
  automatically — nothing to configure there.
- The client portal and public signup are separate, unauthenticated-by-
  design entry points (`/portal/login`, `/signup`) — that's intentional,
  not a hole in the operator auth above; see `app/portal.py`'s module
  docstring for the IDOR/session-scoping model, and note both are rate-
  limited per source IP (`app/ratelimit.py`) against brute-forcing/abuse.
  That limiter is in-memory and per-process — see its own docstring for
  what that means if you ever scale past a single worker process.
- The SSRF guard (`app/agents/crawler.py`) refuses to crawl a target that
  resolves to a private/loopback/link-local/reserved address by default.
  This matters even with auth on: a typo'd or since-repointed client domain
  shouldn't be able to make this scanner fetch an internal service or a
  cloud metadata endpoint on your hosting platform. `ALLOW_PRIVATE_CRAWL_TARGETS=1`
  exists only for local fixture-site testing — never set it in a real deploy.

## Ops: health checks, backups, WhatsApp, error tracking

- **`/healthz`** — unauthenticated liveness/readiness endpoint (checks the
  DB is actually reachable). Both `fly.toml` and `railway.json` are wired
  to poll it; the Dockerfile also defines a `HEALTHCHECK` for local
  `docker run` use.
- **`python -m app.ops`** (or the dashboard's `/ops/health` JSON endpoint,
  also surfaced as a banner on the client list page) — a *separate* check
  from `/healthz`: it answers "is scanning actually keeping up with the
  weekly promise?", catching a client that's gone stale (cron silently
  stopped) or whose last few scans all failed, neither of which `/healthz`
  would ever catch since the process itself is fine either way. Wire this
  into its own daily schedule — `.github/workflows/weekly-scan.yml` now
  runs both the weekly scan AND a daily health check as two jobs in one
  workflow file.
- **Backups** — `fly volumes` / Railway's persistent volume protect against
  a redeploy wiping data, but neither is an independent backup: a deleted
  volume or a platform-account issue takes your only copy with it.
  `scripts/backup_db.py` does a safe, consistent hot-copy of the live
  SQLite DB (uses SQLite's own backup API, not a raw file copy, so it's
  correct even mid-write) to a timestamped file with automatic pruning —
  cron it daily (`python3 scripts/backup_db.py`) and point `--out` at a
  second, independent volume or synced path. For continuous, near-real-time
  off-host replication instead of periodic snapshots,
  [litestream](https://litestream.io/) is the standard tool for exactly
  this SQLite-to-S3-style-storage use case — worth adopting once there's a
  real object-storage bucket to point it at; not wired in here since that
  needs your own storage credentials to actually run.
- **Real WhatsApp sending** — set `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`,
  and `TWILIO_WHATSAPP_FROM` (all three) to switch from the simulated
  console-log alerts to real Twilio WhatsApp sending; leaving any one unset
  keeps simulation on. See `.env.example`. A failed send is recorded per
  alert (`delivery_status='failed'` in the dashboard's alert log) and never
  stops the rest of that scan's alerts/drafts from being processed.
- **Error tracking** — set `SENTRY_DSN` and add `sentry-sdk` to
  `requirements.txt` (commented out by default — see the file) to send
  unhandled exceptions to Sentry. Optional; the app runs identically without it.

## Going beyond MVP hosting

If traffic or client count grows past what a single small VM handles: the
Diff/Classifier/Crawler agents are already decoupled from the web process
(they don't share in-memory state, only the SQLite file), so the natural
next step is swapping SQLite for Postgres and moving the crawler to a
separate worker/queue (e.g. Celery + Redis, or Fly's own Machines-as-workers
pattern) rather than running Playwright inline in a web request. Not needed
for a pilot with a handful of clients — worth knowing the path exists.
