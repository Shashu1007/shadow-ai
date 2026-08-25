# DPDP Drift Scanner — MVP

Crawls a client's website on a schedule, extracts everything that counts as a
"personal data collection point" or a "third-party data flow" under India's
DPDP Act, snapshots it, and diffs each new crawl against the last one. New
form field, new tracker, consent banner broken, privacy policy changed —
each fires a plain-English alert with the specific DPDP obligation it touches.

**The pitch:** Everyone else audits you once. We watch your site every week.

This build follows `dpdp-scanner-mvp-spec.md` (project docs) and implements
the v1 scope: form fields, cookies, third-party scripts, consent banner,
privacy policy. Login-flow / subdomain discovery are intentionally deferred
(v1.5+ per spec) — see "Scope notes" below.

---

## Architecture

Four agents, sequential, one client per run — same shape as any supervisor/
worker pipeline:

```
Crawler Agent  →  Classifier Agent  →  Diff Agent  →  Notifier Agent
(Playwright)      (Gemini or          (pure code,     (WhatsApp-style
                   rule-based mock)    no LLM)          alert + dashboard
                                                         + draft notices)
```

- **`app/agents/crawler.py`** — headless Playwright crawl, depth-limited,
  robots.txt-respecting, rate-limited. Captures forms/fields, cookies (1P vs
  3P), `<script src>` + network-observed third-party domains, consent banner
  presence, privacy policy page + content hash. Refuses to crawl a target
  that resolves to a private/loopback/link-local/reserved address (an SSRF
  guard — see `_validate_crawl_target`), so a typo'd or since-repointed
  client domain can't make the scanner fetch an internal service.
- **`app/agents/classifier.py`** — tags each finding with a DPDP data
  category and obligation. **Swappable backend**: set `GEMINI_API_KEY` to use
  a real Gemini JSON-mode call (retried with backoff on transient
  failures; every field validated against the schema before use, so one
  malformed item in a response can't discard the whole page's good
  findings); without it, a deterministic rule-based mock classifier runs
  instead. Both paths emit the same schema, so nothing downstream cares
  which one ran. Low-confidence findings are routed to a human review queue
  AND excluded from client-facing alerts regardless of severity (see
  Guardrails below).
- **`app/agents/differ.py`** — pure code, no LLM. Compares this scan's
  findings against the client's last snapshot (matched on a normalized
  `detail_hash`) and produces `new` / `changed` / `removed` lists with
  High/Medium/Low severity per the spec's rules.
- **`app/agents/notifier.py`** — formats the WhatsApp-style alert (High/Medium
  only — Low is dashboard-only, no alert). **Swappable channel**: real
  Twilio WhatsApp sending when `TWILIO_ACCOUNT_SID`/`TWILIO_AUTH_TOKEN`/
  `TWILIO_WHATSAPP_FROM` are all set, otherwise the original console-log +
  dashboard-only simulation (`channel=whatsapp_sim`). A failed send is
  recorded per-alert and never stops the rest of that scan. Also auto-drafts
  (never auto-publishes) a privacy-notice paragraph + data-inventory row for
  new notice/consent findings.

`app/orchestrator.py` wires all four together, persists every stage to
SQLite for the audit trail, and isolates failures per-stage (a bad crawl
target is recorded as a failed scan, not an uncaught crash — see
"Robustness" below). `app/web.py` is a small, **authenticated** Flask
dashboard (see Security below) for browsing clients, scan history, diffs,
alerts, the review queue, and drafts. `app/ops.py` is a separate fleet
health self-check; `scripts/backup_db.py` is a standalone SQLite backup
script. Neither runs automatically — see DEPLOY.md for wiring them into a
schedule.

---

## Why Flask instead of FastAPI

The build spec assumed FastAPI, but the sandbox this was built in has no
PyPI network access (a fixed egress allowlist, not something `pip install`
retries fix). Flask, Jinja2, SQLite, Playwright, BeautifulSoup, and pydantic
were all already available, so the dashboard is server-rendered Flask
instead — functionally identical for this MVP's needs. If you'd rather run
FastAPI, `requirements.txt` lists the original stack; swapping `app/web.py`
to FastAPI + Jinja2Templates is a same-day change, nothing else in the
pipeline depends on the web framework.

---

## Deploying this so it's actually running somewhere

**→ See `DEPLOY.md`** for step-by-step Fly.io and Railway deploys (both use
the included `Dockerfile`, which bundles Playwright/Chromium via Microsoft's
official Playwright image so you don't hand-install ~15 system libraries).
Both are cheap-to-start options with a persistent volume for the SQLite DB
and a path to weekly scheduled scans (`.github/workflows/weekly-scan.yml`
for Fly, Railway's built-in cron for Railway).

The sections below are for running it locally — useful for development, or
before you deploy anywhere.

## Setup

Everything below assumes normal internet access (unlike the build sandbox).

```bash
cd dpdp-scanner
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
playwright install chromium   # downloads the browser binary
```

The repo ships with a small **pre-populated demo database**
(`data/scanner.db`) so you can explore the dashboard immediately — one demo
client (`acmetest.example`) with two scans showing a real drift event (a
consent banner that went missing). Delete `data/scanner.db` to start clean;
it's recreated (schema + any pending migrations — see `app/db/migrations.py`)
automatically on the next scan or dashboard load.

Before running the dashboard for real, copy `.env.example` to `.env` (or set
the equivalents in your shell/platform) and at minimum set
`DASHBOARD_PASSWORD` — see "Security" below.

## Running a scan

```bash
python run_scan.py --domain example.com --whatsapp "+919999999999"
# or scan every active client already registered:
python run_scan.py --all
```

- First scan for a client establishes the baseline — findings are logged and
  drafted, but **no WhatsApp alerts fire** (everything is "new" by
  definition on scan one; alerting on all of it would be exactly the false-
  positive noise the spec warns kills adoption). Real drift alerts start
  from the second scan on.
- Point `--start-url` at something else (e.g. a staging URL, or
  `tests/fixture_site` served locally — see below) to crawl a different
  entry point than `https://<domain>/`.
- A crawl failure (site down, DNS broken, or a target the SSRF guard
  rejects) is recorded as a scan with `status=failed` and an error message
  — it shows up in that client's own scan history, and with `--all`, one
  client failing doesn't stop the rest of the fleet from being scanned.
- Without `GEMINI_API_KEY` set, classification runs on the built-in
  rule-based mock (see `app/config.py` for the known-vendor list and
  sensitive-field patterns — extend these freely). Set `GEMINI_API_KEY` (and
  optionally `GEMINI_MODEL`, default `gemini-1.5-flash`) to classify with a
  real Gemini call instead; transient failures are retried with backoff, and
  it falls back to the mock automatically after retries are exhausted or on
  a non-retryable error.
- Without `TWILIO_ACCOUNT_SID`/`TWILIO_AUTH_TOKEN`/`TWILIO_WHATSAPP_FROM` all
  set, WhatsApp sending simulates (logs + dashboard only); set all three to
  send real WhatsApp messages via Twilio.

**Weekly scheduling** — this MVP intentionally has no in-process scheduler.
Cron it:

```cron
0 6 * * 1  cd /path/to/dpdp-scanner && python3 run_scan.py --all >> logs/scan.log 2>&1
0 7 * * *  cd /path/to/dpdp-scanner && python3 -m app.ops >> logs/health.log 2>&1
0 3 * * *  cd /path/to/dpdp-scanner && python3 scripts/backup_db.py >> logs/backup.log 2>&1
```

(See DEPLOY.md for the equivalent GitHub Actions / Railway cron setup on a
real deployment, and `.env.example` for `LOG_FILE` if you want rotation
instead of plain `>>` redirection.)

## Running the dashboard

```bash
python -m app.web
# → http://localhost:5000 — prompts for the first operator's DASHBOARD_USERNAME/
#   DASHBOARD_PASSWORD if set (only seeds the FIRST operator on a brand-new DB —
#   see "Security" below); otherwise runs unauthenticated with a warning banner.
```

Client list (with a fleet health banner if anything's stale or failing) →
scan history (audit trail) → diff history → alert log → human review queue →
auto-drafted notice/inventory content → `/operators` to add/deactivate
additional operator accounts. "Mark handled" flips an alert's status;
nothing here auto-publishes anything client-facing.

## Client portal + self-serve signup

```bash
# A visitor can register themselves:
open http://localhost:5000/signup
# An existing client logs in at:
open http://localhost:5000/portal/login
```

The portal is read-only for scan/diff history, plus one real action:
approving or rejecting their own drafted notices (`/portal/drafts`) —
audited (`drafts.decided_by`/`decided_at`), but never auto-published. An
operator sets/revokes a client's portal password from that client's detail
page in the dashboard (`/clients/<id>`) — there's no email flow, so relay
it to them directly. Signup creates the client and logs them in but does
**not** trigger a scan; that's still an operator step (see
`ONBOARDING.md`).

## Testing without a live site

A local fixture site is included at `tests/fixture_site/` — forms with
sensitive fields (DOB, password, bank account), a known-vendor tracker
script, a consent-banner text heuristic, and a privacy policy page. Serve it
and scan it like a real site (note `ALLOW_PRIVATE_CRAWL_TARGETS=1` — the
SSRF guard blocks `localhost` by default, this is the one sanctioned
exception, see Security below):

```bash
python3 -m http.server 8899 --directory tests/fixture_site &
ALLOW_PRIVATE_CRAWL_TARGETS=1 python3 run_scan.py --domain acmetest.example --start-url http://localhost:8899/
```

Unit tests cover every agent plus the security/resilience work below, no
browser or live network needed for any of them:

```bash
for f in tests/test_*.py; do python3 "$f"; done
```

| File | Covers |
|---|---|
| `test_classifier.py` | mock classifier category/relevance tagging |
| `test_differ.py` | severity scoring rules |
| `test_web_auth.py` | dashboard auth, CSRF, input validation, error handling |
| `test_crawler_safety.py` | SSRF guard |
| `test_classifier_resilience.py` | Gemini retry/backoff, per-finding schema validation |
| `test_notifier_whatsapp.py` | Twilio send, retry/backoff, sim fallback |
| `test_orchestrator_resilience.py` | per-stage failure isolation |
| `test_guardrails.py` | no generated text states a compliance conclusion; low-confidence findings never alert |
| `test_ops.py` | fleet health self-check |
| `test_backup_db.py` | SQLite hot-backup + retention |
| `test_operators.py` | multi-operator accounts: add/deactivate, can't lock out the last active operator |
| `test_portal.py` | client portal login, session scoping/IDOR, draft approve/reject audit trail |
| `test_signup.py` | public self-serve signup: validation, duplicate-domain rejection, rate limiting |
| `test_export_review_sample.py` | stratified sampling logic for the compliance-review export tool |

---

## Security

- **Multi-operator dashboard auth** (`app/auth.py`) — HTTP Basic, backed by
  a real `operators` table, not one shared credential. `DASHBOARD_USERNAME`/
  `DASHBOARD_PASSWORD` (or `DASHBOARD_PASSWORD_HASH`) only seed the *first*
  operator on a brand-new database; after that, add/deactivate operators
  from the dashboard's `/operators` page or headlessly via
  `python3 scripts/manage_operators.py`. Off by default, but loudly: a
  warning banner renders on every page and a warning logs on startup if no
  operator exists yet. **Set one before this is reachable by anyone but
  you** — see DEPLOY.md.
- **Client-facing portal** (`app/portal.py`, `/portal/login`) — separate,
  session-based login for clients themselves, scoped strictly to their own
  data (never shares the operator credential space). A client can view
  their own scan/diff history and approve or reject their own drafted
  notices. An operator sets/revokes a client's portal password from that
  client's detail page. Rate-limited per source IP against brute-forcing.
- **Public self-serve signup** (`/signup`, no payment) — creates a
  `plan_tier='trial'` client and logs the visitor straight into their
  portal, but never triggers a scan automatically; an operator still runs
  (or approves) the first crawl. Rate-limited per source IP.
- **CSRF protection** on every state-changing dashboard/portal/signup
  request, automatic — one mechanism covering all three auth surfaces.
- **SSRF guard** (`app/agents/crawler.py`) — refuses to crawl a target that
  resolves to a private/loopback/link-local/reserved address by default.
- **Security headers** (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, a same-origin `Content-Security-Policy`) on every
  response; generic 404/403/500 pages that never leak a stack trace to a
  client (full detail still goes to the server log).
- `FLASK_DEBUG` defaults off; Werkzeug's debug console is an RCE risk if
  ever exposed — never set this in production.

## Robustness / error isolation

- **Per-stage failure isolation** in the orchestrator (`app/orchestrator.py`):
  a crawl failure is recorded as `scans.status='failed'` with an error
  message rather than crashing; a failed WhatsApp send is isolated per-alert
  so it can't stop the rest of a scan's alerts or drafts.
- **`run_scan.py --all`** scans every active client with per-client
  isolation — one client's outage doesn't skip the rest of the fleet.
- **Schema migrations** (`app/db/migrations.py`) — versioned, idempotent,
  safe to run against the pre-populated demo DB or any live deployment;
  `init_db()` applies them automatically on every startup.
- **SQLite WAL mode + busy_timeout** (`app/db/conn.py`) for safe concurrent
  reads/writes between the dashboard (2 gunicorn workers) and a cron scan.
- **Classifier retries** transient Gemini failures with backoff and
  validates every field of the response against the schema, so one
  malformed item can't discard an entire page's good findings.
- **Ops self-check** (`app/ops.py`, `/ops/health`) — flags a client that's
  gone stale (no recent scan) or whose last few scans all failed; distinct
  from `/healthz`, which only checks the process/DB are up.
- **Backups** (`scripts/backup_db.py`) — safe hot-copy of the live SQLite DB
  with retention, independent of platform-volume durability.

## Guardrails implemented (per spec, "day one")

- Low-confidence classifier findings → human review queue, **and excluded
  from client-facing alerts regardless of severity** (`app/agents/
  notifier.py`) — a real gap was found and fixed here during hardening: a
  low-confidence finding of a type that auto-scores High severity (e.g.
  `third_party_script`) could previously still fire a WhatsApp alert, which
  contradicted the spec's own guardrail. `tests/test_guardrails.py` covers
  the fix end-to-end.
- First scan for a client is a silent baseline — no alert spam on day one.
- Only High/Medium severity diff entries fire a WhatsApp alert; Low sits in
  the dashboard only. A client can raise their own bar to High-only
  (`clients.min_alert_severity`), never lower it below Medium.
- Every scan is persisted permanently (`scans` + `findings` tables, and
  never `DELETE`d — enforced by a source-level test) — the audit trail
  survives independent of whether any alert fired or the scan itself
  succeeded.
- Crawler respects `robots.txt` and rate-limits between page loads
  (`CRAWL_DELAY_SECONDS` in `app/config.py`).
- Drafted notice paragraphs / data-inventory rows are always `status=draft`
  — nothing is auto-published.
- **No generated text ever states a compliance conclusion** ("you are
  compliant", "this violates DPDP", etc.) — enforced by
  `app/guardrails.py`, fuzz-tested across every WhatsApp alert / drafted
  notice template combination in `tests/test_guardrails.py`, and applied at
  runtime to Gemini's free-text `detail` field (the one place client-facing
  text isn't from a fixed template) — a flagged phrase forces low
  confidence rather than reaching a client. In every case the product
  describes what was found and which obligation it touches, never a legal
  conclusion about compliance status.

## Two real bugs found and fixed during verification

Worth knowing about since they shaped how `detail_hash` works:

1. **Consent banner was evaluated per-page.** A banner loaded once (e.g. via
   the homepage) covers a whole site, but the original per-page check flagged
   every subpage without an inline banner as "missing" — false positives on
   scan one. Fixed by rolling it up into a single site-wide finding
   (`_site_consent_banner_finding` in `classifier.py`).
2. **Privacy policy / consent banner state changes double-fired.** Both
   findings were originally hashed by their *current content* (content hash,
   or "present" vs "absent"), so a text edit or a banner disappearing looked
   like "old finding removed + brand new finding appeared" instead of one
   "changed" event — two alerts for one incident, and a misleading "page no
   longer reachable" message for what was really just an edit. Fixed by
   keying `detail_hash` on stable identity (the page URL, or a constant
   site-wide key) and letting the *content* differ inside `detail`, which is
   what the Diff Agent actually compares to decide `changed` vs `new`/
   `removed`. Both fixes have regression tests in `tests/test_differ.py` and
   `tests/test_classifier.py`.

## Scope notes (matches spec — not gaps to fix)

Not in this MVP by design: RoPA automation, DPA/vendor contract generation,
Consent Manager (Rule 4) integration, breach-notification workflow,
DPO-as-a-service dashboard, backend/database PII scanning, login-flow
detection, subdomain discovery. These are called out in the spec as
deliberately deferred until the scan-and-diff loop is proven with real
customers.

## Before any real customer

Per the spec: get one compliance-literate person to review the classifier's
DPDP mapping logic (`app/config.py` field patterns + `app/agents/
classifier.py` relevance rules) against 10–15 real findings before this goes
in front of a paying client. This has not been done — the mock classifier's
category/relevance assignments are a reasonable first pass, not a
compliance sign-off. `python3 scripts/export_review_sample.py` exports a
stratified sample of real findings to a CSV worksheet for that reviewer —
it does not perform the review itself, it just removes the excuse that
there's no easy way to get a representative sample to look at. See
`GO_NO_GO_CHECKLIST.md` for the full current status.
