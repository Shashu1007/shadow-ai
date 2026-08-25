# DPDP Drift Scanner — GTM readiness checklist

Written after two passes on top of the original MVP build (see
`claude/dpdp-scanner-mvp-build-notes.md` and `dpdp-scanner-mvp-spec.md` in
this project for what came before): an initial hardening pass, then a
second pass closing the three items that hardening pass left "still
blocking." This is an honest status list, not a sales document — items
marked ⚠ are real blockers, not formalities.

## What changed in this pass (multi-operator + client portal + signup)

113 automated tests now (up from 75 after the hardening pass, 19 in the
original build), all passing, no browser/network required for any of them.
The three items the previous pass explicitly could not close:

- **Multi-operator dashboard accounts** (`app/auth.py`, `/operators`,
  `scripts/manage_operators.py`) replace the single shared
  `DASHBOARD_USERNAME`/`DASHBOARD_PASSWORD` credential. Each operator has
  their own username/password, can be deactivated individually (revoking
  just their access, not everyone's), and the system refuses to deactivate
  the last active operator (that would lock everyone out). The env vars now
  only *seed* the first operator on a brand-new database — after that,
  operators are managed via the dashboard or the CLI script.
- **Client-facing portal** (`app/portal.py`, session-based login at
  `/portal/login`, separate from operator Basic Auth entirely) lets a
  client log in with their own domain + a password their operator sets, see
  their own scan/diff history read-only, and **approve or reject their own
  drafted notices** — a real, audited action (`drafts.decided_by`/
  `decided_at`) that explicitly does not publish or send anything; the copy
  on the page says so. Every portal route re-derives which client it's
  serving from the session, never from a URL/form parameter — verified with
  a dedicated IDOR test (`test_client_a_cannot_see_or_act_on_client_bs_draft`).
- **Public self-serve trial signup** (`/signup`, no payment) — a visitor
  registers their own domain + a portal password and lands straight in
  their portal. It deliberately does **not** trigger a scan automatically:
  a public unauthenticated form is reachable by anyone, and running the
  crawler against whatever domain a stranger types in is a different risk
  profile than an operator-vetted onboarding. The signup does show up
  immediately in the operator dashboard with zero scans — that list *is*
  the approval queue; running the client's first scan (`run_scan.py` or a
  future dashboard button) is the explicit approval step.
- **Compliance-review support tooling** (`scripts/export_review_sample.py`)
  — exports a stratified sample of real findings (spread across finding
  type and confidence, not just whatever's most common) to a CSV worksheet
  with blank reviewer-verdict columns. This does **not** perform or
  substitute for the compliance review below — it only saves the reviewer
  from digging through the dashboard or hand-writing SQL to get a
  representative sample to work from.

## Status by area

### ✅ Done — pilot-ready, and now past hands-on-pilot-only

- Everything from the previous hardening pass: dashboard auth + CSRF, SSRF
  guard, per-stage error isolation, versioned migrations, the low-confidence
  alert guardrail fix, fleet health self-check, backup script, onboarding +
  demo docs.
- Multi-operator accounts, client portal (read-only view + draft
  approve/reject), public self-serve signup — see above. All three were
  explicitly "still blocking" after the last pass; all three are closed.
- 113/113 automated tests passing, including dedicated IDOR, CSRF, rate-limit,
  and audit-trail regression tests for every new route.
- Migrations 0006–0008 (operators table, `clients.portal_password_hash`,
  `drafts.decided_at`/`decided_by`) verified against the real pre-populated
  demo DB — applies cleanly, idempotent on a second run, zero data loss.

### ⚙️ Built, but needs YOUR credentials/accounts/decisions to actually activate

- **Real Gemini classification** — code path exists, retried/validated.
  A live key (provided this session) could **not** be verified from this
  build sandbox: outbound requests to `generativelanguage.googleapis.com`
  are blocked by this environment's own network egress proxy (a
  `403 Forbidden` at the proxy layer, confirmed by direct inspection — not
  an error from Google, and not evidence the key itself is bad or good).
  The code's retry-then-fallback-to-mock behavior worked exactly as
  designed when this happened, which is the part that *was* verified. Test
  the key from your actual deploy environment before relying on it, and
  **rotate that key** — it was shared in this chat, which this session
  cannot guarantee is a private channel.
- **Real WhatsApp sending** — code path exists via Twilio, retried; needs
  `TWILIO_ACCOUNT_SID`/`TWILIO_AUTH_TOKEN`/`TWILIO_WHATSAPP_FROM`. Currently
  simulates (logs + dashboard only).
- **A live deploy** — still never observed to succeed against a live Docker
  daemon or Fly/Railway in any session this project has gone through,
  including this one. Do a real test deploy before trusting this
  unattended.
- **Backups to real off-host storage** — `scripts/backup_db.py` does a
  correct hot-copy locally; real object storage or litestream needs your
  account.
- **Portal password delivery** — there's no email/SMS integration. An
  operator sets a client's portal password from the dashboard and has to
  relay it to them directly (WhatsApp, a call). Fine at pilot scale, a real
  gap if this needs to scale past hands-on relationships.

### ⚠ Still blocking — not something any build session can close

- **The compliance-literate DPDP mapping review has not happened.** This is
  unchanged from the original build and from the previous hardening pass,
  and remains the single real blocker. Code guardrails (low-confidence
  routing, the compliance-conclusion-language filter, and now a proper
  stratified sample export) reduce the *blast radius* of a wrong
  classification and make the review itself easier to actually do — none of
  it validates that `app/config.py`'s field patterns or `app/agents/
  classifier.py`'s relevance rules are right under DPDP. That needs a human
  who knows the law. Run `python3 scripts/export_review_sample.py` against
  real scan data and hand the CSV to that person — this is now genuinely
  the only step left before a real customer.

## Bottom line

The three gaps this checklist flagged as "still blocking" after the first
hardening pass — no multi-operator accounts, no client-facing login, no
self-serve signup — are closed, tested, and verified against the real demo
database. What's left is not a code problem: it's the compliance review,
which was true before either build session and remains true after both. Get
that review done (the sample-export tool above makes it a same-day task,
not a data-archaeology project) and this product has a real, honest path to
a first paying, self-served customer — not just a hands-on pilot.
