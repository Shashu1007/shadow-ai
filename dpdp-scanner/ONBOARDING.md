# Onboarding a pilot client

This is a checklist for bringing on a first real client, not a script to
read to them — use DEMO.md for the actual walkthrough. Follow this in order;
each step exists because skipping it is exactly how the guardrails in
README.md ("Guardrails implemented") get quietly bypassed in practice.

## Before you say yes to a pilot

- [ ] **Confirm the compliance review has happened, or set expectations that
      it hasn't.** Per README.md's "Before any real customer" section, the
      classifier's DPDP mapping logic has not been reviewed by a
      compliance-literate person against real findings. Either do that
      review first, or be explicit with the pilot client that findings are
      "worth investigating," not "a compliance sign-off" — this is not
      optional cover-your-back language, it's the actual current state of
      the product.
- [ ] Confirm `DASHBOARD_PASSWORD` (and `SECRET_KEY`) is set on whatever
      deployment you're about to point at this client's real site (see
      DEPLOY.md). Do not demo or pilot against an unauthenticated
      dashboard. If more than one person on your side needs dashboard
      access, add them as their own operator via `/operators` — don't share
      one login between people (see README's "Security" section).
- [ ] Decide `plan_tier` for this client: `trial` caps the crawl at
      `TRIAL_MAX_PAGES` (10 by default) — enough for a real first scan
      without an unbounded crawl of their production site before they've
      committed to anything. There's still no billing/upgrade flow (see
      "Not yet built" below) — bump `plan_tier` by hand
      (`sqlite3 data/scanner.db "UPDATE clients SET plan_tier='paid' WHERE
      domain='...'"`) once they're a real customer.

## Adding the client

Two ways in:

1. **You add them** — from the dashboard: **+ Add Client** → enter their
   domain (a pasted full URL is fine, it gets normalized) and WhatsApp
   number. Or from the CLI:
   `python run_scan.py --domain <their-domain> --whatsapp <their-number>`
   — this also creates the client record if it doesn't exist yet. Then set
   a portal password for them from their client detail page
   (`/clients/<id>` → "Client portal access") and relay it directly — there's
   no email flow.
2. **They self-register** — point them at `/signup`. This creates the
   client and logs them straight into their own portal, but does **not**
   run a scan — the new signup shows up in your dashboard client list with
   zero scans, which is your approval queue. Treat every self-serve signup
   the same as case 1 from here: you still run and review their first scan
   yourself before they see anything alarming in their portal.

Either way, from here:

1. **Run the first scan** (the baseline). No WhatsApp alert fires on this
   one by design (see README.md) — everything is "new" on scan one, and
   alerting on all of it would be noise, not signal.
2. **Review the baseline findings yourself before telling the client
   anything**, especially anything the review queue flagged
   (`/review-queue` in the dashboard). This is the step that stands in for
   the not-yet-done compliance review on a per-client basis: you're the
   human checking the classifier's work before it reaches someone who might
   act on it. `python3 scripts/export_review_sample.py` can pull a
   representative sample across all clients if you want a second, more
   rigorous pass at some cadence rather than just eyeballing each new
   client's baseline.
3. **Check the drafted content** (`/clients/<id>/drafts`, or the client's
   own `/portal/drafts` once they have portal access) — the auto-drafted
   notice paragraphs and inventory rows are templates with explicit
   `[DRAFT — confirm ... before publishing]` markers. Read them. Nothing
   here should ever be handed to a client as finished text — the client can
   now approve/reject a draft from their own portal, but that only records
   their decision in this system, it still doesn't publish anything
   anywhere. Say that to them explicitly the first time they use it.

## Setting expectations with the client

- This is a monitoring tool, not a compliance certification. Say that
  plainly — it's also literally a guardrail the product enforces in code
  (see README's Guardrails section): it never tells them "you are
  compliant" or "you are not compliant."
- Real drift alerts start from the *second* scan. If you want to demo
  drift behavior for them, you need two scans with something actually
  different in between — see DEMO.md.
- Scans are weekly by default (matches the pitch: "Everyone else audits you
  once. We watch your site every week."). Confirm the cron/scheduled job
  covering their domain is actually running — `python -m app.ops` (or the
  dashboard's fleet health banner) will flag it if scanning has gone stale.

## Not yet built (don't imply these exist to a client)

- **No billing or plan upgrade flow.** Self-serve signup exists (`/signup`)
  and multi-operator dashboard access exists (`/operators`) — what's still
  missing is payment: `plan_tier` is a DB column you bump by hand once a
  client has actually paid you some other way. Don't imply `/signup` is a
  paid-plan checkout; it creates a `trial`-tier account only.
- **No email/SMS for the client portal.** A client's portal password is set
  by an operator (or by themselves at `/signup`) and has to be relayed or
  remembered directly — there's no "forgot password" flow. A locked-out
  client needs an operator to reset it from their client detail page.
- No RoPA export, DPA/vendor contract generation, Consent Manager
  integration, or breach-notification workflow — all explicitly deferred
  per the spec (see README's "Scope notes").
