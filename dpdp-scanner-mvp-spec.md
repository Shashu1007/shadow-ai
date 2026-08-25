# DPDP Drift Scanner — MVP Build Spec

## What this MVP actually does (and doesn't)

**Does:** Crawls a client's website (and optionally app-facing API surface) on a schedule, extracts everything that counts as a "personal data collection point" or a "third-party data flow" under DPDP, snapshots it, and diffs each new crawl against the last one. When something new shows up — a form field, a tracker, a vendor script, a consent banner change — it fires an alert with a plain-English explanation of what obligation it touches.

**Doesn't (not in MVP):** RoPA automation, DPA/vendor contract generation, Consent Manager (Rule 4) integration, breach-notification workflow, DPO-as-a-service dashboard, backend/database PII scanning. Those come after the first paying customers, once the scan-and-diff loop is proven. Scope creep here is the main way this MVP dies before it ships.

The whole pitch is one sentence: **"Everyone else audits you once. We watch your site every week."**

---

## Architecture — 4 agents, matches the team pattern you're already building

```
┌─────────────┐     ┌────────────────┐     ┌─────────────┐     ┌──────────────┐
│ Crawler     │ --> │ Classifier      │ --> │ Diff Agent  │ --> │ Notifier     │
│ Agent       │     │ Agent (Gemini)  │     │             │     │ Agent        │
└─────────────┘     └────────────────┘     └─────────────┘     └──────────────┘
   Playwright          extracts + tags        compares vs         WhatsApp +
   headless crawl      findings against        last snapshot       dashboard
   + network capture   DPDP categories          in DB               alert
```

- **Crawler Agent** — headless browser (Playwright), visits every reachable page up to a depth limit, captures: rendered HTML, all network requests (for cookies/trackers), all `<form>` elements and their input fields, all `<script src>` domains, the existence/text of any cookie-consent banner and privacy policy page.
- **Classifier Agent** — feeds the crawl output to Gemini with a structured prompt (schema below) to tag each finding: what kind of personal data it collects, which third party it goes to, and which DPDP obligation it touches. This is the only LLM call in the loop — everything else is deterministic.
- **Diff Agent** — pure code, no LLM. Compares this snapshot's findings against the last stored snapshot per domain. Outputs three lists: `new`, `changed`, `removed`.
- **Notifier Agent** — takes the diff, formats a WhatsApp message (client-facing) and a dashboard entry, and writes the update into that client's living compliance doc (privacy-notice draft, plain-English data inventory).

Reuse whatever supervisor/worker plumbing you already have for the agency's internal agent team — this is the same shape, just four workers instead of your outreach/delivery split.

---

## What exactly to detect on each crawl

| Category | How to detect | Why it matters under DPDP |
|---|---|---|
| **Form fields** | Parse every `<form>`; list input `name`/`type`/`label` (email, phone, DOB, address, PAN/Aadhaar-shaped patterns, etc.) | Each field is a data point requiring purpose-specific notice + consent |
| **Cookies set** | Capture `Set-Cookie` headers + `document.cookie` after page load; classify first-party vs third-party by domain | Non-essential cookies need consent before they fire |
| **Third-party scripts** | Every `<script src>` and network request to an external domain; match against a known-vendor list (GA4, Meta Pixel, Hotjar, Intercom, Razorpay, etc.) plus flag unknown domains | Each vendor is a data processor/transfer that needs a DPA and disclosure |
| **Consent banner presence/config** | Check for known CMP scripts (or absence of one); diff the banner text/options if present | Detects if consent capture broke, was removed, or changed silently |
| **Privacy policy page** | Fetch and hash the privacy-policy URL; diff hash + do a rough text-diff on change | Flags stale notices after the product changes |
| **Login/signup flow presence** | Detect auth-related forms/routes (`/signup`, `/login`, OAuth buttons) | Marks where account creation — and DOB/age-gate obligations for children's data — happens |
| **New subdomains/routes (optional, v2)** | Compare sitemap or crawl-discovered URL list over time | Catches new product surfaces spinning up unnoticed |

Keep v1 to the first five rows. Login-flow detection and subdomain discovery are v1.5.

---

## Classifier prompt shape (Gemini call)

Feed the classifier one page's raw findings at a time, not the whole site — smaller context, more reliable extraction. Ask for strict JSON back:

```json
{
  "url": "string",
  "findings": [
    {
      "type": "form_field | cookie | third_party_script | consent_banner | privacy_policy",
      "detail": "e.g. 'input name=phone, label=Mobile Number'",
      "data_category": "contact | financial | health | children | behavioral | identity | none",
      "third_party_domain": "string or null",
      "dpdp_relevance": "notice | consent | security_safeguard | children_data | cross_border_transfer | none",
      "confidence": "high | medium | low"
    }
  ]
}
```

Force JSON mode / schema-constrained output if the Gemini API tier you're on supports it — free-text classification here will drift and break your diff logic. Anything the model tags `confidence: low` goes into a human-review queue instead of a client-facing alert; false positives are what will get this product uninstalled.

---

## Snapshot & diff data model

Minimal schema — one table pair does the job:

```
clients          (id, domain, whatsapp_number, plan_tier, created_at)
scans             (id, client_id, scanned_at, page_count, raw_findings_json)
findings          (id, scan_id, type, detail_hash, data_category, third_party_domain, dpdp_relevance)
diffs             (id, client_id, prev_scan_id, curr_scan_id, new[], changed[], removed[], severity)
```

`detail_hash` = hash of the normalized finding (type + domain + field name) — this is what the diff engine matches on to decide "same finding, still there" vs "new."

**Severity scoring for the diff** (keeps alerts from becoming noise):
- **High** — new third-party script/tracker, new financial/health/children's data field, consent banner missing or broken
- **Medium** — new non-sensitive form field, privacy policy page changed
- **Low** — cosmetic page changes with no data implication (don't alert on these at all — just log them)

Only High and Medium fire a WhatsApp alert. Low sits in the dashboard only.

---

## Alert format (WhatsApp)

Keep it to one glance — founders won't read a report on WhatsApp:

```
🔔 DPDP scan — [client domain]
New this week: Hotjar tracking script added to /pricing
→ Third-party data flow, no vendor DPA on file, consent banner doesn't cover it yet
[View details] [Mark handled]
```

Link out to the dashboard for the full diff and the auto-drafted notice-update text. WhatsApp is the trigger, not the record.

---

## What gets auto-generated from a finding

For each **new** finding tagged `notice` or `consent`, auto-draft (don't auto-publish):
- One paragraph for the privacy notice, in the client's existing notice style, stating what's now collected and why
- One row for a running data-inventory sheet (field, purpose, vendor, retention — a RoPA in miniature)

This is templated Gemini output against the client's existing privacy-policy text as context, always presented as a draft the client approves before it goes live. Never auto-publish legal text.

---

## Build order (roughly 2–3 weeks to a demoable MVP)

1. **Week 1** — Crawler Agent + snapshot storage. Point it at your own site or a test site, get clean structured output for forms/cookies/scripts. No LLM yet — get the deterministic layer solid first.
2. **Week 1–2** — Classifier Agent. Wire in Gemini, get JSON output reliable on real crawl data, build the low-confidence review queue.
3. **Week 2** — Diff Agent + severity scoring. Run two crawls a few days apart on a real site, confirm the diff is accurate and not noisy.
4. **Week 2–3** — Notifier Agent (WhatsApp) + minimal dashboard (even a simple table view is fine for the first demo).
5. **Before any real customer** — get one compliance-literate person to review the classifier's DPDP mapping logic against 10–15 real findings. This is the step not to skip.

---

## Guardrails to build in from day one

- Every finding the classifier is unsure about goes to human review, never straight to the client.
- The product explains what it found and why it might matter — it does not tell a client "you are compliant" or "you are not compliant." That's a legal conclusion; this is a monitoring tool, not a law firm.
- Log every scan permanently — the audit trail (proof you were watching, and when) is itself worth something to a client during a real DPBI inquiry, separate from the alerts.
- Rate-limit and respect `robots.txt` on crawls — this is someone else's production site.
