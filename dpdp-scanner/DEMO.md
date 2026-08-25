# Demo script

A 10-15 minute walkthrough for a prospect, using the included fixture site
so the drift event is real and reproducible — not a screenshot, an actual
live scan finding an actual change. Practice this once end-to-end before
doing it live; the timing notes below assume you have.

## Setup (do this before the call, not during it)

```bash
# Terminal 1 — serve the fixture site
python3 -m http.server 8899 --directory tests/fixture_site

# Terminal 2 — fresh demo DB so the story is clean
rm -f data/scanner.db
ALLOW_PRIVATE_CRAWL_TARGETS=1 python3 run_scan.py --domain acmetest.example \
    --start-url http://localhost:8899/ --whatsapp "+919999999999"

# Terminal 3 — dashboard
python -m app.web
```

Confirm in the dashboard (`http://localhost:5000`) that `acmetest.example`
shows one scan, findings logged, and (correctly) zero alerts — that's the
baseline-scan-is-silent behavior, worth narrating in the demo itself (see
below).

## The pitch (30 seconds, say this first)

"Everyone else audits your site once, hands you a PDF, and walks away. We
watch it every week. The moment something changes — a new tracker script, a
form field that started collecting a phone number, your consent banner
breaking — you get a WhatsApp message the same day, not at your next annual
audit."

## Walkthrough

1. **Show the baseline scan** (dashboard → client detail page). Point out:
   scan history, findings list, and — important — that *no alert fired* on
   this first scan. Explain why: everything is "new" by definition on scan
   one, so alerting on all of it would just be noise. This is a guardrail,
   not a missing feature — say that explicitly, it's a strength.

2. **Introduce a real change to the fixture site.** Before the call, or
   live if you're comfortable with the timing, add a tracker script to
   `tests/fixture_site/pricing.html` — this mirrors the spec's own example
   scenario. A minimal edit:

   ```html
   <script src="https://static.hotjar.com/c/hotjar-000000.js"></script>
   ```

3. **Run the second scan** live:

   ```bash
   ALLOW_PRIVATE_CRAWL_TARGETS=1 python3 run_scan.py --domain acmetest.example \
       --start-url http://localhost:8899/ --whatsapp "+919999999999"
   ```

   Narrate the terminal output as it happens — severity, the alert message
   text. This is the moment that sells it: point out the alert fired
   *because something changed*, and read the message text out loud —
   "New this week: script from static.hotjar.com (Hotjar) → New third-party
   script/tracker detected — data processor/transfer risk (third-party data
   flow, check DPA/cross-border transfer)."

4. **Show the dashboard diff view** for that scan — new/changed/removed,
   severity. Then the **alert log** — this is what a real WhatsApp message
   would have looked like (or, if you have `TWILIO_*` configured against a
   sandbox number, actually send it to your own phone for the demo).

5. **Show the drafted content** (`/clients/<id>/drafts`) — the auto-drafted
   privacy-notice paragraph and inventory row for the new finding. Be
   explicit that this is a draft, never auto-published — "you approve
   everything before it goes anywhere."

6. **Close on the one honest caveat, don't skip this**: "This tells you
   what changed and what obligation it likely touches — it's not a lawyer
   and it won't tell you 'you're compliant.' That's deliberate: a tool that
   confidently tells you you're fine is worse than one that flags things
   for you to check." This is a real guardrail the product enforces in
   code (see README.md) — it's also just good, honest positioning that
   builds trust rather than overpromising.

## If they ask "what if it's wrong?"

Point to the review queue: anything the classifier isn't confident about
never reaches a client-facing alert — it goes to a human review queue
first. Low-confidence findings are excluded from alerts *regardless* of how
severe they'd otherwise look, which is a real, tested guarantee (see
`tests/test_guardrails.py`), not a marketing claim.

## If they ask "what does it cost / how do I sign up?"

There's no self-serve flow yet (see ONBOARDING.md's "Not yet built"
section) — this is a pilot-stage product, and that's fine to say plainly.
