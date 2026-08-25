"""Static config: known vendor domains, sensitive field patterns, thresholds."""
import os
import re

# --- LLM classifier ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")
GEMINI_MAX_RETRIES = int(os.environ.get("GEMINI_MAX_RETRIES", "3"))
GEMINI_TIMEOUT_SECONDS = float(os.environ.get("GEMINI_TIMEOUT_SECONDS", "30"))
# Defensive cap on how many forms/scripts/cookies from one page get sent to
# Gemini in one call — a malformed or spam page with hundreds of matches
# would otherwise balloon token cost/latency and risk a timeout for no
# compliance benefit (the field patterns/vendor list already run against
# the crawler's full unfiltered output via the mock classifier regardless).
MAX_ITEMS_PER_PAGE_FOR_CLASSIFIER = int(os.environ.get("MAX_ITEMS_PER_PAGE_FOR_CLASSIFIER", "60"))

# --- WhatsApp sending (Twilio) ---
# All three must be set to switch the Notifier Agent from simulation
# (logs + dashboard only) to real sending — see app/agents/notifier.py.
# TWILIO_WHATSAPP_FROM is the Twilio-provisioned WhatsApp sender, e.g.
# "whatsapp:+14155238886" for the Twilio sandbox number, or your own
# approved WhatsApp Business sender in production.
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "").strip()
TWILIO_WHATSAPP_FROM = os.environ.get("TWILIO_WHATSAPP_FROM", "").strip()
WHATSAPP_SEND_MAX_RETRIES = int(os.environ.get("WHATSAPP_SEND_MAX_RETRIES", "2"))

# --- Crawl behavior ---
MAX_CRAWL_DEPTH = int(os.environ.get("MAX_CRAWL_DEPTH", "2"))
MAX_PAGES = int(os.environ.get("MAX_PAGES", "25"))
# Trial-tier clients (clients.plan_tier == 'trial', the schema default for
# every new client) get a smaller crawl cap — enough to give a real,
# useful first scan and demo the product, without one trial signup running
# an unbounded crawl against someone's production site before they've paid
# for anything. Any other plan_tier value uses the full MAX_PAGES.
TRIAL_MAX_PAGES = int(os.environ.get("TRIAL_MAX_PAGES", "10"))
CRAWL_DELAY_SECONDS = float(os.environ.get("CRAWL_DELAY_SECONDS", "1.0"))
REQUEST_TIMEOUT_MS = int(os.environ.get("REQUEST_TIMEOUT_MS", "15000"))
USER_AGENT = "DPDPDriftScanner/0.1 (+compliance-monitoring-bot)"

# SSRF guard (see app/agents/crawler.py:_validate_crawl_target). Leave this
# OFF (default) in every real deployment — it exists only so local fixture-
# site testing against http://localhost:8899/ (see README) keeps working.
ALLOW_PRIVATE_CRAWL_TARGETS = os.environ.get("ALLOW_PRIVATE_CRAWL_TARGETS", "0") == "1"

# --- Known third-party vendor domains (substring match against script/request host) ---
KNOWN_VENDORS = {
    "google-analytics.com": "Google Analytics",
    "googletagmanager.com": "Google Tag Manager",
    "analytics.google.com": "Google Analytics",
    "connect.facebook.net": "Meta Pixel",
    "facebook.com/tr": "Meta Pixel",
    "hotjar.com": "Hotjar",
    "static.hotjar.com": "Hotjar",
    "widget.intercom.io": "Intercom",
    "intercomcdn.com": "Intercom",
    "checkout.razorpay.com": "Razorpay",
    "razorpay.com": "Razorpay",
    "js.stripe.com": "Stripe",
    "cdn.segment.com": "Segment",
    "cdn.amplitude.com": "Amplitude",
    "clarity.ms": "Microsoft Clarity",
    "doubleclick.net": "Google Ads / DoubleClick",
    "googlesyndication.com": "Google AdSense",
    "hubspot.com": "HubSpot",
    "js.hs-scripts.com": "HubSot",
    "mixpanel.com": "Mixpanel",
    "zdassets.com": "Zendesk",
    "freshworks.com": "Freshworks",
    "cdn.mouseflow.com": "Mouseflow",
    "cloudflareinsights.com": "Cloudflare Insights",
    "sentry.io": "Sentry",
    "youtube.com": "YouTube Embed",
    "ytimg.com": "YouTube Embed",
    "vimeo.com": "Vimeo Embed",
    "typeform.com": "Typeform",
    "calendly.com": "Calendly",
    "linkedin.com/px": "LinkedIn Insight Tag",
    "snap.licdn.com": "LinkedIn Insight Tag",
    "tiktok.com": "TikTok Pixel",
    "analytics.tiktok.com": "TikTok Pixel",
    "pinterest.com/ct": "Pinterest Tag",
    "twitter.com/i/adsct": "X (Twitter) Ads Pixel",
    "ads-twitter.com": "X (Twitter) Ads Pixel",
    "onesignal.com": "OneSignal",
    "moengage.com": "MoEngage",
    "clevertap.com": "CleverTap",
    "freshchat.com": "Freshchat",
}

# --- Known consent-management-platform script markers ---
KNOWN_CMPS = {
    "cookiebot.com": "Cookiebot",
    "cookieyes.com": "CookieYes",
    "onetrust.com": "OneTrust",
    "usercentrics.eu": "Usercentrics",
    "termly.io": "Termly",
    "iubenda.com": "iubenda",
    "cookielaw.org": "OneTrust",
    "quantcast.com": "Quantcast Choice",
    "trustarc.com": "TrustArc",
}

# --- Field-name pattern -> data category (used by mock classifier + as prior for LLM) ---
FIELD_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # (compiled regex on field name/label/type, data_category, dpdp_relevance)
    (re.compile(r"e[-]?mail", re.I), "contact", "notice"),
    (re.compile(r"phone|mobile|contact.?no", re.I), "contact", "notice"),
    (re.compile(r"address|city|pincode|zip|postal", re.I), "contact", "notice"),
    (re.compile(r"\bdob\b|date.?of.?birth|birthday", re.I), "children", "children_data"),
    (re.compile(r"\bage\b", re.I), "children", "children_data"),
    (re.compile(r"pan(\s|_)?(card|number)?\b", re.I), "identity", "consent"),
    (re.compile(r"aadhaar|aadhar", re.I), "identity", "consent"),
    (re.compile(r"passport", re.I), "identity", "consent"),
    (re.compile(r"credit.?card|debit.?card|card.?number|cvv|bank.?account|ifsc|upi", re.I), "financial", "consent"),
    (re.compile(r"salary|income", re.I), "financial", "consent"),
    (re.compile(r"health|medical|diagnos|disease|blood.?group|allerg", re.I), "health", "consent"),
    (re.compile(r"gender|sex\b", re.I), "identity", "notice"),
    (re.compile(r"password|passwd", re.I), "identity", "security_safeguard"),
    (re.compile(r"^name$|full.?name|first.?name|last.?name", re.I), "identity", "notice"),
]

# --- Detection routes / paths considered auth flows ---
AUTH_PATH_PATTERNS = re.compile(r"/(signup|sign-up|register|login|log-in|sign-in|signin|auth)\b", re.I)

LOW_CONFIDENCE_TO_REVIEW = True  # per spec: low-confidence findings never go straight to client

# --- Ops self-check (app/ops.py) ---
# A client not scanned in this many days (e.g. cron silently stopped firing,
# or every recent attempt failed) is flagged as stale by the self-check.
# Weekly scanning is the product's own pitch ("we watch your site every
# week"), so anything past ~10 days means the pitch isn't being delivered.
STALE_SCAN_THRESHOLD_DAYS = int(os.environ.get("STALE_SCAN_THRESHOLD_DAYS", "10"))
# How many of a client's most recent scans get checked when looking for a
# "every recent attempt failed" pattern (vs. one-off transient failure).
CONSECUTIVE_FAILURE_WINDOW = int(os.environ.get("CONSECUTIVE_FAILURE_WINDOW", "3"))

# --- Client portal session cookie (app/portal.py) ---
# Off by default so local/plain-HTTP development (and the fixture-site demo
# in DEMO.md) keeps working without a TLS terminator in front of it. Set
# SESSION_COOKIE_SECURE=1 in any real deployment — Fly/Railway terminate TLS
# in front of the app, so the app itself sees plain HTTP even in prod; this
# flag has to be turned on explicitly rather than auto-detected.
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"

# --- Optional error tracking ---
SENTRY_DSN = os.environ.get("SENTRY_DSN", "").strip()

# --- Logging ---
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FILE = os.environ.get("LOG_FILE", "").strip() or None
LOG_FILE_MAX_BYTES = int(os.environ.get("LOG_FILE_MAX_BYTES", str(5 * 1024 * 1024)))
LOG_FILE_BACKUP_COUNT = int(os.environ.get("LOG_FILE_BACKUP_COUNT", "5"))
