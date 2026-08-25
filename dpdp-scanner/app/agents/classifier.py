"""
Classifier Agent
=================
Takes one page's raw crawl findings and tags each with DPDP-relevant metadata,
per the spec's JSON schema:

  { url, findings: [ { type, detail, data_category, third_party_domain,
                        dpdp_relevance, confidence } ] }

Swappable backend:
  - If GEMINI_API_KEY is set, calls the Gemini API in JSON mode.
  - Otherwise, falls back to a deterministic rule-based mock classifier
    (pattern matching against known vendors + sensitive field-name regexes)
    so the rest of the pipeline (diff, severity, alerts, dashboard) can be
    built, demoed, and tested without a live LLM dependency.

Either path emits the same ClassifiedFinding objects, so nothing downstream
needs to know which backend produced them.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from urllib.parse import urlparse

import pydantic

from app.config import (
    GEMINI_API_KEY, GEMINI_MODEL, FIELD_PATTERNS, AUTH_PATH_PATTERNS,
    GEMINI_MAX_RETRIES, GEMINI_TIMEOUT_SECONDS, MAX_ITEMS_PER_PAGE_FOR_CLASSIFIER,
)
from app.guardrails import contains_compliance_conclusion
from app.models import PageCrawlResult, ClassifiedFinding, RawFinding, DataCategory, DPDPRelevance, Confidence

logger = logging.getLogger("classifier")

# Valid literal values, pulled from the pydantic models themselves so this
# never drifts out of sync with app/models.py.
_VALID_TYPES = {"form_field", "cookie", "third_party_script", "consent_banner", "privacy_policy"}
_VALID_CATEGORIES = set(DataCategory.__args__)
_VALID_RELEVANCE = set(DPDPRelevance.__args__)
_VALID_CONFIDENCE = set(Confidence.__args__)


def _detail_hash(finding_type: str, key: str) -> str:
    """Normalize (type + stable key) into the diff-matching hash."""
    raw = f"{finding_type}::{key}".strip().lower()
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def _classify_field_pattern(name: str, ftype: str, label: str) -> tuple[str, str]:
    """Return (data_category, dpdp_relevance) from field-name/label pattern matching."""
    haystack = f"{name} {ftype} {label}"
    for pattern, category, relevance in FIELD_PATTERNS:
        if pattern.search(haystack):
            return category, relevance
    return "none", "notice" if haystack.strip() else "none"


def _mock_classify_page(page: PageCrawlResult) -> list[ClassifiedFinding]:
    """Rule-based fallback classifier — no LLM call, fully deterministic."""
    findings: list[ClassifiedFinding] = []

    # form fields
    for form in page.forms:
        for field in form.get("fields", []):
            name = field.get("name", "")
            ftype = field.get("type", "")
            label = field.get("label", "")
            category, relevance = _classify_field_pattern(name, ftype, label)
            confidence = "high" if category != "none" else "medium"
            if not name and not label:
                confidence = "low"
            detail = f"input name={name or '(unnamed)'}, type={ftype}, label={label or '(none)'}"
            findings.append(ClassifiedFinding(
                url=page.url,
                type="form_field",
                detail=detail,
                data_category=category,
                third_party_domain=None,
                dpdp_relevance=relevance,
                confidence=confidence,
                detail_hash=_detail_hash("form_field", f"{urlparse(page.url).path}|{name or label}"),
            ))

    # third-party scripts
    for script in page.scripts:
        domain = script.get("domain", "")
        vendor = script.get("vendor")
        confidence = "high" if vendor else "medium"
        detail = f"script from {domain}" + (f" ({vendor})" if vendor else " (unrecognized vendor)")
        findings.append(ClassifiedFinding(
            url=page.url,
            type="third_party_script",
            detail=detail,
            data_category="behavioral",
            third_party_domain=domain,
            dpdp_relevance="cross_border_transfer" if vendor else "notice",
            confidence=confidence,
            detail_hash=_detail_hash("third_party_script", domain),
        ))

    # cookies (only non-first-party ones matter for consent obligations)
    for cookie in page.cookies:
        if cookie.get("first_party"):
            continue
        name = cookie.get("name", "")
        domain = cookie.get("domain", "")
        findings.append(ClassifiedFinding(
            url=page.url,
            type="cookie",
            detail=f"third-party cookie '{name}' set by {domain}",
            data_category="behavioral",
            third_party_domain=domain,
            dpdp_relevance="consent",
            confidence="medium",
            detail_hash=_detail_hash("cookie", f"{domain}|{name}"),
        ))

    # NOTE: consent banner is evaluated site-wide, not per-page — see
    # _site_consent_banner_finding() called once from classify_crawl(). A banner
    # only needs to appear on one page (e.g. the homepage) to cover the site,
    # so per-page absence is not itself meaningful and would otherwise fire a
    # false "missing" signal on every subpage.

    # privacy policy — detail_hash keys on the URL (stable identity: "this is the
    # policy page"), NOT the content hash. The content hash instead lives inside
    # `detail`, so the Diff Agent sees a hash mismatch on the same finding as a
    # "changed" entry (spec: policy content changed -> Medium), rather than as a
    # "removed" + "new" pair, which would wrongly read as the page disappearing.
    if page.is_privacy_policy:
        findings.append(ClassifiedFinding(
            url=page.url,
            type="privacy_policy",
            detail=f"privacy policy page (content hash {page.privacy_policy_hash[:12] if page.privacy_policy_hash else 'n/a'})",
            data_category="none",
            third_party_domain=None,
            dpdp_relevance="notice",
            confidence="high",
            detail_hash=_detail_hash("privacy_policy", page.url),
        ))

    # auth flow marker (v1.5 per spec, but cheap to flag now — tagged low confidence review item)
    if AUTH_PATH_PATTERNS.search(urlparse(page.url).path):
        findings.append(ClassifiedFinding(
            url=page.url,
            type="form_field",
            detail="page matches auth/signup route pattern — verify age-gate / children's-data handling",
            data_category="children",
            third_party_domain=None,
            dpdp_relevance="children_data",
            confidence="low",
            detail_hash=_detail_hash("auth_route", urlparse(page.url).path),
        ))

    return findings


def _safe_classified_finding(f: dict, page_url: str, fallback_url: str) -> ClassifiedFinding | None:
    """Build one ClassifiedFinding from a raw Gemini response object,
    coercing/validating every field against the schema in app/models.py
    instead of trusting the model's output verbatim.

    Rationale: `type` is a pydantic Literal — constructing ClassifiedFinding
    with a value Gemini invented (a hallucinated type string, a typo) raises
    a ValidationError. Previously that exception propagated up and discarded
    EVERY finding already parsed for the page, falling all the way back to
    the mock classifier — one malformed item in a 20-item response threw
    away 19 good ones. Here, an unrecognized `type` causes just that one
    finding to be skipped (logged); an unrecognized data_category/
    dpdp_relevance/confidence is coerced to a safe default (and forced to
    low confidence, so it still lands in the human review queue rather than
    silently getting a made-up label).
    """
    ftype = f.get("type")
    if ftype not in _VALID_TYPES:
        logger.warning("Gemini returned unrecognized finding type %r for %s — skipping that finding", ftype, page_url)
        return None

    category = f.get("data_category")
    relevance = f.get("dpdp_relevance")
    confidence = f.get("confidence")
    coerced_low_confidence = False

    if category not in _VALID_CATEGORIES:
        category = "none"
        coerced_low_confidence = True
    if relevance not in _VALID_RELEVANCE:
        relevance = "none"
        coerced_low_confidence = True
    if confidence not in _VALID_CONFIDENCE:
        confidence = "medium"
        coerced_low_confidence = True

    detail = str(f.get("detail", ""))[:2000]  # cap pathological detail strings

    # Runtime guardrail: `detail` is free text from Gemini, not a fixed
    # template — nothing stops the model from occasionally phrasing a
    # finding as a compliance conclusion ("you are not compliant because
    # ..."). The product's hard line (spec: "it does not tell a client
    # 'you are compliant' or 'you are not compliant'") has to hold even
    # when the wording comes from the LLM, not just from our own templates.
    # Forcing low confidence here routes it to human review AND (per the
    # notifier's ALERTABLE filter) keeps it out of the client-facing
    # WhatsApp alert entirely — see app/agents/notifier.py.
    violation = contains_compliance_conclusion(detail)
    if violation:
        logger.warning(
            "Gemini finding for %s %s — forcing low confidence for human review. detail=%r",
            page_url, violation, detail,
        )
        coerced_low_confidence = True

    key = f.get("third_party_domain") or detail

    try:
        return ClassifiedFinding(
            url=str(f.get("url") or page_url or fallback_url),
            type=ftype,
            detail=detail,
            data_category=category,
            third_party_domain=f.get("third_party_domain"),
            dpdp_relevance=relevance,
            confidence="low" if coerced_low_confidence else confidence,
            detail_hash=_detail_hash(ftype, key),
        )
    except pydantic.ValidationError as e:
        logger.warning("Discarding unparseable Gemini finding for %s: %s", page_url, e)
        return None


# Transient conditions worth retrying — a bad request or an auth failure
# won't fix itself on retry, so those fall straight through to the mock
# classifier instead of burning attempts (and latency) retrying them.
_RETRYABLE_STATUS_CODES = {408, 409, 425, 429, 500, 502, 503, 504}


def _gemini_classify_page(page: PageCrawlResult) -> list[ClassifiedFinding]:
    """Real Gemini JSON-mode call. Only used when GEMINI_API_KEY is configured.
    Retries transient failures (timeouts, 429/5xx) with backoff; anything
    non-transient, or retries exhausted, falls back to the mock classifier
    so a scan never simply fails because the LLM had a bad moment — see
    README/DEPLOY.md, this fallback behavior is a deliberate MVP guardrail,
    not just an implementation shortcut."""
    import httpx

    def _cap(items: list, label: str) -> list:
        if len(items) > MAX_ITEMS_PER_PAGE_FOR_CLASSIFIER:
            logger.warning(
                "%s has %d %s, capping to %d before sending to Gemini (page likely malformed/spam)",
                page.url, len(items), label, MAX_ITEMS_PER_PAGE_FOR_CLASSIFIER,
            )
            return items[:MAX_ITEMS_PER_PAGE_FOR_CLASSIFIER]
        return items

    raw_payload = {
        "url": page.url,
        "forms": _cap(page.forms, "forms"),
        "cookies": _cap([c for c in page.cookies if not c.get("first_party")], "third-party cookies"),
        "scripts": _cap(page.scripts, "scripts"),
        "consent_banner": page.consent_banner,
        "is_privacy_policy": page.is_privacy_policy,
    }

    prompt = f"""You are a DPDP (India's Digital Personal Data Protection Act) compliance classifier.
Given raw crawl findings for ONE web page (JSON below), classify each finding per this exact schema:

{{
  "url": "string",
  "findings": [
    {{
      "type": "form_field | cookie | third_party_script | consent_banner | privacy_policy",
      "detail": "short human-readable description",
      "data_category": "contact | financial | health | children | behavioral | identity | none",
      "third_party_domain": "string or null",
      "dpdp_relevance": "notice | consent | security_safeguard | children_data | cross_border_transfer | none",
      "confidence": "high | medium | low"
    }}
  ]
}}

Rules:
- Emit one finding object per form field, per third-party script/cookie, and one for the consent banner / privacy policy if present.
- Use "low" confidence for anything ambiguous — these get routed to human review, never shown to the client directly, so err toward caution.
- Return STRICT JSON only, no markdown fences, no commentary.

Raw findings:
{json.dumps(raw_payload, indent=2)}
"""

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"response_mime_type": "application/json"},
    }

    last_error: Exception | None = None
    for attempt in range(1, GEMINI_MAX_RETRIES + 1):
        try:
            resp = httpx.post(url, json=body, timeout=GEMINI_TIMEOUT_SECONDS)
            if resp.status_code in _RETRYABLE_STATUS_CODES and attempt < GEMINI_MAX_RETRIES:
                wait = min(2 ** attempt, 20)
                logger.warning(
                    "Gemini call for %s got HTTP %s (attempt %d/%d), retrying in %ss",
                    page.url, resp.status_code, attempt, GEMINI_MAX_RETRIES, wait,
                )
                time.sleep(wait)
                continue
            resp.raise_for_status()

            data = resp.json()
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            parsed = json.loads(text)

            findings = []
            for f in parsed.get("findings", []):
                if not isinstance(f, dict):
                    continue
                built = _safe_classified_finding(f, page.url, parsed.get("url", page.url))
                if built:
                    findings.append(built)
            return findings

        except (httpx.TimeoutException, httpx.TransportError) as e:
            last_error = e
            if attempt < GEMINI_MAX_RETRIES:
                wait = min(2 ** attempt, 20)
                logger.warning(
                    "Gemini call for %s failed (%s) on attempt %d/%d, retrying in %ss",
                    page.url, e, attempt, GEMINI_MAX_RETRIES, wait,
                )
                time.sleep(wait)
                continue
            break
        except Exception as e:
            # Non-transient (bad JSON, unexpected response shape, 4xx client
            # error via raise_for_status, etc.) — retrying won't help.
            last_error = e
            break

    logger.warning(
        "Gemini classification failed for %s after %d attempt(s), falling back to mock classifier: %s",
        page.url, GEMINI_MAX_RETRIES, last_error,
    )
    return _mock_classify_page(page)


def classify_page(page: PageCrawlResult) -> list[ClassifiedFinding]:
    """Entry point — routes to Gemini or the mock classifier based on config."""
    if page.error:
        return []
    if GEMINI_API_KEY:
        return _gemini_classify_page(page)
    return _mock_classify_page(page)


def _site_consent_banner_finding(pages: list[PageCrawlResult]) -> ClassifiedFinding:
    """
    Consent banner is a SITE-LEVEL concept, not per-page: a CMP loaded once
    (typically via the homepage or a shared layout) covers the whole site.
    Evaluating it per-page would falsely flag every subpage as "missing" even
    when the site is fully covered. We take the best signal seen across all
    crawled pages: present + named CMP > present + heuristic-only > absent.
    """
    best = {"present": False, "cmp": None, "source": None}
    for page in pages:
        cb = page.consent_banner
        if not cb or not cb.get("present"):
            continue
        if not best["present"]:
            best = cb
        elif cb.get("source") == "script" and best.get("source") != "script":
            best = cb  # prefer a known-CMP script match over a text heuristic

    if best["present"]:
        cmp_name = best.get("cmp")
        detail = f"consent banner present site-wide (CMP: {cmp_name or 'unknown'})"
        confidence = "high" if cmp_name and cmp_name != "unknown/custom" else "medium"
    else:
        detail = "no consent banner detected anywhere on the site"
        confidence = "medium"

    return ClassifiedFinding(
        url=pages[0].url if pages else "",
        type="consent_banner",
        detail=detail,
        data_category="none",
        third_party_domain=None,
        dpdp_relevance="consent",
        confidence=confidence,
        # stable key regardless of present/absent state — a present->absent
        # transition must surface as one "changed" entry (Diff Agent already
        # scores that High via _severity_for_changed), not as a "removed"
        # (old state) + "new" (new state) pair, which would double-alert on
        # the same underlying event.
        detail_hash=_detail_hash("consent_banner", "site_wide"),
    )


def classify_crawl(pages: list[PageCrawlResult]) -> list[ClassifiedFinding]:
    """Classify every page in a crawl report, page by page (per spec: smaller context),
    plus one site-wide consent-banner rollup finding (see _site_consent_banner_finding)."""
    all_findings: list[ClassifiedFinding] = []
    for page in pages:
        page_findings = classify_page(page)
        # consent_banner is handled site-wide below, not per-page
        all_findings.extend(f for f in page_findings if f.type != "consent_banner")

    crawled_pages = [p for p in pages if not p.error]
    if crawled_pages:
        all_findings.append(_site_consent_banner_finding(crawled_pages))

    return all_findings
