"""
Notifier Agent
==============
Takes a DiffResult and:
  1. Formats a WhatsApp-style alert for each High/Medium severity entry
     (Low sits in the dashboard only — never fires an alert, per spec).
  2. "Sends" it via a swappable channel: real Twilio WhatsApp sending when
     TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_WHATSAPP_FROM are all
     set, otherwise the original console-log + `alerts` table simulation
     (channel='whatsapp_sim') — same presence-based swap pattern as the
     classifier's GEMINI_API_KEY. A misconfigured/erroring Twilio call
     raises rather than silently pretending to succeed; the orchestrator is
     what catches that per-alert (see app/orchestrator.py) and records
     delivery_status='failed' without stopping the rest of the scan.
  3. Auto-drafts (never auto-publishes) a privacy-notice paragraph and a
     data-inventory row for each NEW finding tagged dpdp_relevance in
     {notice, consent}.

Only High/Medium diff entries produce alerts. All diff entries (including Low)
are still logged to the DB for the audit trail.
"""
from __future__ import annotations

import logging
import time

from app.config import (
    TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_FROM,
    WHATSAPP_SEND_MAX_RETRIES,
)
from app.models import DiffResult, DiffEntry

logger = logging.getLogger("notifier")

TWILIO_CONFIGURED = bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_WHATSAPP_FROM)

ALERTABLE_SEVERITIES = {"high", "medium"}
DRAFT_RELEVANCE = {"notice", "consent"}
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

SEVERITY_EMOJI = {"high": "🔴", "medium": "🟡", "low": "⚪"}


KIND_LABEL = {"new": "New this week", "changed": "Changed this week", "removed": "Removed this week"}


def format_whatsapp_alert(domain: str, entry: DiffEntry, kind: str, dashboard_url: str = "") -> str:
    """One-glance WhatsApp message per the spec's format. `kind` is 'new' | 'changed' | 'removed'."""
    f = entry.finding
    detail = f.get("detail", "")
    relevance = f.get("dpdp_relevance", "none")
    relevance_label = {
        "notice": "requires privacy notice update",
        "consent": "requires consent capture",
        "security_safeguard": "security safeguard concern",
        "children_data": "children's data / age-gate concern",
        "cross_border_transfer": "third-party data flow, check DPA/cross-border transfer",
        "none": "flagged for review",
    }.get(relevance, "flagged for review")

    emoji = SEVERITY_EMOJI.get(entry.severity, "⚪")
    label = KIND_LABEL.get(kind, "New this week")
    lines = [
        f"{emoji} DPDP scan — {domain}",
        f"{label}: {detail}",
        f"→ {entry.reason} ({relevance_label})",
    ]
    if dashboard_url:
        lines.append(f"[View details]({dashboard_url}) [Mark handled]")
    return "\n".join(lines)


def build_alert_messages(domain: str, diff: DiffResult, dashboard_url: str = "", min_severity: str = "medium") -> list[dict]:
    """Return alertable entries from new+changed+removed as message dicts.

    `min_severity` lets a client raise their own alert bar to "high" only
    (clients.min_alert_severity — set from the dashboard/CLI for a client
    who finds Medium alerts too noisy for their workflow). It can only ever
    RAISE the bar, never lower it below "medium": the spec is explicit that
    Low severity never fires a client alert ("false positives are what will
    get this product uninstalled") — that floor isn't a per-client setting.
    """
    threshold = SEVERITY_ORDER.get(min_severity, SEVERITY_ORDER["medium"])
    threshold = max(threshold, SEVERITY_ORDER["medium"])

    messages = []
    for kind, entries in (("new", diff.new), ("changed", diff.changed), ("removed", diff.removed)):
        for entry in entries:
            # Low-confidence findings must NEVER reach a client alert,
            # regardless of severity — the spec's own words: "Anything the
            # model tags confidence: low goes into a human-review queue
            # instead of a client-facing alert; false positives are what
            # will get this product uninstalled." Severity alone isn't a
            # substitute for that check: a low-confidence finding of type
            # third_party_script/cookie/sensitive-category still scores
            # High by TYPE in the Diff Agent (app/agents/differ.py) even
            # though the classifier itself wasn't sure about it — without
            # this check, a shaky classification would still buzz a
            # client's phone.
            if entry.finding.get("confidence") == "low":
                continue
            if entry.severity in ALERTABLE_SEVERITIES and SEVERITY_ORDER[entry.severity] >= threshold:
                messages.append({
                    "severity": entry.severity,
                    "message": format_whatsapp_alert(domain, entry, kind, dashboard_url),
                    "finding": entry.finding,
                })
    return messages


def _send_whatsapp_sim(to_number: str | None, message: str) -> dict:
    logger.info("[WHATSAPP SIM] to=%s\n%s\n", to_number or "(no number on file)", message)
    return {"channel": "whatsapp_sim", "to": to_number, "status": "logged", "delivered": False}


def _normalize_whatsapp_number(to_number: str) -> str:
    n = to_number.strip()
    if not n.startswith("whatsapp:"):
        if not n.startswith("+"):
            n = "+" + n
        n = f"whatsapp:{n}"
    return n


def _send_whatsapp_twilio(to_number: str | None, message: str) -> dict:
    """Real send via Twilio's WhatsApp API. Only called when TWILIO_* env
    vars are all set (see TWILIO_CONFIGURED). A quick single retry absorbs a
    momentary network blip; anything else (bad number, auth failure, Twilio
    account issue) raises immediately — the orchestrator is what decides
    what happens to the rest of the scan when a send fails, this function's
    only job is "did the message actually go, yes or no"."""
    import httpx

    if not to_number:
        raise ValueError("no WhatsApp number on file for this client — cannot send a real alert")

    url = f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json"
    data = {
        "From": _normalize_whatsapp_number(TWILIO_WHATSAPP_FROM),
        "To": _normalize_whatsapp_number(to_number),
        "Body": message,
    }

    last_error: Exception | None = None
    for attempt in range(1, WHATSAPP_SEND_MAX_RETRIES + 1):
        try:
            resp = httpx.post(url, data=data, auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN), timeout=15.0)
            resp.raise_for_status()
            payload = resp.json()
            return {
                "channel": "whatsapp", "to": to_number, "status": payload.get("status", "sent"),
                "delivered": True, "provider_sid": payload.get("sid"),
            }
        except (Exception,) as e:
            last_error = e
            # Only retry on things that look transient (network-level); a
            # 4xx from Twilio (bad number, bad auth) won't fix itself.
            status = getattr(getattr(e, "response", None), "status_code", None)
            transient = status is None or status >= 500
            if transient and attempt < WHATSAPP_SEND_MAX_RETRIES:
                wait = min(2 ** attempt, 10)
                logger.warning("WhatsApp send to %s failed (attempt %d/%d), retrying in %ss: %s",
                                to_number, attempt, WHATSAPP_SEND_MAX_RETRIES, wait, e)
                time.sleep(wait)
                continue
            break

    raise RuntimeError(f"Twilio WhatsApp send failed: {last_error}") from last_error


def send_whatsapp(to_number: str | None, message: str) -> dict:
    """
    Swappable send function — real Twilio send when TWILIO_ACCOUNT_SID /
    TWILIO_AUTH_TOKEN / TWILIO_WHATSAPP_FROM are configured, otherwise the
    original console-log + DB-only simulation. Raises on a real, failed send
    (see _send_whatsapp_twilio) rather than returning a fake success —
    callers (app/orchestrator.py) catch that per-alert and record it as
    delivery_status='failed' without losing the rest of the scan.
    """
    if TWILIO_CONFIGURED:
        return _send_whatsapp_twilio(to_number, message)
    return _send_whatsapp_sim(to_number, message)


def draft_notice_paragraph(domain: str, finding: dict) -> str:
    """Template draft privacy-notice paragraph for a new notice/consent finding."""
    detail = finding.get("detail", "")
    category = finding.get("data_category", "none")
    ftype = finding.get("type")
    third_party = finding.get("third_party_domain")

    if ftype == "form_field":
        return (
            f'We collect the following through our forms on {domain}: {detail}. '
            f'This data is categorized as "{category}" and is used to provide and improve our services. '
            f'[DRAFT — confirm purpose and retention period before publishing.]'
        )
    if ftype == "third_party_script":
        return (
            f'We use {third_party or "a third-party"} on {domain} to support site functionality/analytics. '
            f'This may involve sharing data with this third party. '
            f'[DRAFT — confirm whether a Data Processing Agreement is on file before publishing.]'
        )
    if ftype == "cookie":
        return (
            f'{domain} sets a cookie via {third_party or "a third party"} ({detail}). '
            f'[DRAFT — confirm this is covered by the consent banner before publishing.]'
        )
    return f'[DRAFT] New item detected on {domain}: {detail}. Review before adding to the privacy notice.'


def draft_inventory_row(domain: str, finding: dict) -> dict:
    """One row for the running data-inventory sheet (a RoPA in miniature)."""
    return {
        "field_or_item": finding.get("detail", ""),
        "purpose": "(to confirm)",
        "vendor": finding.get("third_party_domain") or "internal",
        "data_category": finding.get("data_category", "none"),
        "retention": "(to confirm)",
        "source_page": finding.get("url", domain),
    }


def build_drafts(domain: str, diff: DiffResult) -> list[dict]:
    """Drafts are only generated for NEW findings with notice/consent relevance."""
    drafts = []
    for entry in diff.new:
        f = entry.finding
        if f.get("dpdp_relevance") in DRAFT_RELEVANCE:
            drafts.append({
                "finding": f,
                "notice_paragraph": draft_notice_paragraph(domain, f),
                "inventory_row": draft_inventory_row(domain, f),
            })
    return drafts
