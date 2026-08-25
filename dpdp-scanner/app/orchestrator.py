"""
Supervisor / orchestrator — runs Crawler -> Classifier -> Diff -> Notifier
for one client, in sequence, and persists every stage to the DB for audit.

This is the "same shape as your outreach/delivery agent team, four workers
instead of two" piece the spec calls for. No async/queueing needed for MVP —
straight sequential calls, one client per invocation.

Error isolation: this function is designed to never let one bad site take
down a whole cron run. A crawl failure (site down, DNS broken, SSRF-rejected
target) is caught, recorded as a `scans` row with status='failed' and an
error_message (so it shows up in the client's own audit trail, not just a
log line nobody reads), and returned as a normal — not exceptional — result
with `success: False`. `run_scan.py --all` relies on this: it loops over
every active client and this function returning cleanly (success or not) is
what lets client #4's outage not stop client #5 and #6 from being scanned.
"""
from __future__ import annotations

import json
import logging

from app import repository as repo
from app.agents.crawler import crawl_site, CrawlTargetRejected
from app.agents.classifier import classify_crawl
from app.agents.differ import diff_findings
from app.agents.notifier import build_alert_messages, send_whatsapp, build_drafts
from app.config import LOW_CONFIDENCE_TO_REVIEW, MAX_PAGES, TRIAL_MAX_PAGES

logger = logging.getLogger("orchestrator")


def _failed_result(client_id: int, domain: str, scan_id: int | None, error: str) -> dict:
    return {
        "client_id": client_id, "domain": domain, "scan_id": scan_id,
        "success": False, "error": error,
        "page_count": 0, "finding_count": 0, "diff_id": None, "severity": None,
        "new_count": 0, "changed_count": 0, "removed_count": 0,
        "alerts_sent": [], "drafts_created": 0, "is_first_scan": None,
    }


def run_scan_for_client(domain: str, whatsapp_number: str | None = None,
                         start_url: str | None = None) -> dict:
    """
    Full pipeline for one client. `start_url` overrides the crawl entrypoint
    (useful for http://localhost test fixtures); defaults to https://<domain>/.
    Returns a summary dict for CLI/dashboard display. Does not raise for an
    ordinary scan failure (bad site, unreachable domain) — see module
    docstring; a dict with success=False is the expected way that shows up.
    """
    client = repo.get_or_create_client(domain, whatsapp_number)
    client_id = client["id"]

    entry_url = start_url or f"https://{domain}/"
    max_pages = TRIAL_MAX_PAGES if client.get("plan_tier") == "trial" else MAX_PAGES
    logger.info(
        "Starting scan for client_id=%s domain=%s entry=%s plan_tier=%s max_pages=%s",
        client_id, domain, entry_url, client.get("plan_tier"), max_pages,
    )

    # 1. Crawl — the stage most exposed to the outside world (DNS, a down
    # site, a slow site, an SSRF-rejected target), so it gets its own
    # try/except and its own failure record rather than propagating.
    try:
        crawl_report = crawl_site(entry_url, max_pages=max_pages)
    except CrawlTargetRejected as e:
        logger.error("Scan rejected for client_id=%s domain=%s: %s", client_id, domain, e)
        scan_id = repo.create_scan(client_id=client_id, page_count=0, raw_findings={}, status="failed", error_message=str(e))
        return _failed_result(client_id, domain, scan_id, str(e))
    except Exception as e:
        logger.exception("Crawl failed for client_id=%s domain=%s", client_id, domain)
        scan_id = repo.create_scan(client_id=client_id, page_count=0, raw_findings={}, status="failed", error_message=str(e))
        return _failed_result(client_id, domain, scan_id, str(e))

    # 2. Classify — classify_crawl/classify_page already degrade gracefully
    # per-page (Gemini failures fall back to the mock classifier, see
    # app/agents/classifier.py), so this is a last-resort guard rather than
    # the primary error path.
    try:
        classified = classify_crawl(crawl_report.pages)
    except Exception as e:
        logger.exception("Classification failed for client_id=%s domain=%s", client_id, domain)
        scan_id = repo.create_scan(
            client_id=client_id, page_count=crawl_report.page_count,
            raw_findings={"crawl": crawl_report.model_dump()},
            status="failed", error_message=f"classification failed: {e}",
        )
        return _failed_result(client_id, domain, scan_id, str(e))

    classified_dicts = [f.model_dump() for f in classified]

    prev_scan = repo.get_latest_scan(client_id)

    # persist this scan + its findings
    scan_id = repo.create_scan(
        client_id=client_id,
        page_count=crawl_report.page_count,
        raw_findings={"crawl": crawl_report.model_dump(), "classified": classified_dicts},
    )
    repo.bulk_insert_findings(scan_id, classified_dicts)

    # route low-confidence findings to human review, never straight to client
    if LOW_CONFIDENCE_TO_REVIEW:
        stored = repo.get_findings_for_scan(scan_id)
        for row in stored:
            if row["confidence"] == "low":
                repo.enqueue_review(row["id"], client_id)

    # 3. Diff against previous scan (if any)
    prev_findings = repo.get_findings_for_scan(prev_scan["id"]) if prev_scan else []
    curr_findings = repo.get_findings_for_scan(scan_id)

    diff_result = diff_findings(
        client_id=client_id,
        prev_scan_id=prev_scan["id"] if prev_scan else None,
        curr_scan_id=scan_id,
        prev_findings=prev_findings,
        curr_findings=curr_findings,
    )

    diff_id = repo.create_diff(
        client_id=client_id,
        prev_scan_id=diff_result.prev_scan_id,
        curr_scan_id=diff_result.curr_scan_id,
        new=[e.model_dump() for e in diff_result.new],
        changed=[e.model_dump() for e in diff_result.changed],
        removed=[e.model_dump() for e in diff_result.removed],
        severity=diff_result.severity,
    )

    # 4. Notify — only High/Medium fire alerts; drafts only for NEW notice/consent findings.
    # On a client's very FIRST scan there is no prior snapshot, so every finding shows up
    # as "new" by definition — that's establishing a baseline, not drift. Alerting on all of
    # it would be exactly the noise the spec warns kills adoption ("false positives are what
    # will get this product uninstalled"), so the first scan logs everything to the dashboard
    # and drafts, but does not fire WhatsApp alerts. Real alerts start from the second scan on.
    is_first_scan = prev_scan is None
    min_severity = client.get("min_alert_severity", "medium") if isinstance(client, dict) else "medium"
    alert_messages = build_alert_messages(
        domain, diff_result, dashboard_url=f"/clients/{client_id}/diffs/{diff_id}", min_severity=min_severity,
    )
    sent_alerts = []
    if not is_first_scan:
        for am in alert_messages:
            # Each send is isolated: a failed WhatsApp delivery (bad number,
            # provider outage) must not stop the remaining alerts in this
            # scan from being attempted, and must not take down the rest of
            # the pipeline (drafts still need to run either way). The alert
            # itself is always recorded — delivery_status distinguishes
            # "we tried to tell the client and it worked" from "...and it
            # didn't" without losing the audit trail either way.
            try:
                receipt = send_whatsapp(whatsapp_number, am["message"])
                delivery_status = "sent" if receipt.get("delivered") else receipt.get("status", "sim")
                delivery_error = None
            except Exception as e:
                logger.exception("send_whatsapp failed for client_id=%s diff_id=%s", client_id, diff_id)
                receipt = {"channel": "error", "to": whatsapp_number, "status": "failed", "delivered": False}
                delivery_status = "failed"
                delivery_error = str(e)

            repo.create_alert(
                client_id, diff_id, am["severity"], am["message"],
                delivery_status=delivery_status, delivery_error=delivery_error,
            )
            sent_alerts.append({"severity": am["severity"], "message": am["message"], "receipt": receipt})

    drafts = build_drafts(domain, diff_result)
    # match each draft back to its finding_id in the DB (by detail_hash) so it's linkable
    findings_by_hash = {f["detail_hash"]: f for f in curr_findings}
    for d in drafts:
        finding_row = findings_by_hash.get(d["finding"]["detail_hash"])
        if not finding_row:
            continue
        repo.create_draft(client_id, finding_row["id"], "notice_paragraph", d["notice_paragraph"])
        repo.create_draft(client_id, finding_row["id"], "inventory_row", json.dumps(d["inventory_row"]))

    logger.info(
        "Scan complete: client=%s scan_id=%s pages=%s findings=%s severity=%s first_scan=%s alerts_sent=%s drafts=%s",
        domain, scan_id, crawl_report.page_count, len(curr_findings), diff_result.severity,
        is_first_scan, len(sent_alerts), len(drafts),
    )

    return {
        "client_id": client_id,
        "domain": domain,
        "scan_id": scan_id,
        "success": True,
        "error": None,
        "page_count": crawl_report.page_count,
        "finding_count": len(curr_findings),
        "diff_id": diff_id,
        "severity": diff_result.severity,
        "new_count": len(diff_result.new),
        "changed_count": len(diff_result.changed),
        "removed_count": len(diff_result.removed),
        "alerts_sent": sent_alerts,
        "drafts_created": len(drafts),
        "is_first_scan": is_first_scan,
    }
