"""
Tests for orchestrator error isolation (app/orchestrator.py): a crawl
failure must be recorded as a failed scan (not an uncaught exception), and
one alert's failed WhatsApp send must not stop the rest of the pipeline.

crawl_site and classify_crawl are monkeypatched with canned results so these
run as fast, offline unit tests — no real Playwright browser, no network.
The crawler's own behavior (including the SSRF guard) is covered separately
in tests/test_crawler_safety.py; this file is about what the orchestrator
does with whatever the crawler/classifier hand it, good or bad.
"""
import sys
import tempfile
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _fresh_env():
    """Reimport the whole app.* namespace against a fresh throwaway DB, same
    reasoning as tests/test_web_auth.py's _fresh_app — `from app.x import y`
    caches the submodule as a package attribute, independent of sys.modules,
    so a partial pop leaves stale bindings across tests."""
    for mod in list(sys.modules):
        if mod == "app" or mod.startswith("app."):
            sys.modules.pop(mod, None)
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    import app.db.conn as conn_mod
    conn_mod.DB_PATH = Path(path)
    conn_mod.init_db()
    import app.orchestrator as orch_mod
    import app.repository as repo_mod
    from app.models import CrawlReport, PageCrawlResult
    return orch_mod, repo_mod, CrawlReport, PageCrawlResult


def test_crawl_failure_recorded_as_failed_scan_not_raised():
    orch, repo, CrawlReport, PageCrawlResult = _fresh_env()

    def _boom(url, **kwargs):
        raise RuntimeError("DNS resolution failed")

    orch.crawl_site = _boom
    result = orch.run_scan_for_client("broken-site.example", start_url="https://broken-site.example/")

    assert result["success"] is False
    assert "DNS resolution failed" in result["error"]
    scan = repo.get_latest_scan(result["client_id"])
    assert scan["status"] == "failed"
    assert "DNS resolution failed" in scan["error_message"]


def test_ssrf_rejection_recorded_as_failed_scan():
    orch, repo, CrawlReport, PageCrawlResult = _fresh_env()

    def _reject(url, **kwargs):
        raise orch.CrawlTargetRejected("host resolves to a private address")

    orch.crawl_site = _reject
    result = orch.run_scan_for_client("internal-only.example")

    assert result["success"] is False
    assert "private address" in result["error"]
    scan = repo.get_latest_scan(result["client_id"])
    assert scan["status"] == "failed"


def _canned_crawl_report(CrawlReport, PageCrawlResult, domain="alert-test.example"):
    return CrawlReport(
        domain=domain, started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:05Z",
        page_count=1,
        pages=[PageCrawlResult(url=f"https://{domain}/", status_code=200)],
    )


def test_one_failed_alert_send_does_not_stop_the_rest_or_the_drafts():
    orch, repo, CrawlReport, PageCrawlResult = _fresh_env()
    from app.models import ClassifiedFinding

    domain = "alert-test.example"
    orch.crawl_site = lambda url, **kw: _canned_crawl_report(CrawlReport, PageCrawlResult, domain)

    # Two HIGH-severity, alertable, distinct findings so the notify loop has
    # more than one message to send.
    findings = [
        ClassifiedFinding(
            url=f"https://{domain}/pricing", type="third_party_script",
            detail="script from hotjar.com", data_category="behavioral",
            third_party_domain="hotjar.com", dpdp_relevance="cross_border_transfer",
            confidence="high", detail_hash="finding_one",
        ),
        ClassifiedFinding(
            url=f"https://{domain}/apply", type="form_field",
            detail="input name=diagnosis", data_category="health",
            dpdp_relevance="consent", confidence="high", detail_hash="finding_two",
        ),
    ]
    orch.classify_crawl = lambda pages: findings

    # First scan establishes baseline (no alerts fire on scan 1 by design).
    r1 = orch.run_scan_for_client(domain, whatsapp_number="+919999999999")
    assert r1["success"] is True
    assert r1["is_first_scan"] is True
    assert len(r1["alerts_sent"]) == 0

    # Second scan: same two findings are unchanged (no new diff), so add a
    # THIRD new finding to actually trigger alertable diff entries this time.
    findings_v2 = findings + [
        ClassifiedFinding(
            url=f"https://{domain}/checkout", type="third_party_script",
            detail="script from new-tracker.example", data_category="behavioral",
            third_party_domain="new-tracker.example", dpdp_relevance="cross_border_transfer",
            confidence="medium", detail_hash="finding_three",
        ),
        ClassifiedFinding(
            url=f"https://{domain}/checkout", type="cookie",
            detail="third-party cookie '_x' set by new-tracker.example", data_category="behavioral",
            third_party_domain="new-tracker.example", dpdp_relevance="consent",
            confidence="medium", detail_hash="finding_four",
        ),
    ]
    orch.classify_crawl = lambda pages: findings_v2

    call_count = {"n": 0}

    def _flaky_send(to_number, message):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise ConnectionError("simulated Twilio outage")
        return {"channel": "whatsapp_sim", "to": to_number, "status": "logged", "delivered": False}

    orch.send_whatsapp = _flaky_send

    r2 = orch.run_scan_for_client(domain, whatsapp_number="+919999999999")

    assert r2["success"] is True, "a failed WhatsApp send must not fail the whole scan"
    assert call_count["n"] >= 2, "the second alert must still be attempted after the first one raised"
    assert len(r2["alerts_sent"]) == call_count["n"], "every attempted alert (sent or failed) is still recorded"

    alerts = repo.list_alerts(client_id=r2["client_id"])
    delivery_statuses = {a["delivery_status"] for a in alerts}
    assert "failed" in delivery_statuses, "the failed send must be recorded as failed, not silently dropped"
    failed_alert = next(a for a in alerts if a["delivery_status"] == "failed")
    assert "Twilio outage" in failed_alert["delivery_error"]


def test_trial_tier_client_gets_capped_max_pages():
    orch, repo, CrawlReport, PageCrawlResult = _fresh_env()
    domain = "trial-client.example"
    repo.create_client(domain, plan_tier="trial")

    captured = {}

    def _capturing_crawl(url, max_pages=None, **kw):
        captured["max_pages"] = max_pages
        return _canned_crawl_report(CrawlReport, PageCrawlResult, domain)

    orch.crawl_site = _capturing_crawl
    orch.classify_crawl = lambda pages: []
    orch.run_scan_for_client(domain)

    assert captured["max_pages"] == orch.TRIAL_MAX_PAGES
    assert orch.TRIAL_MAX_PAGES < orch.MAX_PAGES


def test_paid_tier_client_gets_full_max_pages():
    orch, repo, CrawlReport, PageCrawlResult = _fresh_env()
    domain = "paid-client.example"
    repo.create_client(domain, plan_tier="paid")

    captured = {}

    def _capturing_crawl(url, max_pages=None, **kw):
        captured["max_pages"] = max_pages
        return _canned_crawl_report(CrawlReport, PageCrawlResult, domain)

    orch.crawl_site = _capturing_crawl
    orch.classify_crawl = lambda pages: []
    orch.run_scan_for_client(domain)

    assert captured["max_pages"] == orch.MAX_PAGES


if __name__ == "__main__":
    import inspect
    mod = sys.modules[__name__]
    tests = [f for name, f in inspect.getmembers(mod) if name.startswith("test_")]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL {t.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR {t.__name__}: {e!r}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
