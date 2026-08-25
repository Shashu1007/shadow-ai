"""
Tests for the legal/compliance guardrails described in app/guardrails.py:

1. No generated client-facing text (WhatsApp alerts, drafted notices,
   drafted inventory rows) ever states a compliance conclusion — fuzzed
   across every severity/type/relevance combination the templates can
   produce.
2. A compliance-conclusion phrase injected into a Gemini-generated `detail`
   string gets caught and forced to low confidence rather than passed
   through to a client.
3. Low-confidence findings never reach a client-facing alert, even when
   their TYPE would otherwise auto-score High/Medium severity — this was a
   real gap (see app/agents/notifier.py's comment on the fix): confidence
   and severity were checked independently, so a shaky low-confidence
   classification of a type like third_party_script could still fire a
   WhatsApp alert despite the spec's explicit guardrail.
4. The audit trail (scans/findings/diffs/alerts) is append-only — no DELETE
   statement anywhere in the data-access layer.
5. End-to-end: a low-confidence finding lands in the review queue and does
   NOT produce a WhatsApp alert, even on a second scan where alerting is
   otherwise active.
"""
import itertools
import os
import re
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.guardrails import contains_compliance_conclusion


# --- 1. direct pattern tests ---

def test_obvious_violations_are_caught():
    violating = [
        "You are DPDP compliant, no further action needed.",
        "This means your site is not compliant with the DPDP Act.",
        "Your consent flow is non-compliant.",
        "This script is in violation of the DPDP Act.",
        "This vendor relationship is in breach of your obligations.",
        "Collecting this field is illegal under DPDP.",
        "You must obtain fresh consent immediately.",
        "This setup is guaranteed to pass a DPDP audit.",
    ]
    for text in violating:
        assert contains_compliance_conclusion(text) is not None, f"should have flagged: {text!r}"


def test_legitimate_findings_language_is_not_flagged():
    clean = [
        "New third-party script/tracker detected — data processor/transfer risk.",
        "This field is categorized as financial data.",
        "Confirm whether a Data Processing Agreement is on file before publishing.",
        "Consent banner present site-wide (CMP: OneTrust).",
        "Privacy policy content changed since last scan.",
        "We use Hotjar on example.com to support site functionality/analytics.",
    ]
    for text in clean:
        assert contains_compliance_conclusion(text) is None, f"false positive on legitimate text: {text!r}"


# --- 2. fuzz every notifier template across the full combinatorial space ---

def test_whatsapp_alert_templates_never_state_a_compliance_conclusion():
    from app.agents.notifier import format_whatsapp_alert
    from app.models import DiffEntry

    types = ["form_field", "cookie", "third_party_script", "consent_banner", "privacy_policy"]
    categories = ["contact", "financial", "health", "children", "behavioral", "identity", "none"]
    relevances = ["notice", "consent", "security_safeguard", "children_data", "cross_border_transfer", "none"]
    severities = ["high", "medium", "low"]
    kinds = ["new", "changed", "removed"]

    checked = 0
    for ftype, category, relevance, severity, kind in itertools.product(types, categories, relevances, severities, kinds):
        finding = {
            "url": "https://client.example/page", "type": ftype,
            "detail": f"input name=test, type=text, label=Test ({category})",
            "data_category": category, "third_party_domain": "vendor.example",
            "dpdp_relevance": relevance, "confidence": "medium",
        }
        entry = DiffEntry(finding=finding, severity=severity, reason="New non-sensitive form field.")
        message = format_whatsapp_alert("client.example", entry, kind, dashboard_url="/clients/1/diffs/1")
        violation = contains_compliance_conclusion(message)
        assert violation is None, f"template output flagged ({violation}): {message!r}"
        checked += 1
    assert checked == len(types) * len(categories) * len(relevances) * len(severities) * len(kinds)


def test_draft_templates_never_state_a_compliance_conclusion():
    from app.agents.notifier import draft_notice_paragraph, draft_inventory_row

    findings = [
        {"type": "form_field", "detail": "input name=diagnosis", "data_category": "health", "third_party_domain": None, "url": "https://x.example/apply"},
        {"type": "third_party_script", "detail": "script from hotjar.com", "data_category": "behavioral", "third_party_domain": "hotjar.com", "url": "https://x.example/pricing"},
        {"type": "cookie", "detail": "third-party cookie '_ga'", "data_category": "behavioral", "third_party_domain": "google-analytics.com", "url": "https://x.example/"},
        {"type": "privacy_policy", "detail": "privacy policy page", "data_category": "none", "third_party_domain": None, "url": "https://x.example/privacy"},
    ]
    for f in findings:
        paragraph = draft_notice_paragraph("client.example", f)
        row = draft_inventory_row("client.example", f)
        assert contains_compliance_conclusion(paragraph) is None, f"drafted notice flagged: {paragraph!r}"
        assert contains_compliance_conclusion(str(row)) is None, f"drafted inventory row flagged: {row!r}"


# --- 3. runtime guardrail on LLM-generated free text ---

def test_classifier_forces_low_confidence_when_gemini_detail_states_a_conclusion():
    from app.agents.classifier import _safe_classified_finding

    f = {
        "type": "form_field",
        "detail": "This field means you are not DPDP compliant.",
        "data_category": "contact", "dpdp_relevance": "notice", "confidence": "high",
    }
    built = _safe_classified_finding(f, "https://client.example/signup2", "https://client.example/")
    assert built is not None
    assert built.confidence == "low", "a compliance-conclusion phrase from the LLM must force low confidence"


# --- 4. low-confidence findings never reach a client alert, regardless of severity ---

def test_low_confidence_third_party_script_does_not_alert_despite_high_severity_by_type():
    from app.agents.differ import diff_findings
    from app.agents.notifier import build_alert_messages

    curr = [{
        "detail_hash": "h1", "type": "third_party_script", "detail": "script from mystery.example",
        "data_category": "behavioral", "dpdp_relevance": "cross_border_transfer", "confidence": "low",
    }]
    diff = diff_findings(client_id=1, prev_scan_id=10, curr_scan_id=11, prev_findings=[], curr_findings=curr)
    assert diff.new[0].severity == "high", "sanity check: this type auto-scores High regardless of confidence"

    messages = build_alert_messages("client.example", diff)
    assert messages == [], "a low-confidence finding must never produce a client-facing alert, even at High severity"


def test_medium_confidence_same_finding_does_alert():
    # control case — proves the low-confidence test above isn't just always empty
    from app.agents.differ import diff_findings
    from app.agents.notifier import build_alert_messages

    curr = [{
        "detail_hash": "h1", "type": "third_party_script", "detail": "script from mystery.example",
        "data_category": "behavioral", "dpdp_relevance": "cross_border_transfer", "confidence": "medium",
    }]
    diff = diff_findings(client_id=1, prev_scan_id=10, curr_scan_id=11, prev_findings=[], curr_findings=curr)
    messages = build_alert_messages("client.example", diff)
    assert len(messages) == 1


# --- 5. audit trail is append-only ---

def test_repository_has_no_delete_statements():
    repo_source = (Path(__file__).resolve().parent.parent / "app" / "repository.py").read_text()
    # Match SQL DELETE statements specifically (not the English word
    # "delete" appearing in a comment/docstring, which is fine).
    sql_deletes = re.findall(r"DELETE\s+FROM", repo_source, re.I)
    assert not sql_deletes, f"repository.py must never DELETE audit-trail rows, found: {sql_deletes}"


def test_migrations_have_no_delete_or_drop_statements():
    mig_source = (Path(__file__).resolve().parent.parent / "app" / "db" / "migrations.py").read_text()
    assert not re.findall(r"DELETE\s+FROM", mig_source, re.I)
    assert not re.findall(r"DROP\s+TABLE", mig_source, re.I)


# --- end-to-end: review queue never auto-promotes to a client alert ---

def test_end_to_end_low_confidence_finding_lands_in_review_queue_not_in_an_alert():
    for mod in list(sys.modules):
        if mod == "app" or mod.startswith("app."):
            sys.modules.pop(mod, None)
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    import app.db.conn as conn_mod
    conn_mod.DB_PATH = Path(path)
    conn_mod.init_db()
    import app.orchestrator as orch
    import app.repository as repo
    from app.models import CrawlReport, PageCrawlResult, ClassifiedFinding

    domain = "guardrail-e2e.example"
    orch.crawl_site = lambda url, **kw: CrawlReport(
        domain=domain, started_at="t0", finished_at="t1", page_count=1,
        pages=[PageCrawlResult(url=f"https://{domain}/", status_code=200)],
    )

    baseline = [ClassifiedFinding(
        url=f"https://{domain}/", type="form_field", detail="input name=name",
        data_category="identity", dpdp_relevance="notice", confidence="high", detail_hash="baseline",
    )]
    orch.classify_crawl = lambda pages: baseline
    r1 = orch.run_scan_for_client(domain)
    assert r1["success"] is True and r1["is_first_scan"] is True

    # Second scan: a NEW low-confidence third_party_script finding — the
    # type that auto-scores High severity by itself.
    shaky_finding = ClassifiedFinding(
        url=f"https://{domain}/checkout", type="third_party_script",
        detail="script from ambiguous-domain.example", data_category="behavioral",
        third_party_domain="ambiguous-domain.example", dpdp_relevance="cross_border_transfer",
        confidence="low", detail_hash="shaky_one",
    )
    orch.classify_crawl = lambda pages: baseline + [shaky_finding]
    r2 = orch.run_scan_for_client(domain, whatsapp_number="+919999999999")

    assert r2["success"] is True
    assert r2["new_count"] == 1, "the shaky finding should show up in the diff"
    assert len(r2["alerts_sent"]) == 0, "a low-confidence finding must not produce a client alert even on a non-baseline scan"

    review_items = repo.list_review_queue(status="pending")
    assert any(item["detail"] == "script from ambiguous-domain.example" for item in review_items), \
        "the low-confidence finding must land in the human review queue"

    alerts = repo.list_alerts(client_id=r2["client_id"])
    assert alerts == [], "no alert row should exist for this scan at all — the only diff entry was the suppressed low-confidence one"


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
