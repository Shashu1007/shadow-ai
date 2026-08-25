"""Unit tests for the mock classifier — deterministic, no network/browser needed."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents.classifier import classify_crawl
from app.models import PageCrawlResult


def _page(**kwargs) -> PageCrawlResult:
    defaults = dict(url="https://client.example/test", status_code=200)
    defaults.update(kwargs)
    return PageCrawlResult(**defaults)


def test_sensitive_field_categories():
    page = _page(forms=[{
        "action": "/apply", "method": "post",
        "fields": [
            {"name": "card_number", "type": "text", "label": "Credit Card Number"},
            {"name": "diagnosis", "type": "text", "label": "Medical Diagnosis"},
            {"name": "aadhaar", "type": "text", "label": "Aadhaar Number"},
        ],
    }])
    findings = classify_crawl([page])
    by_name = {f.detail: f for f in findings if f.type == "form_field"}
    cats = {f.data_category for f in findings if f.type == "form_field"}
    assert "financial" in cats
    assert "health" in cats
    assert "identity" in cats
    # sensitive categories should be high confidence (clear pattern match)
    for f in findings:
        if f.data_category in ("financial", "health"):
            assert f.confidence == "high"


def test_known_vendor_vs_unknown_script():
    page = _page(scripts=[
        {"src": "https://www.googletagmanager.com/gtag/js", "domain": "www.googletagmanager.com", "vendor": "Google Tag Manager"},
        {"src": "https://mystery-tracker.example/x.js", "domain": "mystery-tracker.example", "vendor": None},
    ])
    findings = [f for f in classify_crawl([page]) if f.type == "third_party_script"]
    known = next(f for f in findings if "googletagmanager" in f.detail)
    unknown = next(f for f in findings if "mystery-tracker" in f.detail)
    assert known.confidence == "high"
    assert known.dpdp_relevance == "cross_border_transfer"
    assert unknown.confidence == "medium"


def test_third_party_cookie_flagged_first_party_ignored():
    page = _page(cookies=[
        {"name": "session_id", "domain": "client.example", "first_party": True},
        {"name": "_ga", "domain": ".google-analytics.com", "first_party": False},
    ])
    findings = [f for f in classify_crawl([page]) if f.type == "cookie"]
    assert len(findings) == 1
    assert "_ga" in findings[0].detail
    assert findings[0].dpdp_relevance == "consent"


def test_consent_banner_is_site_wide_not_per_page():
    # homepage has a banner, subpage doesn't -> site should report "present", not two conflicting findings
    home = _page(url="https://client.example/", consent_banner={"present": True, "cmp": "OneTrust", "source": "script"})
    sub = _page(url="https://client.example/about", consent_banner={"present": False, "cmp": None, "source": None})
    findings = classify_crawl([home, sub])
    banner_findings = [f for f in findings if f.type == "consent_banner"]
    assert len(banner_findings) == 1, "consent banner must be a single site-wide finding, not per-page"
    assert "present site-wide" in banner_findings[0].detail
    assert banner_findings[0].confidence == "high"


def test_consent_banner_absent_everywhere():
    home = _page(url="https://client.example/", consent_banner={"present": False, "cmp": None, "source": None})
    findings = classify_crawl([home])
    banner_findings = [f for f in findings if f.type == "consent_banner"]
    assert len(banner_findings) == 1
    assert "no consent banner detected anywhere" in banner_findings[0].detail


def test_privacy_policy_hashed():
    page = _page(is_privacy_policy=True, privacy_policy_hash="abc123def456")
    findings = [f for f in classify_crawl([page]) if f.type == "privacy_policy"]
    assert len(findings) == 1
    assert findings[0].confidence == "high"
    assert findings[0].dpdp_relevance == "notice"


def test_dob_flagged_as_children_data():
    page = _page(forms=[{
        "action": "/signup", "method": "post",
        "fields": [{"name": "dob", "type": "date", "label": "Date of Birth"}],
    }])
    findings = [f for f in classify_crawl([page]) if f.type == "form_field"]
    assert findings[0].data_category == "children"
    assert findings[0].dpdp_relevance == "children_data"


def test_auth_route_flagged_low_confidence_for_review():
    page = _page(url="https://client.example/signup")
    findings = classify_crawl([page])
    auth_findings = [f for f in findings if "auth/signup route" in f.detail]
    assert len(auth_findings) == 1
    assert auth_findings[0].confidence == "low", "must route to human review, never straight to client"


def test_page_with_crawl_error_yields_no_findings():
    page = _page(error="timeout")
    findings = classify_crawl([page])
    assert findings == []


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
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
