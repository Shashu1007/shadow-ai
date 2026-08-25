"""Unit tests for the Diff Agent — severity scoring per the spec's rules."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents.differ import diff_findings


def _f(hash_, type_, detail, category="none", relevance="none", confidence="medium"):
    return {
        "detail_hash": hash_, "type": type_, "detail": detail,
        "data_category": category, "dpdp_relevance": relevance, "confidence": confidence,
    }


def test_new_third_party_script_is_high():
    result = diff_findings(1, 10, 11, prev_findings=[], curr_findings=[
        _f("h1", "third_party_script", "script from hotjar.com", relevance="cross_border_transfer"),
    ])
    assert result.severity == "high"
    assert result.new[0].severity == "high"


def test_new_sensitive_field_is_high():
    result = diff_findings(1, 10, 11, prev_findings=[], curr_findings=[
        _f("h1", "form_field", "input name=diagnosis", category="health"),
    ])
    assert result.new[0].severity == "high"


def test_new_nonsensitive_field_is_medium():
    result = diff_findings(1, 10, 11, prev_findings=[], curr_findings=[
        _f("h1", "form_field", "input name=full_name", category="none"),
    ])
    assert result.new[0].severity == "medium"


def test_privacy_policy_new_page_is_medium():
    result = diff_findings(1, 10, 11, prev_findings=[], curr_findings=[
        _f("h1", "privacy_policy", "privacy policy page (hash abc)"),
    ])
    assert result.new[0].severity == "medium"


def test_privacy_policy_content_change_is_changed_not_removed_plus_new():
    # detail_hash must key on URL identity, not content hash — otherwise a text
    # edit looks like "old page gone, new page appeared" instead of "changed".
    same_hash = "privacy_policy_url_hash"
    prev = [_f(same_hash, "privacy_policy", "privacy policy page (content hash aaa111)")]
    curr = [_f(same_hash, "privacy_policy", "privacy policy page (content hash bbb222)")]
    result = diff_findings(1, 10, 11, prev_findings=prev, curr_findings=curr)
    assert result.new == [], "content change must not appear as a brand-new finding"
    assert result.removed == [], "content change must not appear as the page disappearing"
    assert len(result.changed) == 1
    assert result.changed[0].severity == "medium"
    assert "content changed" in result.changed[0].reason.lower()


def test_consent_banner_present_to_absent_is_one_changed_entry_not_removed_plus_new():
    # Like privacy_policy, the site-wide consent banner finding must use a STABLE
    # hash key regardless of present/absent state, so a present->absent transition
    # reads as one "changed" (High) event, not a redundant removed+new pair that
    # would fire two separate WhatsApp alerts for the same underlying change.
    same_hash = "consent_banner_site_wide_hash"
    prev = [_f(same_hash, "consent_banner", "consent banner present site-wide (CMP: OneTrust)")]
    curr = [_f(same_hash, "consent_banner", "no consent banner detected anywhere on the site")]
    result = diff_findings(1, 10, 11, prev_findings=prev, curr_findings=curr)
    assert result.new == [], "must not appear as a brand-new finding"
    assert result.removed == [], "must not appear as the banner disappearing separately"
    assert len(result.changed) == 1
    assert result.changed[0].severity == "high"
    assert "now missing" in result.changed[0].reason.lower()
    assert result.severity == "high"


def test_unchanged_finding_produces_no_diff_entries():
    same = _f("h1", "form_field", "input name=email", category="contact")
    result = diff_findings(1, 10, 11, prev_findings=[same], curr_findings=[same])
    assert result.new == []
    assert result.changed == []
    assert result.removed == []
    assert result.severity == "low"


def test_removed_finding_low_by_default():
    prev = [_f("h1", "form_field", "input name=full_name")]
    result = diff_findings(1, 10, 11, prev_findings=prev, curr_findings=[])
    assert result.removed[0].severity == "low"


def test_first_scan_has_no_prev_scan_id():
    result = diff_findings(1, None, 1, prev_findings=[], curr_findings=[
        _f("h1", "form_field", "input name=email", category="contact"),
    ])
    assert result.prev_scan_id is None
    assert len(result.new) == 1


def test_max_severity_across_diff():
    curr = [
        _f("h1", "form_field", "input name=full_name"),   # medium
        _f("h2", "third_party_script", "script from x.com", relevance="cross_border_transfer"),  # high
    ]
    result = diff_findings(1, 10, 11, prev_findings=[], curr_findings=curr)
    assert result.severity == "high"


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
