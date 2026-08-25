"""
Tests for the Gemini classifier path's resilience: retry-on-transient-error,
no-retry-on-permanent-error, and per-finding schema validation so one bad
item in a response doesn't discard an entire page's good findings.

No real network calls — httpx.post is monkeypatched with a small stub that
returns canned httpx.Response objects (or raises), and time.sleep is
monkeypatched to a no-op so retry-backoff tests run instantly.
"""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

import app.agents.classifier as classifier_mod
from app.models import PageCrawlResult


def _page(**kwargs) -> PageCrawlResult:
    defaults = dict(url="https://client.example/signup2")  # avoid tripping the auth-route heuristic in mock fallback tests
    defaults.update(kwargs)
    return PageCrawlResult(**defaults)


def _gemini_response(status_code: int, findings: list[dict] | None = None) -> httpx.Response:
    req = httpx.Request("POST", "https://generativelanguage.googleapis.com/fake")
    if findings is not None:
        body = {"candidates": [{"content": {"parts": [{"text": json.dumps({"url": "https://client.example/x", "findings": findings})}]}}]}
        return httpx.Response(status_code, json=body, request=req)
    return httpx.Response(status_code, json={"error": "boom"}, request=req)


class _ScriptedPost:
    """Stand-in for httpx.post — returns each response in `responses` in
    order (repeating the last one if exhausted), and records call count."""
    def __init__(self, responses: list[httpx.Response]):
        self.responses = responses
        self.calls = 0

    def __call__(self, url, json=None, timeout=None):
        resp = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return resp


def _patch(monkeypatch_target, responses):
    scripted = _ScriptedPost(responses)
    httpx.post = scripted
    classifier_mod.time.sleep = lambda *a, **kw: None  # skip real backoff delays in tests
    return scripted


def _restore(original_post, original_sleep):
    httpx.post = original_post
    classifier_mod.time.sleep = original_sleep


def test_valid_response_used_directly_no_fallback():
    original_post, original_sleep = httpx.post, classifier_mod.time.sleep
    try:
        scripted = _patch(None, [_gemini_response(200, findings=[
            {"type": "form_field", "detail": "input name=email", "data_category": "contact",
             "dpdp_relevance": "notice", "confidence": "high", "third_party_domain": None},
        ])])
        page = _page(forms=[{"fields": [{"name": "unrelated", "type": "text", "label": ""}]}])
        results = classifier_mod._gemini_classify_page(page)
        assert scripted.calls == 1
        assert len(results) == 1
        assert results[0].data_category == "contact"
    finally:
        _restore(original_post, original_sleep)


def test_transient_503_then_success_retries_and_recovers():
    original_post, original_sleep = httpx.post, classifier_mod.time.sleep
    try:
        scripted = _patch(None, [
            _gemini_response(503),
            _gemini_response(200, findings=[
                {"type": "cookie", "detail": "third-party cookie", "data_category": "behavioral",
                 "dpdp_relevance": "consent", "confidence": "medium", "third_party_domain": "x.com"},
            ]),
        ])
        page = _page()
        results = classifier_mod._gemini_classify_page(page)
        assert scripted.calls == 2, "should have retried once after the 503"
        assert len(results) == 1
        assert results[0].type == "cookie"
    finally:
        _restore(original_post, original_sleep)


def test_persistent_5xx_exhausts_retries_and_falls_back_to_mock():
    original_post, original_sleep = httpx.post, classifier_mod.time.sleep
    try:
        scripted = _patch(None, [_gemini_response(503)])  # every attempt fails the same way
        page = _page(forms=[{"fields": [{"name": "email", "type": "email", "label": "Email"}]}])
        results = classifier_mod._gemini_classify_page(page)
        assert scripted.calls == classifier_mod.GEMINI_MAX_RETRIES
        # fell back to the mock classifier, which DOES tag the email field
        assert any(r.data_category == "contact" for r in results)
    finally:
        _restore(original_post, original_sleep)


def test_permanent_4xx_does_not_retry_falls_back_immediately():
    original_post, original_sleep = httpx.post, classifier_mod.time.sleep
    try:
        scripted = _patch(None, [_gemini_response(401)])  # auth failure — retrying won't help
        page = _page(forms=[{"fields": [{"name": "email", "type": "email", "label": "Email"}]}])
        results = classifier_mod._gemini_classify_page(page)
        assert scripted.calls == 1, "a non-retryable status must not burn retry attempts"
        assert any(r.data_category == "contact" for r in results)  # mock fallback still ran
    finally:
        _restore(original_post, original_sleep)


def test_one_malformed_finding_does_not_discard_the_rest():
    original_post, original_sleep = httpx.post, classifier_mod.time.sleep
    try:
        _patch(None, [_gemini_response(200, findings=[
            {"type": "form_field", "detail": "good one", "data_category": "contact",
             "dpdp_relevance": "notice", "confidence": "high"},
            {"type": "this-is-not-a-real-type", "detail": "hallucinated type", "data_category": "contact"},
            {"type": "third_party_script", "detail": "another good one", "data_category": "behavioral",
             "dpdp_relevance": "cross_border_transfer", "confidence": "medium", "third_party_domain": "y.com"},
        ])])
        page = _page()
        results = classifier_mod._gemini_classify_page(page)
        assert len(results) == 2, "the two valid findings must survive even though one entry had a bogus type"
        assert {r.detail for r in results} == {"good one", "another good one"}
    finally:
        _restore(original_post, original_sleep)


def test_invalid_category_coerced_and_forced_low_confidence():
    original_post, original_sleep = httpx.post, classifier_mod.time.sleep
    try:
        _patch(None, [_gemini_response(200, findings=[
            {"type": "form_field", "detail": "weird field", "data_category": "not-a-real-category",
             "dpdp_relevance": "notice", "confidence": "high"},
        ])])
        page = _page()
        results = classifier_mod._gemini_classify_page(page)
        assert len(results) == 1
        assert results[0].data_category == "none"
        assert results[0].confidence == "low", "an out-of-schema field must be forced to low confidence for human review, not silently trusted"
    finally:
        _restore(original_post, original_sleep)


def test_oversized_page_payload_is_capped_before_sending():
    original_post, original_sleep = httpx.post, classifier_mod.time.sleep
    captured = {}

    def _capturing_post(url, json=None, timeout=None):
        captured["body"] = json
        return _gemini_response(200, findings=[])

    try:
        httpx.post = _capturing_post
        classifier_mod.time.sleep = lambda *a, **kw: None
        many_forms = [{"fields": [{"name": f"f{i}", "type": "text", "label": ""}]} for i in range(500)]
        page = _page(forms=many_forms)
        classifier_mod._gemini_classify_page(page)
        prompt_text = captured["body"]["contents"][0]["parts"][0]["text"]
        assert '"f499"' not in prompt_text, "payload must be capped, not send all 500 forms to the LLM"
    finally:
        _restore(original_post, original_sleep)


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
