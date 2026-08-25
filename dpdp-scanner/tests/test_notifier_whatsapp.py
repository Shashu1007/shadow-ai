"""
Tests for the Notifier Agent's WhatsApp sending (app/agents/notifier.py):
the sim/Twilio swap, retry-on-transient-failure, no-retry-on-permanent-
failure, and number normalization. No real network calls — httpx.post is
monkeypatched with canned httpx.Response objects.
"""
import os
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx


def _fresh_notifier(**env):
    """TWILIO_CONFIGURED is computed at module-import time from env vars, so
    each scenario needs a clean reimport of the whole app.* namespace — see
    tests/test_web_auth.py for why popping just the leaf module isn't
    enough (package-attribute caching on `from app import x`)."""
    for var in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_WHATSAPP_FROM"):
        os.environ.pop(var, None)
    os.environ.update(env)
    for mod in list(sys.modules):
        if mod == "app" or mod.startswith("app."):
            sys.modules.pop(mod, None)
    import app.agents.notifier as notifier_mod
    return notifier_mod


def _twilio_response(status_code: int, sid: str = "SMfake", status: str = "queued") -> httpx.Response:
    req = httpx.Request("POST", "https://api.twilio.com/fake")
    return httpx.Response(status_code, json={"sid": sid, "status": status}, request=req)


def test_sim_mode_used_when_twilio_not_configured():
    notifier = _fresh_notifier()
    assert notifier.TWILIO_CONFIGURED is False
    receipt = notifier.send_whatsapp("+919999999999", "hello")
    assert receipt["channel"] == "whatsapp_sim"
    assert receipt["delivered"] is False


def test_twilio_send_success_when_fully_configured():
    notifier = _fresh_notifier(TWILIO_ACCOUNT_SID="AC123", TWILIO_AUTH_TOKEN="secret", TWILIO_WHATSAPP_FROM="whatsapp:+14155238886")
    assert notifier.TWILIO_CONFIGURED is True

    original_post = httpx.post
    captured = {}
    try:
        def _fake_post(url, data=None, auth=None, timeout=None):
            captured["data"] = data
            captured["auth"] = auth
            return _twilio_response(201, sid="SM999", status="queued")
        httpx.post = _fake_post

        receipt = notifier.send_whatsapp("+919999999999", "New tracker detected")
        assert receipt["delivered"] is True
        assert receipt["provider_sid"] == "SM999"
        assert captured["data"]["To"] == "whatsapp:+919999999999"
        assert captured["data"]["From"] == "whatsapp:+14155238886"
        assert captured["auth"] == ("AC123", "secret")
    finally:
        httpx.post = original_post


def test_partial_twilio_config_falls_back_to_sim():
    # Only two of three vars set — must not half-enable real sending.
    notifier = _fresh_notifier(TWILIO_ACCOUNT_SID="AC123", TWILIO_AUTH_TOKEN="secret")
    assert notifier.TWILIO_CONFIGURED is False
    receipt = notifier.send_whatsapp("+919999999999", "hello")
    assert receipt["channel"] == "whatsapp_sim"


def test_permanent_4xx_failure_raises_without_retrying():
    notifier = _fresh_notifier(TWILIO_ACCOUNT_SID="AC123", TWILIO_AUTH_TOKEN="secret", TWILIO_WHATSAPP_FROM="whatsapp:+14155238886")
    original_post, original_sleep = httpx.post, notifier.time.sleep
    calls = {"n": 0}
    try:
        def _fake_post(url, data=None, auth=None, timeout=None):
            calls["n"] += 1
            return _twilio_response(400)
        httpx.post = _fake_post
        notifier.time.sleep = lambda *a, **kw: None

        raised = False
        try:
            notifier.send_whatsapp("+919999999999", "hello")
        except RuntimeError:
            raised = True
        assert raised
        assert calls["n"] == 1, "a 400 (bad request) must not be retried"
    finally:
        httpx.post = original_post
        notifier.time.sleep = original_sleep


def test_transient_5xx_retries_then_succeeds():
    notifier = _fresh_notifier(TWILIO_ACCOUNT_SID="AC123", TWILIO_AUTH_TOKEN="secret", TWILIO_WHATSAPP_FROM="whatsapp:+14155238886")
    original_post, original_sleep = httpx.post, notifier.time.sleep
    calls = {"n": 0}
    try:
        def _fake_post(url, data=None, auth=None, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                return _twilio_response(503)
            return _twilio_response(201, sid="SM111")
        httpx.post = _fake_post
        notifier.time.sleep = lambda *a, **kw: None

        receipt = notifier.send_whatsapp("+919999999999", "hello")
        assert receipt["delivered"] is True
        assert calls["n"] == 2
    finally:
        httpx.post = original_post
        notifier.time.sleep = original_sleep


def test_missing_number_raises_immediately_without_network_call():
    notifier = _fresh_notifier(TWILIO_ACCOUNT_SID="AC123", TWILIO_AUTH_TOKEN="secret", TWILIO_WHATSAPP_FROM="whatsapp:+14155238886")
    original_post = httpx.post
    called = {"n": 0}
    try:
        httpx.post = lambda *a, **kw: called.__setitem__("n", called["n"] + 1)
        raised = False
        try:
            notifier.send_whatsapp(None, "hello")
        except ValueError:
            raised = True
        assert raised
        assert called["n"] == 0
    finally:
        httpx.post = original_post


def test_normalize_whatsapp_number_variants():
    notifier = _fresh_notifier()
    assert notifier._normalize_whatsapp_number("+919999999999") == "whatsapp:+919999999999"
    assert notifier._normalize_whatsapp_number("919999999999") == "whatsapp:+919999999999"
    assert notifier._normalize_whatsapp_number("whatsapp:+919999999999") == "whatsapp:+919999999999"


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
