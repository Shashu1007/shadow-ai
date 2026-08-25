"""
Tests for the crawler's SSRF guard (_validate_crawl_target in
app/agents/crawler.py). Uses literal IP addresses in test URLs so these run
fully offline — no real DNS lookup or browser needed, since
socket.getaddrinfo resolves a literal IP to itself without a network call.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents.crawler import _validate_crawl_target, CrawlTargetRejected


def _rejects(url: str) -> bool:
    try:
        _validate_crawl_target(url)
        return False
    except CrawlTargetRejected:
        return True


def test_public_ip_allowed():
    assert not _rejects("http://8.8.8.8/")


def test_loopback_rejected():
    assert _rejects("http://127.0.0.1/")
    assert _rejects("http://[::1]/")


def test_private_rfc1918_rejected():
    assert _rejects("http://10.0.0.5/")
    assert _rejects("http://192.168.1.1/")
    assert _rejects("http://172.16.0.1/")


def test_cloud_metadata_endpoint_rejected():
    # 169.254.169.254 is the AWS/GCP/Azure instance-metadata address — the
    # single most common real-world SSRF target, worth its own explicit test.
    assert _rejects("http://169.254.169.254/latest/meta-data/")


def test_non_http_scheme_rejected():
    assert _rejects("file:///etc/passwd")
    assert _rejects("javascript:alert(1)")
    assert _rejects("ftp://example.com/")


def test_url_with_no_hostname_rejected():
    assert _rejects("http:///path-only")


def test_unresolvable_host_rejected():
    assert _rejects("http://this-domain-does-not-exist-dpdp-scanner-test.invalid/")


def test_allow_private_override_permits_loopback():
    import app.agents.crawler as crawler_mod
    original = crawler_mod.ALLOW_PRIVATE_CRAWL_TARGETS
    crawler_mod.ALLOW_PRIVATE_CRAWL_TARGETS = True
    try:
        assert not _rejects("http://127.0.0.1:8899/")
    finally:
        crawler_mod.ALLOW_PRIVATE_CRAWL_TARGETS = original


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
