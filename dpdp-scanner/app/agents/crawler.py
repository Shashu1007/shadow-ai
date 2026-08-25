"""
Crawler Agent
=============
Headless Playwright crawl of a client domain, depth-limited, robots.txt-respecting,
rate-limited. Captures per spec v1 (first five detection rows):

  1. Form fields        -> every <form>, its input name/type/label
  2. Cookies set         -> Set-Cookie headers + document.cookie after load, 1P vs 3P
  3. Third-party scripts -> <script src> + external network requests, matched vs known vendors
  4. Consent banner      -> known CMP script presence / banner text
  5. Privacy policy page -> fetch + hash for later diffing

Deterministic only — no LLM calls happen here.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import socket
import time
import urllib.robotparser as robotparser
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeoutError

from app.config import (
    MAX_CRAWL_DEPTH, MAX_PAGES, CRAWL_DELAY_SECONDS, REQUEST_TIMEOUT_MS,
    USER_AGENT, KNOWN_VENDORS, KNOWN_CMPS, AUTH_PATH_PATTERNS,
    ALLOW_PRIVATE_CRAWL_TARGETS,
)
from app.models import PageCrawlResult, CrawlReport

logger = logging.getLogger("crawler")

PRIVACY_POLICY_HINTS = re.compile(r"privacy[-_]?polic|data[-_]?protection", re.I)


class CrawlTargetRejected(Exception):
    """Raised when a crawl entry URL fails safety validation — bad scheme,
    or resolves to a private/loopback/link-local/reserved IP. This is a
    scanner meant to point at OTHER PEOPLE'S public websites; without this
    check, a client domain (or a DNS entry that changes after signup) that
    resolves to an internal address — a cloud metadata endpoint
    (169.254.169.254), a loopback service, an internal-only admin panel —
    would get the same headless-browser visit + content capture as any
    public page, and the results would land in that client's own dashboard.
    That's a real SSRF risk, not a theoretical one, for anything that fetches
    an operator-supplied URL server-side."""


def _validate_crawl_target(url: str) -> None:
    """Raises CrawlTargetRejected if `url` shouldn't be fetched. Best-effort:
    resolves the hostname once, up front. This does NOT protect against DNS
    rebinding (a hostname that resolves to a public IP at check-time and a
    private one at connect-time) — closing that fully would need a custom
    Playwright network route pinning the resolved IP, out of scope for this
    pass; documented here so it isn't mistaken for a complete guarantee."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise CrawlTargetRejected(f"unsupported URL scheme: {parsed.scheme!r}")

    host = parsed.hostname
    if not host:
        raise CrawlTargetRejected("URL has no hostname")

    if ALLOW_PRIVATE_CRAWL_TARGETS:
        # Explicit opt-in only — used for local fixture-site testing
        # (tests/fixture_site via `--start-url http://localhost:8899/`, per
        # README) and nothing else. Never set this in a production deploy.
        return

    try:
        addrinfo = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise CrawlTargetRejected(f"could not resolve host {host!r}: {e}")

    for family, _, _, _, sockaddr in addrinfo:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise CrawlTargetRejected(
                f"host {host!r} resolves to a non-public address ({ip}) — refusing to crawl. "
                f"Set ALLOW_PRIVATE_CRAWL_TARGETS=1 only for local fixture-site testing."
            )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def _is_same_site(base_domain: str, url: str) -> bool:
    d = _domain_of(url)
    return d == base_domain or d.endswith("." + base_domain)


def _match_vendor(domain: str) -> str | None:
    for key, name in KNOWN_VENDORS.items():
        if key in domain:
            return name
    return None


def _match_cmp(domain_or_text: str) -> str | None:
    for key, name in KNOWN_CMPS.items():
        if key in domain_or_text:
            return name
    return None


def _load_robots(base_url: str) -> robotparser.RobotFileParser:
    rp = robotparser.RobotFileParser()
    robots_url = urljoin(base_url, "/robots.txt")
    try:
        rp.set_url(robots_url)
        rp.read()
    except Exception:
        # If robots.txt is unreachable, default to permissive (still rate-limited).
        pass
    return rp


def _extract_forms(soup: BeautifulSoup) -> list[dict]:
    forms = []
    for form in soup.find_all("form"):
        fields = []
        for inp in form.find_all(["input", "select", "textarea"]):
            name = inp.get("name") or inp.get("id") or ""
            ftype = inp.get("type", "text") if inp.name == "input" else inp.name
            if ftype in ("submit", "button", "hidden", "csrf"):
                continue
            # try to find an associated <label>
            label_text = ""
            field_id = inp.get("id")
            if field_id:
                label = soup.find("label", attrs={"for": field_id})
                if label:
                    label_text = label.get_text(strip=True)
            if not label_text:
                placeholder = inp.get("placeholder", "")
                label_text = placeholder
            if not name and not label_text:
                continue
            fields.append({"name": name, "type": ftype, "label": label_text})
        if fields:
            forms.append({
                "action": form.get("action", ""),
                "method": form.get("method", "get").lower(),
                "fields": fields,
            })
    return forms


def _extract_scripts(soup: BeautifulSoup, page_url: str) -> list[dict]:
    scripts = []
    seen = set()
    for tag in soup.find_all("script", src=True):
        src = urljoin(page_url, tag["src"])
        domain = _domain_of(src)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        vendor = _match_vendor(src) or _match_vendor(domain)
        scripts.append({"src": src, "domain": domain, "vendor": vendor})
    return scripts


def _detect_consent_banner(soup: BeautifulSoup, scripts: list[dict]) -> dict | None:
    for s in scripts:
        cmp_name = _match_cmp(s["src"]) or _match_cmp(s["domain"])
        if cmp_name:
            return {"present": True, "cmp": cmp_name, "source": "script"}
    # heuristic: look for common cookie-consent DOM markers
    text = soup.get_text(" ", strip=True).lower()
    banner_markers = ["accept cookies", "we use cookies", "cookie preferences", "manage cookies", "accept all"]
    for marker in banner_markers:
        if marker in text:
            return {"present": True, "cmp": "unknown/custom", "source": "text_heuristic"}
    return {"present": False, "cmp": None, "source": None}


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def crawl_site(start_url: str, max_depth: int = MAX_CRAWL_DEPTH, max_pages: int = MAX_PAGES) -> CrawlReport:
    """Breadth-first crawl of start_url's domain up to max_depth / max_pages.

    Raises CrawlTargetRejected if start_url itself is unsafe to fetch (see
    _validate_crawl_target) — this is deliberately NOT caught here, so a bad
    entry point fails the whole scan clearly (orchestrator records it as
    scan status='failed') rather than silently crawling nothing. Links
    discovered mid-crawl that fail validation are skipped individually
    (logged, recorded as a page error) instead of aborting an otherwise-good
    scan over one bad link.
    """
    _validate_crawl_target(start_url)
    base_domain = _domain_of(start_url)
    started_at = _now_iso()
    robots = _load_robots(start_url)

    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(start_url, 0)]
    pages: list[PageCrawlResult] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(user_agent=USER_AGENT)
        page = context.new_page()
        page.set_default_timeout(REQUEST_TIMEOUT_MS)

        while queue and len(pages) < max_pages:
            url, depth = queue.pop(0)
            norm_url = url.split("#")[0]
            if norm_url in visited:
                continue
            visited.add(norm_url)

            if not robots.can_fetch(USER_AGENT, norm_url):
                pages.append(PageCrawlResult(url=norm_url, error="blocked_by_robots_txt"))
                continue

            try:
                _validate_crawl_target(norm_url)
            except CrawlTargetRejected as e:
                logger.warning("Skipping discovered link %s: %s", norm_url, e)
                pages.append(PageCrawlResult(url=norm_url, error="rejected_unsafe_target"))
                continue

            network_hosts: set[str] = set()

            def _on_request(req):
                try:
                    network_hosts.add(_domain_of(req.url))
                except Exception:
                    pass

            page.on("request", _on_request)

            try:
                resp = page.goto(norm_url, wait_until="networkidle")
                status_code = resp.status if resp else None
                html = page.content()
                cookies = context.cookies()
                soup = BeautifulSoup(html, "lxml")

                forms = _extract_forms(soup)
                scripts = _extract_scripts(soup, norm_url)

                # merge network-observed third-party hosts not already caught via <script src>
                script_domains = {s["domain"] for s in scripts}
                for host in network_hosts:
                    if host and host != base_domain and not host.endswith("." + base_domain) and host not in script_domains:
                        vendor = _match_vendor(host)
                        scripts.append({"src": f"https://{host}/ (network request)", "domain": host, "vendor": vendor})
                        script_domains.add(host)

                consent = _detect_consent_banner(soup, scripts)

                is_privacy = bool(PRIVACY_POLICY_HINTS.search(norm_url)) or bool(
                    soup.title and PRIVACY_POLICY_HINTS.search(soup.title.get_text())
                )
                privacy_hash = None
                privacy_excerpt = None
                if is_privacy:
                    body_text = soup.get_text(" ", strip=True)
                    privacy_hash = _hash_text(body_text)
                    privacy_excerpt = body_text[:500]

                cookie_dicts = [
                    {
                        "name": c.get("name"),
                        "domain": c.get("domain"),
                        "first_party": _domain_of("https://" + c.get("domain", "").lstrip(".")) == base_domain
                        or (c.get("domain") or "").lstrip(".").endswith(base_domain),
                    }
                    for c in cookies
                ]

                pages.append(PageCrawlResult(
                    url=norm_url,
                    status_code=status_code,
                    html_hash=_hash_text(html),
                    forms=forms,
                    cookies=cookie_dicts,
                    scripts=scripts,
                    consent_banner=consent,
                    is_privacy_policy=is_privacy,
                    privacy_policy_hash=privacy_hash,
                    privacy_policy_text_excerpt=privacy_excerpt,
                ))

                # enqueue same-site links
                if depth < max_depth:
                    for a in soup.find_all("a", href=True):
                        link = urljoin(norm_url, a["href"]).split("#")[0]
                        if _is_same_site(base_domain, link) and link not in visited:
                            queue.append((link, depth + 1))

            except PWTimeoutError:
                pages.append(PageCrawlResult(url=norm_url, error="timeout"))
            except Exception as e:
                pages.append(PageCrawlResult(url=norm_url, error=str(e)))
            finally:
                page.remove_listener("request", _on_request)
                time.sleep(CRAWL_DELAY_SECONDS)

        browser.close()

    return CrawlReport(
        domain=base_domain,
        started_at=started_at,
        finished_at=_now_iso(),
        pages=pages,
        page_count=len(pages),
    )
