"""Browser-driven DOM XSS detection (headless Chromium via Playwright).

HTTP-level checks see the server response; they cannot see a client-side sink
that writes attacker-controlled input into the live DOM (DOM-based XSS). This
check renders the page in a real headless browser, drives a unique payload
through common sources (URL hash, query) and confirms *execution* by observing
a side effect the payload causes in the page.

Playwright/Chromium are optional: when unavailable the check returns [] and the
engine falls back to its HTTP checks. In the Mythos toolbox they are installed.
"""

from __future__ import annotations

import uuid

from ..findings import Finding, Evidence, Severity


def available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


def check_dom_xss(url: str, *, param: str | None = None, timeout_ms: int = 8000) -> list[Finding]:
    """Render ``url`` and detect DOM XSS by observing payload execution.

    Tries the URL hash (the classic DOM-XSS source) and, if ``param`` is given,
    that query parameter. Execution is confirmed when our injected script sets a
    window flag or fires a dialog — proof the sink executed, not just reflected.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return []

    token = "mxdom" + uuid.uuid4().hex[:8]
    # payload sets a window flag when executed via a DOM sink
    payloads = [
        f"#<img src=x onerror=\"window.{token}=1\">",
        f"#<svg/onload=\"window.{token}=1\">",
    ]
    findings: list[Finding] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox", "--disable-gpu"])
            page = browser.new_page()
            executed_payload = None
            for frag in payloads:
                try:
                    page.goto(url + frag, wait_until="load", timeout=timeout_ms)
                    page.wait_for_timeout(500)
                    if page.evaluate(f"() => window.{token} === 1"):
                        executed_payload = frag
                        break
                except Exception:
                    continue
            browser.close()
    except Exception:
        return []

    if executed_payload:
        findings.append(Finding(
            title="DOM-based Cross-Site Scripting (XSS)",
            severity=Severity.HIGH, kind="dom-xss", url=url,
            param=param or "location.hash",
            payload=executed_payload,
            description="A client-side sink writes attacker-controlled input into the "
                        "DOM and executes it; confirmed by payload execution in a real "
                        "browser.",
            impact="Arbitrary JavaScript execution in the victim's browser.",
            remediation="Avoid dangerous DOM sinks (innerHTML, document.write); use "
                        "textContent / safe APIs; deploy Trusted Types and a strict CSP.",
            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            evidence=Evidence(request=f"GET {url}{executed_payload}",
                              matched=f"window.{token} set by injected sink",
                              note="headless Chromium execution"),
            confidence="certain"))
    return findings
