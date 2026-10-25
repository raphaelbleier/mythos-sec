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


def check_dom_xss(url: str, *, param: str | None = None, timeout_ms: int = 8000,
                  query_params: list[str] | None = None) -> list[Finding]:
    """Render ``url`` and detect DOM XSS by observing payload execution.

    Drives payloads through two source classes — the URL hash (``location.hash``)
    and query parameters (``location.search``) — across several sink shapes
    (innerHTML, document.write). Execution is confirmed when the injected script
    sets a window flag: proof the sink executed, not merely reflected.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return []
    from urllib.parse import quote

    token = "mxdom" + uuid.uuid4().hex[:8]
    inner = [f"<img src=x onerror=\"window.{token}=1\">",
             f"<svg/onload=\"window.{token}=1\">"]
    # build candidate full URLs: hash source, then query source on likely params
    candidates = [url + "#" + p for p in inner]
    qparams = list(query_params or [])
    if param:
        qparams.append(param)
    qparams += ["q", "search", "name", "input", "data", "msg"]
    sep = "&" if "?" in url else "?"
    for qp in dict.fromkeys(qparams):
        for p in inner:
            candidates.append(f"{url}{sep}{qp}={quote(p)}")

    findings: list[Finding] = []
    executed_payload = None
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-gpu"])
            page = browser.new_page()
            for cand in candidates:
                try:
                    page.goto(cand, wait_until="load", timeout=timeout_ms)
                    page.wait_for_timeout(400)
                    if page.evaluate(f"() => window.{token} === 1"):
                        executed_payload = cand
                        break
                    page.evaluate(f"() => {{ try{{ delete window.{token} }}catch(e){{}} }}")
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
            evidence=Evidence(request=f"GET {executed_payload}",
                              matched=f"window.{token} set by injected sink",
                              note="headless Chromium execution"),
            confidence="certain"))
    return findings
