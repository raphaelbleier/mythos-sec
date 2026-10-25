"""Browser DOM-XSS check. Skipped where Playwright/Chromium are not installed
(e.g. the slim CI image); runs in the Mythos toolbox."""

import pytest

from mythos.scan import browser


@pytest.mark.skipif(not browser.available(), reason="playwright not installed")
@pytest.mark.parametrize("path", ["/dom", "/dom_write", "/dom_query"])
def test_dom_xss_detected(vulnapp, path):
    # three sink classes: innerHTML-via-hash, document.write, query-source innerHTML
    f = browser.check_dom_xss(vulnapp + path)
    assert f and f[0].kind == "dom-xss" and f[0].confidence == "certain"


@pytest.mark.skipif(not browser.available(), reason="playwright not installed")
def test_dom_xss_not_flagged_on_safe_page(vulnapp):
    # the plain index has no DOM sink; must not be flagged
    f = browser.check_dom_xss(vulnapp + "/")
    assert f == []


def test_browser_check_graceful_without_playwright(monkeypatch):
    # when playwright import fails, the check returns [] (engine falls back)
    import mythos.scan.browser as b
    monkeypatch.setattr(b, "available", lambda: False)
    # check_dom_xss handles ImportError internally and returns []
    assert isinstance(b.check_dom_xss("http://127.0.0.1:1/nope", timeout_ms=200), list)
