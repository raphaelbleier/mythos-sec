"""Crawler JS endpoint mining (no network): relative + root-relative paths."""

from collections import deque

from mythos.recon.crawl import CrawlResult, _mine_js


def test_mine_js_relative_and_root_relative():
    r = CrawlResult(seed="http://t/")
    body = (
        'this.http.get("rest/products/search?q="+q);'      # bare relative (SPA)
        'fetch("/api/Users");'                              # root-relative
        'const u="api/BasketItems/1";'                      # bare relative
        'img.src="/assets/logo.png";'                       # asset, skipped
    )
    _mine_js(r, "t", "http://t/main.js", body, deque(), 0)
    paths = {e.split("http://t")[-1] for e in r.endpoints}
    assert "/rest/products/search" in paths
    assert "/api/Users" in paths
    assert "/api/BasketItems/1" in paths
    assert "/assets/logo.png" not in paths
