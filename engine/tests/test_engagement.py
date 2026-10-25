"""End-to-end: run the full engagement against the vuln app and score it
against ground truth. This mirrors the evaluation harness used for the poster."""

import json
from pathlib import Path

from mythos.orchestrator import run_engagement

GT = json.loads((Path(__file__).resolve().parents[2]
                 / "lab" / "vulnapp" / "ground_truth.json").read_text())


def test_full_engagement_coverage(client, vulnapp, tmp_path):
    res = run_engagement(client, vulnapp + "/", workdir=tmp_path,
                         max_pages=50, log=lambda *a: None)
    found_kinds = {f.kind for f in res.store.findings}

    expected = {e["kind"] for e in GT["expected_findings"]}
    missing = expected - found_kinds
    # core web classes must all be detected end-to-end
    assert not missing, f"missed vulnerability classes: {missing}"

    # false-positive guard: /safe must not produce an XSS finding
    xss_urls = [f.url for f in res.store.findings if f.kind == "reflected-xss"]
    assert not any("/safe" in u for u in xss_urls)

    # artifacts written
    assert (tmp_path / "findings.json").exists()
    assert (tmp_path / "report.md").exists()
    report = (tmp_path / "report.md").read_text()
    assert "Mythos Engagement Report" in report
    assert "SQL Injection" in report


def test_crawl_finds_js_endpoint(client, vulnapp, tmp_path):
    res = run_engagement(client, vulnapp + "/", workdir=tmp_path,
                         do_scan=False, max_pages=50, log=lambda *a: None)
    endpoints = {e["url"].split("?")[0] for e in res.crawl["endpoints"]}
    # /api/data and /profile are only referenced from app.js
    assert any(u.endswith("/api/data") for u in endpoints)
