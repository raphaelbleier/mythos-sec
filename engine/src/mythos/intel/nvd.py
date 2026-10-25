"""NVD (National Vulnerability Database) CVE lookup.

Queries the public NVD 2.0 API for CVEs matching a product/keyword (optionally a
version), so the agent can map a fingerprinted technology to known CVEs — the
CVE-intelligence idea from HexStrike, kept transparent and rate-limited.

No API key required (public endpoint; low rate). Returns a compact list.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search(keyword: str, version: str = "", limit: int = 8, timeout: int = 20) -> list[dict]:
    term = f"{keyword} {version}".strip()
    qs = urllib.parse.urlencode({"keywordSearch": term, "resultsPerPage": max(1, min(limit, 20))})
    req = urllib.request.Request(f"{NVD}?{qs}", headers={"User-Agent": "mythos-sec/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except Exception as exc:
        return [{"error": f"NVD query failed: {exc}"}]
    out = []
    for item in data.get("vulnerabilities", [])[:limit]:
        cve = item.get("cve", {})
        cid = cve.get("id", "")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:220]
                break
        score, sev = _cvss(cve)
        out.append({"id": cid, "cvss": score, "severity": sev, "summary": desc})
    return out


def _cvss(cve: dict):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            d = arr[0].get("cvssData", {})
            return d.get("baseScore"), d.get("baseSeverity") or arr[0].get("baseSeverity")
    return None, None
