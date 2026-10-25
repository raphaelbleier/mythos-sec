"""Engagement orchestrator.

Runs the phases in order and writes artifacts into the engagement directory:

    recon   -> fingerprint, subdomains (subfinder), crawl (katana|native),
               content discovery (ffuf|native)
    scan    -> nuclei (templated), dalfox (XSS), sqlmap (SQLi), nikto,
               plus native quick checks and passive header/CORS checks
    report  -> findings.json + report.md

External tools are used when present; otherwise the native engine covers the
headline web bug classes. Everything is scope-gated by the HttpClient.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from . import external
from .findings import FindingStore
from .http_client import HttpClient, ScopeViolation, BudgetExceeded
from .oast import OastListener
from .recon import crawl as crawl_mod
from .recon import discover as discover_mod
from .recon.fingerprint import fingerprint
from .report import render_markdown, render_summary
from .scan import advanced as adv_mod
from .scan import headers as headers_mod
from .scan import idor as idor_mod
from .scan.common import points_from_crawl
from .scan.quick import ALL_PARAM_CHECKS
from .state import CoverageMatrix


@dataclass
class EngagementResult:
    target: str
    fingerprint: dict = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[dict] = field(default_factory=list)
    crawl: dict = field(default_factory=dict)
    discovery: dict = field(default_factory=dict)
    nmap: dict = field(default_factory=dict)
    coverage: dict = field(default_factory=dict)
    tools_used: dict = field(default_factory=dict)
    store: FindingStore = field(default_factory=FindingStore)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "fingerprint": self.fingerprint,
            "subdomains": self.subdomains,
            "live_hosts": self.live_hosts,
            "crawl": self.crawl,
            "discovery": self.discovery,
            "nmap": self.nmap,
            "coverage": self.coverage,
            "tools_used": self.tools_used,
            "summary": self.store.counts(),
            "findings": [f.to_dict() for f in self.store.findings],
        }


def run_engagement(client: HttpClient, target: str, *, workdir: Path | None = None,
                   do_recon: bool = True, do_scan: bool = True,
                   max_pages: int = 150, wordlist: str | None = None,
                   mode: str = "standard", log=print) -> EngagementResult:
    """mode: quick | standard | deep. deep adds slow time-based oracles."""
    res = EngagementResult(target=target)
    res.tools_used = external.available_tools()
    host = urlparse(target).hostname or target
    scope = client.scope

    # ---- RECON ---------------------------------------------------------
    if do_recon:
        log("[recon] fingerprinting target")
        res.fingerprint = fingerprint(client, target).to_dict()

        log("[recon] passive header check (root)")
        res.store.extend(headers_mod.check_security_headers(client, target))

        if external.have("subfinder") and _is_domain(host):
            log("[recon] subfinder: enumerating subdomains")
            res.subdomains = subs = external.subfinder(host)
            in_scope_subs = [s for s in subs if scope.contains(s)]
            if external.have("httpx") and in_scope_subs:
                res.live_hosts = external.httpx_probe(in_scope_subs)

        log("[recon] crawling attack surface")
        if external.have("katana"):
            urls = [u for u in external.katana(target, depth=3, timeout=90)
                    if scope.contains(u)]
            cres = crawl_mod.CrawlResult(seed=target)
            for u in urls:
                from urllib.parse import urlparse as _up, parse_qs
                cres.add_endpoint(u, list(parse_qs(_up(u).query).keys()), "js")
            # still run native crawl for forms, then merge
            native = crawl_mod.crawl(client, target, max_pages=max_pages)
            for ep in native.endpoints.values():
                cres.add_endpoint(ep.url, ep.params, ep.source)
            cres.forms = native.forms
            cres.pages = native.pages
        else:
            cres = crawl_mod.crawl(client, target, max_pages=max_pages)

        # Parameter discovery (arjun): give parameterless REST/SPA endpoints
        # testable parameters so the scan phase has injection points on APIs.
        if external.have("arjun") and mode in ("standard", "deep"):
            log("[recon] arjun parameter discovery")
            cands = [target] + [e.url for e in cres.endpoints.values()
                                if not e.params and "?" not in e.url]
            cands = sorted(set(cands),
                           key=lambda u: 0 if re.search(
                               r"(api|rest|search|query|json|graphql|lookup|find)",
                               u, re.I) else 1)
            for u in cands[:6]:
                if not scope.contains(u):
                    continue
                try:
                    params = external.arjun(u, timeout=60)
                except Exception:
                    params = []
                if params:
                    cres.add_endpoint(u, params, "arjun")

        res.crawl = cres.to_dict()
        log(f"[recon] {len(cres.endpoints)} endpoints, {len(cres.forms)} forms, "
            f"{len(cres.pages)} pages")

        log("[recon] content discovery")
        if external.have("ffuf") and wordlist:
            hits = external.ffuf(f"{urlparse(target).scheme}://{urlparse(target).netloc}",
                                 wordlist)
            res.discovery = {"base": target, "hits": hits}
        dres, dfind = discover_mod.discover(client, target)
        if not res.discovery:
            res.discovery = dres.to_dict()
        res.store.extend(dfind)

        # Passive cookie / CORS checks across the discovered surface (bounded).
        log("[recon] cookie / CORS checks across surface")
        surface: list[str] = []
        seen_surface: set[str] = set()
        for u in list(cres.pages) + [e.url for e in cres.endpoints.values()]:
            key = u.split("?")[0]
            if key in seen_surface:
                continue
            seen_surface.add(key)
            if scope.contains(u):
                surface.append(u)
            if len(surface) >= 40:
                break
        for u in surface:
            try:
                res.store.extend(headers_mod.check_cookies(client, u))
                res.store.extend(headers_mod.check_cors(client, u))
            except (ScopeViolation, BudgetExceeded):
                break
            except Exception:
                continue
    else:
        cres = crawl_mod.crawl(client, target, max_pages=max_pages)
        res.crawl = cres.to_dict()

    # ---- SCAN ----------------------------------------------------------
    if do_scan and scope.rules.allow_active:
        points = points_from_crawl(cres)
        log(f"[scan] {len(points)} injection points")

        # Templated scan across the whole target (fast, broad).
        if external.have("nuclei"):
            log("[scan] nuclei templated scan")
            _safe(res.store, lambda: external.nuclei(target, timeout=300))

        # Native checks on every injection point. quick = headline classes;
        # standard adds SSTI/CRLF/IDOR; deep adds the slow time-based oracles.
        param_checks = list(ALL_PARAM_CHECKS)
        if mode in ("standard", "deep"):
            param_checks += [adv_mod.check_ssti, adv_mod.check_crlf, idor_mod.check_idor]
        if mode == "deep":
            param_checks += [adv_mod.check_command_injection, adv_mod.check_blind_sqli]

        oast = None
        try:
            oast = OastListener(public_host=_oast_host()).__enter__()
            log(f"[scan] OAST listener on :{oast.port}")
        except Exception:
            oast = None

        for i, pt in enumerate(points, 1):
            for check in param_checks:
                try:
                    res.store.extend(check(client, pt))
                except (ScopeViolation, BudgetExceeded):
                    break
                except Exception:
                    continue
            # SSRF via out-of-band callback on url/redirect-like params
            if oast is not None and re.search(r"(url|uri|next|redirect|dest|target|"
                                              r"callback|fetch|load|path|file|host)",
                                              pt.param, re.I):
                try:
                    res.store.extend(adv_mod.check_ssrf(client, pt, oast))
                except Exception:
                    pass
            if i % 25 == 0:
                log(f"[scan] checked {i}/{len(points)} points")

        # GraphQL introspection on graphql-looking endpoints
        for ep in cres.endpoints.values():
            if "graphql" in ep.url.lower() and scope.contains(ep.url):
                try:
                    res.store.extend(adv_mod.check_graphql_introspection(client, ep.url))
                except Exception:
                    pass

        # JWT weaknesses: scan captured traffic for JWT-like tokens
        res.store.extend(_jwt_from_traffic(client, target))

        if oast is not None:
            oast.stop()

        # Deep per-endpoint tools on parameterized GET endpoints. Each tool is
        # isolated: a parser error or crash in one never aborts the engagement.
        param_urls = [e.url for e in cres.endpoints.values()
                      if "?" in e.url or e.params]
        dmax = int(os.environ.get("MYTHOS_DALFOX_MAX", "6"))
        smax = int(os.environ.get("MYTHOS_SQLMAP_MAX", "3"))
        if external.have("dalfox"):
            log("[scan] dalfox XSS on parameterized endpoints")
            for url in param_urls[:dmax]:
                if scope.contains(url):
                    _safe(res.store,
                          lambda u=url: external.dalfox(_with_params(u, cres), timeout=60))
        if external.have("sqlmap") and scope.rules.allow_exploit:
            log("[scan] sqlmap on parameterized endpoints")
            for url in param_urls[:smax]:
                if scope.contains(url):
                    _safe(res.store,
                          lambda u=url: external.sqlmap(_with_params(u, cres), timeout=120))
        if external.have("nikto"):
            log("[scan] nikto server scan")
            _safe(res.store, lambda: external.nikto(target))
    elif do_scan:
        log("[scan] skipped: scope rules.allow_active is false")

    # ---- coverage matrix ----------------------------------------------
    res.coverage = _build_coverage(cres, target, res.store, mode).to_dict()

    # ---- persist -------------------------------------------------------
    if workdir:
        _persist(res, workdir, client)
    return res


# classes each mode exercises on a parameterized endpoint
_MODE_CLASSES = {
    "quick": ["reflected-xss", "sqli", "open-redirect", "path-traversal"],
    "standard": ["reflected-xss", "sqli", "open-redirect", "path-traversal",
                 "ssti", "crlf-injection", "idor", "ssrf"],
    "deep": ["reflected-xss", "sqli", "open-redirect", "path-traversal",
             "ssti", "crlf-injection", "idor", "ssrf", "command-injection"],
}


def _build_coverage(cres, target: str, store, mode: str) -> CoverageMatrix:
    cov = CoverageMatrix()
    tested = _MODE_CLASSES.get(mode, _MODE_CLASSES["standard"])
    endpoints = [target] + [e.url for e in cres.endpoints.values()]
    for ep in endpoints:
        cov.ensure(ep)
        has_params = ("?" in ep) or any(
            e.url == ep and e.params for e in cres.endpoints.values())
        for bc in (tested if has_params else ["cors-misconfig", "sensitive-exposure"]):
            cov.mark(ep, bc, "tested")
    for f in store.findings:
        cov.mark(f.url.split("#")[0], f.kind, "finding")
    return cov


def _with_params(url: str, cres) -> str:
    """Ensure the URL carries test values for its params (dalfox/sqlmap need a query)."""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    p = urlparse(url)
    q = parse_qs(p.query)
    ep = cres.endpoints.get(url.split("?")[0]) or cres.endpoints.get(url)
    names = list(q.keys()) or (ep.params if ep else [])
    if not q and names:
        q = {n: ["1"] for n in names}
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


def _safe(store, fn) -> None:
    """Run an external-tool call, swallowing any failure so one tool never
    aborts the engagement. Findings it returns are merged into the store."""
    try:
        store.extend(fn() or [])
    except Exception:
        pass


def _oast_host() -> str:
    # Address the target should call back to. For the local lab the target
    # containers reach the toolbox via host.docker.internal; override as needed.
    return os.environ.get("MYTHOS_OAST_HOST", "127.0.0.1")


_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")


def _jwt_from_traffic(client: HttpClient, target: str):
    from .scan import advanced as adv
    seen: set[str] = set()
    findings = []
    for tx in client.transactions:
        blob = (tx.resp_body or "") + " " + " ".join(tx.resp_headers.values())
        for token in _JWT_RE.findall(blob):
            if token in seen:
                continue
            seen.add(token)
            findings.extend(adv.check_jwt(token, url=tx.url))
    return findings


def _is_domain(host: str) -> bool:
    if not host:
        return False
    parts = host.split(".")
    if len(parts) < 2:
        return False
    return not all(p.isdigit() for p in parts)  # not an IP


def _persist(res: EngagementResult, workdir: Path, client: HttpClient) -> None:
    workdir = Path(workdir)
    (workdir / "findings.json").write_text(
        json.dumps(res.to_dict(), indent=2), encoding="utf-8")
    (workdir / "report.md").write_text(
        render_markdown(res.target, res.store, res.to_dict()), encoding="utf-8")
    (workdir / "summary.txt").write_text(
        render_summary(res.target, res.store), encoding="utf-8")
    if res.coverage:
        (workdir / "coverage.json").write_text(
            json.dumps(res.coverage, indent=2), encoding="utf-8")
    # raw evidence log
    evid = [vars(t) for t in client.transactions]
    (workdir / "transactions.json").write_text(
        json.dumps(evid, indent=2)[:5_000_000], encoding="utf-8")
