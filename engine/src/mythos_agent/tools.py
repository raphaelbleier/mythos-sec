"""Tool registry for the Mythos agent.

Each tool wraps a Mythos engine capability (or a Kali tool) and returns a short
text observation the LLM can reason over. All network access goes through the
scope-aware HttpClient, so the agent cannot leave the engagement scope.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable

from mythos import external
from mythos.findings import Finding, FindingStore, Severity, Evidence
from mythos.http_client import HttpClient, ScopeViolation, BudgetExceeded
from mythos.recon.crawl import crawl, CrawlResult
from mythos.recon.discover import discover
from mythos.recon.fingerprint import fingerprint
from mythos.scan.common import InjectionPoint, points_from_crawl
from mythos.scan import quick, advanced, headers as headers_mod, idor as idor_mod
from mythos.scan import api as api_mod


@dataclass
class AgentState:
    target: str
    client: HttpClient
    store: FindingStore = field(default_factory=FindingStore)
    crawl: CrawlResult | None = None

    def endpoints(self):
        return list(self.crawl.endpoints.values()) if self.crawl else []


_PARAM_CHECKS = {
    "reflected-xss": quick.check_xss, "sqli": quick.check_sqli,
    "open-redirect": quick.check_open_redirect, "path-traversal": quick.check_path_traversal,
    "ssti": advanced.check_ssti, "crlf": advanced.check_crlf,
    "command-injection": advanced.check_command_injection,
    "blind-sqli": advanced.check_blind_sqli, "idor": idor_mod.check_idor,
}


@dataclass
class Tool:
    name: str
    description: str
    run: Callable[[AgentState, dict], str]


def _fingerprint(st: AgentState, args: dict) -> str:
    fp = fingerprint(st.client, args.get("url") or st.target)
    return json.dumps(fp.to_dict())[:1200]


def _crawl(st: AgentState, args: dict) -> str:
    st.crawl = crawl(st.client, args.get("url") or st.target,
                     max_pages=int(args.get("max_pages", 60)))
    eps = [{"url": e.url, "params": e.params} for e in st.crawl.endpoints.values()]
    return json.dumps({"pages": len(st.crawl.pages), "forms": len(st.crawl.forms),
                       "endpoints": eps[:60]})[:3000]


def _discover(st: AgentState, args: dict) -> str:
    res, finds = discover(st.client, args.get("url") or st.target)
    for f in finds:
        st.store.add(f)
    return json.dumps({"hits": res.hits[:30], "findings_added": len(finds)})[:1500]


def _list_endpoints(st: AgentState, args: dict) -> str:
    eps = [{"url": e.url, "params": e.params, "source": e.source} for e in st.endpoints()]
    return json.dumps(eps[:80])[:3000] if eps else "no endpoints yet (run crawl first)"


def _http(st: AgentState, args: dict) -> str:
    method = (args.get("method") or "GET").upper()
    url = args["url"]
    try:
        resp = st.client.request(method, url, params=args.get("params"),
                                 data=args.get("data"), json=args.get("json"))
    except ScopeViolation as e:
        return f"BLOCKED (out of scope): {e}"
    except BudgetExceeded as e:
        return f"BUDGET EXCEEDED: {e}"
    if resp is None:
        return "request failed (no response)"
    body = (resp.text or "")[:1200]
    return json.dumps({"status": resp.status_code,
                       "headers": dict(list(resp.headers.items())[:12]),
                       "body": body})[:2000]


def _check(st: AgentState, args: dict) -> str:
    kind = args.get("kind", "")
    fn = _PARAM_CHECKS.get(kind)
    if not fn:
        return f"unknown check {kind!r}; valid: {', '.join(_PARAM_CHECKS)}"
    pt = InjectionPoint(method=(args.get("method") or "GET").upper(),
                        url=args["url"], param=args.get("param", ""),
                        base_params=args.get("base_params") or {},
                        where=args.get("where", "query"),
                        template=args.get("template", ""))
    try:
        finds = fn(st.client, pt)
    except Exception as e:
        return f"check error: {e}"
    for f in finds:
        st.store.add(f)
    return json.dumps([{"kind": f.kind, "severity": f.severity.value,
                        "confidence": f.confidence} for f in finds]) or "no finding"


def _passive(st: AgentState, args: dict) -> str:
    url = args.get("url") or st.target
    finds = []
    finds += headers_mod.check_security_headers(st.client, url)
    finds += headers_mod.check_cookies(st.client, url)
    finds += headers_mod.check_cors(st.client, url)
    finds += api_mod.check_sensitive_api_response(st.client, url)
    for f in finds:
        st.store.add(f)
    return json.dumps([{"kind": f.kind, "severity": f.severity.value} for f in finds]) or "none"


def _run_tool(st: AgentState, args: dict) -> str:
    tool = args.get("tool", "")
    url = args.get("url") or st.target
    if not external.have(tool):
        return f"tool {tool!r} not available"
    finds = []
    if tool == "nuclei":
        finds = external.nuclei(url, timeout=300)
    elif tool == "dalfox":
        finds = external.dalfox(url, timeout=120)
    elif tool == "sqlmap":
        finds = external.sqlmap(url, timeout=180)
    elif tool == "nikto":
        finds = external.nikto(url, timeout=300)
    else:
        return f"tool {tool!r} not wired for the agent"
    for f in finds:
        st.store.add(f)
    return json.dumps([{"kind": f.kind, "severity": f.severity.value,
                        "source": f.source} for f in finds]) or "no findings"


def _record(st: AgentState, args: dict) -> str:
    try:
        f = Finding(title=args["title"], severity=Severity(args.get("severity", "medium")),
                    kind=args.get("kind", "manual"), url=args.get("url", st.target),
                    param=args.get("param", ""), description=args.get("description", ""),
                    evidence=Evidence(matched=args.get("evidence", "")),
                    confidence=args.get("confidence", "tentative"))
    except Exception as e:
        return f"record error: {e}"
    st.store.add(f)
    return f"recorded: {f.kind} ({f.severity.value})"


def registry() -> dict[str, Tool]:
    return {t.name: t for t in [
        Tool("fingerprint", "Fingerprint a URL (server, tech, title). args: {url?}", _fingerprint),
        Tool("crawl", "Crawl the target for endpoints/forms/params. args: {url?, max_pages?}", _crawl),
        Tool("discover", "Probe common sensitive paths (.git/.env/backups/etc). args: {url?}", _discover),
        Tool("list_endpoints", "List discovered endpoints and their params. args: {}", _list_endpoints),
        Tool("http_request", "Send one HTTP request (scope-checked). args: {method?, url, params?, data?, json?}", _http),
        Tool("check", "Run a vulnerability check on a parameter. args: {kind, url, param, method?, where?(query|body|json|path), base_params?, template?}. kinds: "
             + ", ".join(_PARAM_CHECKS), _check),
        Tool("passive_checks", "Run header/cookie/CORS/API-exposure checks on a URL. args: {url?}", _passive),
        Tool("run_tool", "Run a Kali tool and parse findings. args: {tool(nuclei|dalfox|sqlmap|nikto), url?}", _run_tool),
        Tool("record_finding", "Record a confirmed finding. args: {title, severity, kind, url, param?, description?, evidence?}", _record),
    ]}
