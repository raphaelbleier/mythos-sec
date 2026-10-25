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


from mythos.state import CoverageMatrix, TaskTree, Task


@dataclass
class AgentState:
    target: str
    client: HttpClient
    store: FindingStore = field(default_factory=FindingStore)
    crawl: CrawlResult | None = None
    # durable shared state across steps (not just the transcript)
    coverage: CoverageMatrix = field(default_factory=CoverageMatrix)
    tasks: TaskTree = field(default_factory=TaskTree)
    notes: list[str] = field(default_factory=list)

    def endpoints(self):
        return list(self.crawl.endpoints.values()) if self.crawl else []

    def state_summary(self) -> str:
        import json as _j
        open_tasks = [f"{t.id}:{t.kind}:{t.status}:{t.objective[:40]}"
                      for t in self.tasks.open_tasks()][:8]
        return _j.dumps({
            "findings": self.store.counts(),
            "coverage": self.coverage.summary() if self.coverage.endpoints else {},
            "open_tasks": open_tasks,
            "notes": self.notes[-5:],
        })[:1200]


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


def _scan_all(st: AgentState, args: dict) -> str:
    """Exhaustive native sweep over every crawled injection point + passive checks."""
    if st.crawl is None:
        st.crawl = crawl(st.client, st.target, max_pages=int(args.get("max_pages", 60)))
    pts = points_from_crawl(st.crawl)
    checks = [quick.check_xss, quick.check_sqli, quick.check_open_redirect,
              quick.check_path_traversal, advanced.check_ssti, advanced.check_crlf,
              idor_mod.check_idor]
    before = len(st.store)
    for pt in pts:
        for fn in checks:
            try:
                for f in fn(st.client, pt):
                    st.store.add(f)
            except Exception:
                continue
    # passive across a bounded surface
    seen = set()
    for u in ([st.target] + [e.url for e in st.crawl.endpoints.values()])[:40]:
        key = u.split("?")[0]
        if key in seen:
            continue
        seen.add(key)
        for fn in (headers_mod.check_cookies, headers_mod.check_cors,
                   api_mod.check_sensitive_api_response):
            try:
                for f in fn(st.client, u):
                    st.store.add(f)
            except Exception:
                continue
    # update coverage matrix from the swept surface + findings
    for pt in pts:
        st.coverage.ensure(pt.url)
    for f in st.store.findings:
        st.coverage.mark(f.url.split("#")[0], f.kind, "finding")
    new = [{"kind": f.kind, "severity": f.severity.value, "url": f.url, "param": f.param}
           for f in st.store.findings]
    return json.dumps({"injection_points": len(pts), "total_findings": len(st.store),
                       "new_this_sweep": len(st.store) - before,
                       "findings": new[:40]})[:3500]


def _note(st: AgentState, args: dict) -> str:
    txt = str(args.get("text", "")).strip()
    if txt:
        st.notes.append(txt)
    return f"noted ({len(st.notes)} notes)"


def _plan_task(st: AgentState, args: dict) -> str:
    op = args.get("op", "add")
    if op == "add":
        tid = f"t{len(st.tasks.tasks)+1}"
        st.tasks.add(Task(id=tid, kind=str(args.get("kind", "TEST")).upper(),
                          target=args.get("target", st.target),
                          objective=args.get("objective", ""),
                          status="ready"))
        return f"task {tid} added"
    if op == "done" and args.get("id"):
        try:
            st.tasks.transition(args["id"], "done")
            return f"task {args['id']} done"
        except Exception as e:
            return f"task error: {e}"
    return "args: {op: add|done, kind?, objective?, id?}"


def _browser_dom_xss(st: AgentState, args: dict) -> str:
    from mythos.scan import browser
    if not browser.available():
        return "browser (playwright/chromium) not available in this environment"
    try:
        finds = browser.check_dom_xss(args["url"], param=args.get("param"))
    except Exception as e:
        return f"browser error: {e}"
    for f in finds:
        st.store.add(f)
    return json.dumps([{"kind": f.kind, "severity": f.severity.value,
                        "payload": f.payload[:60]} for f in finds]) or "no DOM XSS"


def _bola(st: AgentState, args: dict) -> str:
    """Two-account BOLA: attacker identity reads the victim's object_url."""
    from mythos.scan.bola import check_bola
    import dataclasses as _dc
    idents = st.client.scope.identities
    if not idents:
        return "no second identity configured (set scope.identities with 2 users)"
    atk_scope = _dc.replace(st.client.scope, auth=idents[0])
    attacker = HttpClient(scope=atk_scope, proxy=st.client.proxy)
    try:
        finds = check_bola(st.client, attacker, args["object_url"],
                           attacker_own_url=args.get("attacker_own_url"))
    except Exception as e:
        return f"bola error: {e}"
    for f in finds:
        st.store.add(f)
    return json.dumps([{"kind": f.kind, "severity": f.severity.value} for f in finds]) \
        or "no BOLA (attacker denied or same object)"


def _cve_lookup(st: AgentState, args: dict) -> str:
    from mythos.intel import nvd
    res = nvd.search(args.get("product", ""), args.get("version", ""),
                     limit=int(args.get("limit", 6)))
    return json.dumps(res)[:2500]


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
        Tool("scan_all", "Exhaustive sweep: run every native vuln check on ALL crawled injection points + passive checks. Call once after crawl for breadth, then reason about depth. args: {}", _scan_all),
        Tool("run_tool", "Run a Kali tool (local or via the toolbox container) and parse findings. args: {tool(nuclei|dalfox|sqlmap|nikto), url?}", _run_tool),
        Tool("browser_dom_xss", "Headless-Chromium DOM-XSS check on a URL (query + hash sinks). args: {url, param?}", _browser_dom_xss),
        Tool("bola", "Two-account BOLA: confirm the attacker identity can read the victim's object. Needs scope.identities. args: {object_url, attacker_own_url?}", _bola),
        Tool("cve_lookup", "Look up known CVEs for a product/version via NVD. args: {product, version?, limit?}", _cve_lookup),
        Tool("note", "Save a durable note (persists across steps). args: {text}", _note),
        Tool("plan_task", "Manage the task tree. args: {op: add|done, kind?, objective?, id?}", _plan_task),
        Tool("record_finding", "Record a confirmed finding. args: {title, severity, kind, url, param?, description?, evidence?}", _record),
    ]}
