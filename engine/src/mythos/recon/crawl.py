"""In-scope web crawler.

Breadth-first spider that stays within the engagement scope and the target's
registrable host. Extracts links, forms (with their inputs), and query
parameters, and mines inline/linked JavaScript for additional endpoints. The
result is the attack surface the scan phase operates on.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urldefrag

from bs4 import BeautifulSoup

from ..http_client import HttpClient, ScopeViolation, BudgetExceeded

# endpoints referenced from JS, two complementary patterns:
#   quoted root-relative paths:  "/api/x", fetch("/y?a=1")
_JS_ENDPOINT = re.compile(r"""["'](/[a-zA-Z0-9_\-./]{2,120})""")
#   api/rest/graphql/vN paths ANYWHERE (even in template literals like
#   `${base}/rest/products/search`): the prefix is specific enough to be safe.
#   A non-word lookbehind avoids matching mid-identifier.
_JS_API = re.compile(
    r"(?<![A-Za-z0-9_])(/?(?:api|rest|graphql|v[0-9]+)/[a-zA-Z0-9_\-./]{1,120})")
_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
             ".woff2", ".ttf", ".eot", ".css", ".pdf", ".zip", ".mp4", ".webp")
# never follow these during authenticated crawls: they destroy the session
_SESSION_KILLERS = re.compile(r"(logout|signout|sign-out|logoff|log-off|/exit|destroy)", re.I)


@dataclass
class Form:
    url: str
    action: str
    method: str
    inputs: list[dict] = field(default_factory=list)  # {name,type,value}

    def param_names(self) -> list[str]:
        return [i["name"] for i in self.inputs if i.get("name")]


@dataclass
class Endpoint:
    url: str
    params: list[str] = field(default_factory=list)
    source: str = "link"   # link | form | js | sitemap


@dataclass
class CrawlResult:
    seed: str
    pages: list[str] = field(default_factory=list)
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    forms: list[Form] = field(default_factory=list)

    def add_endpoint(self, url: str, params: list[str], source: str) -> None:
        url, _ = urldefrag(url)
        ep = self.endpoints.get(url)
        if ep is None:
            self.endpoints[url] = Endpoint(url=url, params=sorted(set(params)), source=source)
        else:
            ep.params = sorted(set(ep.params) | set(params))

    def to_dict(self) -> dict:
        return {
            "seed": self.seed,
            "pages": self.pages,
            "forms": [vars(f) for f in self.forms],
            "endpoints": [
                {"url": e.url, "params": e.params, "source": e.source}
                for e in self.endpoints.values()
            ],
        }


def _same_site(seed_host: str, url: str) -> bool:
    host = urlparse(url).hostname or ""
    if not host:
        return False
    return host == seed_host or host.endswith("." + seed_host) or seed_host.endswith("." + host)


def crawl(client: HttpClient, seed: str, *, max_pages: int = 150,
          max_depth: int = 3) -> CrawlResult:
    result = CrawlResult(seed=seed)
    seed_host = urlparse(seed).hostname or ""
    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(seed, 0)])

    _seed_from_robots_sitemap(client, seed, queue)

    while queue and len(result.pages) < max_pages:
        url, depth = queue.popleft()
        url, _ = urldefrag(url)
        if url in seen or depth > max_depth:
            continue
        seen.add(url)
        if any(url.lower().split("?")[0].endswith(e) for e in _SKIP_EXT):
            continue
        try:
            resp = client.get(url)
        except (ScopeViolation, BudgetExceeded):
            continue
        if resp is None:
            continue
        ctype = resp.headers.get("content-type", "")
        result.pages.append(url)

        q = parse_qs(urlparse(url).query)
        if q:
            result.add_endpoint(url, list(q.keys()), "link")

        if "javascript" in ctype or url.lower().endswith(".js"):
            _mine_js(result, seed_host, url, resp.text or "", queue, depth)
            continue
        if "html" not in ctype:
            continue

        soup = BeautifulSoup(resp.text or "", "lxml")
        # links
        for a in soup.find_all("a", href=True):
            nxt = urljoin(url, a["href"])
            if _SESSION_KILLERS.search(nxt):
                continue  # don't log ourselves out mid-crawl
            if nxt.startswith(("http://", "https://")) and _same_site(seed_host, nxt) \
                    and client.scope.contains(nxt):
                nq = parse_qs(urlparse(nxt).query)
                if nq:
                    result.add_endpoint(nxt, list(nq.keys()), "link")
                if nxt not in seen:
                    queue.append((nxt, depth + 1))
        # scripts
        for s in soup.find_all("script", src=True):
            js = urljoin(url, s["src"])
            if _same_site(seed_host, js) and js not in seen and client.scope.contains(js):
                queue.append((js, depth + 1))
        # inline scripts
        for s in soup.find_all("script", src=False):
            _mine_js(result, seed_host, url, s.get_text() or "", queue, depth)
        # forms
        for form in soup.find_all("form"):
            _extract_form(result, url, form)

    return result


def _extract_form(result: CrawlResult, page_url: str, form) -> None:
    action = urljoin(page_url, form.get("action") or page_url)
    method = (form.get("method") or "get").upper()
    inputs = []
    for el in form.find_all(["input", "textarea", "select"]):
        name = el.get("name")
        if not name:
            continue
        inputs.append({
            "name": name,
            "type": el.get("type", el.name),
            "value": el.get("value", ""),
        })
    f = Form(url=page_url, action=action, method=method, inputs=inputs)
    result.forms.append(f)
    if method == "GET" and f.param_names():
        result.add_endpoint(action, f.param_names(), "form")


def _mine_js(result: CrawlResult, seed_host: str, base: str, body: str,
             queue: deque, depth: int) -> None:
    origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
    body = body or ""
    matches = set(_JS_ENDPOINT.findall(body)) | set(_JS_API.findall(body))
    for m in matches:
        m = m.rstrip(".")  # trailing dot from minified concatenation
        if m.startswith("//") or any(m.lower().endswith(e) for e in _SKIP_EXT):
            continue
        # bare relative api/rest paths resolve against the site root, not the
        # directory of the JS file (which may live under /assets/)
        full = urljoin(origin + "/", m) if not m.startswith("/") else urljoin(origin, m)
        if _same_site(seed_host, full):
            q = parse_qs(urlparse(full).query)
            result.add_endpoint(full, list(q.keys()), "js")


def _seed_from_robots_sitemap(client: HttpClient, seed: str, queue: deque) -> None:
    base = f"{urlparse(seed).scheme}://{urlparse(seed).netloc}"
    for path in ("/robots.txt", "/sitemap.xml"):
        try:
            resp = client.get(base + path)
        except Exception:
            continue
        if resp is None or resp.status_code != 200:
            continue
        for m in re.findall(r"(?:Disallow|Allow|Sitemap):\s*(\S+)", resp.text or "", re.I):
            nxt = urljoin(base, m)
            if client.scope.contains(nxt):
                queue.append((nxt, 1))
        for loc in re.findall(r"<loc>\s*([^<]+)</loc>", resp.text or ""):
            if client.scope.contains(loc.strip()):
                queue.append((loc.strip(), 1))
