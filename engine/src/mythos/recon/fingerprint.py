"""Technology fingerprinting.

Identifies server, frameworks, languages, CMS and JS libraries from response
headers, cookies, body signatures and the favicon hash. Deliberately
signature-driven and extensible; not a replacement for whatweb/Wappalyzer but
enough to steer the scan phase on any web app.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

from ..http_client import HttpClient

# (label, where, regex) — where in {"header:<name>", "cookie", "body", "generator"}
SIGNATURES: list[tuple[str, str, str]] = [
    ("nginx", "header:server", r"nginx"),
    ("Apache", "header:server", r"apache"),
    ("IIS", "header:server", r"iis|microsoft-iis"),
    ("PHP", "header:x-powered-by", r"php"),
    ("PHP", "cookie", r"PHPSESSID"),
    ("ASP.NET", "header:x-powered-by", r"asp\.net"),
    ("ASP.NET", "cookie", r"ASP\.NET_SessionId"),
    ("Express", "header:x-powered-by", r"express"),
    ("Node.js", "header:x-powered-by", r"node"),
    ("Java/Servlet", "cookie", r"JSESSIONID"),
    ("Flask/Werkzeug", "header:server", r"werkzeug"),
    ("Django", "cookie", r"csrftoken|sessionid"),
    ("Rails", "cookie", r"_session_id|_rails"),
    ("Laravel", "cookie", r"laravel_session|XSRF-TOKEN"),
    ("WordPress", "body", r"/wp-content/|/wp-includes/|wp-json"),
    ("Drupal", "body", r"Drupal\.settings|/sites/default/files"),
    ("Joomla", "body", r"/media/jui/|Joomla!"),
    ("React", "body", r"data-reactroot|__REACT_DEVTOOLS|react\.production"),
    ("Angular", "body", r"ng-version|angular\.js"),
    ("Vue.js", "body", r"data-v-[0-9a-f]{8}|vue\.js"),
    ("jQuery", "body", r"jquery[-.]?([0-9.]+)?(\.min)?\.js"),
    ("Bootstrap", "body", r"bootstrap(\.min)?\.(css|js)"),
    ("Cloudflare", "header:server", r"cloudflare"),
    ("Varnish", "header:via", r"varnish"),
    ("Swagger/OpenAPI", "body", r"swagger-ui|openapi\.json|/v2/api-docs"),
    ("GraphQL", "body", r"graphql"),
]


@dataclass
class Fingerprint:
    url: str
    status: Optional[int] = None
    server: str = ""
    title: str = ""
    technologies: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    favicon_hash: str = ""
    waf: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url, "status": self.status, "server": self.server,
            "title": self.title, "technologies": self.technologies,
            "cookies": self.cookies, "favicon_hash": self.favicon_hash,
            "waf": self.waf,
        }


_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_GEN = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)


def fingerprint(client: HttpClient, url: str) -> Fingerprint:
    resp = client.get(url)
    fp = Fingerprint(url=url)
    if resp is None:
        return fp
    fp.status = resp.status_code
    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    fp.headers = hdrs
    fp.server = hdrs.get("server", "")
    body = resp.text or ""
    m = _TITLE.search(body)
    if m:
        fp.title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    fp.cookies = [c.split("=")[0] for c in resp.headers.get("set-cookie", "").split(",") if "=" in c]
    gen = _GEN.search(body)
    generator = gen.group(1) if gen else ""

    techs: set[str] = set()
    for label, where, pattern in SIGNATURES:
        rx = re.compile(pattern, re.I)
        if where.startswith("header:"):
            name = where.split(":", 1)[1]
            if rx.search(hdrs.get(name, "")):
                techs.add(label)
        elif where == "cookie":
            if rx.search(resp.headers.get("set-cookie", "")):
                techs.add(label)
        elif where == "body":
            if rx.search(body):
                techs.add(label)
        elif where == "generator" and generator and rx.search(generator):
            techs.add(label)
    if generator:
        techs.add(generator.strip()[:60])
    fp.technologies = sorted(techs)

    # crude WAF hinting
    waf_hdr = (hdrs.get("server", "") + hdrs.get("via", "") +
               " ".join(k for k in hdrs if k.startswith(("x-sucuri", "x-akamai"))))
    for name, pat in (("Cloudflare", "cloudflare"), ("Akamai", "akamai"),
                      ("Sucuri", "sucuri"), ("Imperva", "incapsula")):
        if re.search(pat, waf_hdr, re.I):
            fp.waf = name
            break

    fp.favicon_hash = _favicon_hash(client, url)
    return fp


def _favicon_hash(client: HttpClient, base: str) -> str:
    from urllib.parse import urljoin
    try:
        resp = client.get(urljoin(base, "/favicon.ico"))
    except Exception:
        return ""
    if resp is None or resp.status_code != 200 or not resp.content:
        return ""
    return hashlib.md5(resp.content).hexdigest()
