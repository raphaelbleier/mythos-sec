"""Compact native fallback checks.

These exist so the engine still finds the headline web bug classes when no
toolbox/Docker is available, and so the test suite has deterministic ground
truth. When the toolbox is present the orchestrator prefers dalfox (XSS),
sqlmap (SQLi) and nuclei (templated) over these.

Covered: reflected XSS, error-based SQLi, open redirect, path traversal.
"""

from __future__ import annotations

import re
import uuid

from ..findings import Finding, Evidence, Severity
from ..http_client import HttpClient
from .common import InjectionPoint, send

# ---- reflected XSS -----------------------------------------------------
_XSS_PROBE = "mx{tok}x'\"<svg/onload=1>"


def check_xss(client: HttpClient, point: InjectionPoint) -> list[Finding]:
    tok = uuid.uuid4().hex[:8]
    payload = _XSS_PROBE.format(tok=tok)
    resp = send(client, point, payload)
    if resp is None or not resp.text:
        return []
    body = resp.text
    ctype = resp.headers.get("content-type", "")
    if "html" not in ctype:
        return []
    # reflected unencoded in an exploitable form?
    marker = f"mx{tok}x"
    if marker not in body:
        return []
    raw_tag = "<svg/onload=1>" in body
    raw_quote = (marker + "'") in body or (marker + '"') in body
    if not (raw_tag or raw_quote):
        return []  # reflected but encoded
    return [Finding(
        title="Reflected Cross-Site Scripting (XSS)",
        severity=Severity.HIGH, kind="reflected-xss",
        url=point.url, param=point.param, payload=payload,
        description=f"The parameter {point.param!r} reflects input into the HTML "
                    "response without adequate output encoding.",
        impact="An attacker can execute arbitrary JavaScript in a victim's browser, "
               "stealing sessions or performing actions as the victim.",
        remediation="Context-aware output encoding; deploy a Content-Security-Policy.",
        evidence=Evidence(request=point.label() + f" payload={payload}",
                          response=_excerpt(body, marker), matched="<svg/onload=1>"),
        confidence="firm")]


# ---- error-based SQL injection ----------------------------------------
_SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)|postgresql.*error",
    r"sqlite3?\.(OperationalError|Warning)",
    r"SQLITE_ERROR",
    r"unrecognized token:",
    r'near ".+": syntax error',
    r"ORA-\d{5}",
    r"syntax error at or near",
    r"SQLSTATE\[",
    r"com\.mysql\.jdbc",
    r"org\.hibernate",
    r"System\.Data\.SqlClient",
    r"MySqlException",
]
_SQL_RX = re.compile("|".join(_SQL_ERRORS), re.I)


def check_sqli(client: HttpClient, point: InjectionPoint) -> list[Finding]:
    base = send(client, point, "1")
    err = send(client, point, "1'\"")
    if err is None or not err.text:
        return []
    m = _SQL_RX.search(err.text)
    if m and not (base and _SQL_RX.search(base.text or "")):
        return [Finding(
            title="SQL Injection (error-based)",
            severity=Severity.CRITICAL, kind="sqli",
            url=point.url, param=point.param, payload="1'\"",
            description=f"Injecting a quote into {point.param!r} triggers a database "
                        "error, indicating the input reaches a SQL query unsanitized.",
            impact="Full read/write access to the database, authentication bypass, "
                   "and in many cases remote code execution.",
            remediation="Use parameterized queries / prepared statements. Never build "
                        "SQL by string concatenation of user input.",
            evidence=Evidence(request=point.label() + " payload=1'\"",
                              response=_excerpt(err.text, m.group(0)),
                              matched=m.group(0)),
            confidence="firm")]
    return []


# ---- open redirect -----------------------------------------------------
_REDIR_HINT = re.compile(r"(redirect|return|next|url|target|dest|continue|goto)", re.I)


def check_open_redirect(client: HttpClient, point: InjectionPoint) -> list[Finding]:
    if not _REDIR_HINT.search(point.param):
        return []
    evil = "https://mythos-evil.example/"
    resp = send(client, point, evil, allow_redirects=False)
    if resp is None:
        return []
    loc = resp.headers.get("location", "")
    if resp.status_code in (301, 302, 303, 307, 308) and loc.startswith(evil):
        return [Finding(
            title="Open Redirect",
            severity=Severity.MEDIUM, kind="open-redirect",
            url=point.url, param=point.param, payload=evil,
            description=f"The parameter {point.param!r} controls the Location header "
                        "and redirects to an attacker-supplied absolute URL.",
            impact="Enables convincing phishing and can be chained into OAuth token theft.",
            remediation="Redirect only to a server-side allowlist of paths; reject "
                        "absolute URLs to external hosts.",
            evidence=Evidence(request=point.label() + f" payload={evil}",
                              response=f"HTTP {resp.status_code}\nLocation: {loc}",
                              matched=evil),
            confidence="firm")]
    return []


# ---- path traversal ----------------------------------------------------
_TRAVERSAL = "../../../../etc/passwd"
_PASSWD_RX = re.compile(r"root:.*:0:0:")


def check_path_traversal(client: HttpClient, point: InjectionPoint) -> list[Finding]:
    resp = send(client, point, _TRAVERSAL)
    if resp is None or not resp.text:
        return []
    m = _PASSWD_RX.search(resp.text)
    if m:
        return [Finding(
            title="Path Traversal / Local File Inclusion",
            severity=Severity.HIGH, kind="path-traversal",
            url=point.url, param=point.param, payload=_TRAVERSAL,
            description=f"The parameter {point.param!r} allows reading files outside the "
                        "web root using directory traversal sequences.",
            impact="Disclosure of arbitrary server files, including credentials and "
                   "source code; may escalate to code execution.",
            remediation="Resolve and canonicalize paths, then confirm they stay within an "
                        "allowed base directory. Prefer opaque identifiers over file paths.",
            evidence=Evidence(request=point.label() + f" payload={_TRAVERSAL}",
                              response=_excerpt(resp.text, "root:"), matched=m.group(0)),
            confidence="firm")]
    return []


ALL_PARAM_CHECKS = [check_xss, check_sqli, check_open_redirect, check_path_traversal]


def _excerpt(body: str, needle: str, width: int = 120) -> str:
    i = body.find(needle)
    if i < 0:
        return body[:width]
    start = max(0, i - width // 2)
    return body[start:start + width]
