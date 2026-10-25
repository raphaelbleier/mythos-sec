"""Passive checks on a response: security headers, cookie flags, CORS.

These run on the fingerprint response and need no injection, so they are safe
to run on any target regardless of the active-scanning setting.
"""

from __future__ import annotations

from typing import Iterable

from ..findings import Finding, Evidence, Severity
from ..http_client import HttpClient


def check_security_headers(client: HttpClient, url: str) -> list[Finding]:
    resp = client.get(url)
    if resp is None:
        return []
    h = {k.lower(): v for k, v in resp.headers.items()}
    findings: list[Finding] = []

    def missing(name: str, title: str, sev: str, impact: str, fix: str):
        if name not in h:
            findings.append(Finding(
                title=title, severity=Severity(sev), kind="missing-security-header",
                url=url, param=name,
                description=f"The response from {url} does not set the {name} header.",
                impact=impact, remediation=fix,
                evidence=Evidence(request=f"GET {url}",
                                  response="(header absent)", matched=name),
                confidence="firm"))

    missing("content-security-policy", "Missing Content-Security-Policy", "low",
            "Without a CSP the impact of an injected script (XSS) is unconstrained.",
            "Deploy a restrictive Content-Security-Policy.")
    missing("strict-transport-security", "Missing HTTP Strict-Transport-Security", "low",
            "Users can be downgraded to HTTP and have traffic intercepted.",
            "Send Strict-Transport-Security with a long max-age on all HTTPS responses.")
    missing("x-frame-options", "Missing X-Frame-Options / frame-ancestors", "low",
            "The page can be framed by a third party, enabling clickjacking.",
            "Set X-Frame-Options: DENY or a CSP frame-ancestors directive.")
    missing("x-content-type-options", "Missing X-Content-Type-Options", "info",
            "Browsers may MIME-sniff responses, enabling some injection attacks.",
            "Set X-Content-Type-Options: nosniff.")
    return findings


def check_cookies(client: HttpClient, url: str) -> list[Finding]:
    """Flag session cookies set without HttpOnly / Secure / SameSite."""
    resp = client.get(url)
    if resp is None:
        return []
    findings: list[Finding] = []
    raw_cookies = (resp.raw.headers.getlist("set-cookie")
                   if hasattr(resp.raw, "headers") else
                   resp.headers.get("set-cookie", "").split("\n"))
    for raw in raw_cookies:
        if not raw or "=" not in raw:
            continue
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        problems = []
        if "httponly" not in low:
            problems.append("HttpOnly")
        if "secure" not in low and url.startswith("https"):
            problems.append("Secure")
        if "samesite" not in low:
            problems.append("SameSite")
        if problems:
            findings.append(Finding(
                title=f"Cookie {name} missing flags: {', '.join(problems)}",
                severity=Severity.LOW, kind="cookie-flags", url=url, param=name,
                description=f"Set-Cookie for {name!r} is missing: {', '.join(problems)}.",
                impact="Missing HttpOnly exposes the cookie to XSS; missing Secure allows "
                       "transmission over HTTP; missing SameSite enables CSRF.",
                remediation="Set HttpOnly, Secure and SameSite=Lax/Strict on session cookies.",
                evidence=Evidence(request=f"GET {url}", response=raw[:200], matched=name),
                confidence="firm"))
    return findings


def check_cors(client: HttpClient, url: str) -> list[Finding]:
    """Reflected-origin and wildcard-with-credentials CORS misconfiguration."""
    evil = "https://mythos-evil.example"
    resp = client.get(url, headers={"Origin": evil})
    if resp is None:
        return []
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
    findings: list[Finding] = []
    if acao == evil and acac == "true":
        findings.append(Finding(
            title="CORS misconfiguration: arbitrary origin reflected with credentials",
            severity=Severity.HIGH, kind="cors-misconfig", url=url,
            description=f"{url} reflects the request Origin in Access-Control-Allow-Origin "
                        "and allows credentials.",
            impact="A malicious site can read authenticated responses on behalf of a victim.",
            remediation="Validate Origin against an allowlist; never combine a reflected "
                        "origin with Access-Control-Allow-Credentials: true.",
            evidence=Evidence(request=f"GET {url}\nOrigin: {evil}",
                              response=f"Access-Control-Allow-Origin: {acao}\n"
                                       f"Access-Control-Allow-Credentials: {acac}",
                              matched=evil),
            confidence="firm"))
    elif acao == "*" and acac == "true":
        findings.append(Finding(
            title="CORS misconfiguration: wildcard origin with credentials",
            severity=Severity.MEDIUM, kind="cors-misconfig", url=url,
            description=f"{url} returns Access-Control-Allow-Origin: * with credentials allowed.",
            impact="Weakens the same-origin policy for authenticated requests.",
            remediation="Do not use a wildcard ACAO together with credentials.",
            evidence=Evidence(request=f"GET {url}", response=f"ACAO: *  ACAC: {acac}", matched="*"),
            confidence="firm"))
    return findings
