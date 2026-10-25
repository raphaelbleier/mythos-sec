"""Advanced vulnerability checks.

Harder bug classes beyond the headline four. These are the checks that make
Mythos useful against real applications, not just training apps:

  * SSTI (server-side template injection) — arithmetic oracle
  * OS command injection — time-based oracle
  * blind SQL injection — time-based oracle
  * CRLF / HTTP response header injection
  * SSRF — out-of-band (needs an OastListener)
  * GraphQL introspection exposure
  * JWT weaknesses — alg:none acceptance and weak HMAC secret

Time-based checks measure differential latency and are inherently noisy; they
report with confidence "tentative" and should be confirmed by the exploiter.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time

from ..findings import Finding, Evidence, Severity
from ..http_client import HttpClient
from .common import InjectionPoint, send

# ---- SSTI --------------------------------------------------------------
# Distinct primes so a product can't be confused with a reflected literal.
_SSTI_PROBES = [
    ("{{1337*1337}}", "1787569"),
    ("${1337*1337}", "1787569"),
    ("#{1337*1337}", "1787569"),
    ("<%= 1337*1337 %>", "1787569"),
]


def check_ssti(client: HttpClient, point: InjectionPoint) -> list[Finding]:
    for payload, expect in _SSTI_PROBES:
        resp = send(client, point, payload)
        if resp is None or not resp.text:
            continue
        if expect in resp.text and payload not in resp.text:
            return [Finding(
                title="Server-Side Template Injection (SSTI)",
                severity=Severity.CRITICAL, kind="ssti",
                url=point.url, param=point.param, payload=payload,
                description=f"The parameter {point.param!r} is evaluated by a server-side "
                            f"template engine: the expression {payload} rendered as {expect}.",
                impact="Template expression evaluation typically leads to remote code "
                       "execution on the server.",
                remediation="Never render user input as a template. Use a logic-less "
                            "template context and pass user data only as bound variables.",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                evidence=Evidence(request=point.label() + f" payload={payload}",
                                  response=_around(resp.text, expect), matched=expect),
                confidence="firm")]
    return []


# ---- time-based oracles ------------------------------------------------
def _timed(client: HttpClient, point: InjectionPoint, value: str) -> float | None:
    start = time.monotonic()
    resp = send(client, point, value)
    if resp is None:
        return None
    return time.monotonic() - start


def _confirm_time(client, point, payload, delay) -> bool:
    """Confirm a time-based oracle: slow payload is reliably slower than baseline."""
    base = _timed(client, point, "1")
    slow = _timed(client, point, payload)
    if base is None or slow is None:
        return False
    if slow < delay * 0.7:
        return False
    # re-test to reject jitter
    base2 = _timed(client, point, "1")
    slow2 = _timed(client, point, payload)
    return (slow2 is not None and base2 is not None
            and slow2 >= delay * 0.7 and slow2 - base2 >= delay * 0.5)


_CMD_PAYLOADS = ["; sleep 3", "| sleep 3", "`sleep 3`", "$(sleep 3)", "& sleep 3"]


def check_command_injection(client: HttpClient, point: InjectionPoint) -> list[Finding]:
    for payload in _CMD_PAYLOADS:
        if _confirm_time(client, point, "1" + payload, delay=3.0):
            return [Finding(
                title="OS Command Injection (time-based)",
                severity=Severity.CRITICAL, kind="command-injection",
                url=point.url, param=point.param, payload=payload,
                description=f"Injecting {payload!r} into {point.param!r} delays the "
                            "response, indicating the input reaches an OS shell.",
                impact="Arbitrary command execution on the server.",
                remediation="Never pass user input to a shell. Use argument arrays and "
                            "avoid shell=True; validate against a strict allowlist.",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                evidence=Evidence(request=point.label() + f" payload=1{payload}",
                                  matched="response delayed ~3s", note="time-based oracle"),
                confidence="tentative")]
    return []


_SQL_TIME = ["1' AND SLEEP(3)-- -", "1 AND SLEEP(3)", "1'; SELECT pg_sleep(3)-- -",
             "1' OR SLEEP(3)#"]


def check_blind_sqli(client: HttpClient, point: InjectionPoint) -> list[Finding]:
    for payload in _SQL_TIME:
        if _confirm_time(client, point, payload, delay=3.0):
            return [Finding(
                title="Blind SQL Injection (time-based)",
                severity=Severity.CRITICAL, kind="sqli",
                url=point.url, param=point.param, payload=payload,
                description=f"A time-based payload in {point.param!r} delays the response, "
                            "indicating SQL injection even without visible errors.",
                impact="Full database compromise via blind extraction.",
                remediation="Use parameterized queries / prepared statements.",
                evidence=Evidence(request=point.label() + f" payload={payload}",
                                  matched="response delayed ~3s", note="time-based oracle"),
                confidence="tentative")]
    return []


# ---- CRLF / header injection ------------------------------------------
def check_crlf(client: HttpClient, point: InjectionPoint) -> list[Finding]:
    marker = "mythoscrlf"
    payload = f"test%0d%0aX-Mythos-Injected:{marker}"
    # send raw (do not urlencode again) by placing in the value
    resp = send(client, point, f"test\r\nX-Mythos-Injected:{marker}")
    if resp is None:
        return []
    if resp.headers.get("X-Mythos-Injected", "") == marker:
        return [Finding(
            title="CRLF / HTTP Response Header Injection",
            severity=Severity.MEDIUM, kind="crlf-injection",
            url=point.url, param=point.param, payload=payload,
            description=f"The parameter {point.param!r} allows injecting CRLF sequences "
                        "into the response headers.",
            impact="Header injection enables response splitting, cache poisoning and "
                   "cookie fixation.",
            remediation="Strip CR/LF from any user input used in response headers.",
            evidence=Evidence(request=point.label(),
                              response=f"X-Mythos-Injected: {marker}", matched=marker),
            confidence="firm")]
    return []


# ---- SSRF (out-of-band) -----------------------------------------------
def check_ssrf(client: HttpClient, point: InjectionPoint, oast) -> list[Finding]:
    """Needs an OastListener. Confirms SSRF only on a real callback."""
    if oast is None:
        return []
    token = oast.new_token()
    payload = oast.callback_url(token)
    send(client, point, payload)
    time.sleep(1.0)  # allow the target to make the out-of-band request
    if oast.saw(token):
        hit = oast.interactions(token)[0]
        return [Finding(
            title="Server-Side Request Forgery (SSRF)",
            severity=Severity.HIGH, kind="ssrf",
            url=point.url, param=point.param, payload=payload,
            description=f"The parameter {point.param!r} caused the server to make an "
                        "out-of-band request to an attacker-controlled host.",
            impact="SSRF can reach internal services, cloud metadata endpoints and "
                   "otherwise unreachable hosts.",
            remediation="Validate and allowlist outbound URLs; block internal ranges and "
                        "the cloud metadata IP; resolve and re-check after redirects.",
            evidence=Evidence(request=point.label() + f" payload={payload}",
                              response=f"OOB callback from {hit.client} to {hit.path}",
                              matched=token),
            confidence="certain")]
    return []


# ---- GraphQL introspection --------------------------------------------
_INTROSPECTION = '{"query":"{__schema{types{name}}}"}'


def check_graphql_introspection(client: HttpClient, url: str) -> list[Finding]:
    resp = client.post(url, data=_INTROSPECTION,
                       headers={"Content-Type": "application/json"})
    if resp is None:
        return []
    try:
        data = resp.json()
    except Exception:
        return []
    if isinstance(data, dict) and data.get("data", {}).get("__schema"):
        return [Finding(
            title="GraphQL introspection enabled",
            severity=Severity.LOW, kind="graphql-introspection", url=url,
            description="The GraphQL endpoint answers introspection queries, exposing the "
                        "full schema.",
            impact="Reveals every type, query and mutation, easing further attacks.",
            remediation="Disable introspection in production.",
            evidence=Evidence(request=f"POST {url} {_INTROSPECTION}",
                              response="__schema returned", matched="__schema"),
            confidence="firm")]
    return []


# ---- JWT weaknesses ----------------------------------------------------
_WEAK_SECRETS = ["secret", "password", "123456", "changeme", "jwt", "key",
                 "admin", "test", "secretkey", "your-256-bit-secret"]


def check_jwt(token: str, url: str = "") -> list[Finding]:
    """Static analysis of a captured JWT: alg:none and weak HMAC secret."""
    parts = token.split(".")
    if len(parts) != 3:
        return []
    try:
        header = json.loads(_b64d(parts[0]))
    except Exception:
        return []
    findings = []
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        findings.append(Finding(
            title="JWT accepts 'alg: none'", severity=Severity.HIGH, kind="jwt-alg-none",
            url=url, description="The JWT header uses alg:none, meaning the signature is "
            "not verified.",
            impact="Tokens can be forged with arbitrary claims (authentication bypass).",
            remediation="Reject alg:none; pin the expected algorithm server-side.",
            evidence=Evidence(matched="alg:none", note=parts[0]), confidence="firm"))
    if alg == "hs256":
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        sig = _b64d_raw(parts[2])
        for secret in _WEAK_SECRETS:
            expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            if hmac.compare_digest(expected, sig):
                findings.append(Finding(
                    title=f"JWT signed with weak secret ({secret!r})",
                    severity=Severity.HIGH, kind="jwt-weak-secret", url=url,
                    description="The HS256 JWT is signed with a trivially guessable secret.",
                    impact="The secret lets an attacker forge valid tokens for any user.",
                    remediation="Use a long, random, high-entropy signing key from a secret "
                                "manager; rotate it.",
                    evidence=Evidence(matched=f"secret={secret}"), confidence="certain"))
                break
    return findings


def _b64d(seg: str) -> bytes:
    return _b64d_raw(seg)


def _b64d_raw(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


# checks that operate on a single parameter injection point
PARAM_CHECKS_ADVANCED = [check_ssti, check_crlf, check_command_injection, check_blind_sqli]


def _around(body: str, needle: str, width: int = 120) -> str:
    i = body.find(needle)
    if i < 0:
        return body[:width]
    return body[max(0, i - width // 2): i + width // 2]
