"""API-specific checks.

check_sensitive_api_response: flags a JSON endpoint that returns sensitive
fields (passwords, tokens, secrets, private keys) to an unauthenticated or
low-privilege caller — e.g. a debug endpoint dumping every user's credentials.
This is the kind of broken-access / excessive-data-exposure issue that matters
on real APIs and that a header/injection scan never surfaces.
"""

from __future__ import annotations

import re

from ..findings import Finding, Evidence, Severity
from ..http_client import HttpClient

_KEYS = (r'password|passwd|pwd|secret|api[_-]?key|token|private[_-]?key|'
         r'access[_-]?token|client[_-]?secret|ssn|credit[_-]?card')
_SENSITIVE_KEY = re.compile(r'"(' + _KEYS + r')"\s*:', re.I)
# key + value, to redact the value (string, number, bool or null)
_SENSITIVE_KV = re.compile(
    r'("(?:' + _KEYS + r')"\s*:\s*)("[^"]*"|true|false|null|-?\d+(?:\.\d+)?)', re.I)


def check_sensitive_api_response(client: HttpClient, url: str) -> list[Finding]:
    resp = client.get(url)
    if resp is None or resp.status_code != 200:
        return []
    ctype = resp.headers.get("content-type", "")
    body = resp.text or ""
    if "json" not in ctype and not body.lstrip().startswith(("{", "[")):
        return []
    hits = _SENSITIVE_KEY.findall(body)
    if len(hits) < 1:
        return []
    kinds = sorted({h.lower() for h in hits})
    # many hits (e.g. a dump of every user's password) is clearly a leak
    severity = Severity.HIGH if len(hits) >= 3 else Severity.MEDIUM
    return [Finding(
        title="Sensitive data exposure in API response",
        severity=severity, kind="sensitive-exposure", url=url,
        description=f"The endpoint returns JSON containing sensitive fields "
                    f"({', '.join(kinds)}) to the caller.",
        impact="Credentials, tokens or secrets are disclosed, enabling account "
               "takeover or lateral movement.",
        remediation="Never return secret fields in API responses; scope data to the "
                    "authenticated principal; remove debug/dump endpoints from production.",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        evidence=Evidence(request=f"GET {url}",
                          response=_redact(body)[:400],
                          matched=f"{len(hits)} sensitive field(s): {', '.join(kinds)}"),
        confidence="firm")]


def _redact(body: str) -> str:
    # show the shape without printing the actual secret values
    return _SENSITIVE_KV.sub(r'\1"***"', body)
