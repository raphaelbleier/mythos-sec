"""IDOR / BOLA heuristic check.

Broken object-level authorization is context-dependent and cannot be proven by
a scanner alone, so this check is deliberately conservative and reports with
low confidence. It flags an endpoint where changing a numeric object reference
returns a different, non-empty object while unauthenticated — a strong lead the
exploiter (or a human) should confirm against the app's authorization model.
"""

from __future__ import annotations

import re

from ..findings import Finding, Evidence, Severity
from ..http_client import HttpClient
from .common import InjectionPoint, send

_ID_PARAM = re.compile(r"(^id$|_id$|uid|user|account|acct|order|invoice|doc|"
                       r"file|object|num|ref|customer|profile)", re.I)
# anti-CSRF / session tokens are not object references — never flag them as IDOR
_TOKEN_PARAM = re.compile(r"(token|csrf|nonce|xsrf|captcha|_wpnonce|authenticity)", re.I)


# auth/registration endpoints are not object references
_AUTH_PATH = re.compile(r"(register|signup|sign-up|login|signin|sign-in|logout|"
                        r"create|auth|token|session)", re.I)


def check_idor(client: HttpClient, point: InjectionPoint) -> list[Finding]:
    if _TOKEN_PARAM.search(point.param):
        return []
    if _AUTH_PATH.search(point.url):
        return []
    if not _ID_PARAM.search(point.param):
        return []
    base_val = point.base_params.get(point.param, "1")
    # pick two concrete integer references to compare
    try:
        n = int(re.sub(r"\D", "", base_val) or "1")
    except ValueError:
        n = 1
    a, b = str(n), str(n + 1)

    ra = send(client, point, a)
    rb = send(client, point, b)
    if ra is None or rb is None:
        return []
    if ra.status_code != 200 or rb.status_code != 200:
        return []
    ba, bb = (ra.text or ""), (rb.text or "")
    if not ba or not bb or ba == bb:
        return []
    # both references return distinct, substantial objects without auth
    if len(ba) < 8 or len(bb) < 8:
        return []
    if abs(len(ba) - len(bb)) > max(len(ba), len(bb)):
        return []  # wildly different sizes -> likely not the same object type
    return [Finding(
        title="Potential IDOR / Broken Object Level Authorization",
        severity=Severity.MEDIUM, kind="idor",
        url=point.url, param=point.param, payload=f"{point.param}={a} vs {b}",
        description=f"Changing {point.param!r} from {a} to {b} returns a different object "
                    "while unauthenticated. If these objects belong to different users, "
                    "this is an authorization flaw.",
        impact="An attacker can read or modify other users' objects by changing an id.",
        remediation="Enforce per-object authorization on every request; scope queries to "
                    "the authenticated principal; use unguessable identifiers.",
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        evidence=Evidence(request=point.label() + f" ({point.param}={a} then {b})",
                          response=f"len({a})={len(ba)} vs len({b})={len(bb)}",
                          matched="distinct objects for sequential ids"),
        confidence="tentative")]
