"""Broken Object Level Authorization (BOLA / IDOR) via two identities.

The reliable way to prove BOLA is the two-account method: if user B can read
(or act on) an object that belongs to user A, authorization is broken. A
single-session heuristic (see scan/idor.py) only raises leads; this check
*confirms* BOLA by replaying A's object request with B's credentials and
showing B receives A's object.

Inputs are two HttpClients, each authenticated as a different user (set up from
`scope.identities`). The orchestrator / exploiter drives object discovery; this
module performs the cross-access comparison and verdict.
"""

from __future__ import annotations

import difflib

from ..findings import Finding, Evidence, Severity
from ..http_client import HttpClient


def _similar(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()


def check_bola(victim: HttpClient, attacker: HttpClient, object_url: str,
               *, attacker_own_url: str | None = None) -> list[Finding]:
    """Confirm BOLA: can `attacker` read `object_url` (the victim's object)?

    object_url       — a URL that returns the VICTIM's object (victim can read it)
    attacker_own_url — optional URL of the ATTACKER's own equivalent object, used
                       to show the two objects differ (so a match on object_url is
                       genuine cross-user access, not a shared/public resource).
    """
    v = victim.get(object_url)
    if v is None or v.status_code != 200 or not (v.text or ""):
        return []
    a = attacker.get(object_url)
    if a is None or a.status_code != 200:
        return []  # attacker correctly denied -> no BOLA
    # attacker received a 200 for the victim's object; is it the victim's data?
    if _similar(v.text or "", a.text or "") < 0.9:
        return []  # different content -> not the same object, inconclusive
    # guard against public/shared objects: attacker's own object should differ
    if attacker_own_url:
        own = attacker.get(attacker_own_url)
        if own is not None and _similar(own.text or "", a.text or "") > 0.95:
            return []  # same as attacker's own -> likely a generic/public response
    return [Finding(
        title="Broken Object Level Authorization (BOLA) — confirmed cross-user access",
        severity=Severity.HIGH, kind="bola", url=object_url,
        description="A second user (attacker identity) successfully read an object that "
                    "belongs to another user (victim identity), proving missing "
                    "object-level authorization.",
        impact="Any authenticated user can read or modify other users' objects by "
               "referencing their identifiers.",
        remediation="Enforce per-object ownership checks on every request; scope every "
                    "query to the authenticated principal.",
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        evidence=Evidence(
            request=f"victim GET {object_url}\nattacker GET {object_url} (B's token)",
            response="attacker received the victim's object (content match "
                     f"{_similar(v.text, a.text):.0%})",
            matched="cross-user object read"),
        confidence="certain")]
