"""Finding model: the unit of output for the engine.

A Finding is deduplicated, carries a severity and an optional CVSS 3.1 vector,
and holds the evidence (request/response, matched string) needed to reproduce
it. Findings render to bug-bounty Markdown via mythos.report.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


# CVSS 3.1 base vectors for the common web classes (used when the check does
# not compute a per-instance vector). These are conservative defaults.
DEFAULT_CVSS: dict[str, str] = {
    "reflected-xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "stored-xss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
    "sqli": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "open-redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
    "path-traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "ssrf": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
    "cors-misconfig": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    "sensitive-exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "missing-security-header": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "cookie-flags": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
}


@dataclass
class Evidence:
    request: str = ""
    response: str = ""
    matched: str = ""
    note: str = ""


@dataclass
class Finding:
    title: str
    severity: Severity
    kind: str                      # stable slug, e.g. "reflected-xss"
    url: str
    description: str = ""
    param: str = ""
    payload: str = ""
    cvss: str = ""
    impact: str = ""
    remediation: str = ""
    confidence: str = "firm"       # firm | tentative | certain
    # closure state (Strix-style): candidate until proven; confirmed needs a PoC;
    # ruled_out names the control that stops it; open_proof_gap = unverified.
    status: str = "candidate"      # candidate | confirmed | ruled_out | open_proof_gap
    evidence: Evidence = field(default_factory=Evidence)
    source: str = "mythos-engine"  # or "nuclei", "sqlmap", ...
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        if not self.cvss:
            self.cvss = DEFAULT_CVSS.get(self.kind, "")
        # a certain finding with evidence is already confirmed
        if self.status == "candidate" and self.confidence == "certain" \
                and (self.evidence.request or self.evidence.matched):
            self.status = "confirmed"

    @property
    def has_poc(self) -> bool:
        return bool(self.payload or self.evidence.matched or self.evidence.request)

    # host-level issues: the same cookie/header is one issue per host, not per path
    _HOST_LEVEL = {"cookie-flags", "missing-security-header", "cors-misconfig"}

    @property
    def dedup_key(self) -> str:
        path = "" if self.kind in self._HOST_LEVEL else _path(self.url)
        raw = f"{self.kind}|{_host(self.url)}|{path}|{self.param}"
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["dedup_key"] = self.dedup_key
        return d


class FindingStore:
    """Collects findings, dropping duplicates by dedup_key."""

    def __init__(self) -> None:
        self._by_key: dict[str, Finding] = {}

    def add(self, finding: Finding) -> bool:
        key = finding.dedup_key
        if key in self._by_key:
            # keep the higher-severity / higher-confidence instance
            existing = self._by_key[key]
            if finding.severity.rank > existing.severity.rank:
                self._by_key[key] = finding
            return False
        self._by_key[key] = finding
        return True

    def extend(self, findings) -> None:
        for f in findings:
            if f:
                self.add(f)

    @property
    def findings(self) -> list[Finding]:
        return sorted(self._by_key.values(),
                      key=lambda f: (-f.severity.rank, f.kind, f.url))

    def __len__(self) -> int:
        return len(self._by_key)

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self._by_key.values():
            out[f.severity.value] += 1
        return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or ""


def _path(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).path or "/"
