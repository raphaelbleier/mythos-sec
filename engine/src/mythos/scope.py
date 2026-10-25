"""Engagement scope model and enforcement.

The scope is the authorization boundary of an engagement. Every request the
engine makes is checked against it. A target is in scope when its host matches
an in-scope pattern AND does not match any out-of-scope pattern.

Scope is loaded from ``scope.yaml`` in the engagement directory. Example:

    target: https://example.com
    in_scope:
      - "*.example.com"
      - "example.com"
      - "203.0.113.0/24"
    out_of_scope:
      - "admin.example.com"
      - "*.internal.example.com"
    rules:
      rate_limit_rps: 5
      max_requests: 20000
      allow_active: true          # active scanning permitted
      allow_exploit: false        # proof-of-concept exploitation permitted
    program: "Example BBP"
    notes: "No DoS. No automated scanning of login forms."
"""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


@dataclass
class ScopeRules:
    rate_limit_rps: float = 5.0
    max_requests: int = 20000
    allow_active: bool = True
    allow_exploit: bool = False

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ScopeRules":
        d = d or {}
        return cls(
            rate_limit_rps=float(d.get("rate_limit_rps", 5.0)),
            max_requests=int(d.get("max_requests", 20000)),
            allow_active=bool(d.get("allow_active", True)),
            allow_exploit=bool(d.get("allow_exploit", False)),
        )


@dataclass
class Auth:
    """Authenticated-scanning credentials, applied to every in-scope request."""
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    bearer: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Auth":
        d = d or {}
        return cls(
            cookies={str(k): str(v) for k, v in (d.get("cookies") or {}).items()},
            headers={str(k): str(v) for k, v in (d.get("headers") or {}).items()},
            bearer=str(d.get("bearer", "")),
        )

    def active(self) -> bool:
        return bool(self.cookies or self.headers or self.bearer)


@dataclass
class Scope:
    target: str = ""
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    rules: ScopeRules = field(default_factory=ScopeRules)
    auth: Auth = field(default_factory=Auth)
    # operator-supplied known API endpoints (realistic for bounty: you know the
    # API). Paths or full URLs; added to the crawl surface and scanned.
    seed_endpoints: list[str] = field(default_factory=list)
    # extra identities (second+ user) for two-account BOLA/authorization testing
    identities: list[Auth] = field(default_factory=list)
    program: str = ""
    notes: str = ""

    # ---- loading -------------------------------------------------------
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Scope":
        idents = []
        for x in d.get("identities") or []:
            idents.append(Auth.from_dict(x.get("auth") if isinstance(x, dict) and "auth" in x else x))
        return cls(
            target=str(d.get("target", "")),
            in_scope=[str(x) for x in (d.get("in_scope") or [])],
            out_of_scope=[str(x) for x in (d.get("out_of_scope") or [])],
            rules=ScopeRules.from_dict(d.get("rules") or {}),
            auth=Auth.from_dict(d.get("auth") or {}),
            seed_endpoints=[str(x) for x in (d.get("seed_endpoints") or [])],
            identities=idents,
            program=str(d.get("program", "")),
            notes=str(d.get("notes", "")),
        )

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        path = Path(path)
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        scope = cls.from_dict(data)
        if not scope.in_scope and scope.target:
            # Derive a minimal in-scope entry from the target host.
            host = urlparse(scope.target).hostname
            if host:
                scope.in_scope = [host]
        return scope

    # ---- matching ------------------------------------------------------
    @staticmethod
    def _host_of(target: str) -> str:
        if "://" in target:
            return urlparse(target).hostname or ""
        # bare host[:port] or host/path
        netloc = target.split("/")[0]
        return netloc.split(":")[0]

    @staticmethod
    def _match_one(host: str, pattern: str) -> bool:
        host = host.strip().lower()
        pattern = pattern.strip().lower()
        if not host or not pattern:
            return False
        # CIDR / IP match
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            try:
                return ipaddress.ip_address(host) in net
            except ValueError:
                return False
        except ValueError:
            pass
        # glob / exact host match
        if fnmatch.fnmatch(host, pattern):
            return True
        # bare "example.com" should also cover the apex itself
        return host == pattern

    def contains(self, target: str) -> bool:
        """True if ``target`` (url or host) is authorized by this scope."""
        host = self._host_of(target)
        if not host:
            return False
        if any(self._match_one(host, p) for p in self.out_of_scope):
            return False
        return any(self._match_one(host, p) for p in self.in_scope)

    def reason(self, target: str) -> str:
        """Human-readable explanation of an in/out-of-scope decision."""
        host = self._host_of(target)
        if not host:
            return f"could not parse a host from {target!r}"
        for p in self.out_of_scope:
            if self._match_one(host, p):
                return f"{host} matches OUT-OF-SCOPE pattern {p!r}"
        for p in self.in_scope:
            if self._match_one(host, p):
                return f"{host} matches in-scope pattern {p!r}"
        return f"{host} matches no in-scope pattern"


DEFAULT_SCOPE_YAML = """\
# Mythos engagement scope. This file is the authorization boundary.
# Only hosts listed under in_scope (and not under out_of_scope) will be touched.
target: "{target}"

in_scope:
  - "{host}"

out_of_scope: []

rules:
  rate_limit_rps: 5        # requests per second ceiling
  max_requests: 20000      # hard request budget for the engagement
  allow_active: true       # permit active scanning (fuzzing, injection probes)
  allow_exploit: false     # permit proof-of-concept exploitation

program: ""                # bug-bounty program / client name
notes: ""                  # program rules, e.g. "no DoS, no login fuzzing"
"""


def default_scope_yaml(target: str) -> str:
    host = Scope._host_of(target) or target
    return DEFAULT_SCOPE_YAML.format(target=target, host=host)
