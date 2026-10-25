"""Scope-aware HTTP client.

A thin wrapper over requests.Session that:
  * refuses to touch hosts outside the engagement scope (hard enforcement at
    the engine layer, independent of the Claude Code warn-only hook),
  * enforces a request budget and a requests-per-second ceiling,
  * records every request/response pair as evidence,
  * supports an upstream proxy (e.g. Burp) and custom headers.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .scope import Scope

DEFAULT_UA = "mythos-sec/0.1 (+authorized-security-testing)"


class ScopeViolation(Exception):
    """Raised when a request would leave the engagement scope."""


class BudgetExceeded(Exception):
    """Raised when the engagement request budget is exhausted."""


@dataclass
class Transaction:
    method: str
    url: str
    status: Optional[int]
    req_headers: dict[str, str]
    req_body: Optional[str]
    resp_headers: dict[str, str]
    resp_body: str
    elapsed_ms: float
    error: Optional[str] = None


@dataclass
class HttpClient:
    scope: Scope
    proxy: Optional[str] = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 15.0
    verify_tls: bool = False
    _session: requests.Session = field(init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _count: int = field(default=0, init=False)
    _last_ts: float = field(default=0.0, init=False)
    transactions: list[Transaction] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        s = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3,
                      status_forcelist=(502, 503, 504), allowed_methods=None)
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.headers.update({"User-Agent": DEFAULT_UA, "Accept": "*/*"})
        s.headers.update(self.extra_headers)
        if self.proxy:
            s.proxies.update({"http": self.proxy, "https": self.proxy})
        self._session = s
        if not self.verify_tls:
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    @property
    def request_count(self) -> int:
        return self._count

    def _throttle(self) -> None:
        rps = max(self.scope.rules.rate_limit_rps, 0.1)
        min_gap = 1.0 / rps
        with self._lock:
            now = time.monotonic()
            wait = self._last_ts + min_gap - now
            if wait > 0:
                time.sleep(wait)
            self._last_ts = time.monotonic()

    def request(self, method: str, url: str, *, allow_redirects: bool = True,
                **kwargs: Any) -> Optional[requests.Response]:
        if not self.scope.contains(url):
            raise ScopeViolation(self.scope.reason(url))
        if self._count >= self.scope.rules.max_requests:
            raise BudgetExceeded(
                f"request budget {self.scope.rules.max_requests} reached")
        self._throttle()
        self._count += 1
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_tls)
        start = time.monotonic()
        body = kwargs.get("data") or kwargs.get("json")
        try:
            resp = self._session.request(method, url,
                                         allow_redirects=allow_redirects, **kwargs)
        except requests.RequestException as exc:
            self.transactions.append(Transaction(
                method=method.upper(), url=url, status=None,
                req_headers=dict(self._session.headers), req_body=_str(body),
                resp_headers={}, resp_body="",
                elapsed_ms=(time.monotonic() - start) * 1000, error=str(exc)))
            return None
        elapsed = (time.monotonic() - start) * 1000
        self.transactions.append(Transaction(
            method=method.upper(), url=resp.url, status=resp.status_code,
            req_headers=dict(resp.request.headers), req_body=_str(body),
            resp_headers=dict(resp.headers), resp_body=_safe_text(resp),
            elapsed_ms=elapsed))
        return resp

    def get(self, url: str, **kw: Any) -> Optional[requests.Response]:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> Optional[requests.Response]:
        return self.request("POST", url, **kw)

    def head(self, url: str, **kw: Any) -> Optional[requests.Response]:
        return self.request("HEAD", url, allow_redirects=False, **kw)


def _str(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        return v.decode("utf-8", "replace")
    return str(v)


def _safe_text(resp: requests.Response, limit: int = 2_000_000) -> str:
    try:
        text = resp.text
    except Exception:
        return ""
    return text[:limit]
