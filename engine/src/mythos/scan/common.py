"""Shared scan primitives: injection points and baseline requests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

from ..http_client import HttpClient
from ..recon.crawl import CrawlResult


@dataclass
class InjectionPoint:
    """A single place a payload can be injected: one parameter of one request."""
    method: str              # GET | POST
    url: str                 # base url (query stripped for the injected param)
    param: str
    base_params: dict[str, str] = field(default_factory=dict)  # other params held constant
    where: str = "query"     # query | body

    def build(self, value: str) -> tuple[str, dict]:
        """Return (url, kwargs) for a request with ``param`` set to ``value``."""
        params = dict(self.base_params)
        params[self.param] = value
        if self.where == "query":
            parsed = urlparse(self.url)
            query = urlencode(params, doseq=True)
            url = urlunparse(parsed._replace(query=query))
            return url, {}
        if self.where == "json":
            return self.url, {"json": params}
        return self.url, {"data": params}

    def label(self) -> str:
        return f"{self.method} {self.url} [{self.where}:{self.param}]"


def points_from_crawl(crawl: CrawlResult) -> list[InjectionPoint]:
    """Derive injection points from discovered endpoints and forms."""
    points: list[InjectionPoint] = []
    seen: set[tuple] = set()

    for ep in crawl.endpoints.values():
        parsed = urlparse(ep.url)
        base = urlunparse(parsed._replace(query=""))
        existing = dict(parse_qsl(parsed.query))
        names = ep.params or list(existing.keys())
        for name in names:
            key = ("GET", base, name)
            if key in seen:
                continue
            seen.add(key)
            others = {k: v for k, v in existing.items() if k != name}
            points.append(InjectionPoint(
                method="GET", url=base, param=name, base_params=others, where="query"))

    for form in crawl.forms:
        base = form.action
        held = {i["name"]: (i.get("value") or "test") for i in form.inputs if i.get("name")}
        where = "query" if form.method == "GET" else "body"
        for name in form.param_names():
            key = (form.method, base, name)
            if key in seen:
                continue
            seen.add(key)
            others = {k: v for k, v in held.items() if k != name}
            points.append(InjectionPoint(
                method=form.method, url=base, param=name,
                base_params=others, where=where))
    return points


def send(client: HttpClient, point: InjectionPoint, value: str, **extra):
    url, kwargs = point.build(value)
    kwargs.update(extra)
    return client.request(point.method, url, **kwargs)
