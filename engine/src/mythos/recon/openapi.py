"""OpenAPI / Swagger spec import.

Link-crawling cannot discover a pure JSON API's endpoints (they are not
referenced from any HTML or JS). The standard way to test an API is from its
spec: this probes the common spec locations, parses the paths, substitutes a
test value for path templates, and returns concrete endpoints with their query
parameters so the scan phase has a real surface to work on.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..http_client import HttpClient

SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs",
    "/v3/api-docs", "/swagger/v1/swagger.json", "/openapi", "/api/openapi.json",
    # springdoc under a service base path (e.g. crAPI identity)
    "/identity/v3/api-docs", "/identity/api-docs", "/api/v3/api-docs",
]
_TEMPLATE = re.compile(r"\{[^}]+\}")


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def fetch_spec(client: HttpClient, target: str) -> dict | None:
    base = _origin(target)
    for p in SPEC_PATHS:
        try:
            r = client.get(urljoin(base, p))
        except Exception:
            continue
        if r is None or r.status_code != 200:
            continue
        try:
            spec = r.json()
        except Exception:
            continue
        if isinstance(spec, dict) and spec.get("paths"):
            return spec
    return None


def _body_params(op: dict) -> list[str]:
    """Extract JSON request-body property names (OpenAPI3 requestBody or
    Swagger2 in:body parameter schema)."""
    names: set[str] = set()
    # OpenAPI 3: requestBody.content[*].schema.properties
    rb = op.get("requestBody")
    if isinstance(rb, dict):
        for media in (rb.get("content") or {}).values():
            schema = (media or {}).get("schema") or {}
            names.update((schema.get("properties") or {}).keys())
    # Swagger 2: parameters with in:body -> schema.properties
    for pm in op.get("parameters") or []:
        if isinstance(pm, dict) and pm.get("in") == "body":
            schema = pm.get("schema") or {}
            names.update((schema.get("properties") or {}).keys())
    return sorted(n for n in names if isinstance(n, str))


def parse_spec(spec: dict, base: str) -> list[dict]:
    """Return [{url, method, query_params, body_params}] from a spec."""
    origin = _origin(base)
    base_path = (spec.get("basePath") or "").rstrip("/")  # swagger 2
    out: list[dict] = []
    for path, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        concrete = _TEMPLATE.sub("1", path)               # /users/v1/{u} -> /users/v1/1
        full = urljoin(origin, (base_path + "/" + concrete.lstrip("/")).replace("//", "/")
                       if base_path else concrete)
        path_level_params = methods.get("parameters") or []
        for method, op in methods.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch"):
                continue
            if not isinstance(op, dict):
                op = {}
            params = list(path_level_params) + (op.get("parameters") or [])
            qp = sorted({pm["name"] for pm in params
                         if isinstance(pm, dict) and pm.get("in") == "query" and pm.get("name")})
            pp = sorted({pm["name"] for pm in params
                         if isinstance(pm, dict) and pm.get("in") == "path" and pm.get("name")})
            # also catch {templates} present in the path but not declared as params
            pp = sorted(set(pp) | {m.strip("{}") for m in _TEMPLATE.findall(path)})
            tmpl = urljoin(origin, (base_path + "/" + path.lstrip("/")).replace("//", "/")
                           if base_path else path)
            out.append({"url": full, "method": method.upper(),
                        "query_params": qp, "body_params": _body_params(op),
                        "path_params": pp, "path_template": tmpl})
    return out


def import_endpoints(client: HttpClient, target: str) -> list[dict]:
    spec = fetch_spec(client, target)
    if not spec:
        return []
    return parse_spec(spec, target)
