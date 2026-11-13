# Gateway and Edge Bypass (edge vs origin differential)

**Class:** server-side / infrastructure  **Updated:** 2026-11-13

## What it is
A CDN, WAF, API gateway or reverse proxy enforces auth, routing or blocking,
and the origin trusts that the edge did so. If the two parse the request
differently, a request the edge allows reaches a route the edge meant to
block, or the origin trusts a header the edge should have stripped. Generic
mechanism and probes in `knowledge/techniques/parser-differentials.md`; this
note is the access-control view. Framework-specific case: Next.js
`x-middleware-subrequest` in `knowledge/web/framework-nextjs-rsc.md`.

## How Mythos detects it
- Find a route that returns 401/403/404 at the edge but that the origin
  serves (admin, actuator, internal API, `/api/internal/`, metrics). Edge
  fingerprint: `Server`, `Via`, `X-Cache`, `CF-Ray`, `X-Amz-Cf-Id`, error
  page style. Compare with a request that bypasses the edge only if the origin
  is in scope and reachable by name (never by scanning for origin IPs of an
  unlisted host).
- Collect the protected-route list from recon and the OpenAPI document.

## How to confirm (non-destructive)
Pairs, always the protected URL P and a control URL C that is public. Read
only; one request per variant, with a cache buster.

```
GET /admin                  -> 403 (edge rule)         baseline
GET /admin/                 GET //admin   GET /./admin   GET /admin%2f
GET /%61dmin                GET /admin;x=1             GET /admin%00 (framework dependent)
GET /public/..;/admin       GET /public/%2e%2e/admin   GET /public/%252e%252e/admin
GET /admin.                 (trailing dot in path)     GET /admin HTTP/1.1 with Host: x.example.
GET /anything + X-Original-URL: /admin   (also X-Rewrite-URL)
GET /admin + X-Forwarded-For: 127.0.0.1  (also X-Real-IP, X-Forwarded-Host, Forwarded)
POST /admin + X-HTTP-Method-Override: GET  (also _method=GET, X-Method-Override)
GET /admin + Host: internal.example     (Host override, only an in-scope name)
```

Orange Tsai's "Breaking Parser Logic" (Black Hat USA 2018) documents the
class: Tomcat treats a path parameter (`;x=1`) and `/..;/` differently from
the proxy in front of it, so an ACL on the proxy sees one path and the origin
serves another. Modern equivalents appear whenever a decode, a normalization
or a path-parameter strip happens on one side only.

Oracle: not the status code alone. The origin response body for P must match
what an authorized session sees (a stable marker such as a title, an
`/admin`-only JSON key) and must differ from the edge's block page. Negative
control: the same variant against C returns C's content (the variant is
well formed), and the baseline P is still 403 with no variant. Auth enforced
only at the gateway: call the origin API with a variant that skips the
gateway route and no token; a 200 with account data (own account only, ideally
from a second request with the agent's own token to compare shape) shows the
origin does no auth of its own. Internal-header trust: a header such as
`X-User-Id`, `X-Forwarded-User`, `X-Auth-Role` or `x-middleware-*` that
changes the identity or role seen by the app is a trust boundary failure;
prove it with the agent's own account (switch to B's id only for an account
the agent created).

## Proof standard
`reproduced` = P returns the origin's protected content with the variant, 403
without, C control fine, body marker matched. `validated(proof)` = stored PoC
re-run in a fresh context. Impact must be shown with a benign read of one
marker; no state-changing method on a protected route unless it is the agent's
own object.

Does NOT count: a different status code (302/404 vs 403) on a variant; a 200
that serves the SPA shell or a generic error body; a header that is reflected
but changes nothing; an admin page that loads and then fails on its first API
call (the API is the boundary, check it).

## Remediation
Enforce authorization at the origin per request, not only at the gateway;
normalize once and route on the normalized path; strip client-supplied
`X-Forwarded-*`, `X-Original-URL` and internal headers at the edge; reject
ambiguous paths (`;`, encoded slashes, backslashes) before routing.

## Sources
- Orange Tsai, "Breaking Parser Logic: Take Your Path Normalization Off and
  Pop 0days Out", Black Hat USA 2018-08-08 and DEF CON 26.
- PortSwigger Research, "Top 10 web hacking techniques of 2025" (2026-02-05),
  #10 parser differentials.
- Not verified: nginx-specific behaviour for the `..;/` sequence; the
  `..;/` mismatch is documented for Tomcat behind a non-normalizing proxy.
