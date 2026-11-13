# Framework: Next.js and React Server Components

**Class:** framework / server-side  **Updated:** 2026-11-13

## What it is
Next.js apps put auth in `middleware`, route handlers and Server Actions, and stream React
Server Components over the Flight protocol (`text/x-component`). Two verified bug families:
internal-header trust in middleware (CVE-2025-29927) and unsafe deserialization of Flight payloads
(CVE-2025-55182, "React2Shell"). Version fingerprint decides which probes are worth sending.

## How Mythos detects it
Fingerprints below are framework behaviour seen in practice, not taken from a cited source.
- `x-powered-by: Next.js` (often stripped), `/_next/static/...` and `/_next/data/<buildId>/`,
  `<script id="__NEXT_DATA__">` (Pages Router, carries `buildId`, `props`), `self.__next_f.push`
  chunks (App Router), `Vary: RSC, Next-Router-State-Tree`, `/_next/image?url=`.
- RSC on: a request with header `RSC: 1` returns `Content-Type: text/x-component`. A Server Action
  endpoint accepts `POST` with a `Next-Action: <id>` header (ids are in the client chunks).
- Version: `/_next/static/chunks/*` filenames, `_buildManifest.js`, or the framework's version in
  the bundle; report as a range, not a guess. Build ID is not a version.
- Note: the `/_next/image` route is an SSRF sink when `remotePatterns` is too wide: see `ssrf.md`.

## Version to CVE (only entries checked against a primary advisory)
| CVE | what | affected | fixed | disclosed |
|---|---|---|---|---|
| CVE-2025-29927 | middleware skipped via `x-middleware-subrequest` | `next` 11.1.4 to <12.3.5, 13.0.0 to <13.5.9, 14.0 to <14.2.25, 15.0 to <15.2.3 | 12.3.5, 13.5.9, 14.2.25, 15.2.3 (no patch listed for 11.x; workaround: block the header) | 2025-03-21 (GHSA-f82v-jwr5-mffw) |
| CVE-2025-55182 | unauthenticated RCE, Flight deserialization, CVSS 10.0 | `react-server-dom-webpack`/`-parcel`/`-turbopack` 19.0, 19.1.0, 19.1.1, 19.2.0; Next.js App Router on 15.x, 16.x and 14.3.0-canary.77+ | React 19.0.1, 19.1.2, 19.2.1; Next.js per-line patch releases in the React advisory | 2025-12-03 (react.dev) |
The react.dev page lists Next.js fix numbers in two places that disagree for 15.4.x and the 15.x
canary, and it was later updated (2026-01-26) with follow-on DoS and source-exposure CVEs. Take the
Next.js fix version from `nextjs.org` security advisories at test time, not from this table.
The Next.js-specific CVE ID for React2Shell was rejected as a duplicate of CVE-2025-55182 (press
reports, not the CVE record). The PoC details of 29927 are from public write-ups, the advisory
itself only states the header and the workaround.

## How to confirm (non-destructive)
**Middleware bypass (29927).** Pick a route the app protects with middleware (`/admin`,
`/dashboard`; you see a redirect to login or a 401/403 unauthenticated). Differential, same route:
```
curl -si https://t/admin                                                   # baseline: 307/401/403
curl -si https://t/admin -H 'x-middleware-subrequest: middleware'          # Next 13/14: file is middleware.ts
curl -si https://t/admin -H 'x-middleware-subrequest: src/middleware'      # project uses src/
curl -si https://t/admin -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'  # 15.x recursion limit
```
Value forms come from public write-ups (Assetnote 2025-03-24); `pages/_middleware` is the 12.x name.
Proof = the baseline is refused, the header variant returns the protected page content that only an
authenticated principal sees, **and** the backing data is not public (an unauthenticated request to
the same page returns the same content on a route with no middleware = nothing was bypassed; try a
route known public as the negative control). Read-only GET only; never use the bypass to reach
admin write actions. If the target fixes it by stripping the header at the edge, the middleware
route on `/admin` stays refused: that is "not vulnerable", not an error.

**Flight deserialization (55182).** Do not send a code-executing payload. Allowed checks, in
order: (1) version evidence (above); (2) the app answers `RSC: 1` with `text/x-component`; (3) a
Server Action or Flight endpoint exists. For the third step a **no-op or out-of-band marker** only:
a request that, if deserialized unsafely, causes a DNS/HTTP hit to a per-test OAST name
(`<token>.<oast>`) and changes nothing on the host. The exact multipart body shape was not verified
here; build it from the vendor advisory or a vetted scanner template (check whether the pinned nuclei ships a
template; not verified) and read it before sending. Version in range alone is `candidate`; a token OAST hit
from the target's IP with the marker request, none with a control request that omits the Flight
fields, is `reproduced`. A response differential on a malformed payload (500 vs 400) is only a
candidate. Never run `id`, write files, or spawn a shell.

## What does NOT count
`x-powered-by: Next.js` or a version in range without a probe result, a 200 on `/admin` that also
returns 200 unauthenticated without the header, a redirect that the header "fixed" only because
the static page itself is public, a scanner template hit with no stored request/response, any RCE
claim without an OAST hit tied to a per-test token.

## Remediation
Upgrade to the patched Next.js and React lines; strip `x-middleware-subrequest` from external
requests at the edge as a stopgap; do not make middleware the only authorization layer (check in
the route handler or data layer); restrict `images.remotePatterns`.

## Sources
- GitHub Security Advisory GHSA-f82v-jwr5-mffw, Authorization Bypass in Next.js Middleware (2025-03-21)
- Assetnote / Searchlight Cyber, analysis of CVE-2025-29927 (2025-03-24)
- React blog, Critical Security Vulnerability in React Server Components (2025-12-03, updated 2026-01-26)
- Related: `gateway-bypass.md` (internal-header trust), `headers-cors.md`, `ssrf.md`, `skills/stored-xss-oast/SKILL.md` (OAST token practice)
