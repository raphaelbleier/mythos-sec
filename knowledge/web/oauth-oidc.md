# OAuth 2.0 / OpenID Connect flows

**Class:** authentication  **Updated:** 2026-11-13

## What it is
The authorization server (AS) or the client (the app that offers "log in with
X") accepts a flow step it should refuse, so an authorization code or token
reaches the wrong party or is bound to the wrong user. Bugs sit in the
`redirect_uri` check, `state`/`nonce` binding, code redemption, PKCE
enforcement, issuer and audience checks, and the optional endpoints (dynamic
registration, device code, magic links). Token internals are in `jwt.md`.

## Setup: own client, own accounts, own OAST host
- Two test accounts (`userA`, `userB`) from `auth-session`, at the app and at
  the IdP if it is separate. The code or token that leaks in every test below
  is the one issued to a test account; never to a real user.
- An OAST host (interactsh `*.oast.*`, lab `http://oast:8080/<token>`). Mint
  one token per check so a late hit maps to one request.
- Drive the browser parts with the `mythos-browser` agent. To capture a
  callback without the client consuming it, abort the navigation to the
  callback URL in Playwright (`page.route`) and record the URL. Redeem codes
  with curl.
- If you may register your own client, use it for the AS checks. Otherwise test
  the app's own public client with your own login.

## Flow map (do this first)
From one recorded login, note and write down: `response_type` (`code`, or
implicit/hybrid `token`, `id_token`), `client_id`, `redirect_uri`, `scope`,
`state`, `nonce`, `code_challenge` + method, `response_mode`, the token
endpoint and its client auth, and where `state` is kept (cookie, session,
`localStorage`). Fetch `/.well-known/openid-configuration` and RFC 8414
metadata: `code_challenge_methods_supported`,
`authorization_response_iss_parameter_supported`, `registration_endpoint`,
`device_authorization_endpoint`, `response_modes_supported`.
Implicit and hybrid flows put tokens in the URL fragment: a candidate in
itself (RFC 9700 says do not use them).

## redirect_uri mutations
Registered value `https://app.example/cb`, attacker host `A` = your OAST host.
Send each in the authorization request as `userA`; baseline is the exact value.

| mutation | example |
|---|---|
| other path, same host | `https://app.example/other` |
| path suffix / traversal | `/cb/x`, `/cb/../x`, `/cb%2f..%2fx`, `/cb;x` |
| query or fragment appended | `/cb?x=1`, `/cb%23x` |
| subdomain or lookalike | `https://x.app.example/cb`, `https://app.example.A/cb` |
| userinfo / authority tricks | `https://app.example@A/cb`, `https://A%23@app.example/cb`, `https://A\@app.example/cb` |
| scheme, port, case, trailing dot | `http://`, `:8443`, `APP.example.` |
| parameter pollution | two `redirect_uri=` values (validator and redirector may pick different ones) |
| loopback | `http://localhost/cb`, `http://127.0.0.1:1/cb` (native-app allowance, RFC 8252) |
| open-redirect chain | `https://app.example/redir?next=https://A/` (registered host with a redirect, XSS or postMessage sink) |

**Oracle.** First order: the AS answers `302` with `Location` pointing at the
mutated URI, not an error page (`candidate`). Proof: the browser follows it and
the code or token arrives at your OAST host, in the query, the fragment
(open-redirect chain: it surfaces via `Referer` or a script) or the `Referer`
header. Negative control: an unrelated host (`https://A/cb` outright) is
refused by the same AS. One accepted mutation is enough; stop there.

## Checks
1. **State not enforced or not bound (login CSRF).** As `userA`, start a flow
   and stop at the callback; keep the callback URL (unused code). In a second
   context logged in as `userB` (or logged out), open it. Proof: the second
   context is now signed in as `userA`, or `userB`'s account gains `userA`'s IdP
   identity. Controls: callback with `state` removed or altered is rejected;
   the same callback in the originating context works. Also drop `state` from
   the authorization request: the AS and client should refuse or the client
   must still verify its own binding.
2. **Code reuse and binding.** Redeem one code twice; redeem it with a
   different `redirect_uri` or `client_id`. Each second success is a finding
   (RFC 6749 4.1.2, 4.1.3: single use, bound to client and redirect).
   Proof is `200` with tokens on the second call; control is the first call
   plus a code with one character changed returning `invalid_grant`.
3. **PKCE absent or downgraded.** Authorize with `code_challenge`, redeem
   with no `code_verifier` and with a wrong one. `200` = verifier not
   enforced. Authorize with no `code_challenge` at all, or
   `code_challenge_method=plain`: if the AS issues a code and redeems it, a
   client that sent S256 can be downgraded. Control: correct verifier works,
   wrong one returns `invalid_grant`.
4. **Mix-up (missing `iss`).** PKCE does not stop mix-up (RFC 9700,
   RFC 9207). Applies only if the client supports more than one AS. Check
   that the AS returns `iss` in the authorization response and that the
   client rejects a callback whose `iss` is another issuer. Full proof needs
   a second AS you run yourself; without it, report `candidate` with the
   metadata evidence and say what is missing.
5. **Cross-client acceptance.** Mint an ID token or access token for a second
   client you registered at the same IdP (your own account) and present it
   to the app's login or API. Accepted = `aud`/`azp` not checked, so any
   third-party client can replay a token it received. For ID tokens also
   check `nonce` replay: reuse an old `nonce`/ID token.
6. **Identity binding.** Log in with an IdP account whose email is `userB`'s
   address but unverified (an IdP you can create accounts on). Accepted login
   as `userB` = app trusts `email` without `email_verified`, or keys on email
   instead of `sub` (nOAuth class, Descope 2023-06). Own accounts only.
7. **Scope and audience.** Request `scope` beyond the registered or consented
   set (`admin`, `offline_access`), and widen `scope` at refresh. Proof is the
   issued token's scope claim (or introspection) plus an API call that needs it.
   Check `resource`/`aud` (RFC 8707): a token for API 1 accepted by API 2.
8. **response_mode and type switching.** Change `response_type` to `token` or
   `id_token` and `response_mode` to `query`: tokens in a query string leak
   through `Referer`, logs and history. Check which modes the AS honours that
   the client never uses. Include error branches: send an invalid `scope`,
   `prompt=none` with no session, `access_denied`, and check that the error
   redirect validates `redirect_uri` as strictly as the success path (the
   idea behind "OAuth Non-Happy Path to ATO"; its exact method is not
   reproduced here).
9. **Dynamic client registration (RFC 7591).** If `registration_endpoint`
   is open, register one client named `mythos-<token>` with
   `redirect_uris`, `logo_uri`, `jwks_uri` and `sector_identifier_uri` set
   to OAST URLs. An OAST hit from the AS is a server-side fetch (SSRF, treat
   under `ssrf.md`). Delete the client afterwards (RFC 7592) or list it for
   cleanup. Open registration alone is configuration-grade.
10. **Device code (RFC 8628).** Request a device code and sample at most 10
    of your own `user_code`s: record alphabet, length, structure; entropy
    well under ~30 bits is a finding on arithmetic, no guessing needed. Check
    that the verification page shows the client name and scope, `interval` and
    `slow_down` are enforced, an approved code cannot be approved again, and
    `device_code` expires. Never guess a live `user_code`.
11. **Magic links and one-time tokens.** Request a link for your own account:
    (a) open it twice; (b) open it in a different browser context; (c) look
    for third-party requests on the landing page and its `Referrer-Policy`
    (token in `Referer`); (d) request with `Host: A` or `X-Forwarded-Host: A`
    and read your own mailbox: link host is `A` = poisoning (the click
    sends the token to `A`); (e) sample 5 to 10 of your own tokens for
    length, structure and counters. Never brute-force.
12. **Cookie tossing.** If you legitimately control a sibling subdomain in
    scope, set a `Domain=.example.com` cookie with your own `state` or
    session id and run a login from `userB`'s context; a client that does not
    use `__Host-` cookies may bind the flow to your value (Ward, 2024-11).
    Otherwise record "cookies are not `__Host-` prefixed" as a precondition only.

## What does not count as proof
A `302` to your host without the code arriving; an AS that echoes the
`redirect_uri` into an error page; a code that appears only in your own
browser URL; open dynamic registration with no fetch or redirect effect;
missing PKCE on a confidential client that authenticates at the token
endpoint; `state` absent on a flow that uses `nonce` and a PKCE verifier
bound to the browser (still note it).

## Remediation
Exact string match of pre-registered `redirect_uri`; single-use short-lived
codes bound to client and redirect; PKCE required for all clients; `state`
or PKCE bound to the user agent; `iss` per RFC 9207 and checked by clients;
validate `aud`, `azp`, `nonce` and `sub`, never email; no implicit flow;
authenticated or disabled dynamic registration; `__Host-` cookies.

## Sources
- RFC 9700, OAuth 2.0 Security Best Current Practice (2025-01)
- RFC 9207, OAuth Authorization Server Issuer Identification (2022-03)
- RFC 6749, 7636 (PKCE), 7591/7592 (registration), 8252, 8628, 8707
- PortSwigger Top 10 Web Hacking Techniques of 2024, published 2025-02-04:
  #8 "OAuth Non-Happy Path to ATO" (Oxrz; article date not on the list),
  #10 "Hijacking OAuth flows via Cookie Tossing" (Elliot Ward, Snyk Labs,
  2024-11-26)
- PortSwigger Web Security Academy, OAuth authentication
- Descope, "nOAuth" (2023-06): mutable, unverified Azure AD `email` claim used as identifier
