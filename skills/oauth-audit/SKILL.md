---
name: oauth-audit
description: OAuth 2.0 / OpenID Connect flow audit for a Mythos engagement - redirect_uri mutations, state and login CSRF, code reuse, PKCE enforcement, missing iss, cross-client and identity binding, scope and response_mode checks, dynamic registration, device code and magic links, each proven by an authorization code or token arriving at an OAST host the agent controls, using the agent's own accounts. Use when recon or auth-session finds an authorization endpoint, a "log in with" button, /.well-known/openid-configuration, a /device or /register endpoint, or a magic-link login.
---

# OAuth audit: the code reached my host, or the check held

An authorization-server `302` to a mutated `redirect_uri` is a hint, not a
finding. Proof is a code or token for the agent's **own** test account that
arrives at an OAST host the agent controls, or a token endpoint that answers
`200` when it must not. Method and mutation lists live in
`knowledge/web/oauth-oidc.md`; token checks in `knowledge/web/jwt.md`. Read
the first before step 2.

Prerequisites: `scope.rules.allow_active`; sessions from **auth-session**
(`userA`, `userB`, `S=engagements/<dir>/sessions`), run `session_check.py`
first; an OAST base as in **stored-xss-oast** (lab `http://oast:8080`, else
`interactsh-client`); the **mythos-browser** agent. Registering clients and
other state changes also need `allow_exploit` and the user's go (see
**exploit**). The authorization server is in scope only if `scope.yaml` lists
it: against a third-party IdP (Google, Microsoft, GitHub) test the target's
callback and token handling, never the IdP itself.

## 1. Map the flow

Record one login as `userA` with the browser agent. Write
`engagements/<dir>/scan/oauth-flow.md`: authorization and token endpoints,
`client_id`, `response_type`, `redirect_uri`, `scope`, where `state`/`nonce`
live, PKCE method, `response_mode`, and the discovery document
(`/.well-known/openid-configuration`: `registration_endpoint`,
`device_authorization_endpoint`, `code_challenge_methods_supported`,
`authorization_response_iss_parameter_supported`). Implicit or hybrid flow is a
`candidate` on its own. Mint one token per check into
`scan/oauth-tokens.jsonl` (`token, check, request, ts`), e.g.
`python3 -c 'import secrets;print("mx-oa-"+secrets.token_hex(5))'`, and use
it as the redirect path: `<oast>/<token>`.

## 2. redirect_uri mutations

Send the authorization request as `userA` for each mutation in the knowledge
table, without following redirects, and read `Location`:

```
H=$(sed 's/.*/-H "&"/' $S/userA.headers | tr '\n' ' ')     # session for the AS host
eval curl -s -o /dev/null -D- $H "'<authz>?response_type=code&client_id=<id>&scope=<s>&state=x&redirect_uri=<urlencoded mutation>'"
```

`Location` on the mutated URI = `candidate`. Hand that URL to the browser
agent as `userA`; abort the navigation to the callback and record the URL.
The code arriving at `<oast>/<token>` (or in `Referer` for an open-redirect
chain) with the unrelated-host control refused = `reproduced`. Stop at the
first accepted mutation.

## 3. Flow binding

- **State / login CSRF:** callback URL from `userA`'s unused flow, opened in
  `userB`'s context; control: altered `state`, and the callback in its own
  context.
- **Code reuse and binding:** redeem one code twice, and with another
  `redirect_uri`; control: first redemption, mangled code.
- **PKCE:** redeem with no and with a wrong `code_verifier`; authorize with no
  challenge and with `plain`.
- **iss and cross-client:** check metadata for `iss` support; present a
  token minted for your second client to the app login and API. Mix-up needs
  an AS you run; without it, `candidate` with the evidence.
- **Identity binding:** IdP account with `userB`'s email unverified; a `sub`
  that differs from the email.

## 4. Scope, mode, optional endpoints

- **scope and audience:** over-broad `scope` at authorize and refresh; read the
  issued scope from the token or introspection and call an API that needs it.
- **response_mode / type:** `token`, `id_token`, `response_mode=query`; error
  branches (`prompt=none`, bad scope) validated like the success path.
- **Dynamic registration (`allow_exploit`):** one client `mythos-<token>`
  with OAST URLs in `logo_uri`, `jwks_uri`, `sector_identifier_uri`; an OAST
  hit is SSRF evidence for the **web-scan** SSRF row. Delete the client after.
- **Device code:** at most 10 of your own `user_code`s for entropy
  arithmetic; never guess a live code.
- **Magic links:** open twice, open in another context, `Host`/
  `X-Forwarded-Host` poisoning on your own address read from your own mailbox,
  `Referrer-Policy`, 5 to 10 own tokens for structure.

## Rules

- Own accounts only; the leaked code or token must be `userA`'s or `userB`'s.
- No brute force of codes, `user_code`s, state or magic-link tokens. Respect
  `rules.rate_limit_rps` and `max_requests`.
- A scanner or mail prefetch can burn a single-use code: attribute every OAST
  hit by source and `User-Agent` before counting it.
- Clean up: delete registered clients, unlink test identities.

## Closure states

Per **exploit**, every check ends in exactly one state in
`findings/<id>.md`:

| state | meaning here |
|---|---|
| `candidate` | `Location` to a mutated URI, missing `iss`/PKCE metadata, implicit flow, version match; no OAST hit |
| `reproduced` | OAST hit or `200` from the abused request with the negative control done, once by hand |
| `validated(proof)` | stored PoC (`findings/<id>.poc.sh` plus the browser script) re-run in a fresh context gives the same hit |
| `rejected(reason)` | the control also passed, enforced, by design, or not reproducible |

Record the exact request, the OAST log line or token response, the control and
the account used. Add an `oauth` row per check to `scan/coverage.md`.
Hand `reproduced` rows to **exploit** for the validator pass, then **report**.
