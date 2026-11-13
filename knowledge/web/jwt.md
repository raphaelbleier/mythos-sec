# JWT (signature, key lookup, token confusion)

**Class:** authentication  **Updated:** 2026-11-13

## What it is
The server trusts a bearer token that a client can edit. It breaks in three
places: the signature is not verified (or verified with an attacker-chosen
algorithm or key), the key lookup is steerable (`kid`, `jku`, `x5u`, `jwk`),
or the token is valid but for a different purpose (wrong audience, wrong
token type). OAuth flow bugs are in `oauth-oidc.md`; this note is about the
token itself.

Classic RS256-to-HS256 confusion (public key used as the HMAC secret) is now
mostly a legacy check: current libraries bind the key type to the algorithm.
Send it once, do not build a finding around expecting it. The live bugs in
2026 are key-source trust, nested-token handling and audience/type checks.

## How Mythos detects it
- Capture every JWT-shaped value (`eyJ...`, three or five dot-separated
  segments) from headers, cookies, bodies and `localStorage`. Decode header
  and claims first: `alg`, `kid`, `jku`/`x5u`/`jwk`, `typ`, `iss`, `aud`,
  `exp`, `sub`. Five segments means JWE: note it.
- Fetch `/.well-known/openid-configuration` and its `jwks_uri`. Which `kid`s
  and `use` (`sig`/`enc`) values are published tells you which tests apply.
- `scripts/mythos jwt_tool <token> -M at` runs the scripted checks; treat its
  output as candidates. Offline cracking of the agent's own HS256 token:
  `jwt_tool <token> -C -d <wordlist>` or `hashcat -m 16500`.

## How to confirm (non-destructive)
Every test uses a token minted for the agent's own test account and changes
only a benign claim, or swaps `sub` to the agent's second account (`userB`).
Never forge a claim for an account the agent did not create.

**Oracle:** pick an endpoint that returns 401 without a token and reflects the
identity in the body (`GET /me`). Baseline: valid token returns userA's
profile. Negative control for every test below: the same token with one
signature byte flipped must return 401/403. Accepted = the forged token
returns the profile of the claimed subject (userB's email), not just 200.

1. **alg none:** header `{"alg":"none"}` (also `None`, `NONE`, `nOnE`),
   payload with `sub` = userB, empty signature, trailing dot kept.
2. **Weak HS256 secret:** crack offline from the agent's own token, then sign
   a token for userB. A cracked secret alone is a `candidate` (dev and prod
   may differ); acceptance by the target is the proof.
3. **jku / x5u (remote key set):** set `jku` to a URL on a host you control.
   A hit on the OAST host proves the server fetches attacker URLs (an SSRF
   primitive, record it as such). To prove token forgery, host a JWKS with
   your own key and sign with it; accepted = the server trusts the header URL.
   If a host allowlist exists, test the mutations from `oauth-oidc.md`
   (`@`, suffix, open redirect on an allowed host).
4. **Embedded `jwk`:** put your public key in the header, sign with your
   private key. Accepted = the server trusts the key it is handed.
5. **`kid` as a path:** `"kid":"../../../../dev/null"` with an HS256 token
   signed with an empty secret, or a static file with known content
   (`/proc/sys/kernel/hostname` signed with its content). **`kid` as SQL:**
   `' UNION SELECT 'k'-- -` then sign with `k`. Read-only fragments only; no
   stacked queries. Accepted token is the proof; a 500 on `kid='` alone is a
   `candidate` for SQLi, not for JWT.
6. **`crit`:** RFC 7515 4.1.11 requires rejecting a token whose `crit` names
   an extension the verifier does not know. Testable only with a key you hold
   (own issuer, lab, cracked secret). Acceptance is non-compliance, usually
   hardening-grade; report it only if it bypasses a control.
7. **Nested JWE/JWS and PlainJWT:** if `jwks_uri` publishes an encryption
   key (or the app accepts 5-segment tokens), wrap a PlainJWT (`alg:none`)
   with userB's `sub` in a JWE encrypted to that public key. pac4j-jwt
   CVE-2026-29000 skipped signature validation for exactly this shape (an
   unsigned inner token inside a JWE; fixed in 4.5.9, 5.7.9, 6.3.3 per
   vendor advisories, affected-version detail varies by source). Also test an
   inner token with a valid-looking but wrong signature.
8. **Audience reuse:** take a token your account got for service A (or client
   X) and send it to service B (or API Y) of the same issuer. Accepted =
   `aud`/`azp` not checked. Control: the same token with `aud` edited fails
   (signature) and a token from a different issuer fails.
9. **Token type confusion:** send the OIDC ID token as `Authorization: Bearer`
   to an API. RFC 9068 access tokens carry `typ: at+jwt`; RFC 8725 3.11
   says to type-check. Accepted = ID token usable as access token; impact is
   largest when ID token `aud` is a public client id.
10. **Lifetime:** replay the agent's own expired token (and one with future
    `nbf`). Accepted = `exp`/`nbf` unchecked. Check logout and password
    change too: the old token should stop working after rotation.

Legacy, one request each: RS256 to HS256 with the JWKS key converted to the
HMAC secret; blank ECDSA signature against old Java verifiers (CVE-2022-21449).

## What does not count as proof
A decoded payload with sensitive claims; `alg:none` returning 200 on an
endpoint that returns 200 with no token at all; a tampered token that gets a
200 where the signature-flipped control also gets 200; a cracked secret never
sent to the target; a `jku` OAST hit without an accepted forged token (that
is SSRF, not JWT forgery).

## Remediation
Pin the algorithm per key; reject `none` and PlainJWT; resolve keys from a
configured JWKS by `kid`, never from `jku`/`x5u`/`jwk` in the token; treat
`kid` as an opaque map key; require `iss`, `aud`, `exp`, and `typ`; use
separate audiences per API; rotate on logout and credential change.

## Sources
- RFC 8725, JWT Best Current Practices (2020-02)
- RFC 7515, JSON Web Signature, sections 4.1.2 to 4.1.11 (2015-05)
- RFC 9068, JWT Profile for OAuth 2.0 Access Tokens (2021-10)
- PortSwigger Web Security Academy, JWT attacks
- pac4j-jwt CVE-2026-29000 advisories (2026-03); mechanism as reported by
  vendor and third-party bulletins, not independently reproduced here
