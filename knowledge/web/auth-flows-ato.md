# Authentication flows and account takeover (reset, MFA, verification, session)

**Class:** authentication / business logic  **Updated:** 2026-11-13

## What it is
Login is a state machine: each step issues a token or a session state that the
next step must check. Account takeover (ATO) bugs are steps that can be
skipped, repeated, reordered or replayed, or tokens that are guessable, not
bound to the user, or leaked. Method: draw the diagram from recorded traffic,
then try the four moves on every arrow. The general method is in
`techniques/state-machine-abuse.md`; oracles in `techniques/oracle-building.md`.

## Hard rules for this class
- Two accounts the agent created (`userA` victim stand-in, `userB` attacker),
  each with a mailbox the agent controls. Never touch any other account.
- Never brute-force an OTP, reset token, magic link or password. Rate-limit
  tests send at most 6 wrong attempts at the agent's own account.
- Poisoned `Host`/`X-Forwarded-Host` mail is requested only for the agent's own
  address. Stop at one enumeration sample of 5 known and 5 unknown identifiers.
- Closure state and proof follow `skills/exploit`: negative control and
  durable read-back (log in as the target afterwards) are required.

## 1. Password reset
```
request(email) -> token mailed -> GET link?token -> POST(token,newpw) -> token consumed -> old sessions revoked
```
- **Host poisoning:** request a reset for `userA` with `Host: A`,
  `X-Forwarded-Host: A`, `X-Forwarded-Server`, `Forwarded: host=A`, and an
  absolute-URI request line (`A` = OAST/own host). Read `userA`'s mailbox:
  link host is `A` = poisoned (the victim click sends the token to `A`).
  Control: the same request with no override yields the real host.
- **Token entropy:** request 5 to 10 tokens for your own accounts. Record
  length, alphabet, any embedded timestamp, counters, or hash of the email or
  time. Predictable structure is the finding; do not guess live tokens.
- **Reuse and lifetime:** use a token twice; use token 1 after token 2 was
  issued; use it after the password changed; use it after expiry.
- **Not bound to the user:** take `userA`'s valid token and change the
  identifier in the final POST (`email`, `user_id`, `username`, JSON array
  `email:[a,b]`) to `userB`'s. Proof: log in as `userB` with the new password.
  Control: wrong token rejected; correct pair works.
- **Leaks:** token in the request-step response body or headers; token in
  `Referer` from the reset page's third-party assets.
- **After reset:** other sessions and old tokens still valid = no revocation.
- **Oracle for the whole flow:** durable state, i.e. successful login with the
  new credential, never the `200` on the POST.

## 2. 2FA / MFA
```
password ok -> partial session -> OTP prompt -> OTP verify -> full session
```
- **Skip:** with only the partial session, request a post-login URL and the
  API (`GET /api/me`, settings, token creation). `200` with account data = the
  second factor is not re-checked. Control: no cookie returns `401`.
- **Response manipulation:** editing `{"verified":false}` or a status code
  matters only if the server already issued a full session at step 1;
  otherwise it is a client-side no-op. Prove with a server-side read.
- **Not re-checked on follow-ups:** disable 2FA, change email, change password,
  create API key, view backup codes: each must demand the OTP or current
  password again.
- **OTP binding and reuse:** `userB`'s valid OTP submitted in `userA`'s partial
  session; the same OTP twice; an OTP past its window.
- **Rate limit:** send at most 6 wrong codes on your own account and watch for
  `429`, a lockout, a rising counter. No limit after 6 is a `candidate`; do
  not continue to prove it.
- **Backup codes:** regenerating invalidates old ones; each works once; the
  listing endpoint needs re-authentication.
- **Side doors:** social login, magic link, password reset and legacy API
  tokens that reach a full session without the second factor; a
  "remember this device" cookie that is guessable or not bound to the user.

## 3. Email change and verification
```
change(new) -> verify link to new (and old?) -> confirmed -> email used for login and reset
```
- Does the new address take effect before verification (login, reset, `/me`)?
- Is the verification token bound to the account, or does `userA`'s token
  verify `userB`'s pending address?
- Is the current password or the old mailbox required?
- **Pre-hijacking** (Sudhodanan and Paverd, USENIX Security 2022): register as
  attacker with the address of `userB`'s mailbox, unverified, with a password;
  then sign `userB` up or in through SSO or verification. If the attacker's
  password still opens the merged account, that is the finding. Run it with
  your own two accounts only.
- Address normalization: case, `+tag`, dots, Unicode lookalikes creating a
  second account that collides with the first.

## 4. Session fixation and lifecycle
```
GET /login -> session id S0 -> login -> id rotated? -> logout -> S invalid server-side?
```
- Cookie before and after login: unchanged = fixation. Proof: replay `S0` from
  a clean context, `/me` returns `userA`. Rank by how an attacker would plant
  `S0` (sibling subdomain, XSS); without a plant path it is low.
- Logout and password change must kill the server-side session: replay the
  old cookie afterwards.
- Session id in URL, in `Referer`, or in a non-`HttpOnly` cookie next to XSS.

## 5. Username enumeration
Compare login, reset, registration and 2FA responses for a known account and a
nonexistent one, five samples each, after the normalization in
`techniques/oracle-building.md` (status, body, length, headers, median
time). A stable difference is the finding; many programs exclude it, so read
the scope rules first.

## What does not count as proof
A `200` on the reset or OTP POST; a poisoned `Host` header reflected in the
HTTP response but not in the email; a client-side response edit with no
server-side effect; a guessable-looking token with no accepted use; a rate
limit "not observed" over 6 requests.

## Remediation
Bind every token to user, purpose and one use; random 128-bit tokens, short
expiry, invalidate on reuse, newer token and password change; build links from
configured origin, never `Host`; the OTP gate lives on the server session, not
in the client; rotate the session id at login and privilege change; require
re-authentication for 2FA, email and password changes; uniform responses.

## Sources
- OWASP WSTG ATHN and SESS chapters; OWASP Forgot Password Cheat Sheet
- PortSwigger Web Security Academy: authentication, password reset poisoning
- Sudhodanan and Paverd, "Pre-hijacking Attacks on Web User Accounts",
  USENIX Security 2022 (2022-08)
- Kettle, "Smashing the state machine" (2023-08), for the skip/repeat/reorder frame
