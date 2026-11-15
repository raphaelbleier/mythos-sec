# Passkeys and WebAuthn

**Class:** authentication  **Updated:** 2026-11-14

## What it is
A passkey is a public key the relying party stores and an assertion the
authenticator signs. The cryptography is not where implementations fail. Seven
other things are.

**Origin.** The signed `clientDataJSON` carries the `origin`, and a relying
party that does not check it accepts an assertion produced for another origin.
That is a bypass.

**RP ID breadth — an observation, not a bypass.** An RP ID set broader than the
site (`example.com` for `app.example.com`) lets any subdomain assert for the
whole domain, which is worth recording. It is not a specification violation:
§13.4.9 explicitly permits a relying party to accept any subdomain of its RP
ID, and §5.11 related-origin requests make a foreign origin legal when the site
declares it at `/.well-known/webauthn`. So fetch that file before scoring
anything, and report breadth as hardening unless the reach to a takeable
subdomain is itself proven.

**Challenge binding.** If the server does not bind the challenge to the session
and retire it after one use, a complete assertion replays, and the assertion is
then a bearer token. That is a bypass. The challenge's *length* is a different
and weaker question: it is a SHOULD in §13.4.3, and the "at least 16 bytes"
figure usually quoted at it is the **Credential ID**'s requirement, not the
challenge's. Do not report a short challenge as a spec violation.

**signCount — an observation, not a bypass.** Many relying parties ignore it,
and some synced-credential providers legitimately send `0` forever, so a
rollback is accepted and credential cloning goes undetected. This is the
feature meant to detect theft, and the move to synced passkeys broke it widely.
But §7.2 says a non-increasing counter "is a signal, but not proof, that the
authenticator may be cloned" and leaves the response to the relying party. So
an accepted rollback is recorded as an observation, beside whatever the relying
party's own documentation claims about cloning detection, and never as an
authentication bypass.

**Downgrade.** The best-documented real-world weakness: after a passkey is
enrolled, the password, SMS or email path is still reachable and can be forced
by a client that claims not to support WebAuthn. A spoofed unsupported browser
has been reported causing an identity provider to offer the weaker factor. A
passkey rollout with the old path live buys nothing.

**Recovery and enrolment.** Adding a second passkey, or removing the first,
without re-authenticating with the existing one, is the whole account. So is an
account-recovery flow that enrols the attacker's passkey.

**Enumeration.** A login-begin response that differs for a known and an unknown
user, or that lists credential ids before authentication, is user enumeration
with a cryptographic veneer.

## How Mythos detects it
- `skills/account-takeover` step 5. `scripts/authflows webauthn <url>` sends no
  assertion of its own: it emits the CDP calls for the virtual authenticator,
  so no hardware token is needed — `WebAuthn.enable`, then
  `WebAuthn.addVirtualAuthenticator` with `protocol: ctap2`,
  `transport: internal`, resident key and user verification on. The agent runs
  them with the `browser` tool, registers a credential on **its own** account,
  controls every field of the assertion, and hands the observations back with
  `authflows webauthn <url> --judge FILE`. `--rp-id` overrides the RP ID, whose
  default is the target host.
- The grader draws the bypass/observation line above, so take its wording into
  the finding rather than restating it.
- Cheap reads first: the RP ID in the registration options, whether
  `userVerification` is `required` or `preferred`, whether the login-begin
  response differs per user, and which fallback factors the account still
  offers after enrolment.

## How to confirm (non-destructive)
Every test runs against accounts the operator owns, and the proof is that the
agent authenticated as its own second account, or added a credential to it,
with material the first account controls. **A passkey test aimed at anybody
else's account is an attack on a person and is refused in every mode.**

The negative control is the same assertion with the correct origin, RP ID,
challenge and counter, which must succeed. Without it, a refusal only shows the
request was malformed, not that the check exists. Per check:

| check | the manipulation | the control |
|---|---|---|
| origin | replay a valid assertion with a foreign `origin` in `clientDataJSON` | the same assertion with the real origin: accepted |
| RP ID breadth (observation) | assert with an RP ID broader than the site | the site's own RP ID: accepted. Read `/.well-known/webauthn` first: §13.4.9 and §5.11 make breadth legal |
| challenge | replay a complete, already-accepted assertion | a fresh challenge: accepted |
| signCount (observation) | assert with a counter at or below the last accepted value | the expected counter: accepted. Never scored as a bypass: §7.2 leaves the response to the RP, and synced passkeys report 0 forever |
| downgrade | complete login through a fallback factor while a passkey is enrolled; then force it by claiming no WebAuthn support | the passkey path, working |
| recovery | add or remove a credential with only a session, no re-authentication | the same action with re-authentication required |

No brute force: no credential-id guessing, no challenge search, no login loop.
Where the only proof would be guessing, the finding is the missing limit, shown
with N <= 10 and the ceiling stated.

## Remediation
Verify `origin` against an exact allowlist and the RP ID hash against the
narrowest RP ID that works; bind each challenge to the session, make it
single-use and short-lived; store and check `signCount` where the
authenticator provides one, and say so; require re-authentication with an
existing credential before enrolling or removing another; retire the weaker
factors once a passkey is enrolled, or treat the account as protected only to
the strength of its weakest path; return an identical login-begin response for
known and unknown users.

## Sources
- W3C WebAuthn Level 3: §7.2 (a non-increasing signCount "is a signal, but not proof, that the authenticator may be cloned"; the response is the Relying Party's choice), §13.4.3 (challenge length is a SHOULD; the 16-byte minimum belongs to the Credential ID), §13.4.9 (an RP may accept any subdomain of its RP ID), §5.11 (related-origin requests, declared at `/.well-known/webauthn`)
- uzyn, "Passkey has a theft-detection feature but big tech broke it" (2025) — signCount in synced providers
- The Hacker News, "How attackers bypass synced passkeys" (2025-10), reporting Proofpoint on forced downgrade in Entra ID
- hivesecurity, passkey phishing and WebAuthn implementation flaws
- Scott Helme, "Having our passkeys implementation security tested"
- Ulqinaku et al., USENIX Security 2021, on FIDO downgrade (second-hand)
- PortSwigger Top 10 2025 nominations: passkey / FIDO auth bypass (CVE-2025-26788)
