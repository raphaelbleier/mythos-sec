---
name: sso-federation
description: SAML, OIDC/OAuth federation and account-linking audit for a Mythos engagement - signature stripping and XSW1-XSW8 wrapping, NameID comment truncation, Audience/Recipient/Destination/time enforcement, assertion replay, IdP-initiated and RelayState redirects, DTD and XXE in the SAML parser, metadata and certificate rotation, redirect_uri matching, state and nonce binding, PKCE downgrade, response_type/response_mode downgrade, prompt=none, id_token alg:none and HS/RS confusion, audience confusion, token substitution, kid/jku/x5u tricks, authorization-code injection and reuse, and the account-linking class where an unverified email from one IdP claims an existing local account - every row with its manipulation, its oracle and the unmodified control, against identities the operator owns. Use when recon finds a SAML ACS or metadata endpoint, a "log in with" button, an /oauth/authorize or /oauth/token endpoint, /.well-known/openid-configuration, an id_token anywhere, or a settings page that connects and disconnects an external identity.
---

# SSO federation: the SP read an element the signature does not cover

The flaws in this skill all have the same shape. Two parties trust each other
across a document, and something the *user* can choose ends up where the
relying party expected something the *issuer* chose: an element a signature
does not cover, an email claim nobody verified, a `redirect_uri` a prefix match
accepted, a code nobody bound to a client. The proof is always the same too:
the operator's second account's session, handed over by a document the operator
built, with the unmodified flow succeeding in the same run.

**`authflows` is not this skill.** Reset, MFA, session rotation, email change
and passkeys are **account-takeover**. This skill owns the flows run *with a
second party*, and its tool is `scripts/federation`. `oauth-audit` remains the
browser-driven half of the OAuth work — the authorization request opened in a
real browser, the callback aborted, the code caught at an OAST host. Run it
alongside this one: `federation oidc` reads `Location` headers, which is a
lead, and the browser is what turns a lead into a code arriving somewhere.

Method and oracle tables live in `knowledge/web/saml-scim-sso.md` (SAML, SCIM),
`knowledge/web/oauth-oidc.md` (the flows, the `redirect_uri` table, the linking
class) and `knowledge/web/jwt.md` (token internals). Read the one your step
names before you send anything.

## Preconditions, and the one rule that is not negotiable

- **Two accounts the operator owns**, from **auth-session**: `userA` as the
  identity the control asserts, `userB` as the identity every mutation asserts.
  Every subcommand takes them as `--own`, repeatable and required, and every
  subject, NameID, email and `sub` the run would assert is checked against that
  list before a byte leaves. A captured credential is checked too: its NameID,
  `email`, `sub` or `preferred_username` must be on the list. A federation test
  aimed at anyone else's identity is an attempt to log in as that person, and
  the script refuses it in every mode. There is no scope rule, flag or
  environment variable that permits it.
- **The IdP is in `scope.yaml` or you do not touch it.** A request to an
  authorization server, a JWKS host or an OAST host is ours. `scripts/federation`
  refuses an out-of-scope destination and names it, rather than warning after
  the request has gone. Against a third-party IdP (Google, Microsoft, GitHub)
  that scope will not exist: test the target's ACS, callback and token handling
  and leave the IdP alone.
- **A read-back oracle.** `--oracle-url` is an endpoint that names the
  logged-in identity (`/api/me`, `/saml/whoami`, a profile page), read with the
  session the flow issued. Without one, no row gets better than
  `candidate (weak)` and the output says so. The row matches on the identity
  *that row* asserts, by address and by its local part; `--oracle-match`
  overrides that for every row at once, so leave it unset unless neither form
  appears in the answer.
- `scope.rules.allow_active`. Registering a second client, or anything else
  that changes state at the IdP, also needs `allow_exploit` (see **exploit**).
- **RSA is not available.** The standard library cannot sign RS256 or
  RSA-SHA256, and this repository adds no dependency for it. Minted documents
  are signed with HMAC (`xmldsig-more#hmac-sha256`, `HS256`) — real algorithms,
  correctly computed, which a production SP will still reject because it trusts
  a certificate. That is not a gap in the test that matters: an accepted
  unsigned or foreign-key document answers *does this SP verify a signature at
  all*, which is the finding. Rows that genuinely need an RSA forgery are
  emitted as `inconclusive` with `rsa_not_covered` and say what would do it
  instead (SAML Raider, a `cryptography` install, or the real IdP). Do not
  report them as held.

## 1. Map the federation

Write `engagements/<dir>/scan/federation.md` before any mutation.

```
script: federation metadata <url> [--also <url>] [--json]
```

Read the SP's SAML metadata (`/saml/metadata`, `/sso/metadata`, `/FederationMetadata/2007-06/FederationMetadata.xml`),
the discovery document (`/.well-known/openid-configuration`,
`/.well-known/oauth-authorization-server`) and the JWKS. Record: the ACS URL
and binding, `WantAssertionsSigned`, every signing certificate with its digest,
the JWKS `kid` set, `code_challenge_methods_supported`,
`response_modes_supported`, `authorization_response_iss_parameter_supported`,
`registration_endpoint`, and the `Cache-Control` on each document. Two
published certificates mean rotation is staged and the retiring key is still
accepted; one means a rotation is a flag day and a metadata-caching stack will
keep trusting the old key — that one is `inconclusive` from a single read, so
put the URL in `scripts/watch` instead of guessing.

Then capture one complete login per protocol with the `browser` tool, as
`userA`, and save the bytes: the `SAMLResponse` (base64, or base64 of deflate
on the Redirect binding) to `scan/saml-capture.b64`, and the `id_token`,
`access_token`, `code`, `state`, `nonce` and `code_verifier` to
`scan/oidc-capture.json`. Every step below is built from those bytes. A capture
from a real IdP is what makes the control succeed, and without a succeeding
control nothing in this skill is readable.

## 2. SAML: does the SP verify the signature it thinks it verifies

```
script: federation saml <acs> --own <id> [--own <id>] --subject <id> [--victim <id>]
                            [--response <file>] [--oracle-url <url>] [--oast <host>]
                            [--relay-state <url>] [--idp <host>] [--only <check>]
                            [--xxe-file <path>] [--keep-documents] [--json]
```

One POST per row, the capture unmodified as the control before the first row
and again after every candidate. Rows, by `--only` name:

- `unsigned` — every `ds:Signature` removed, NameID set to `userB`. The single
  most valuable row in the file: accepted means no signature is required.
- `strip-assertion-sig` — one of two signatures removed, the other left.
- `selfsigned` — `rsa_not_covered`; the mint path is the stdlib half of it.
- `comment-nameid`, `comment-nameid-suffix` — `userB<!---->.evil.invalid`.
  Accepted *and read back as the truncated address* is the Duo 2018 class:
  canonicalization covered the whole string, the SP read the first text node.
- `audience`, `recipient`, `destination` — the assertion addressed elsewhere.
- `expired`, `notbefore-future` — the assertion's own time bounds.
- `replay` — the capture sent twice. The control is the first send.
- `idp-initiated` — `InResponseTo` removed from both places it appears.
- `relaystate` — needs `--relay-state <url>`; a `Location` to that host means
  the ACS is an open redirect that hands over a fresh session.
- `xsw1` … `xsw8` — the eight wrapping shapes. Read the differential, not the
  count: which shapes win tells you which element the SP's reader selects
  versus the one its verifier selected.
- `doctype` — a DOCTYPE accepted at all is the precondition for every
  parser-differential bypass (ruby-saml CVE-2025-25291/-25292, and the
  attribute-pollution, namespace-confusion and void-canonicalization variants
  in `knowledge/web/saml-scim-sso.md`).
- `xxe-internal` — an internal entity in the NameID; the expansion read back
  is the proof.
- `xxe-oast` — needs `--oast <host>`, in scope; the oracle is the catcher's
  log (`curl $OAST/__log`), not this process, and the row says so.
- `xxe-file` — only when the operator names a path with `--xxe-file`. Left out
  means no file is read.

No entity-expansion bomb is built: that is denial of service and it is refused
in code.

## 3. SAML: attach the document, not the label

```
script: federation shapes --own <id> --victim <id> [--response <file>] [--subject <id>]
                          [--acs <url>] [--sign assertion|response|both] [--only <xswN>]
                          [--json]
```

Sends nothing. Prints each wrapping document and the measurable facts about
it — assertion and response counts, signature count, the NameIDs in document
order, and one `[element, parent]` pair per signed element, which *is* the
shape (`xsw6` is `["Assertion", "Signature"]` and nothing else is). Use it to
attach the exact document to a finding, and to show in a report that the
signed element survived byte for byte.

## 4. OIDC and OAuth: the authorization endpoint

```
script: federation oidc <authorize> --own <id> --account <id> --client-id <id>
                        --redirect-uri <registered value> [--oast <host>] [--metadata <url>]
                        [--header 'Cookie: ...'] [--scope '...'] [--only <check>] [--json]
```

The registered `redirect_uri` is the control and an unrelated host
(`redirect_uri/unrelated`) is the table's own control: if that one is accepted,
there is no check at all rather than a loose one, and the rest of the table
says nothing new. 22 mutations, named `redirect_uri/<label>`: `other-path`,
`path-suffix`, `path-traversal`, `path-traversal-encoded`, `path-semicolon`,
`query-appended`, `fragment-encoded` (`%23`), `fragment-plain` (`#`),
`userinfo`, `userinfo-encoded`, `backslash`, `subdomain`, `suffix-host`,
`trailing-dot`, `case`, `port`, `scheme-downgrade`, `scheme-custom`,
`loopback`, `wildcard`. The open-redirect chain is not in the table because it
needs a sink on the registered host: find one with **client-side** or
**web-scan**, then send it here as the `redirect_uri` value with `--only`.

Flow rows: `state-absent`, `nonce-absent`, `pkce-absent`, `pkce-plain`,
`implicit-downgrade`, `idtoken-downgrade`, `hybrid`, `response-mode-query`,
`response-mode-form-post`, `prompt-none`. A downgrade row is graded on the
*kind* of credential that came back: an AS that ignores `response_type` and
returns a code anyway reads as `held`, not as implicit flow.

A `Location` carrying a code is a `candidate`. The proof is the code arriving
somewhere the operator controls, and that step is **oauth-audit** with the
`browser` tool. Whether the *client* binds the `state` it sent is also a
browser step: take `userA`'s unused callback URL into `userB`'s context.

## 5. OIDC and OAuth: the token endpoint

```
script: federation token <token-url> --own <id> --account <id> --client-id <id>
                         --code <captured code> [--client-secret <s>] [--redirect-uri <uri>]
                         [--verifier <code_verifier>] [--other-redirect <uri>]
                         [--other-client <id>] [--injected-code <code>]
                         [--limit-probe <n>] [--only <check>] [--json]
```

The order is fixed and matters: the control redeems first, which is also the
first half of the single-use test. Rows: `code-reuse`, `redirect-rebind`,
`client-rebind`, `verifier-absent`, `verifier-wrong`, `code-injection` (needs
`--injected-code`: a code issued to a *second client of the same AS*, both the
operator's), `rate-limit`.

A code is single use when the implementation is right, so **capture a fresh
code for every run** and expect `inconclusive: the control redemption failed`
when you do not. `--limit-probe` is capped at 10 wrong codes in code; the
output states the ceiling, and the finding is the missing limit, never a
guessed code. Nothing in this file searches a code, `state` or `user_code`
space.

## 6. id_token handling at the relying party

```
script: federation idtoken <rp-url> --own <id> --account <id> --id-token <captured>
                           [--victim-email <id>] [--victim-sub <id>] [--hmac-key <k>]
                           [--other-rp <url>] [--other-issuer <iss>] [--access-token <t>]
                           [--jwks-host <host>] [--field id_token] [--extra-field k=v]
                           [--oracle-url <url>] [--keep-tokens] [--only <check>] [--json]
```

Rows: `alg-none`, `hs-confusion` (`--hmac-key` is the secret to try as the HMAC
key — the IdP's RSA public key or the JWKS `n` value), `aud-confusion`,
`iss-swap`, `nonce-replay`, `token-substitution` (`--access-token`),
`kid-traversal`, `kid-empty`, `kid-sql`, `jku-pointing-elsewhere`,
`x5u-pointing-elsewhere` (both need `--jwks-host`, in scope).

Three of those need no new signature and are therefore the strongest rows
here: `aud-confusion` (register a second client of your own, pass its endpoint
as `--other-rp`, and present the token issued to the first one),
`nonce-replay` and `token-substitution`. Without `--other-rp`,
`aud-confusion` is `inconclusive` and says why — sending the token back to the
endpoint that issued it proves nothing.

## 7. Account linking

```
script: federation linking <link-url> --own <id> --account <id> --local-email <id>
                           [--second-email <id>] [--id-token <captured>] [--issuer <iss>]
                           [--other-issuer <iss>] [--client-id <aud>] [--own-sub <sub>]
                           [--nonce <n>] [--hmac-key <k>] [--unlink-url <url>]
                           [--oracle-url <url>] [--only <check>] [--json]
```

Rows: `unverified-email` (a fresh `(iss, sub)` asserting the local account's
address with `email_verified: false` — the nOAuth class), `idp-collision` (a
second issuer asserting the same verified address), `preclaim` (an IdP identity
for an address a local account was registered with but never confirmed;
`--second-email`), `sub-change-same-email`, and `stale-session` (`--unlink-url`:
disconnect the identity, then reuse the session the link created).

Pass a real captured `--id-token` so the control can succeed. Minted HS256
tokens cannot pass a relying party that verifies RSA signatures, and every row
then reads `inconclusive`, which is the correct answer and not a result.

Where the linking endpoint is a browser flow rather than a POST, drive it with
the `browser` tool and bring the resulting identity back here for the
`stale-session` row.

## Rules

- `--own` on every subcommand, and the identity the mutations assert is
  `userB`'s. Never a third party's, in any mode.
- An IdP, JWKS or OAST host must be in `scope.yaml`. The script refuses and
  names an out-of-scope destination; do not widen the scope to silence it.
- Honour `rules.rate_limit_rps`; it is read from `$MYTHOS_SCOPE` by default.
- Clean up: delete clients you registered, unlink the test identities, and
  note any session you could not revoke.
- A scanner, a mail prefetch or a link preview can consume a single-use code or
  assertion. Attribute every OAST hit by source and `User-Agent` before
  counting it.
- Nothing here is `confirmed`. The script emits `candidate`, `held` or
  `inconclusive`; the validate phase replays the bytes.

## Closure states

Per **exploit**, every check ends in exactly one state in `findings/<id>.md`:

| state | meaning here |
|---|---|
| `candidate` | a row the script graded `candidate` with its read-back, or a `Location` to a mutated `redirect_uri`, or a version or metadata match, with the control recorded |
| `reproduced` | the oracle read back the second account's identity, or tokens came back from a redemption that must have failed, with the negative control done once by hand |
| `validated(proof)` | the stored `--json` run plus `findings/<id>.poc.sh` re-run in a fresh context gives the same read-back |
| `rejected(reason)` | the row read `held` with a succeeding control, or the behaviour is by design (a declared related origin, a staged certificate rotation) |

A row that read `inconclusive` is not a rejection. Write it down with what it
would have needed — a real capture, a second client, `--other-rp`, an RSA
signature, an OAST host — because that sentence is what makes the next
engagement cheaper. Keep the `--json` output of every run under
`engagements/<dir>/scan/` and add a `federation` row per check to
`scan/coverage.md`. Hand `reproduced` rows to **exploit** for the validator
pass, then **report**.

## Lab

`lab/authlab/` (`http://127.0.0.1:5023`) carries a deliberately broken SP and
RP for rehearsing all of this: `/saml/acs` verifies no signature and reads the
first NameID as a text node, `/saml/acs-sigpresent` demands a `ds:Signature`
element and then ignores it while reading the *last* NameID, `/oauth/authorize`
matches `redirect_uri` by substring, `/oidc/callback` never binds `state`, and
`/oidc/link` ignores the id_token's signature, `aud` and `email_verified` and
keys the account on `email`. Oracles: `/saml/whoami` and `/api/me`. Every fake
credential it issues contains `MYTHOS_LAB_CANARY`. `federation selftest` needs
no lab and no Docker: it starts its own loopback SP/RP and asserts the shapes,
the controls and the refusals.
