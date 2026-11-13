# SAML, SCIM and enterprise SSO

**Class:** authentication  **Updated:** 2026-11-13

## What it is
The service provider (SP) accepts a SAML assertion it should not, or a SCIM
provisioning call creates or changes an identity it should not. SAML bugs
come from XML: the signature covers one element while the SP reads another,
or two XML parsers in one stack disagree about what was signed. SCIM bugs
come from the provisioning API being a second, less-guarded way to write
users. Both end the same way: a session as an identity the tester did not
authenticate as. Tests here only ever mint or provision identities that
belong to the agent's own two accounts.

## Why you need your own test IdP
Every SAML check changes a signed document, and the SP trusts exactly one
signing key. Against a corporate IdP you cannot obtain assertions for
arbitrary names, and you must not try. Stand up a test IdP (SimpleSAMLphp,
Keycloak, or the lab's) that the SP under test is configured to trust, with
two users `userA`, `userB`. You then control: which identities get signed,
what key signs them, and a clean control login. If the program offers only a
production IdP, you can still capture your own assertion and run the unsigned
and replay checks below, but wrapping, comment and parser-differential
checks stay `candidate` (version fingerprint only). None of this ships in the
toolbox image; SAML Raider (Burp) or a short python3 script with an XML
library does the editing.

## How Mythos detects it
- Find the ACS endpoint (`/saml/acs`, `/sso/saml`, `/auth/saml/callback`) and
  metadata (`/saml/metadata`). Capture one SP-initiated login as `userA`;
  base64-decode `SAMLResponse` (inflate first for Redirect binding). Note
  signed elements (`Response`, `Assertion`, both), `NameID`, `Audience`,
  `Recipient`, `InResponseTo`, `NotOnOrAfter`, and the signature `Reference`.
- Fingerprint the SP library and version from headers, error pages and the
  product; compare against advisories (below). That alone is a `candidate`.

## How to confirm (non-destructive)
**Oracle:** after posting a modified response to the ACS, the session belongs
to the identity you wrote in it (`GET /me` shows `userB`). Baseline: the
untouched response gives `userA`. Negative control for every row: a response
with one signature byte flipped is rejected.

1. **Unsigned acceptance:** remove `Signature` from `Response` and
   `Assertion`, set `NameID` to `userB`. Also: remove only one of the two
   signatures; sign with your own key while leaving the IdP certificate in
   `KeyInfo`. Accepted = signature not required, or trusted from the message.
2. **Signature wrapping (XSW1 to XSW8):** keep the original signed assertion
   but place a second, unsigned assertion with `NameID` `userB` where the
   SP's XPath finds it first, or move the signed one into `Extensions`/
   `Object`. The signature still verifies against the signed copy; the SP
   consumes the evil one. (Somorovsky et al., 2012.)
3. **Comment injection in NameID:** with the test IdP, issue `NameID`
   `userB@lab<!---->.x`. If canonicalization drops comments but the SP's text
   extraction stops at the comment, the SP sees `userB@lab`. (Duo, 2018.)
4. **Parser differentials and DOCTYPE:** one library verifies with one parser
   and reads with another. ruby-saml CVE-2025-25291 and CVE-2025-25292 (ReXML
   vs Nokogiri, via DOCTYPE and namespace handling; GitHub Security Lab,
   2025-03) gave authentication bypass. "The Fragile Lock" (Fedotkin, Black
   Hat EU, 2025-12-10) adds attribute pollution (`ID` vs `samlp:ID` resolved
   differently), namespace confusion (`xmlns`/`xml` treated as ordinary
   attributes) and **void canonicalization** (a relative namespace URI makes
   libxml2 canonicalization fail, Nokogiri returns an empty string, the digest
   is over nothing). Affected per that write-up: ruby-saml before 1.18.0
   (CVE-2025-66567/-66568, mapping to technique not stated), php-saml,
   xmlseclibs before 3.1.4; XMLSec and Shibboleth xmlsectool reported not
   affected. Without a test IdP, report the version as `candidate`; with one,
   reproduce on a lab SP only.
5. **Recipient, audience, destination, time, replay:** replay an assertion
   issued for another SP or another tenant of the same IdP (both yours);
   an expired `NotOnOrAfter`; an unsolicited response with no `InResponseTo`
   (IdP-initiated acceptance); the same assertion `ID` twice. Accepted =
   the matching check is missing.
6. **Tenant and domain binding (multi-tenant SSO):** with two tenants you
   own, configure tenant 1's IdP to assert an email in tenant 2's domain.
   A session in tenant 2 means the SP does not bind IdP to domain.
7. **XXE and RelayState:** the SAML body is XML, so test it with
   `xxe.md` (OAST); `RelayState` is an open-redirect candidate.

## SCIM (RFC 7643, 7644)
Endpoints: `/scim/v2/Users`, `/Groups`, `/ServiceProviderConfig`, `/Schemas`.
Auth is a long-lived provisioning bearer token. Use only a token you
generated in your own tenant, and only create objects named `mythos-<token>`.
- **Token scope:** `GET /scim/v2/Users` with no token, with an expired token,
  and with the provisioning token of tenant 2 against tenant 1. Cross-tenant
  `GET /Users/<id>` for an id from your other tenant. Does the provisioning
  token reach non-SCIM APIs?
- **Verification bypass:** `PATCH`/`PUT` `emails`, `userName`, `externalId`,
  `active`, `roles` on a user you created. Does an email set by SCIM count
  as verified, skip the confirmation mail, or allow password reset to a
  new address? Does it take over the address another test user holds?
- **Identity collision:** provision a user with an `externalId` or `userName`
  equal to an existing identity's key. Grafana CVE-2025-41115 mapped a numeric
  `externalId` to the internal numeric user id, so a SCIM client could
  override or impersonate an existing user including an admin (Grafana
  Enterprise and Cloud with SCIM enabled, 12.x; disclosed 2025-11, exact
  version range not confirmed here). Test in your own instance: create a
  second admin-role test user, provision `externalId:"<its id>"`, then check
  whether the new identity inherits that user's id or role. Control: a
  non-numeric `externalId`.
- **Filters:** `filter=userName eq "..."` with a quote or `or` clause is an
  injection candidate (use `sql-injection.md` oracles).

## What does not count as proof
A modified assertion rejected with a clear error; a `302` to the ACS without
a session; SAML metadata exposure; a library version match with no
reproduction (`candidate`); a SCIM `200` that created only your own object;
SCIM `ServiceProviderConfig` readable without a token.

## Remediation
Verify the signature over the exact element you read, with the configured IdP
key only; use one XML parser for verification and consumption; reject DOCTYPE,
duplicate IDs and comments in `NameID`; check `Audience`, `Recipient`,
`Destination`, `InResponseTo`, time bounds and assertion id replay; bind IdP
to tenant and domain. SCIM: tenant-scoped, rotated tokens; never map
`externalId` to internal keys; treat SCIM-set emails as unverified.

## Sources
- Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be", USENIX Security 2012 (2012-08)
- Duo Security (Kelby Ludwig), SAML comment-injection disclosure (2018-02)
- GitHub Security Lab, "Sign in as anyone: Bypassing SAML SSO authentication
  with parser differentials" (ruby-saml CVE-2025-25291, CVE-2025-25292) (2025-03)
- PortSwigger Research, "The Fragile Lock: Novel Bypasses For SAML
  Authentication", Black Hat EU 2025-12-10 (post updated 2026-01-21);
  SimpleSAMLphp advisory 202512-01 (2025-12)
- Grafana Labs advisory, CVE-2025-41115 (2025-11)
- RFC 7643, 7644, SCIM (2015-09)
