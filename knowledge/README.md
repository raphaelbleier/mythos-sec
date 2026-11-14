# Mythos knowledge base

Per-bug-class notes the agent reads at runtime, with the `reference` tool, to
pick confirmation steps and cut false positives. A skill points at the file for
the class it is about. Add new notes by following `skills/research-ingest`. One
fact per file; keep them short, dated and sourced.

## Web
- [SQL Injection](web/sql-injection.md)
- [Cross-Site Scripting](web/xss.md)
- [Server-Side Request Forgery](web/ssrf.md)
- [Broken Access Control (BOLA/IDOR, BFLA, BOPLA, tenants)](web/access-control.md) - read for any authorization test: classes, request variations, tenant boundary, false positives.
- [Server-Side Template Injection](web/ssti.md)
- [JWT](web/jwt.md) - read when a bearer token is a JWT: alg, JWKS/jku/jwk/kid trust, nested JWE, audience and type confusion.
- [OAuth 2.0 / OIDC flows](web/oauth-oidc.md) - read at any "log in with", authorization endpoint, device or magic-link flow; used by the `oauth-audit` skill.
- [Auth flows and account takeover](web/auth-flows-ato.md) - read for password reset, 2FA/MFA, email change and verification, session fixation, enumeration.
- [CSRF, cross-site WebSocket hijacking, clickjacking](web/csrf-websocket-clickjacking.md) - read for every cookie-authenticated write, WebSocket handshake and one-click sensitive action; browser proof required.
- [SAML, SCIM and enterprise SSO](web/saml-scim-sso.md) - read when the target has SAML login, an ACS endpoint or a `/scim/v2` API; needs a test IdP.
- [JWT / OAuth / Session (moved)](web/jwt-oauth.md) - pointer to the three notes above.
- [Security headers, cookies, CORS and CSP](web/headers-cors.md) - read for CORS origin tests (null, regex, Vary, credentials) and the CSP analysis procedure.
- [Unsafe Deserialization → RCE](web/deserialization.md)
- [OS Command Injection (CWE-78)](web/command-injection.md)
- [Path Traversal & Arbitrary File Write](web/path-traversal.md)
- [Unrestricted File Upload → RCE](web/file-upload.md)
- [XXE / XML External Entity Injection](web/xxe.md)
- [GraphQL & Modern API Testing](web/graphql-api.md)
- [Race Conditions](web/race-conditions.md)
- [Mass Assignment (BOPLA)](web/mass-assignment.md)
- [Web Cache Poisoning & Deception](web/cache-poisoning.md)
- [HTTP Request Smuggling](web/request-smuggling.md)

## Techniques
Cross-cutting methodology used by the `cve-deep-dive` skill and by the web notes.
- [CVE Triage 2026 (KEV/EPSS pipeline)](techniques/cve-triage-2026.md)
- [Patch Diffing](techniques/patch-diffing.md)
- [Exploit Chaining](techniques/exploit-chaining.md)
- [Oracle building](techniques/oracle-building.md) - read before confirming any class: boolean, time, error, OOB, read-back oracles, controls and response-diff normalization.
- [Auth matrix](techniques/auth-matrix.md) - read before authorization testing: tenants x roles x objects x actions, filled from `scripts/probe`, OpenAPI, GraphQL, HAR and WebSocket.
- [State-machine abuse](techniques/state-machine-abuse.md) - read for any multi-step flow: skip, repeat, reorder, replay, tamper, parallel.

Read [`techniques/source-to-sink.md`](techniques/source-to-sink.md) when the engagement has the source as well as the target: how to trace a request-derived value to a sink by hand when `scripts/sourcemap` reports low confidence, and how to turn a source hypothesis into a live probe. A line of code is never a finding.

## cve/

`cve/` is not a playbook. It holds the committed CVE snapshot that
`scripts/cvefeed` falls back to when a live refresh fails, built from CISA KEV,
EPSS, NVD, the nuclei-template index, GHSA and OSV. Read
[`cve/README.md`](cve/README.md) for the schema, the pruning policy and the
limits of the data: a KEV entry means exploited in the wild somewhere, not that
this target is vulnerable, and EPSS is a prediction rather than evidence.
