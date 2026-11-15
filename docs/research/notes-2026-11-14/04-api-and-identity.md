# API, authentication and authorization testing for web targets (as of 2026-11-14)

Scope: technique and tooling level. Authorized testing only. DoS-risky techniques are flagged "[DoS risk]".
Method note: ~20 tool calls; many web hits were vendor blogs or skill-registry pages and are marked low authority. Where a claim comes only from the agent's general knowledge (no fetched source) it is placed under Inferences, not Cited Findings.

## 0. What Mythos already has (correcting the brief)

### Takeaway
The brief's "no GraphQL, SAML/SCIM, webhook, single-packet" is only half right. Mythos has knowledge notes (prose playbooks) for all four, plus graphw00f in the image. What is missing is skill wiring, scripts and tooling: nothing runs graphql-cop/Clairvoyance/InQL, no SAML/SCIM script, no webhook script, no gRPC/tRPC/JSON-RPC/OData/SOAP/Server-Action/passkey/impersonation/HMAC-signing/mTLS/token-exchange coverage, and race.py depends on h2spacex that is "not in the image".

### Cited Findings
- `knowledge/web/graphql-api.md` (73 lines) covers discovery, introspection, field-suggestion/Clairvoyance, alias and array batching for rate-limit/OTP bypass, per-field authz, subscriptions auth at connection_init, GET/urlencoded CSRF, persisted queries, depth/cost; it states "Mythos has no GraphQL-aware scanner... manual here" — local repo, `/home/bleier/Documents/Programming/mythos-sec/knowledge/web/graphql-api.md`
- `knowledge/web/saml-scim-sso.md` (126 lines) covers unsigned acceptance, XSW1-8, comment injection, parser differentials incl. ruby-saml CVE-2025-25291/25292 and "The Fragile Lock", and a SCIM section; needs your own test IdP — local, `.../knowledge/web/saml-scim-sso.md`
- `knowledge/web/webhooks.md` (80 lines): receiver signature checks (wrong sig, empty secret, non-constant-time compare) and sender SSRF — local, `.../knowledge/web/webhooks.md`
- `knowledge/web/race-conditions.md` + `skills/business-logic/scripts/race.py`: sequential vs parallel wave; single-packet via h2spacex "when installed (not in the image)", else last-byte sync — local, `.../knowledge/web/race-conditions.md`
- Also present: `framework-nextjs-rsc.md`, `mass-assignment.md`, `auth-flows-ato.md` (MFA, session fixation, reset), `oauth-oidc.md`, `jwt.md`, `multi-tenant-isolation.md`, `techniques/auth-matrix.md`.
- Toolbox pins: nuclei v3.11.1, httpx, katana, ffuf, jwt_tool, graphw00f, smuggler.py; h2spacex is a module imported by race.py; no graphql-cop, clairvoyance, InQL, grpcurl, schemathesis, arjun-in-tools.txt, SAML Raider/XSW — local, `.../toolbox/tools.txt`
- Prior repo research already notes Schemathesis supports OpenAPI/GraphQL/gRPC(reflection) and that nuclei race semantics are unverified — local, `.../docs/research/notes-2026-11/auth_business_logic_automation.md`
- grep for gRPC, tRPC, JSON-RPC (except MCP), OData, passkey/WebAuthn, HMAC request signing, mTLS, token exchange (except one MCP line), impersonation (only as an auth-matrix verb), TE.0 across `knowledge/` and `skills/` returned no dedicated coverage.

### Inferences
- Gap type is "operationalization", not "knowledge" for GraphQL/SAML/webhooks/race: write skills + scripts that call the tools and encode the oracles already described.
- The real knowledge gaps are the non-HTTP-JSON RPC families and modern identity features (below).

### Gaps
- Did not read `framework-nextjs-rsc.md` in depth; Server Action coverage depth unverified.

## 1. GraphQL

### Takeaway
A solid toolchain exists (graphw00f fingerprint, graphql-cop checks, Clairvoyance schema recovery, InQL, Schemathesis for schema-driven fuzzing), but all real value is in authorization tests per field/role, which no tool does without a role-aware harness. Several graphql-cop checks are DoS-shaped and must be capped.

### Cited Findings
- graphql-cop checks: alias overloading, batch queries, GET-based queries (CSRF), POST urlencoded (CSRF), tracing/debug, field duplication, field suggestions, GraphiQL, introspection, directive overloading, circular query via introspection, mutation over GET; DoS-risky ones: alias overloading, batch, field duplication, directives overloading, circular introspection; `-o json` gives `curl_verify` per finding; `-e` excludes tests, `-l` lists — [graphql-cop](https://github.com/dolevf/graphql-cop)
- graphw00f fingerprints the GraphQL engine; Clairvoyance rebuilds schema from field-suggestion errors with a wordlist when introspection is off; InQL (Doyensec) is the Burp/CLI introspection tool; BatchQL does batching attacks — [search summary, low authority](https://sallam.gitbook.io/sec-88/api-sec/graphql-api-security-testing/graphql-hacking-tools); [Strobes guide](https://strobes.co/blog/graphql-security-testing-guide)
- Schemathesis v4.21.0 (2026-05-31) lets GraphQL operations chain via non-id identifiers (fullPath, slug) in stateful phases; one reviewer says GraphQL support is less mature than OpenAPI — [yrkan release notes](https://yrkan.com/tools-updates/schemathesis-v4-21-whats-new/); [aicoolies review](https://aicoolies.com/reviews/schemathesis-review)
- Escape claims 100+ GraphQL tests and "+63% more complex true positives vs legacy DAST" (baseline unnamed); no independent benchmark vs ZAP found — [Escape](https://escape.tech/graphql-security); [Escape guide](https://escape.tech/blog/best-graphql-security-tools/)
- JSON-RPC/GraphQL-style batches can mix authorized and unauthorized calls; per-call authz inside the batch is the failure — [StackHawk JSON-RPC](https://www.stackhawk.com/blog/json-rpc-security-best-practices/)

### Inferences
- Agent flow: graphw00f -> introspection probe -> (if off) clairvoyance with suggestion check -> schema to typed op list -> role matrix (anon/userA/userB/admin) over every Query/Mutation field and nested path -> compare with REST twin. Batching/alias checks run with N<=10 and a single-request control (already specified in graphql-api.md); run graphql-cop with `-e` excluding alias/field-duplication/directive/circular tests by default [DoS risk].
- Alias depth/complexity DoS stays a "show the limit is absent via latency slope on own data" check, never a bomb.
- Engine-specific checks (Hasura admin-secret/role headers `x-hasura-role`, Apollo persisted queries APQ, graphql-ws vs subscriptions-transport-ws) from general knowledge; not source-verified here.

### Gaps
- graphql-cop DoS thresholds (100 aliases / 1000 fields) come from README examples; no independent accuracy data on any GraphQL scanner.
- No verified nuclei GraphQL template inventory (did not fetch nuclei-templates tree).

## 2. gRPC, gRPC-web, Connect, tRPC, JSON-RPC, OData, SOAP, Server Actions

### Takeaway
Enumeration path per family differs, and Mythos covers none except Server Actions partly. Reflection (grpcurl) or proto recovery from JS bundles gets gRPC/gRPC-web; tRPC and JSON-RPC are batching-authz problems; Next.js Server Actions need action-ID harvesting.

### Cited Findings
- gRPC: grpcurl list/describe via reflection; when reflection is off recover .proto from mobile app, JS, or source maps; tools grpcurl, grpcui, evans, buf, protoc; Burp does not intercept gRPC out of the box; attack areas: protobuf fuzzing, missing authz on streaming RPCs, gRPC-Web to backend SSRF, mTLS bypass, metadata header injection, h2c smuggling; NCC Group "Attacking gRPC" is the reference whitepaper (low-authority skill-registry aggregation, verify) — [Decepticon api-grpc](https://tessl.io/registry/skills/github/PurpleAILAB/Decepticon/api-grpc); [hackviser](https://hackviser.com/tactics/pentesting/services/grpc)
- gRPC-Web: `nxenon/grpc-pentest-suite` handles `application/grpc-web-text` and `grpc-web+proto`, has a scanner that extracts endpoints/services/messages/fields from webpacked JS and a Burp extension; protoscope for hand-editing frames — [grpc-pentest-suite](https://github.com/nxenon/grpc-pentest-suite)
- HTTP/2 connection reuse makes per-request rate limiting on gRPC brittle (low-authority) — [Decepticon api-grpc](https://tessl.io/registry/skills/github/PurpleAILAB/Decepticon/api-grpc)
- tRPC: endpoints look like `/api/trpc/<router>.<procedure>` with `batch` query parameter (httpBatchLink); protected procedures often check login only, not role; a real batch bug passed authz when any one id in the array belonged to the caller; CVE-2025-68130 is prototype pollution giving authz bypass in the Next.js App Router caller (tRPC 10.27.0 up to <10.45.3 and <11.8.0) — [LogicalHunter](https://medium.com/@LogicalHunter/trpc-security-research-hunting-for-vulnerabilities-in-modern-apis-b0d38e06fa71); [Conar write-up](https://hackmd.io/@hieuPenguinnn/conar-broken-ownership-cross-user-write); [OSV](https://osv.dev/vulnerability/CVE-2025-68130)
- JSON-RPC: single endpoint so authz must inspect `method`; batch arrays risk partial execution — [StackHawk](https://www.stackhawk.com/blog/json-rpc-security-best-practices/)
- Next.js Server Actions: action ID travels in the `Next-Action` header; unused actions' IDs are not in client bundles but an in-use ID can be called with any args; IDs recoverable from build output and source maps; CVE-2026-64643 (unauthenticated disclosure of Server Function IDs from public artifacts; affected 12.0.0-15.5.20 and 16.0.0-16.2.10, fixed 16.2.11 per INCIBE/GitLab entries; sources disagree on "auth bypass" vs "info disclosure"); NextjsServerActionAnalyzer is the tool; backend authz not consistently enforced is the main risk — [Arcjet](https://blog.arcjet.com/next-js-server-action-security/); [Stingrai](https://www.stingrai.io/blog/how-hidden-javascription-action-header-can-bypass-your-access-controls); [GitLab advisory](https://advisories.gitlab.com/npm/next/CVE-2026-64643/); [Red Hat](https://bugzilla.redhat.com/show_bug.cgi?id=2507626)
- Schemathesis lists OpenAPI, GraphQL and gRPC (reflection) as inputs — local `docs/research/notes-2026-11/auth_business_logic_automation.md`

### Inferences
- Proposed `rpc-api` skill with detectors: content-type `application/grpc*`, `application/connect+json`, `/api/trpc/`, `jsonrpc:"2.0"` bodies, `/odata/` + `$metadata`, `?wsdl`, `Next-Action` header. Each emits an operation list into the same Subject x Object x Action matrix used by business-logic.
- Connect (connectrpc) speaks plain JSON over HTTP POST at `/<pkg.Service>/<Method>` with `Content-Type: application/json`, so it is curl-testable without protobuf tooling (general knowledge, unsourced); reflection is separate (`grpc.reflection.v1`).
- OData: test `$metadata` disclosure, `$expand` into forbidden related entities, `$filter`/`$select` oracle on fields the caller can't read, `$batch` with mixed-auth subrequests, `$top` unbounded (general knowledge; no source found).
- SOAP: WSDL fetch, then per-operation role matrix; XXE and WS-Security signature wrapping already partly in deep-server/XXE note. (general knowledge)
- Server Actions: harvest IDs from `_next/static` chunks and source maps, replay each as anon and each role, compare. The agent already has sourcemap script.

### Gaps
- No authoritative OData security-testing source found (search returned none).
- No primary Vercel pentest guidance; NextjsServerActionAnalyzer source not opened.
- NCC "Attacking gRPC" not fetched.

## 3. REST / OpenAPI-driven testing, parameter mining, shadow APIs

### Takeaway
Mythos has OpenAPI diffing for mass assignment and arjun. Missing: spec-driven stateful fuzzing, spec-less route discovery, and version/shadow-API sweeps.

### Cited Findings
- Schemathesis: property-based, OpenAPI+GraphQL, stateful chaining from spec links; v4.19.0 (2026-05-19) reuses extracted values across operations without explicit links; latest seen v4.22.4 (2026-07-08, unverified contents) — [yrkan v4.19](https://yrkan.com/tools-updates/schemathesis-v4-19-whats-new/); [yrkan v4.21](https://yrkan.com/tools-updates/schemathesis-v4-21-whats-new/); [PyPI](https://pypi.org/project/schemathesis/4.20.2/)
- Arjun (s0md3v) discovers hidden params across methods/content types; x8 (Rust) is a faster alternative with Burp ext; wordlist quality is the main limiter — [Intigriti](https://intigriti.com/researchers/blog/hacking-tools/finding-hidden-input-parameters); [x8 docs](https://docs.rs/crate/x8/4.3.1/source/README.md)
- BOLABuster (Unit 42) takes only an OpenAPI 3 spec: identifies endpoints with object-id parameters, labels producer/consumer endpoints, builds dependency trees, LLM-writes two-user bash scripts, orders destructive calls last; found CVE-2024-1313 (Grafana), CVE-2024-22278 (Harbor) and 15 Easy!Appointments endpoints; RESTler with default config found none — [Unit 42](https://unit42.paloaltonetworks.com/automated-bola-detection-and-ai/); [Thinkst/SecTor summary](https://citation.thinkst.com/talk/94257)

### Inferences
- Add: (a) Schemathesis run with `--checks` limited to non-5xx-spam, rate-capped, against a lab/staging clone only for negative tests; (b) producer/consumer dependency graph (BOLABuster idea) to build valid object ids rather than guessing; (c) shadow-API sweep: version swap `/v1`->`/v2`/`/v0`/`/internal`, spec-vs-traffic diff (endpoints seen in HAR/JS but not in spec), method swap (OPTIONS/PUT/PATCH/DELETE), `Accept`/`Content-Type` swap.
- Kiterunner (route wordlists from Swagger corpora) is the standard spec-less API discovery tool but I found no source in this run; katana + JS endpoint extraction + ffuf with an API wordlist is the in-image substitute.
- Param Miner is Burp-only; arjun/x8 are the headless equivalents.

### Gaps
- Kiterunner and shadow-API discovery returned no results; no accuracy numbers for any parameter miner.

## 4. Identity

### Takeaway
OAuth/JWT/SAML/MFA/session are covered as notes. Biggest identity holes: SAML tooling (no test IdP/XSW harness), SCIM execution, passkeys/WebAuthn, token exchange/refresh-rotation depth, impersonation, mTLS, API-key and HMAC request-signing checks.

### Cited Findings
- RFC 9700 (BCP 240, Jan 2025) is the current OAuth security BCP, updating RFC 6749/6750/6819; OAuth 2.1 is still an Internet-Draft (draft-ietf-oauth-v2-1-16, Sept 2026 seen; a -17 is mentioned unverified), so cite RFC 9700 as the normative checklist — [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html); [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
- SAML "The Fragile Lock" (Fedotkin, Black Hat EU Dec 2025): attribute pollution (`ID` vs `samlp:ID`), REXML `xmlns`/`xml` namespace confusion hiding Signature from XPath, "Void Canonicalization" (relative namespace URI makes libxml2 c14n fail so digest is over empty input, reusable to forge a Golden SAML Response), signed IdP error messages as signature source; affects ruby-saml <1.18.0 (CVE-2025-66567/66568), php-saml, xmlseclibs (<3.1.4); XMLSec and Shibboleth xmlsectool not affected; demo on GitLab EE 17.8.4; Burp extension at d0ge/XSW; SAML Raider support "to come"; Okta said it would not change signing behaviour — [PortSwigger](https://portswigger.net/research/the-fragile-lock)
- Earlier: "SAML roulette" (Mar 2025) DTD-handling XSW on ruby-saml — [PortSwigger search result](https://portswigger.net/research/articles)
- Passkeys: many RPs ignore or mis-handle signCount, and some synced-passkey providers always return 0; origin check omissions and over-broad RP ID are implementation bugs; downgrade to fallback methods (e.g. spoofed unsupported browser causing Entra ID to disable passkeys, Proofpoint via THN Oct 2025) and account recovery (attacker adds own passkey) are the best-documented weak points; USENIX Sec 2021 Ulqinaku et al. on FIDO downgrade (second-hand) — [uzyn](https://uzyn.com/2025/passkey-has-a-theft-detection-feature-but-big-tech-broke-it/); [hivesecurity](https://hivesecurity.gitlab.io/posts/passkey-phishing-webauthn-flaws); [The Hacker News](https://thehackernews.com/2025/10/how-attackers-bypass-synced-passkeys.html); [Scott Helme](https://scotthelme.co.uk/bringing-in-the-experts-having-our-passkeys-implementation-security-tested/)
- Existing repo coverage for SCIM, MFA, session fixation, JWT alg confusion, OAuth redirect/state/PKCE — local `knowledge/web/{saml-scim-sso,auth-flows-ato,jwt,oauth-oidc}.md`

### Inferences
- SAML: ship a skill that (1) fetches metadata, (2) decodes SAMLResponse, (3) runs the existing XSW/unsigned list plus Fragile Lock variants via d0ge/XSW or SAML Raider in the toolbox, (4) uses a local test IdP (the note already says one is needed; e.g. a containerised SimpleSAMLphp/Keycloak/samltest-style IdP is an engineering choice, unresearched). Fingerprint library+version, then match to CVE list as `candidate`.
- JWT nested JWS/JWE, `jku`/`x5u`/`kid` injection, `crit`, psychic-signature (CVE-2022-21449) already in jwt.md; add JWKS-cache/`kid` SSRF via OAST.
- Passkey checks an agent can do without a hardware key: use a virtual authenticator (Chrome DevTools WebAuthn / Playwright CDP) to register, then test (a) origin/RPID acceptance by replaying assertion from another origin, (b) challenge reuse, (c) signCount rollback acceptance, (d) fallback path availability (password/SMS/email) after passkey enrol, (e) recovery adds passkey without re-auth, (f) credential-id enumeration on login begin.
- Others from general knowledge (unsourced): refresh-token rotation + reuse detection (replay old refresh, expect family revoke); token exchange (RFC 8693) `audience`/`actor_token` scope escalation; impersonation/"login as" endpoints: header/param used by support tooling, audit trail, privilege of impersonated session, ability to impersonate admin; SSO tenant mix-up (IdP `iss`/`tid`/`hd` checks, email-domain trust, unverified-email account merge); mTLS: cert-bound tokens (RFC 8705) and header-injected client cert (`X-SSL-Client-Cert`/`X-Forwarded-Client-Cert`) trusted from outside; API keys: scope vs role, key in URL/log, prefix enumeration; HMAC request signing: body vs canonical string mismatch, no timestamp/nonce (replay), param-order/duplicate-param canonicalization, signature accepted with `alg`/empty secret, signed header set excludes `Host`/method.
- Device-code phishing and magic links are already in oauth-audit; only the RFC 9700 mapping and `iss`/mix-up (RFC 9207) are worth ensuring.

### Gaps
- No primary W3C WebAuthn L3 or USENIX paper fetched.
- No source verified for token-exchange/impersonation/mTLS/HMAC-signing attack lists; kept as inference.
- SCIM-specific 2026 research not searched.

## 5. Authorization at scale: BOLA/BFLA automation and the false-positive problem

### Takeaway
No standard benchmark or credible independent accuracy number exists. Best published: BACFuzz (role-differential + SQL-oracle, PHP only, 16/17 known, ~26 new, but its own table implies ~30% FP) and BOLABuster (CVEs, no precision). Vendors claim <4% FP without methodology. The robust approach is differential testing with an app-state oracle, not response-similarity.

### Cited Findings
- Autorize labels results "Enforced!", "Bypassed!", "Is Enforced???"; the ambiguous bucket means response differs but control can't be judged; public pages accessed by anon are intended behaviour (FP); tools also yield false negatives — [Black Hills](https://www.blackhillsinfosec.com/finding-access-control-vulnerabilities-with-autorize); [Tevora](https://www.tevora.com/threat-blog/finding-broken-access-controls/)
- AuthMatrix: users x roles x requests matrix, flags possible FPs on expired tokens/wrong regex, but FP detection does not work in Failure Regex Mode; needs Jython — [AuthMatrix](https://github.com/anthrax3/authmatrix); [Security Innovation](https://blog.securityinnovation.com/solve-the-software-security-authorization-testing-riddle-with-authmatrix-for-burp-suite)
- ZAP has an access-control testing add-on (per OWASP WSTG); no details on its FP behaviour found — [WSTG](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema)
- BACFuzz (arXiv 2507.15984): roles logged in once, request seen only under higher role -> BFLA candidate, in all roles -> BOLA candidate; LLM picks reference params; oracle = instrumented SQL (DML with submitted value for BFLA; mutated reference in WHERE for BOLA); 20 PHP apps, 16/17 known, 26 new; table FP column sums to 11 vs 37 reported (my reading, ambiguous); limited to RBAC, DML only, PHP only, no ZAP/Burp comparison — [arXiv](https://arxiv.org/html/2507.15984v1)
- DAST-AI (SBSeg) LLM semantic filter: F1 0.80 and 0.923, FP reduction 86.4% and 50.0% (settings not mapped) — [SBSeg PDF](https://sol.sbc.org.br/index.php/sbseg/article/download/44304/44067/)
- Escape claims FP rate <3.7% (ZeroThreat quotes <=4%), no method published; Escape itself says an unexplained FP rate is a red flag — [Escape](https://escape.tech/blog/best-ai-dast-tools-2/); [Escape buyer's guide](https://escape.tech/blog/dast-tools-buyers-guide/)
- BOLABuster needs >=2 authenticated accounts, OpenAPI 3 input, human validation, ordering of destructive calls — [Unit 42](https://unit42.paloaltonetworks.com/automated-bola-detection-and-ai/)
- OWASP API Security Top 10: 2023 edition remains current; claims of a 2026 API edition are listicles; the 2026 item is the general Top 10 RC1 (Broken Access Control first) — [Qualysec](https://qualysec.com/api-security-standards/) (single secondary source), [gbhackers](https://gbhackers.com/owasp-top-10-2026/) (conflicting dates)

### Inferences
- FP controls the agent should enforce: (1) negative control = owner request replayed unchanged (baseline 200) and anon/other-user requests on a *just-created* object; (2) positive proof = other-user response contains a canary unique to owner's object, or state read-back by owner shows change (write ops); (3) classify "public by design" by checking anon access to a known-public object; (4) normalize dynamic fields before diff; (5) require same result across two repeats and two objects; (6) skip when status 200 body is a generic error envelope. Aligns with existing matrix + Auth Analyzer SAME/SIMILAR/DIFFERENT triage.
- BFLA: derive "higher-role-only" request set by crawling per role (BACFuzz) and replay under lower roles; add verb-tunnelling (`X-HTTP-Method-Override`, method swap) and path-normalization variants (`//`, `;`, `%2e`, case, trailing slash) for gateway-level rules.
- Report the measured confidence tier, not a vendor-style FP percentage; no honest published number can be cited.

### Gaps
- No independent head-to-head of Autorize/Akto/APIsec/Escape/ZAP on BOLA; Akto and APIsec research not found; Salt Security not searched.
- Nuclei auth templates not examined.

## 6. Rate limiting, races, idempotency, webhooks

### Takeaway
Knowledge exists; the executable pieces are weak: h2spacex not in the image (race.py falls back to last-byte sync, which Kettle measured as weaker), no rate-limit-bypass tester, no TE.0 awareness in race context, webhook playbook has no script/OAST helper.

### Cited Findings
- Single-packet attack: many HTTP/2 requests completed in one TCP packet, reported 4-10x more effective than last-byte sync, ~20-30 requests/packet — local `knowledge/web/race-conditions.md` (cites PortSwigger "Smashing the state machine", 2023)
- PortSwigger's Top 10 web hacking techniques 2025 poll lists a single-packet variant for HTTP/3 and single-packet combined with H2->H1 desync; the original single-packet article is Oct 2023 — [PortSwigger poll](https://portswigger.net/polls/top-10-web-hacking-techniques-2025)
- A Nullcon 2025 deck applies single-packet to Keycloak race conditions (third-party) — [Nullcon PDF](https://goa2025.nullcon.net/doc/goa-2025/Nullcon_2025_Your_Identity_Is_mine_v20_Presented.pdf)
- TE.0 smuggling variant in Google Cloud Load Balancer (HTTP/1.1 sites; reported session-token leakage and 0-click ATO; $8,500 bounty); no reliable Azure Application Gateway source found — [Bugcrowd](https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/)
- Webhook receiver/sender checks already in `knowledge/web/webhooks.md` (wrong sig, empty secret, constant-time compare; sender SSRF); cites GHSA-mjgf-xj26-9qf9 — local
- Existing GraphQL note: alias batching as rate-limit bypass with N<=10 own-account — local `knowledge/web/graphql-api.md`

### Inferences
- Install h2spacex (or implement single-packet via `h2` + manual last-frame withholding) in the toolbox; keep waves <=20; gate on resources the agent created. TE.0 and desync are smuggling, [DoS risk]/cross-user impact: only against self-owned connection tests, which `smuggler.py` already approximates; add TE.0 to the smuggling probe list.
- Rate-limit bypass ladder (own account, wrong credentials only): header spoof (`X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`), path/case variants, HTTP/2 multiplexing, GraphQL alias/array batch, JSON array of credentials, reset limit by successful login of own account, per-IP vs per-account. (General knowledge, unsourced.)
- Idempotency: replay same `Idempotency-Key` with different body (expect 4xx/409), concurrent same key (single effect), key reuse across users (cross-tenant replay). Unsourced.
- Webhooks: (a) receiver: replay old valid signed payload (timestamp tolerance, nonce), signature over parsed vs raw body, `Content-Type` swap, header-case/duplicate header, algorithm prefix `sha1=` downgrade; (b) sender SSRF: URL validation bypass (redirects, DNS rebinding, IPv6, `0`, decimal IPs), proof only via OAST callback and own cloud-metadata-free targets; retry storms and unbounded fan-out are [DoS risk]. Mostly covered; add script + OAST.

### Gaps
- Single-packet HTTP/3 and desync-combo details not read (poll snippet only).
- No primary data on nuclei `race: true` semantics.
- TE.0 details are from a Bugcrowd summary; PortSwigger/Kettle not fetched.

## Concrete gap list (for the report writer)

| Gap | Tool / technique |
|---|---|
| GraphQL not runnable, only a note | graphw00f (present) + graphql-cop `-o json` with DoS tests excluded + Clairvoyance + InQL CLI; per-field role matrix; Schemathesis GraphQL for schema-driven checks |
| gRPC / gRPC-web / Connect | grpcurl/grpcui/evans, grpc-pentest-suite, proto recovery from JS/source maps, protoscope, buf; per-method role matrix and streaming authz |
| tRPC / JSON-RPC / OData / SOAP | batch-per-call authz (tRPC `batch=1`, JSON-RPC arrays), OData `$metadata/$expand/$filter/$batch`, WSDL operation matrix |
| Next.js Server Actions | harvest `Next-Action` IDs from chunks/source maps, replay per role; patch-level check vs CVE-2026-64643 |
| Spec-driven fuzzing and dependency graph | Schemathesis (stateful), BOLABuster-style producer/consumer graph |
| Shadow/undocumented APIs | version swaps, spec-vs-traffic diff, katana+ffuf API wordlists, Kiterunner (unverified), arjun/x8 in image |
| SAML execution | test IdP + d0ge/XSW + SAML Raider, Fragile Lock variants (void c14n, attribute pollution, REXML namespace), library/version fingerprint |
| SCIM execution | script from existing note: user create/patch/group role escalation on own tenants |
| Passkeys/WebAuthn | virtual authenticator via CDP; origin/RPID, challenge reuse, signCount, fallback downgrade, recovery |
| Refresh/token exchange/impersonation/mTLS/API-key/HMAC signing | refresh reuse detection, RFC 8693 audience/actor, impersonation endpoint review, XFCC header trust, signed-request canonicalization and replay |
| Authz FP control | canary-in-response + state read-back oracle, public-by-design control, two-object repeat; avoid similarity-only diff (Autorize "Is Enforced???") |
| Single-packet race | h2spacex in image (currently missing), waves <=20, TE.0 added to smuggling probes |
| Webhook playbook execution | replay/timestamp/algo-downgrade script + OAST for sender SSRF |
| API Top 10 reference | stay on OWASP API Top 10:2023 (no verified 2026 API edition); RFC 9700 for OAuth |
