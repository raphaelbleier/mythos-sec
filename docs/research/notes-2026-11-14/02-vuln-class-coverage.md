# Web vulnerability class taxonomy and coverage gaps (as of 2026-11-14)

Method note: about 17 tool calls; mostly primary pages (OWASP, MITRE, PortSwigger). Several sources I wanted (HackerOne per-class shares, Bugcrowd VRT categories, Intigriti 2025 report, WSTG 5.0, Kettle 2026 paper) could not be read in detail. Every "Unsourced" item below is from my training knowledge or judgement, not verified this session. Capability descriptions only.

## 1. Authoritative coverage: what do OWASP, CWE, VRT and HackerOne currently say?

### Takeaway
Access control is #1 everywhere (OWASP A01, CWE-862/863/639/284, Bugcrowd, HackerOne). OWASP 2025 moved SSRF into A01 and added supply chain (A03) and exceptional-condition handling (A10). XSS and SQLi still top the CWE list. API Top 10 is still 2023. WSTG is still 4.2. ASVS is 5.0.

### Cited Findings
- OWASP Top 10 2025: A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, A10 Mishandling of Exceptional Conditions — [top10.owasp.org/2025](https://top10.owasp.org/2025)
- SSRF (own category A10 in 2021) was folded into A01 in 2025; A03 and A10 are the two new categories — [Fastly/Outpost24 summaries via search](https://outpost24.com/blog/owasp-top-10-2025-what-changed) (secondary source)
- CWE Top 25 2025 (CISA/MITRE, published 11-12 Dec 2025; 39,080 CVE records): 1 XSS (79), 2 SQLi (89), 3 CSRF (352), 4 Missing Authorization (862), 5 OOB write, 6 Path Traversal (22), 9 OS Command Injection (78), 10 Code Injection (94), 12 Unrestricted Upload (434), 15 Deserialization (502), 17 Incorrect Authorization (863), 19 Improper Access Control (284), 20 Info Exposure (200), 21 Missing Authentication (306), 22 SSRF (918), 23 Command Injection (77), 24 Authorization Bypass via User-Controlled Key / IDOR (639), 25 Allocation of Resources Without Limits (770) — [MITRE 2025 Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
- Missing Authorization rose five places to 4th — [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/top-25-dangerous-software/)
- OWASP API Security Top 10: 2023 edition (released 7 Jun 2023) is still current; API1 BOLA, API10 Unsafe Consumption of APIs. No 2026 update found — [42Crunch](https://42crunch.com/the-owasp-api-security-top-10-has-been-updated-how-are-companies-reacting/) (secondary; official page not checked)
- ASVS 5.0.0 released 30 May 2025 at Global AppSec EU; 17 chapters (V1 Encoding & Sanitization to V17 WebRTC), about 350 requirements; new chapters include Web Frontend Security, Self-Contained Tokens, OAuth/OIDC, WebRTC — [Global AppSec EU sched](https://owasp2025globalappseceu.sched.com/event/1whCc/introducing-the-50-release-of-the-asvs), [SoftwareMill](https://softwaremill.com/whats-new-in-asvs-5-0/)
- WSTG: latest stable still v4.2 (Dec 2020); v5.0 in progress, no new test list found — [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/latest/1-About/)
- Bugcrowd VRT is at version 1.19 (page gives no date or categories) — [Bugcrowd VRT](https://bugcrowd.com/vulnerability-rating-taxonomy)
- Bugcrowd "Inside the Mind of a CISO 2025": broken access control now the leading category after a 36% rise in critical-rated BAC; critical payouts up 32% on average; hardware vulns +88%, network doubled — [Bugcrowd](https://www.bugcrowd.com/resources/report/inside-the-mind-ciso-resilience-in-an-ai-accelerated-world/)
- HackerOne 9th report (1 Jul 2024 - 30 Jun 2025, released 1 Oct 2025): $81M payouts (+13%), average bounty $1,090, prompt injection +540%; XSS declined from peak while access control, IDOR variants and misconfigurations grow and pay better — [HackerOne](https://www.hackerone.com/blog/2025-hpsr-researcher-signals)
- HackerOne 10th report (data Jul 2025 - Jun 2026): $89.1M bounties, 92,194 valid reports, valid AI reports +222% over two years, source-code vuln reports tripled, open valid reports +131% since 2024 — [HackerOne](https://www.hackerone.com/reports/6th-annual-hacker-powered-security-report) (URL slug says "6th", page text says 10th edition; inconsistent, treat figures with care)
- Older HackerOne top-10 page: XSS top class in bounty programs, misconfiguration top in pentests (older data, June 2022 - June 2023) — [HackerOne Top 10](https://www.hackerone.com/top-10-vulnerabilities)
- Intigriti: XSS was 2nd most common High/Critical in 2023 (10.5%); 14% of 2024 vulns were misconfiguration — [Intigriti](https://www.intigriti.com/blog/business-insights/software-industry-top-vulnerabilities-in-2024-and-what-to-watch-for-in-2025)

### Inferences
- A framework that tests only injection-style classes misses the fastest-growing, best-paid classes (access control, ATO chains, misconfig, supply chain).
- OWASP A10 (exceptional conditions: fail-open, verbose errors, error-driven oracles) lines up with the 2025 PortSwigger #1 (error-based SSTI).

### Gaps
- No per-class HackerOne/Bugcrowd/Intigriti share or payout table for 2025-26 was retrievable. Bugcrowd VRT P1-P5 per class not read. Official OWASP API and WSTG pages not directly verified.

## 2. PortSwigger Top 10 Web Hacking Techniques

### Takeaway
2024 list is dominated by parser/semantic ambiguity, smuggling, OAuth/cache chains and new UI redressing. 2025 list (published 5 Feb 2026) is about error-based and blind oracles, parser differentials, normalization and client-side leaks. Common thread: differential or side-channel observation, not payload spraying.

### Cited Findings
2025 list (published 5-6 Feb 2026; "testing needs" are my inference from the descriptions) — [PortSwigger](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025):
1. Successful Errors: New Code Injection and SSTI Techniques (Korchagin): error-based blind SSTI, polyglot detection. Needs blind template-sink handling and error observation.
2. ORM Leaking More Than You Joined For (Alex Brown): generalised ORM leak via filter/search params. Needs relational-filter probing and boolean/timing oracles.
3. Novel SSRF Technique Involving HTTP Redirect Loops (@shubs): makes blind SSRF visible. Needs controllable redirect server.
4. Lost in Translation: Exploiting Unicode Normalization (Barnett): post-validation normalization bypass. Needs Unicode variant probing.
5. SOAPwn (Bazydlo): .NET Framework HttpWebClientProtocol/WSDL to RCE. Needs .NET SOAP client detection.
6. Cross-Site ETag Length Leak (Kaneko): XS-Leak via ETag. Needs browser-side harness.
7. Next.js, cache, and chains: the stale elixir (Allam): internal cache poisoning chain. Needs framework fingerprint and cache probing.
8. XSS-Leak: Leaking Cross-Origin Redirects (Abello): Chrome connection-pool oracle. Browser harness.
9. Playing with HTTP/2 CONNECT (@flomb): proxy CONNECT abuse, internal port scan. Needs raw HTTP/2 client.
10. Parser Differentials (@joernchen): two components parsing one input differently. Needs differential testing across proxy/backend.
- Honorable mention: HTTP/1.1 Must Die: the desync endgame (Kettle), excluded by the author from the ranking.
- Nomination list (62 entries) is itself a checklist: SAML bypasses, funky chunks smuggling, Cross-Site WebSocket Hijacking in 2025, SVG filter clickjacking, nonce-CSP bypass via disk cache, CSS exfiltration/Fontleak, extension clickjacking, Google Cloud ATO via URL parsing confusion, OpenSSL AEAD misuse, ASP.NET view engine search patterns, CRLF response splitting CSP gadget, IngressNightmare (CVE-2025-1974), ReDisclosure (MySQL full-text), Python arbitrary file write to RCE, SharePoint ToolShell (CVE-2025-53770), prompt injection in GitHub Actions, OAuth authorization code injection / BFF, PDF generator SSRF/LFI, impossible XXE in PHP, blind SSTI, zip path traversal "disguises", Gemini multi-layer attacks, self-XSS escalation, Vega toString gadget XSS, Ruby Array Pack bleed, QuicDraw HTTP/3 fuzzing, Client-Side Path Traversal (CSPT), PermissionJacking, MadeYouReset (HTTP/2), passkey/FIDO auth bypass (CVE-2025-26788), PDO prepared-statement SQLi, WebSocket server-side fuzzing, syntax confusion, bash $RANDOM weakness — [PortSwigger nominations](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025-nominations-open)

2024 list (published 4 Feb 2025) — [PortSwigger](https://portswigger.net/research/top-10-web-hacking-techniques-of-2024):
1. Confusion Attacks in Apache HTTP Server (Orange Tsai): semantic ambiguity between modules. Needs Apache version/module fingerprint.
2. SQL Injection Isn't Dead: Smuggling Queries at the Protocol Level (Gerste): driver integer overflow/protocol smuggling. Source/driver-level review, not payload fuzzing.
3. TE.0 HTTP Request Smuggling (Arnolfo et al.): Google Cloud-hosted sites. Needs raw HTTP/1.1 smuggling probes.
4. WorstFit: Windows ANSI hidden transformers (Orange Tsai, splitline): best-fit character conversion. Windows backends, argument injection.
5. DOMPurify bypasses (Mizu): mutation XSS. Needs sanitizer version check and mXSS corpus.
6. DoubleClickjacking (Yibelo): beats frame restrictions and SameSite. Browser-driven PoC.
7. CVE-2024-4367 PDF.js arbitrary JS (Rinsma): outdated embedded library. Dependency/version detection.
8. OAuth Non-Happy Path to ATO (Oxrz): Referer handling in OAuth error path.
9. ChatGPT ATO via Wildcard Web Cache Deception (Harel): path-decoding mismatch vs cache rule.
10. Hijacking OAuth flows via Cookie Tossing (Ward): subdomain cookie scoping.
- 2025 additional nominee context: HTTP/2 timing attacks ("web timing attacks that actually work"), Ruby-SAML/GitLab bypass CVE-2024-45409 appear on the poll page, final rank unconfirmed — [PortSwigger poll](https://portswigger.net/polls/top-10-web-hacking-techniques-2024)
- 2026 (outside the Top 10 cycle): Kettle's "Can AI do novel security research? Meet the HTTP Terminator" at Black Hat USA and DEF CON 34, Aug 2026: autonomous system (ideation, evaluation, weaponization, cascade) that found new HTTP desync triggers/gadgets; to be open-sourced — [PortSwigger](https://portswigger.net/research/can-ai-do-novel-security-research). Gareth Heyes "CSS: the bomb inside your inbox" Black Hat 5 Aug 2026 (content not read).

### Inferences
- Roughly half of 2024-25 entries need a differential or oracle (observe two parsers or a side channel). A generic scanner that only matches signatures cannot find them.
- Each list's top entries are framework/server-specific (Apache, Next.js, .NET). A fingerprint-driven technique selector is more valuable than a flat checklist.

### Gaps
- Vote scores and the full 2025 expert ranking rationale not read. Kettle 2026 paper details not read.

## 3. Per-class proof standard and newest twist

### Takeaway
Cited material covers SSTI, ORM leak, SSRF, Unicode, cache, smuggling, clickjacking, OAuth, XS-Leaks. Other classes below are unsourced training knowledge and need verification before they go into a spec.

### Cited Findings (class: twist)
- SSTI: error-based and polyglot detection for blind sinks (2025 #1) — see section 2.
- SQLi: protocol-level smuggling (2024 #2); PDO prepared-statement injection and MySQL full-text "ReDisclosure" nominated 2025 — section 2.
- ORM/filter-based data leakage (2025 #2) — section 2.
- SSRF: redirect-loop trick to see blind responses; HTTP/2 CONNECT abuse; URL parsing confusion on Google Cloud; PDF generators as SSRF/LFI sinks — section 2.
- Unicode normalization and parser differentials as WAF/validation bypass (2025 #4, #10) — section 2.
- Cache: wildcard cache deception (2024 #9), Next.js internal cache poisoning (2025 #7) — section 2.
- HTTP/2 and 3: H2 CONNECT, MadeYouReset, QuicDraw H3 fuzzing, TE.0, funky chunks, desync endgame — sections 2 and nominations.
- Clickjacking: DoubleClickjacking (2024 #6), SVG-filter clickjacking and extension (password manager) clickjacking nominated 2025.
- CSRF in a SameSite world: cookie tossing for OAuth (2024 #10); Cross-Site WebSocket Hijacking in 2025 nominated.
- OAuth: Referer/non-happy-path ATO, authorization code injection, BFF discussion — section 2.
- Client-side: DOMPurify mXSS, Client-Side Path Traversal (CSPT), CSS/font exfiltration, nonce-CSP bypass via disk cache, self-XSS escalation, XS-Leaks (ETag, redirect leak) — section 2.
- Supply chain on CI: prompt injection inside GitHub Actions nominated 2025; OWASP 2025 A03 — sections 1-2.
- Passkeys/FIDO and SAML bypasses nominated 2025 — section 2.
- File upload/path traversal: zip "disguises" path traversal nominated; CWE-434 rank 12, CWE-22 rank 6 — sections 1-2.
- IDOR at scale: CWE-639 rank 24; HackerOne says IDOR variants growing and pay better — section 1.

### Inferences (unsourced, from training knowledge; verify)
- Proof standards that bounty triagers accept: SSRF needs an OAST callback plus a content read or cloud-metadata/internal-service access to rate above low. File upload/traversal needs a read or write of a canary file outside the intended root, not just an accepted filename. CSRF needs a state-changing cross-site request that survives SameSite=Lax (top-level GET, 2-minute Lax+POST window, same-site subdomain) and a missing token/Origin check. CORS needs credentialed cross-origin read of sensitive data, not just reflected ACAO. Host-header/password-reset poisoning needs a received email with attacker-controlled link host. 2FA bypass needs a session reaching an authenticated resource without the second factor (response manipulation, code reuse, no rate limit, backup-code/recovery path, OAuth sign-in skipping MFA). Subdomain takeover needs a claimed resource serving a canary, with fingerprint plus provider claimability. Secrets in JS/source maps need a live-validated credential (read-only check) rather than a regex hit. Dependency confusion needs an unclaimed internal package name plus a callback. Prototype pollution needs a gadget with an observable effect. GraphQL needs introspection/suggestion/alias-batching/field-level authz tests. Open redirect is mostly bountied only as a chain link (OAuth token theft, SSRF filter bypass). Clickjacking pays only on sensitive one-click state change with missing framing protection, and DoubleClickjacking widens that.
- WAF bypass is a methodology (encoding/normalization/parser differential, origin discovery, protocol-level tricks), so it belongs in the exploit-proof loop, not as a standalone class.

### Gaps
- No sourced number for payouts per class in 2025-26. DNS rebinding, email header injection/SMTP smuggling, SSE, GraphQL-specific 2025-26 research, and dependency confusion: no sources retrieved.

## 4. What do scanners and agents miss, and what gets paid?

### Takeaway
Agents and scanners reliably find reflected XSS, SQLi, SSRF with callbacks and known CVEs; they miss IDOR/BOLA, broken authorization, business logic and anything needing multi-role context or rule knowledge. Vendor benchmarks, not neutral.

### Cited Findings
- Generic AI pentesting reliably finds reflected XSS, SQLi, SSRF, known-CVE exposure; logic, IDOR, authorization fall outside pattern matching — [Stingrai, Jun 2026](https://www.stingrai.io/blog/traditional-pentesting-vs-ai-pentesting-2026) (vendor)
- Agent caught IDOR/BOLA only when it could test as more than one user — [Strobes, Jun 2026](https://strobes.co/blog/ai-pentesting-business-logic-flaws/) (vendor)
- Aikido reported 49 verified vulns vs XBOW 31 on the same two apps; tools agreed on under 10% of findings — [NHIMG summarising Aikido, 6 Apr 2026](https://nhimg.org/articles/autonomous-pentesting-changes-how-teams-find-logic-flaws-in-saas/) (secondary, vendor)
- Only one of five tools caught an unauthenticated update flaw found through spec-level access analysis (20-flaw app, Apr 2026) — [Escape](https://escape.tech/blog/benchmarking-agentic-ai-pentesting-tools/) (vendor)
- Broken access control is the leading Bugcrowd category and growing; HackerOne says access control/IDOR pay better and XSS is declining — section 1.

### Inferences
- Low overlap between tools means classes are covered unevenly across tools; coverage is a property of the technique list, not of the model.

### Gaps
- No neutral miss-rate numbers; no per-class bounty totals.

## 5. Mythos coverage matrix

Mythos has: recon, generic scanning (nuclei/dalfox/sqlmap/nikto), exploit proof, multi-role sessions, business logic (BOLA/BFLA/mass assignment/race/workflow), stored+blind XSS with OAST, deserialization/XXE/cache poisoning/request smuggling, OAuth/OIDC, multi-tenant isolation, LLM prompt injection, grey-box source review, CVE deep dive, drift watch.

Not in that list (plain statement; some may be partly hit by nuclei or recon templates, but no dedicated skill):
SSRF (incl. blind, redirect-loop, cloud metadata, DNS rebinding); SSTI/code injection (error-based, blind); advanced SQLi/NoSQL/ORM-leak/second-order; file upload and archive/path traversal; CSRF/SameSite and CSWSH; CORS; clickjacking/DoubleClickjacking; open redirect chains; host header, password-reset poisoning, email header injection; 2FA/MFA, passkey, SAML, JWT/session-token attacks and ATO chains; web cache deception (distinct from poisoning); HTTP/2, H2 CONNECT, HTTP/3 specifics; WebSocket and SSE; prototype pollution; GraphQL; subdomain takeover; secrets in JS/source maps; dependency confusion and CI/CD/supply chain; Unicode/parser-differential and WAF-bypass methodology; client-side classes (mXSS/DOMPurify, CSPT, XS-Leaks, CSP bypass, cookie tossing); rate-limit/resource exhaustion (CWE-770); mishandling of exceptional conditions (A10); exposed config/debug/admin and default creds (A02); PDF/SVG/image processor sinks; agent/MCP tool abuse beyond prompt injection.

## Ranked missing classes (bounty value x prevalence; ranking is my judgement, evidence in sections 1 and 4)
1. SSRF (A01 now, CWE-918, cloud-metadata impact)
2. ATO chains: password reset/host header poisoning, 2FA/MFA bypass, SAML/JWT/passkey, cookie tossing
3. File upload and path traversal/archive extraction (CWE-434, CWE-22)
4. Injection beyond sqlmap: SSTI (blind/error-based), NoSQL, ORM leak, command/code injection
5. Secrets in JS bundles/source maps and exposed config/debug endpoints (A02)
6. Subdomain takeover and dependency confusion/CI-CD supply chain (A03)
7. CSRF/SameSite, CORS, CSWSH
8. GraphQL
9. Web cache deception and HTTP/2-3 protocol issues
10. Prototype pollution and client-side classes (mXSS, CSPT, CSP bypass, XS-Leaks)
11. Open redirect (as chain link), clickjacking/DoubleClickjacking, WebSocket/SSE
12. Rate-limit/resource exhaustion, exceptional-condition handling, WAF-bypass/Unicode methodology as cross-cutting
