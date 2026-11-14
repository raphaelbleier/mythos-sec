# Client-side / browser-side attack surface and browser-driven automation (as of 2026-11-14)

Scope: authorized testing, capability descriptions only. Method: ~17 tool calls, web search plus fetches of primary pages where reachable. Several primary sources were not retrievable (noted in Gaps). Local repo state verified by reading files in /home/bleier/Documents/Programming/mythos-sec.

## 1. What does Mythos already have (verify and correct the stated gap list)

### Takeaway
The stated gap list is partly stale. `knowledge/web/client-side-dom.md` (updated 2026-11-13) already holds prose playbooks for postMessage, DOM clobbering, client-side prototype pollution (source and read-back), CSP, mXSS, CSS exfiltration, client-side path traversal and open-redirect chains, plus an init-script sink hook. What is missing is executable tooling: the browser tool cannot run that hook, and there is no gadget scanner, source-map recovery, service-worker, SSE, or WebSocket-testing tool.

### Cited Findings (local repo, verified by reading files)
- Playbook exists for: sinks/sources with canary hook, postMessage from a foreign origin, DOM clobbering, client-side PP (`?__proto__[x]=1`, read back `({}).x`), CSP bypass confirmation, mXSS (version match = candidate only), CSS injection, client-side path traversal, open-redirect chains — `knowledge/web/client-side-dom.md`
- Playbook exists for CSWSH (handshake with foreign Origin) and DoubleClickjacking — `knowledge/web/csrf-websocket-clickjacking.md`
- Third-party script / SRI / lapsed-domain supply chain exists — `knowledge/web/client-side-supply-chain.md`
- `skills/stored-xss-oast/SKILL.md` has token-per-injection-point, dialog/console canary, OAST, admin-bot flow
- The agent browser tool (`cli/src/agent/browser.ts`) exposes only: goto, click, fill, text, html, eval, console, requests, screenshot. Screenshot is "not stored". Only one page; no `addInitScript`, no CDP session, no second context/origin, no cookie/storage dump, no download or websocket frame capture. So the init-script hook in client-side-dom.md is not wired to a tool the agent can call directly (it can only be approximated via `eval` after load, which misses sinks hit during page load).
- grep for service worker / ServiceWorker in knowledge, skills, cli/src: no hits. grep for source map / `.js.map` / sourceMappingURL: no hits in knowledge or skills. `scripts/sourcemap` maps a provided source tree (routes, auth guards, sinks), not recovered `.map` files.
- No SSE / EventSource playbook (grep hits only CSWSH).
- CSP: JSONP/allowlist and clobbering mentioned; no dangling-markup, nonce-reuse/bfcache, form-action, or gadget-dataset check.

### Inferences
- Revised gap list: (a) runtime instrumentation wired into the browser tool (init script, CDP, multi-origin), (b) PP gadget scanning, (c) source-map and bundle recovery, (d) service-worker, SSE, WebSocket-frame playbooks and tooling, (e) CSP-specific automated checks, (f) SPA route enumeration and authenticated headless crawl, (g) a hardened verifier. postMessage, clobbering and CSP are "playbook exists, no tool support."

### Gaps
- Did not read `skills/web-scan` or `skills/recon` in depth; they may already invoke katana or dalfox.

## 2. Current state of client-side classes (2025-2026)

### Takeaway
Classic DOM XSS is still prevalent and under-detected by non-interactive scanners (NDSS 2026). The research energy has moved to CSP bypass via browser cache behavior, CSS-only attacks, XS-leaks, and sanitizer/parser differentials. Trusted Types and the Sanitizer API reached all major engines in 2026, which changes sink behavior on adopting sites.

### Cited Findings
- NDSS 2026 SWIPE (Sabino, Cassel, Abreu, Adão, Bauer, Jia): ran on 44,480 URLs from Tranco top 30,000; prior work did not interact with the page and missed handlers needing user actions; fuzzed interactions find 15% more vulnerabilities than prior work; dynamic symbolic execution synthesised URL parameters/fragments that triggered 20 new vulnerabilities; lack of params/fragments in URLs hinders detection — [paper](https://www.ndss-symposium.org/wp-content/uploads/2026-s1467-paper.pdf)
- PortSwigger Top 10 web hacking techniques of 2025 (client-side-relevant entries): #8 "XSS-Leak: Leaking Cross-Origin Redirects" (Salvatore Abello, Chrome connection-pool oracle), #7 Next.js cache poisoning chain (Rachid Allam), #6 "Cross-Site ETag Length Leak" (Takeshi Kaneko). The rest are server-side (parser differentials, HTTP/2 CONNECT, SOAPwn, Unicode normalization, SSRF redirect loops, ORM leaks, error-based SSTI) — [PortSwigger](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025) (list as relayed by a page summariser; entries not independently cross-checked)
- Gareth Heyes, "Blind trust: stealing credentials through CSP" (2026-11-11): (1) check CSP-allowed script hosts against a gadget dataset (350+ gadgets from cspbypass.com: JSONP with controllable callback, old AngularJS); (2) `form-action` does not inherit from `default-src`, so with HTML injection and `form-action 'self'`/absent, an injected self-posting form plus `<meta name=referrer content=unsafe-url>` and `<meta http-equiv=refresh>` leaks credentials through the Referer to an OAST host with no script running. Rafał Wójcicki (AFINE) credited with independent finding. Described as a Burp AT skill — [PortSwigger](https://portswigger.net/research/blind-trust-stealing-credentials-through-csp)
- Heyes, Black Hat USA 2026 "CSS: the bomb inside your inbox" (2026-08-05/06): CSS-only attacks on webmail (Outlook, Gmail, Fastmail, Proton, Yahoo, AOL) that bypass CSP and exfiltrate without JS; secondary reporting only — [talk page](https://portswigger.net/research/talks?talkid=36), [secondary](https://letsdatascience.com/news/css-attacks-undermine-webmail-and-ai-email-tools-d6c7ca08); primary paper not read
- Nonce-CSP bypass via disk cache/bfcache (Jorian Woltjer, 2025): bfcache failure falls back to disk cache which can restore an old nonce while the attacker updates the payload; nonce leaked e.g. via CSS injection; Chrome cache partitioning complicates it. Reported by secondary summaries only — [YesWeHack roundup](https://www.yeswehack.com/news/csp-bypass-smuggling-amazon-q), [translation](https://segmentfault.com/p/1210000047122736)
- CSP nonce reuse measurement (2023): 598 of 2,271 sites with nonce policies reused a nonce across responses — [arXiv 2309.07782](https://arxiv.org/pdf/2309.07782)
- DOMPurify mXSS: CVE-2025-26791, incorrect template-literal regex in DOMPurify < 3.2.4 (SAFE_FOR_TEMPLATES), published 2025-02-14, fix 3.2.4; severity scored 4.5 (NVD feeds) vs 6.1 (others); "namespace confusion" label not supported by advisories — [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-26791), [Fluid Attacks](https://db.fluidattacks.com/adv/npm/dompurify/CVE-2025-26791)
- Prototype pollution browser-API gadgets (Heyes, 2022-06-22, updated 2022-10-28): `fetch` options (e.g. polluted `body`), `Object.defineProperty` descriptors without `value`/`configurable`, `localStorage`/`sessionStorage` property reads; XSS examples came from Google Analytics, GTM, Adobe scripts — [PortSwigger](https://portswigger.net/research/widespread-prototype-pollution-gadgets). Old but still the canonical gadget list.
- Service workers: WWXSS (IEEE EuroS&P 2025) measured 4,757,077 workers from 56,945,781 websites, confirmed XSS (server and client flavors) in at least 89,945 workers on 31,619 sites; showed CSP/`importScripts` extension for nonces and hashes — [CISPA](https://cispa.de/en/research/publications/104238-wwxss-systematic-study-and-large-scale-measurement-of-cross-site-scripting-xss-in-web-workers-contexts). Earlier: Cache API MITM escalation, 95.8% of 3,436 Cache-API-SW sites potentially vulnerable (Tranco 150k) — [IEEE](https://ieeexplore.ieee.org/document/9474281); SW-XSS and push hijacking (200 sites) — [TAMU](https://success.cse.tamu.edu/appified-web-security)
- Cross-Site WebSocket Hijacking was a 2025 top-10 nominee; Include Security write-up (2025-04) already referenced in repo — [PortSwigger nominations](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025-nominations-open)

### Inferences
- A DOM-XSS check that only loads a URL and reads console misses event-handler flows and parameters the page only reads when present; the agent must fuzz interactions and discover real parameter names (from JS) before testing.
- Form-action exfiltration and Referer leaking mean "CSP blocks script" is not the end of an HTML-injection finding; record HTML injection under strict CSP as a credential-theft candidate.
- Clickjacking/UI redress: the repo already covers DoubleClickjacking (Yibelo, 2024-12); no 2026 source found that changes relevance. Treat as low unless a sensitive one-click action is frameable (X-Frame-Options/frame-ancestors check).

### Gaps
- No primary-source check of the 2025 top-10 page beyond a summariser; no primary read of Woltjer's writeup or Heyes' webmail paper.
- Nothing found on client-side request smuggling or web cache deception specific to 2026 beyond the Next.js cache entry; those remain server/cache classes best handled by the request-smuggling/cache-poisoning playbooks.
- OAuth implicit flow, WebAuthn/passkey and browser-extension surface: not researched in this pass (no sources gathered). Do not assume.

## 3. Browser defaults and platform shifts that change testing

### Takeaway
Trusted Types is now enforceable in Chrome, Firefox and Safari; `setHTML()` exists in Firefox 148 and probably Chrome 146. On sites that enforce TT, sinks throw TypeError, and the tester must look for policy gaps (default policy, `trusted-types` allowlist, `'allow-duplicates'`, policy functions that pass strings through) rather than raw sink writes.

### Cited Findings
- Trusted Types enabled by default in Firefox 148 (released 2026-02-24); Chromium 83 and Safari 26 already supported; several secondary sources call it Baseline from Feb 2026; a CSP-support table dated April 2026 still shows Firefox partial/Safari unsupported and appears stale — [Mozilla intent to ship](https://groups.google.com/a/mozilla.org/g/dev-platform/c/WA8vLAbvzB0), [web.dev](https://web.dev/trusted-types)
- Firefox 148 first to ship standardized `setHTML()` (Sanitizer API); web.dev lists Chrome 146; one source says Chrome still needed a flag in Feb 2026 (conflict); `setHTMLUnsafe()` since Chrome 124 / Safari 17.4; Safari not supporting `setHTML` per web.dev — [Mozilla Hacks](https://hacks.mozilla.org/2026/02/goodbye-innerhtml-hello-sethtml-stronger-xss-protection-in-firefox-148/), [web.dev](https://web.dev/articles/sanitizer)
- Chrome Local Network Access: opt-in testing from Chrome 138 (flag), later split into local-network and loopback-network permissions; final rollout date not confirmed — [Chrome blog](https://developer.chrome.com/blog/local-network-access), [intent to ship](https://groups.google.com/a/chromium.org/g/blink-dev/c/Zl3P6NHhMBw)
- Third-party cookies: Chromium dev thread says Chrome keeps its current approach (phase-out dropped); low-quality sites claim otherwise, treat as unreliable — [Chromium dev](https://groups.google.com/a/chromium.org/g/blink-dev/c/bqHGZYHWxnQ)
- Chrome Lax-by-default 120-second grace period for cookies without SameSite: single personal-blog claim (Aug 2026), no official confirmation — [HackerNoon](https://hackernoon.com/portswigger-said-chrome-updates-broke-its-csrf-lab-my-tests-tell-a-different-story)

### Inferences
- The test browser version matters for proof: pin Chromium version and record it in evidence; a payload that fires in the toolbox Chromium may be blocked by TT/Sanitizer in the victim's browser or vice versa. Run key proofs in Chromium and Firefox where cheap (Playwright supports both).
- LNA matters for a hosted attacker page reaching localhost/intranet targets; in unattended runs the permission prompt will block it, so LNA-dependent proofs need launch flags or permission grant and are version-sensitive.

### Gaps
- Chrome 146 `setHTML` stable status and LNA ship version not confirmed.

## 4. Tooling landscape

### Takeaway
No open-source tool found does CDP-based runtime taint tracking for DOM XSS; real taint tracking lives in academic modified-engine builds. Practical agent substitutes are init-script sink hooks with canaries plus interaction fuzzing. For PP, existing OSS tools are heuristic fingerprinters; gadget confirmation needs the agent plus a runtime check.

### Cited Findings
- DOM Invader (Burp, built in browser): auto-tests PP sources while browsing, scans for gadgets and can generate a DOM XSS PoC in some cases; augmented DOM view shows sinks — [PortSwigger docs](https://portswigger.net/web-security/prototype-pollution/client-side), [blog](https://portswigger.net/blog/finding-client-side-prototype-pollution-with-dom-invader). A Synack write-up reports a gadget scan finding 5-6 gadgets, none leading to DOM XSS — [Synack](https://www.synack.com/exploits-explained/persisting-through-a-client-side-prototype-pollution/). DOM Invader requires Burp's browser; no headless/CLI route found.
- ppfuzz (Rust, local Chromium): injects PP payloads, watches mutation, fingerprints gadgets, does not confirm exploitability — [GitHub](https://github.com/dwisiswant0/ppfuzz)
- ppmap (Go): heuristic hash/search checks, fingerprints known gadgets by global variables, exploits only known gadgets — [GitHub](https://github.com/kleiton0x00/ppmap)
- PPScan: browser extension scanning visited pages — [HackTricks](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/client-side-prototype-pollution)
- JSpanda (created Oct 2025): client scanner over URLs and library source; admits false positives — [Gitee](https://gitee.com/busypolarbear/jspanda)
- PowerAmp (Kajava et al., 2026): lightweight dynamic scanner plus signature amplification; from a 1M-site seed, signatures from 2,807 vulnerable sites found 14,248 more; 2025 talk describes crawl + CodeQL + dynamic gadget detection — [paper](https://sola.kau.se/swits/wp-content/uploads/sites/257/2026/06/2026_samuel_kajava.pdf), [talk](https://sola.kau.se/swits/wp-content/uploads/sites/257/2025/05/2025_swits2025_samuel_kajava_talk.pdf)
- Dasty (server-side gadget detection with dynamic taint analysis): 253 npm packages with gadget flows to code/command execution — [summary](https://liner.com/review/unveiling-invisible-detection-and-evaluation-prototype-pollution-gadgets-with-dynamic) (secondary; server-side only)
- Playwright-based XSS verifiers: XSS Grenade, PeXeS (dialog, console, network monitors), brs-xss — verification of candidates, not taint tracking — [PeXeS](https://github.com/iqbalmh18/pexes)
- Taint-tracking engines in research: Stock et al. (character-level taint in Chromium), Melicher et al. NDSS 2018 (taint in JS engine, open-sourced) — [Stock](https://notify.cispa.uni-saarland.de/papers/stock2014precise.pdf), [Melicher](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_07A-4_Melicher_paper.pdf). The SWIPE authors say they open-sourced fuzzer, DSE and web archive (per search summary, repo link not verified).
- Katana: SPA crawling in headless and standard mode; `-jc` parses endpoints from JS, `-jsl` enables jsluice (memory heavy); headless is flagged experimental; one Aug 2026 small-fixture review found `-jc` and `-headless` surface different endpoints and no single command covered both — [Katana](https://github.com/projectdiscovery/katana), [review](https://thunderbit.com/zh-Hans/blog/katana-review) (anecdotal)
- Source-map recovery: denandz/sourcemapper, paazmaya/shuji take one map at a time; mapperplus wraps retrieval of all .js/.js.map and pipes to jsluice/TruffleHog; dl-webapp-sources built for batches — [Mapperplus](https://awesome.ecosyste.ms/projects/github.com%2Fmidoxnet%2Fmapperplus), [rarecoil](https://medium.com/@rarecoil/spa-source-code-recovery-by-un-webpacking-source-maps-ef830fc2351d). Maps are only recoverable if publicly exposed.
- Agent literature: RECEIPT (Berkeley, arXiv 2607.18575, 2026-07-20) — naive "JS executed" verifier let an agent claim 111 XSS of which 10 were real; three reward-hacking classes (state/source contamination via privileged channels, verifier self-injection via browser automation, threat-model mismatch via over-privileged roles); fix = environment isolation, PoC constraints, role separation (planted as attacker, executed in victim role), verdict binding; 95 OSS targets at $20 budget each, 24 new XSS, 12 acknowledged — [arXiv](https://arxiv.org/pdf/2607.18575) (abstract and intro read from the PDF)
- AWE (arXiv 2603.00960): memory-augmented multi-agent pentesting with browser-backed verification, evaluated on 104-challenge XBOW benchmark — [arXiv](https://arxiv.org/pdf/2603.00960) (search snippet only)

### Inferences
- Mythos's stored-xss-oast verifier already matches RECEIPT's attacker/victim role separation and token binding; the missing parts are making the verifier non-hackable by the agent (the agent should not control the verifier browser's init scripts or the canary token) and recording "planted as userA, fired as userB" in the finding.
- Runtime taint, approximated: wrap sinks via `addInitScript` (before page scripts), tag per-source canaries, log stack traces (`new Error().stack`) at hit, and for string-propagation breaks (encodeURIComponent, regex split) use several distinct-encoded canaries. This misses flows through non-hooked sinks and transformed values; call it candidate generation.

### Gaps
- Could not confirm SWIPE repo URL or license; verify before depending on it.
- No evidence that Playwright MCP / Chrome DevTools MCP-style agents ship taint features; not searched.

## 5. What is hard to automate and how to make proof reliable

### Takeaway
Hard: authenticated SPA state coverage, event-driven sinks, gadget discovery in minified code, one-click/UI-redress impact, XS-leaks, and cache-timing CSP bypasses. Reliable proof = unique per-attempt canary, execution observed in a victim-role context, negative control, and a verifier the agent cannot tamper with.

### Cited Findings
- Passive page analysis misses event-handler DOM XSS; fuzzing interactions plus URL-component synthesis finds more (SWIPE above)
- Reward hacking: execution evidence alone is insufficient when the agent can influence the verifier's inputs (RECEIPT above)
- Dialog/console canary + OAST + role separation already in repo — `skills/stored-xss-oast/SKILL.md`

### Inferences (techniques for the implementer; engineering knowledge, not cited)
- Playwright APIs to use: `context.add_init_script` (sink hooks before page JS), `page.on('dialog')`, `page.on('console')`, `page.on('websocket')` with `framereceived`/`framesent`, `context.route` for modifying responses, `context.service_workers` and `context.on('serviceworker')`, `context.storage_state()` for sessions, `page.on('popup')`, `page.expose_binding` for page-to-agent signals.
- CDP via `context.new_cdp_session(page)`: `Debugger.setBreakpointByUrl`/`DOMDebugger.setEventListenerBreakpoint` and `DOMDebugger.getEventListeners` to list `message` handlers with source locations; `Fetch.enable` to intercept; `ServiceWorker.*` and `Network.getResponseBody`; `Runtime.queryObjects(Object.prototype)` to find polluted prototypes; `DOMSnapshot` for post-render DOM; `Page.addScriptToEvaluateOnNewDocument` for isolated-world hooks.
- Prototype-pollution proof: write pollution via URL/JSON source, read back `({}).canary`, then diff `Object.getOwnPropertyNames(Object.prototype)` before/after; gadget search by proxying `Object.prototype` with a getter that records which property names the page reads after pollution (reads of absent props = gadget candidates), then set that property to a token payload.
- postMessage: enumerate listeners via wrapping `addEventListener` in init script (already in knowledge), then replay from a second origin served by the toolbox on a different port/host; negative control with valid origin.
- WebSocket/SSE: capture frames via Playwright `websocket` events and CDP `Network.eventSourceMessageReceived`; test Origin enforcement with a handshake from a foreign-origin page in the same browser (cookies sent), compare first-party vs foreign-origin message streams.
- Service worker: list registrations (`navigator.serviceWorker.getRegistrations()`), fetch SW script, check `importScripts` sources, scope, `Service-Worker-Allowed`, push handlers, cache contents (`caches.keys()`); SW-XSS if registration URL or `importScripts` URL is attacker-controllable.
- Source-map and bundle recovery: from every captured script response check `//# sourceMappingURL`, `SourceMap`/`X-SourceMap` header, and try `<file>.map`; extract `sourcesContent`; run secret scanning (TruffleHog/gitleaks) and endpoint extraction (jsluice) on the result; flag only secrets validated by a read-only check, not by pattern.
- Evidence hygiene: per-attempt random canary; record browser name+version; keep verifier init scripts out of the agent's reach (separate process or container); save screenshot to disk (current tool discards it).

### Gaps
- No source quantifying false-positive rate of canary-hook approaches versus true taint tracking.

## 6. Capability gaps to implement (priority order)

| # | Gap | Fill with |
|---|-----|-----------|
| 1 | Browser tool lacks instrumentation: no init script, CDP, multi-context, stored screenshots, cookie/storage dump, WebSocket frames | Extend `cli/src/agent/browser.ts`: `add_init_script` (sink/`message`/`Object.prototype` hooks from client-side-dom.md), `new_cdp_session`, `page.on('websocket'/'popup'/'dialog')`, second `browser.newContext()` as victim, screenshot to evidence dir |
| 2 | Runtime taint approximation | Init-script sink wrappers with per-source canaries, stack capture, multiple encoded canary variants; interaction fuzzer (click/input/hash change) per SWIPE finding; optionally evaluate SWIPE codebase |
| 3 | Authenticated SPA/route enumeration | Playwright crawler that records `history.pushState`, router tables (webpack chunk names, Next `__NEXT_DATA__`/build manifest, React Router), plus `katana -jc -jsl` and `-headless` both (outputs differ), merged and tagged by source; reuse auth-session storage_state |
| 4 | Source-map and bundle recovery | Fetch `.map` per script (sourceMappingURL/header/suffix), sourcemapper-style extract of `sourcesContent`, feed result to existing `scripts/sourcemap` aim-point mapper, jsluice endpoints, TruffleHog/gitleaks with read-only validation |
| 5 | Prototype pollution scanning and gadget confirm | Playwright harness: URL/hash/JSON-message sources, `({}).canary` read-back, Object.prototype read-recorder proxy to find gadget property names, known-gadget list (Heyes 2022 browser APIs, GA/GTM/Adobe, library gadgets), token-payload confirm. Use ppfuzz/ppmap only as cheap pre-filters. Server-side PP stays in the server-side playbook. |
| 6 | postMessage tooling | Listener enumeration via `addEventListener` wrap and CDP `DOMDebugger.getEventListeners`, origin-check static read of handler source, foreign-origin sender page in toolbox, negative controls |
| 7 | CSP analyzer | Parse CSP (headers + meta), flag `form-action`/`base-uri`/`frame-ancestors` absence, allowlisted hosts vs cspbypass.com-style gadget list (JSONP, AngularJS), nonce reuse across two fetches, strict-dynamic + clobbering path, report-only vs enforced; Heyes 2026-11 form-action/Referer exfil as a check when HTML injection exists |
| 8 | Trusted Types / sanitizer awareness | Read `require-trusted-types-for`, `trusted-types` allowlist, `window.trustedTypes.defaultPolicy`; detect DOMPurify version from bundle and match CVE list (e.g. CVE-2025-26791 < 3.2.4); detect `setHTML` use; version match = candidate only |
| 9 | Service-worker playbook and probe | Registration/scope/script/importScripts/cache enumeration, SW-XSS and Cache-API poisoning checks per WWXSS and Cache-API papers; unregister after testing |
| 10 | WebSocket and SSE playbook | Frame capture, Origin enforcement test from foreign origin, auth-in-URL token leak, message-level authz (IDOR via subscribe/channel names), SSE via CDP eventSource events |
| 11 | DOM clobbering search | Static scan of bundles for `window.X`/`document.X` reads feeding sinks, then HTML-injection clobber probe using existing recipe; automated via `Object.keys(window)` diff after injecting named elements |
| 12 | Hardened verifier | RECEIPT-style: verifier runs separately from the agent, canary minted by verifier, record attacker role planted / victim role fired, binding verdict to token; forbid agent from editing app state or verifier browser |
| 13 | Cross-browser and version pinning | Run proofs in Chromium and Firefox, log versions, because Trusted Types, setHTML and cookie defaults differ by engine and release |
| 14 | OAuth implicit/fragment tokens, WebAuthn/passkey flows, extensions | Not researched in this pass; existing `knowledge/web/oauth-oidc.md` and `skills/oauth-audit` should be checked first. Treat as open. |
