# Server-side, infrastructure and cloud-adjacent web attack surface: techniques a web red-team framework needs (as of 2026-11-14)

Scope notes. Research was capped at about 20 tool calls. Primary sources were fetched for the PortSwigger items. Everything else rests on search snippets from secondary sources and is flagged. Items I know from training but could not source are listed under Gaps, not as findings. Authorized testing only. Techniques marked **[RISK]** can damage or disrupt shared state (other users' responses, caches, backends) and must stay lab-only or need explicit program permission.

## 1. HTTP desync in 2026, and what testing needs

### Takeaway
Desync research moved fast in 2025-2026: Kettle's "HTTP/1.1 must die" (Aug 2025) made 0.CL and Expect-based desync practical, "CRLF-Powered Desync Attacks" (Aug 2026) added request splitting through header injection, and PortSwigger's AI-driven "HTTP Terminator" (Aug 2026) found new triggers and a CVE. All of it needs byte-exact, connection-controlled raw HTTP/1.1 (and some HTTP/2) that a normalising proxy cannot provide. Mythos's recording proxy and its single `deep-server` CL.TE recipe cover only the 2019-era subset.

### Cited Findings
- "HTTP/1.1 must die: the desync endgame" was published 6 Aug 2025 and updated 17 Oct 2025. It argues upstream HTTP/2+ is the only durable fix. — [PortSwigger](https://portswigger.net/research/http1-must-die)
- 0.CL (front end ignores CL, back end honours it) normally deadlocks the upstream. It is solved with an early-response gadget and can be converted to CL.0 with a "double desync" that makes victim attacks possible. — [PortSwigger](https://portswigger.net/research/http1-must-die)
- Early-response gadgets: IIS answers `/con` or `/nul` inside a mapped folder before reading the body. nginx answers static-file requests early. Server-level redirects work elsewhere. No viable gadget was found for Apache, which closes the connection on error. — [PortSwigger](https://portswigger.net/research/http1-must-die)
- Expect-based desync has four classes: 0.CL vanilla Expect (T-Mobile staging), 0.CL obfuscated Expect, e.g. `Expect: y 100-continue` (GitLab), CL.0 vanilla Expect (Netlify CDN), CL.0 obfuscated Expect (Akamai). Expect also causes a second response header block that bypasses front-end response-header removal. — [PortSwigger](https://portswigger.net/research/http1-must-die)
- Reported impact: a Cloudflare-internal H2.0 desync exposed over 24M sites (patched within hours, $7,000). Akamai CVE-2025-32094 (CL.0 via obfuscated Expect) took 65 days to resolve and paid 74 bounties totalling $221,000. H2.TE bypassed AWS Desync Guardian (found independently by Thomas Stacey). AWS ALB with IIS: AWS chose not to patch, and mitigation is `routing.http.drop_invalid_header_fields.enabled` plus `routing.http.desync_mitigation_mode = strictest`. — [PortSwigger](https://portswigger.net/research/http1-must-die)
- V-H/H-V header discrepancies (header visible to one tier, hidden from the other) are found by comparing responses to baseline variants (normal Host, omitted Host, masked header), not by timeouts, because timeout detection is heavily WAF-fingerprinted. Parser quirk: a server that did not treat a bare `\n\n` as header end. — [PortSwigger](https://portswigger.net/research/http1-must-die)
- Tooling: HTTP Request Smuggler v3.0 (Burp extension; ImplicitZeroScan reports "Mystery 400" responses) and Turbo Intruder (client rewritten because it broke on Expect; `0cl-find-offset.py` locates injected header lengths). Upstream HTTP/2 was confirmed for HAProxy, F5 BIG-IP, Google Cloud, Imperva and Cloudflare (internal HTTP/1 only), experimental in Apache, absent in nginx, Akamai, CloudFront and Fastly at publication. — [PortSwigger](https://portswigger.net/research/http1-must-die)
- "CRLF-Powered Desync Attacks: Beheading HTTP Streams" (5 Aug 2026): a single injected `Transfer-Encoding` beside `Content-Length` gives CL.TE without a double CRLF. Request splitting via CRLF in the path gives response queue poisoning (RQP). Injection points include custom upstream headers (e.g. `X-Original-Url`) and a reflected session cookie. Most variants are browser-triggerable via `fetch` or navigation, including connection-locked 0.CL (`window.open` plus navigation lands both requests on one connection) and an IP-locked H2 variant using injected `Expect` plus HEAD+Range over-read. Root cause cited for nginx: `$uri` in `proxy_pass` (OpenResty and Tengine flagged). No CVEs. Bounties ranged $500 to $20,000. — [PortSwigger](https://portswigger.net/research/crlf-powered-desync-attacks)
- CRLF-desync detection primitives: injected invalid version `HTTP/13.37` gives 505, injected `Transfer-Encoding: x` gives 501, injected `Expect: asdf` gives 417 with `Connection: close`. CL.TE confirmation uses a timeout. Connection-locked 0.CL is checked by two requests on one keep-alive connection looking for 200 then 400. The telecoms RQP case used about 500 connections for about 20 minutes **[RISK: other users' responses]**. Tooling: Burp extension `t0xodile/crlf-powered-desync-scanner` (Tom Stacey), nuclei templates `turtlesec-software/crlf-desyncs` (Tobia Righi), Hackvertor for encoding, labs released. — [PortSwigger](https://portswigger.net/research/crlf-powered-desync-attacks)
- "Making header injection critical with one prompt" (4 Nov 2026): Burp AT skills chain header-injection finding, desync validation (fuzz until 2 or 3 distinct status codes), gadget mini-crawl (open redirect via Host/X-Forwarded-Host/absolute URL), then redirect other users. The article says RQP was considered and rejected as too dangerous to real users. — [PortSwigger](https://portswigger.net/research/making-http-header-injection-critical-with-one-prompt)
- "HTTP Terminator" (Black Hat USA 2026 / DEF CON 34, 5 Aug 2026; open-sourced): four phases (ideation from RFC fragments giving about 30,000 candidate vectors, evaluation against about 30,000 authorized targets under 1 req/s per domain, weaponization by an agent through Turbo Intruder's MCP interface with deterministic code judging success, cascade). Results: a multipart/byteranges trigger affecting 200+ sites, dual matching Content-Length headers, a "dangling-byte" RQP enhancement, Apache Traffic Server zero-day CVE-2026-63078, and "Shared-Parser Confusion". The author's agent lessons: it mistook pipelining and connection reuse for vulnerabilities, gave up when it could not reuse connections, over-anchored on prompt context, and sometimes strayed to unauthorized targets. Fix: baseline-vs-trigger comparison, deterministic validation gates, fresh context per step, rule out pipelining artefacts. Infrastructure: Burp extension, SQLite, a c7i.2xlarge with 2,000 threads. — [PortSwigger](https://portswigger.net/research/can-ai-do-novel-security-research)
- Browser-powered desync / CL.0 background and the "0.CL deadlock" slides, plus a free Web Security Academy 0.CL lab. — [PortSwigger BH slides](https://portswigger.net/kb/papers/dzmxreq/http1-must-die-slides.pdf), [PortSwigger 0.CL post](https://portswigger.net/blog/http-1-1-must-die-conquering-the-0-cl-challenge)

### Inferences
- Detection is now parser-differential (clean request, baseline vs trigger, status-code fingerprints), not timing. That suits an agent, but only with deterministic validators and control of connection reuse.
- Proof needs a victim-free design. Kettle's own tooling and the Burp AT write-up both avoid or reject cross-user RQP; Mythos's "own connection only" rule is consistent with that. Connection-locked 0.CL and the browser-powered variants are the ones that can be proven on the tester's own connection or browser.
- AWS ALB, Netlify and Akamai-hosted targets were reported with no or partial vendor fix, so fingerprinting the CDN/LB tier is a prerequisite for choosing desync variants.

### Gaps
- No source found on how many of these 2026 techniques are covered by public nuclei templates beyond the TurtleSec CRLF set.
- HTTP/2-specific 2026 work (H2.TE, H2.CL tunnelling, request-smuggling over HTTP/3) was only touched through the Aug 2025 article; no 2026 H2/H3 primary source was read.
- CVE-2026-63078 detail (Apache Traffic Server) was not independently verified beyond the PortSwigger article.

## 2. Mythos constraint: can the recording proxy support desync?

### Takeaway
No. The proxy is a stdlib HTTP/1.1-only forward proxy that parses each message's framing and re-originates upstream connections; desync probes are specifically malformed or ambiguous framing and need byte-exact, connection-pinned, optionally HTTP/2 transport. Mythos already knows this and classes smuggling tools as "cannot be recorded". The gap is a first-class raw-transport path that is still recorded and scoped.

### Cited Findings (local repo, read 2026-11-14)
- The proxy "speaks HTTP/1.1 on both sides, so clients fall back from h2", advertises only `http/1.1` in ALPN, terminates TLS with a per-run CA, and records framing-only bytes. — `/home/bleier/Documents/Programming/mythos-sec/scripts/traffic` (header docstring, lines 24-37; ALPN at 396, 406, 1371)
- `framing()` raises on CL+TE, duplicate or non-numeric CL, whitespace in a framing header name, or odd TE; the request is then handled by `unframed()`, which records an `ambiguous_framing` gap and forwards blindly as a tunnel with byte counts only. — same file, lines 174-196 and 642-650
- `NON_HTTP = {"nmap","masscan","amass","subfinder","smuggler","h2spacex"}` marks tools that cannot be recorded; raw sockets, `smuggler.py` and `h2spacex` leave no line in the record. — same file line 98; `/home/bleier/Documents/Programming/mythos-sec/skills/traffic/SKILL.md` lines 23-26
- The only desync recipe is CL.TE/TE.CL via `smuggler.py` (timing candidates) plus one raw-socket differential pair, in `/home/bleier/Documents/Programming/mythos-sec/skills/deep-server/SKILL.md`; `/home/bleier/Documents/Programming/mythos-sec/knowledge/web/request-smuggling.md` cites only 2019 and 2021 PortSwigger work. grep finds no mention of 0.CL, CL.0, Expect-desync, early-response gadgets, CRLF desync or H2.TE anywhere in `skills/` or `knowledge/`.
- The toolbox has `h2spacex==1.2.2` as a library (no CLI), used by `race.py`; no Turbo Intruder, no HTTP Request Smuggler (both are Burp/Java). — `/home/bleier/Documents/Programming/mythos-sec/toolbox/tools.txt`, `requirements.in`

### Inferences
Why the proxy breaks desync testing:
1. It re-frames traffic. Even in blind-forward mode it opens its own upstream connection, so the target sees the proxy's TLS stack and connection reuse, not the tester's; connection-locked and IP-locked variants (which depend on one specific client connection) cannot be reproduced.
2. A 0.CL probe sends a CL header with the body withheld on purpose. A proxy that reads the framing waits for the missing body bytes and deadlocks or times out before forwarding, the same deadlock the target would show but on the wrong hop.
3. HTTP/2 variants (H2.TE, H2.0, request-header CRLF over H2, Expect over H2) cannot pass an HTTP/1.1-only proxy.
4. Single-connection state (pipelining, keep-alive sequencing, "send request B on the same socket after A's response") is needed for every confirmation and is not preserved across a per-request proxy.

What it would take to support desync properly (infrastructure requirement):
- A **raw transport tool** (new, scoped like the `request` tool) that opens a direct TCP/TLS connection to an in-scope host, sends byte-exact sequences with explicit inter-message timing and half-close control, with optional ALPN `h2` and a minimal H2 frame writer; returns raw bytes and per-message timing. Python sockets plus `h2`/`hyper-h2` frames are enough; no Burp needed.
- **Recording without re-framing**: a tee mode that logs the exact bytes written and read on that socket into `log.jsonl` as `kind:"raw"` records tagged with connection id, so `scripts/traffic replay` can resend a stored sequence byte for byte on a fresh connection. Everything else about the capture line stays unchanged.
- **Scope and rate enforcement in the tool itself**, since the proxy no longer sits in the path: reuse `hooks/scope-guard.py --check`, a per-host request cap, a "no victim connection" guard (fresh connection per probe, close on finish, a unique cache-buster/path token, never reuse a connection pool shared with other users).
- **A deterministic validator**, per Kettle's lessons: baseline vs trigger on clean requests, repeat for stability, reject pipelining/keep-alive artefacts (send the same pair with the framing conflict removed as negative control), exit on first confirmation.
- **Browser-powered variants** need a Chromium with `--proxy-server` unset for the target (or the CA flag) so a page can issue `fetch`/`window.open` on one connection; they require a lab page hosted by the tester and are the riskiest **[RISK]**; keep lab-only.
- Optional: port or drive Request Smuggler logic (header x permutation x strategy matrix) into Python, since the Burp extension is not usable headless. The HTTP Terminator is open source and is the nearest reference design for an agentic harness.

### Gaps
- I did not read the proxy's upstream connection-pooling code, so point 1 (per-request vs reused upstream sockets) is inferred from the framing and tunnel paths only.
- Whether `h2spacex` can send malformed H2 (needed for H2.TE/H2.0) was not checked; its README was not read.

## 3. Web cache poisoning and deception

### Takeaway
The canonical references are still Kettle's cache-entanglement work and the Aug 2024 "Gotta Cache 'em All" path-confusion research; I found no distinct new 2025-2026 cache paper, but desync-to-cache-poisoning is now the dominant high-impact route (CRLF desync + Cloudflare `CDN-Cache-Control` abuse). Mythos has a basic wcvs recipe and one deception recipe, but no coverage of delimiter, normalisation or cache-key discrepancy discovery.

### Cited Findings
- "Gotta Cache 'em All" (published 8 Aug 2024) shows frameworks and servers use different path delimiters, and that Apache and nginx resolve URLs differently, so origin and cache disagree about the path. The paper says the techniques apply to any cache, including origin-embedded ones. PortSwigger's Academy labs are built on it. — [PortSwigger research](https://portswigger.net/research/gotta-cache-em-all), [Academy](https://portswigger.net/web-security/web-cache-deception)
- A 2026 secondary note says Cloudflare, Fastly/Varnish, Akamai and nginx normalise cache keys differently (case, encoding, delimiters, default ports). Secondary source, treat with care. — [ldamoredev notes](https://ldamoredev.github.io/cibersecurity-notes/en/cybersecurity/web-security/web-cache-poisoning.html)
- Cloudflare-specific: `CDN-Cache-Control: private="Location"` plus an ISO-2022-JP charset trick were used in the 2026 CRLF-desync work for response header injection and XSS-on-redirect; chaining desync with cache poisoning is described as enabling full-site takeover. — [PortSwigger CRLF](https://portswigger.net/research/crlf-powered-desync-attacks), [PortSwigger header injection](https://portswigger.net/research/making-http-header-injection-critical-with-one-prompt)
- Mythos has `wcvs` (not in the toolbox image), cache-busted manual poison/clean-read/negative-control, and a userA-then-anonymous deception check with `.css`, `;.css`, `%2f..%2fstatic`. — `/home/bleier/Documents/Programming/mythos-sec/skills/deep-server/SKILL.md`; knowledge note is 1.4 KB at `knowledge/web/cache-poisoning.md`

### Inferences
- Missing in Mythos: systematic delimiter/normalisation discrepancy discovery (origin vs cache pairs), fat GET and parameter-cloaking probes, param-miner-equivalent unkeyed-input discovery, exact-match rule abuse, and a stable "cache oracle" (hit/miss detector per CDN header set). The agent must fingerprint the CDN first (Cloudflare `CF-Cache-Status`, Akamai `X-Cache`, Fastly `X-Served-By`, CloudFront `X-Cache`).
- Poisoning on a shared key is **[RISK]**; the existing cache-buster rule is the right control, but deception tests that cache a real user's page are only safe with the tester's own two accounts.

### Gaps
- No 2025-2026 primary source on parameter cloaking, fat GET or Omer Gil follow-up work was found (search returned only the 2024 paper and secondary blogs). param-miner and wcvs current versions were not checked.

## 4. SSRF in 2026

### Takeaway
IMDSv2 is defeated only when the SSRF controls method and headers, which is why server-side proxies, webhook features and ML/ops tools remain the reliable cloud-credential path; encoding and parser-differential bypasses of SSRF filters are still being published. Mythos has a good OAST-first SSRF note but no cloud-credential-chain or rebinding workflow.

### Cited Findings
- watchTowr disclosed CVE-2026-64849 (CVSS 9.3), SSRF in MLflow model-registry webhooks reaching cloud metadata; scanning began within hours of CVE assignment on 17 Aug 2026. — [startwithidentity summary](https://startwithidentity.com/blog/2026-08-18-mlflow-ssrf-reaches-cloud-metadata-for-credentials.md) (secondary; verify against watchTowr)
- IMDSv2 requires a PUT for the token plus a custom header, so URL-only SSRF generally fails; full method/header control (server-side proxies, misconfigured reverse proxies) defeats it. An org that "uses IMDSv2" may still have instances answering IMDSv1. — [Pentrova](https://pentrova-website.pages.dev/blog/ssrf-cloud-metadata-2026) and [Aviatrix](https://aviatrix.ai/threat-research-center/proxy-server-metadata-service-attack-2026/) (vendor blogs; weak sources)
- Aviatrix reports March 2026 attacks on misconfigured proxies reaching metadata via IPv4-mapped IPv6 and long unsigned-integer IP encodings. GCP's metadata server rejects requests lacking `Metadata-Flavor: Google` or containing `X-Forwarded-For`. — [Aviatrix](https://aviatrix.ai/threat-research-center/proxy-server-metadata-service-attack-2026/)
- Mythos SSRF note covers OAST-first detection, redirect-following probes, numeric/IPv6/userinfo bypasses, scheme handler checks and parser differentials, and names PDF/screenshot renderers, link unfurlers and webhooks as sinks. — `/home/bleier/Documents/Programming/mythos-sec/knowledge/web/ssrf.md`

### Inferences
- Safe proof for cloud-metadata SSRF is a reachability and header-control proof (a request to an OAST host shows method, headers, redirect-follow, and whether `PUT` can be sent), not retrieval of credentials. The credential chain should stop at "metadata endpoint answers with a role name" and never read tokens.
- DNS rebinding needs a controllable authoritative DNS with short TTL; the lab OAST DNS "only sees queries sent to it directly" (per `deep-server`), so rebinding is not testable in the lab as built.

### Gaps
- No primary source found for specific 2026 IMDSv2 bypasses (Truffle Security's page claims three new bypasses, but no technical detail was retrievable). No source for gopher/Redis chains, PDF generator/headless-browser SSRF or image-processing SSRF in 2026; Mythos's note lists these as sinks only.
- I could not confirm the MLflow figures against the watchTowr post.

## 5. Deserialization and template injection

### Takeaway
The 2025-2026 headline is framework-level deserialization in modern JS stacks (React2Shell) and a steady stream of pre-auth Java and .NET deserialization in enterprise products; classic gadget chains are mostly product-specific now. Mythos's OAST-callback-gadget approach is the right safe proof but covers only URLDNS, PHP and pickle examples.

### Cited Findings
- React2Shell, CVE-2025-55182: unauthenticated RCE (CVSS 10) via unsafe deserialization in React Server Components' Flight protocol, disclosed 3 Dec 2025, in CISA KEV with confirmed exploitation. Affects React 19.0.0-19.2.0 and Next.js 15.x/16.x App Router; the duplicate Next.js CVE-2025-66478 was rejected. Versions differ between sources. — [Invicti](https://www.invicti.com/blog/web-security/react2shell-critical-rce-in-react-rsc-next-js-cve-2025-55182-cve-2025-66478), [VulnCheck](https://www.vulncheck.com/blog/cve-2025-55182-react-nextjs)
- Next.js middleware bypass, CVE-2025-29927: trusted external `x-middleware-subrequest`; fixed in 12.3.5, 13.5.9, 14.2.25, 15.2.3. — [Fastly](https://fastly.com/blog/cve-2025-29927-authorization-bypass-in-next-js)
- watchTowr March 2026: BMC FootPrints CVE-2025-71260, VIEWSTATE deserialization RCE, alongside two SSRFs (mirrored copies; not confirmed pre-auth). A SolarWinds Observability self-hosted unauthenticated deserialization RCE (CVE-2026-28325) and Bonita/OFBiz pre-auth Java RCE (CVE-2026-31986, Aug 2026) also appear. — [stack.watch](https://stack.watch/vuln/CVE-2026-28325/), [Help Net Security](https://www.helpnetsecurity.com/2026/08/05/pre-auth-rce-java-bonita-ofbiz-cve-2026-31986) (search snippets; unverified)
- Mythos has deserialization signal list, ysoserial URLDNS, phpggc and pickle callback recipes, XXE OOB, and an SSTI note (4.4 KB), plus `knowledge/web/framework-nextjs-rsc.md`. — `/home/bleier/Documents/Programming/mythos-sec/skills/deep-server/SKILL.md`; knowledge dir listing

### Inferences
- Missing: Ruby (Marshal/YAML), Node (`node-serialize`, RSC Flight, prototype-pollution-to-RCE), .NET `BinaryFormatter`/ViewState/`$type` JSON chains, Java JNDI/Log4Shell-style callbacks other than URLDNS, expression-language (Spring SpEL, OGNL, MVEL) and per-engine SSTI discriminator tables. ysoserial/phpggc are "not in the toolbox image".
- Safe proof pattern per ecosystem is a callback-only or time-delay gadget with a token and a negative control, never a command-execution chain on a real target.

### Gaps
- No 2026-sourced list of current ysoserial/ysoserial.net gadget chains, SSTI per-engine payload sets, or Ruby/Node gadget status was found; not reproduced here from memory.

## 6. File handling

### Takeaway
I found one directly relevant 2026 primary source (SVG sanitizer bypasses). Image/document-parser server-side RCE, archive extraction, PDF/LaTeX/ffmpeg chains and path-traversal variants were not found in this search pass and are Gaps.

### Cited Findings
- "Scalable Vector Grief" (Gareth Heyes, 27 Oct 2026): 6 of 8 SVG sanitizers bypassed; DOMPurify and darylldoyle/svg-sanitizer held; XSLT-via-data-URL XSS (feature deprecated, removal due Nov 2026), Safari `<use>` importing a GIF as SVG, Firefox `Link` header with XSLT data URL. Impact is client-side XSS, not server-side file read or SSRF. — [PortSwigger](https://portswigger.net/research/scalable-vector-grief)
- Mythos's file-upload and path-traversal notes are 1.5 KB each; the CVE snapshot mentions zip-slip, Ghostscript and ffmpeg, ImageMagick appears only in `command-injection.md`; no LaTeX mention anywhere. — `/home/bleier/Documents/Programming/mythos-sec/knowledge/web/file-upload.md`, `path-traversal.md`, `knowledge/cve/snapshot.json`

### Inferences
- A file-pipeline playbook is missing: upload content-type/extension/magic-byte matrix, polyglots, SVG/DOCX/XLSX server-side XML parsing (XXE overlaps `deep-server`), archive extraction (zip-slip, symlink, bomb **[RISK: DoS]**), document-to-PDF and image processing SSRF, and OAST-callback proofs for each renderer.

### Gaps
- No 2025-2026 primary source for ImageMagick/Ghostscript/ffmpeg/LaTeX/PDF-library bugs or new traversal encodings; not searched deeply.

## 7. Cloud and infra exposed via the web tier

### Takeaway
Subdomain takeover remains a mapped, fingerprint-driven problem (can-i-take-over-xyz plus a 2026 Silent Push dangling-DNS report). Everything else in this list (buckets, ingress/Kubernetes, Actuator, dev servers, edge functions, SPF/DMARC) went unsourced in my searches; Mythos has partial notes for buckets, Actuator, takeover and nothing for K8s ingress or email infrastructure.

### Cited Findings
- `EdOverflow/can-i-take-over-xyz` is the community fingerprint list of takeover-prone services; a 2026 Silent Push "Danglegeddon" report mapped 12,500 domains to vulnerable provider CNAMEs. OWASP WSTG says to confirm the fingerprint and that the resource is unclaimed, but not to claim it. — [can-i-take-over-xyz](https://github.com/acealchemycyberblaze/can-i-take-over-xyz) (fork, not the upstream repo), [Silent Push report](https://info.silentpush.com/hubfs/reports-2026/Silent-Push-Danglegeddon-Report-2026.pdf), [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
- Mythos notes present: `subdomain-takeover.md` (4.7 KB), `baas-cloud-storage.md`, `gateway-bypass.md` (mentions Actuator), `recon` skill (mentions `.git`, Actuator). grep finds no matches for ingress, SPF, DMARC, Kubernetes outside the CVE snapshot, or Metasploit.

### Inferences
- Missing: K8s/ingress exposure checks (ingress-nginx admission webhook class, exposed kubelet/dashboard/etcd on web ports), edge-function/CDN misconfiguration (worker routes, origin bypass by direct IP), exposed dev servers (Next.js/Vite dev, `/debug`, source-map and HMR endpoints), secret-in-header/error harvesting, and SPF/DMARC/dangling-MX checks. Email auth findings are low severity in most programs and out of scope for many; treat as informational unless the program lists them.

### Gaps
- No sources found for Kubernetes ingress, edge-function, exposed-bucket or Actuator 2026 research, nor for SPF/DMARC relevance to bounties.

## 8. Supply chain on the web tier

### Takeaway
npm worms are now an established class: Shai-Hulud (Sep 2025) and Shai-Hulud 2.0 (Nov 2025). Mythos's coverage is client-side supply chain (SRI, script trust) plus `.git`/`.env`/source-map exposure checks; dependency confusion is only mentioned in `engagement-setup`.

### Cited Findings
- Shai-Hulud first wave reported Sep 2025 (malicious versions published from 15 Sep; counts 180 to 500+ packages depending on source), harvesting secrets and exfiltrating to public GitHub repos named Shai-Hulud; second wave 24 Nov 2025, with a reported home-directory wipe fallback. Counts conflict across sources. I found no 2026 developments in this search. — [Wiz](https://threats.wiz.io/all-incidents/shai-hulud-ongoing-package-supply-chain-compromise-delivering-data-stealing-malware), [CybelAngel](https://cybelangel.com/blog/the-shai-hulud-malware-attack-on-npm-supply-chain-flash-report/)
- Mythos: `/home/bleier/Documents/Programming/mythos-sec/knowledge/web/client-side-supply-chain.md`, `skills/source-review` (source maps), `skills/recon` (`.git`).

### Inferences
- From a black-box web tester's view the in-scope checks are: exposed build artefacts (`.git`, `.env`, source maps, CI config), third-party script/SRI inventory, internal package names leaked in bundles or manifests (dependency-confusion candidate only, never publish a package without explicit permission **[RISK]**).

### Gaps
- No primary sources on dependency confusion tooling or 2026 npm incidents beyond the 2025 worm.

## 9. Nuclei and CVE-to-exploit sources in 2026

### Takeaway
Nuclei offers AI template generation (cloud editor, CLI `-ai`, a CVE-to-template pipeline), and nuclei itself had two April 2026 advisories fixed in v3.8.0. Mythos pins nuclei v3.11.1 and templates v10.5.2 and has a KEV/EPSS-based `cvefeed`; Metasploit and exploit-db are not integrated.

### Cited Findings
- ProjectDiscovery documents an AI-assisted template editor in its cloud product, a nuclei `-ai` flag, a CVE-to-template automation write-up, and a browser extension generating templates from HackerOne/ExploitDB pages. I found no dated 2026 ProjectDiscovery launch. — [PD docs](https://docs.projectdiscovery.io/cloud/editor/ai), [PD blog](https://projectdiscovery.io/blog/future-of-automating-nuclei-templates-with-ai)
- A June 2026 review page says to upgrade to nuclei v3.8.0, which fixed GHSA-29rg-wmcw-hpf4 (a JavaScript-protocol template could read local files outside the sandbox). Secondary source. — [appsecsanta](https://www.appsecsanta.com/nuclei)
- Triage guidance: combine KEV with EPSS rather than CVSS. KEV count reported as 1,526 (Edgescan) vs 1,754 (Dexpose), different snapshots; 48,185 CVEs published in 2025; Metabase password-reset SQLi CVE-2026-72898 cited as KEV with 12% EPSS. Vendor sources, not primary CISA/FIRST. — [Edgescan](https://info.edgescan.com/hubfs/2026%20Vulnerability%20Stats%20Report.pdf?hsLang=en), [Indusface](https://www.indusface.com/wp-content/uploads/2026/09/zero-day-vulnerability-report-august-2026.pdf)
- Mythos: `cvefeed` merges CISA KEV, EPSS, NVD 2.0, nuclei-templates CVE map, GHSA, OSV; the toolbox pins nuclei v3.11.1 and nuclei-templates v10.5.2. — `/home/bleier/Documents/Programming/mythos-sec/skills/cve-deep-dive/SKILL.md`, `toolbox/tools.txt`

### Inferences
- Because AI-generated templates are fast but not validated, the agent should treat them as candidates and verify against a vulnerable fixture and a negative control, which matches Mythos's existing candidate-vs-proof discipline. Because nuclei had a local-file-read advisory in JS templates, never run untrusted or generated templates outside the container.
- Note: Mythos pins v3.11.1 which post-dates v3.8.0, so the April 2026 advisories are presumably covered; not verified.

### Gaps
- `cent` (community nuclei template collections), template quality benchmarks and Metasploit/exploit-db integration were not researched.

## 10. Mythos playbook coverage versus these areas (from repo grep, 2026-11-14)

### Takeaway
Only deserialization, XXE, cache poisoning/deception and CL.TE/TE.CL smuggling have a `skills/` playbook (`deep-server`); CVE triage has `cve-deep-dive`. Everything else is a knowledge note (passive reference) or absent.

### Cited Findings
- Skills present: auth-session, ai-app, business-logic (race, mass-assign, bola), research-ingest, oauth-audit, exploit, deep-server, tenant-isolation, report, recon, toolbox, continuous, cve-deep-dive, traffic, engagement-setup, stored-xss-oast, source-review, web-scan. — `/home/bleier/Documents/Programming/mythos-sec/skills/`
- Knowledge-only (no skill, no scripts): SSRF (5.2 KB), SSTI (4.4 KB), file upload (1.5 KB), path traversal (1.5 KB), subdomain takeover (4.7 KB), BaaS/cloud storage, client-side supply chain, Next.js RSC, webhooks, gateway bypass. — `/home/bleier/Documents/Programming/mythos-sec/knowledge/web/`
- No coverage found at all (grep zero hits in skills/ and knowledge/): 0.CL/CL.0/Expect desync, early-response gadgets, CRLF-injection desync, H2.TE, Kubernetes/ingress, SPF/DMARC, LaTeX, Metasploit.

### Inferences
Gap table: area, current state, infrastructure requirement

| Area | State | Infrastructure requirement |
|---|---|---|
| Modern desync (0.CL, CL.0, Expect, CRLF, H2.TE, browser-powered) | knowledge dated 2019/2021, one raw CL.TE recipe | raw recorded transport tool, optional H2 frame writer, deterministic baseline/trigger validator, own-connection/no-victim guard, lab with vulnerable front/back-end pairs |
| Cache delimiter/normalisation discrepancy | basic wcvs + manual pair | cache oracle per CDN, wcvs in toolbox image, differential origin/cache path probes, own-account pair fixtures |
| SSRF cloud/internal chains | knowledge note only | OAST with controllable DNS (rebinding), cloud-metadata emulator in lab (IMDSv1/v2, GCP, Azure), method/header-control prober, headless-browser/PDF sink fixtures |
| Deserialization breadth (Ruby/Node/.NET/Java EL), SSTI per-engine | one recipe, SSTI note | ysoserial/ysoserial.net/phpggc plus JRE/.NET in an extra toolbox profile, lab apps per ecosystem, SSTI discriminator corpus |
| File pipelines (upload, archive, doc/image/PDF/LaTeX/ffmpeg) | 1.5 KB notes | OAST-instrumented renderer fixtures, safe archive generator, upload matrix script |
| Cloud/infra exposure (buckets, K8s ingress, dev servers, edge/CDN origin bypass, SPF/DMARC) | partial notes | passive DNS/CT recon, origin-IP discovery, cloud provider fingerprint lists, no extra active capability needed beyond scope guard |
| Supply chain (dependency confusion, build artefacts) | client-side note, `.git` check | package-name extraction from bundles/manifests, registry lookup only (no publishing) |
| Nuclei/CVE sources | cvefeed + pinned nuclei | template-validation harness (fixture + negative control), optional exploit-db/Metasploit-module metadata feed |

### Gaps
- Repo grep is keyword-based; a note could cover a topic under different words.
