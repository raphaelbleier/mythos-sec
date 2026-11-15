# Client-Side DOM: sources, sinks, postMessage, clobbering, prototype pollution

**Class:** client-side  **Updated:** 2026-11-13

## What it is
Script in the page moves attacker-controlled data from a **source** (`location.hash`,
`location.search`, `document.referrer`, `window.name`, `postMessage` data, storage,
a fetched JSON field) into a **sink** (`innerHTML`, `outerHTML`, `insertAdjacentHTML`,
`document.write`, `eval`/`Function`/`setTimeout(string)`, `script.src`, `a.href`/`location =`,
jQuery `$()`/`.html()`, framework escape hatches such as `dangerouslySetInnerHTML`,
`v-html`, `bypassSecurityTrust*`). The server never sees the payload, so scanners that read
HTTP responses miss it. Neighbouring classes covered here: DOM clobbering, client-side
prototype pollution, CSP bypass, mutation XSS, CSS injection, client-side path traversal and
open-redirect chains. Reflected and stored delivery stay in `xss.md`.

## How Mythos detects it
Owner: the **mythos-browser** agent. Static grep of JS bundles for sink names only ranks
candidates.
1. Load the page in Playwright with an init script that wraps the sinks and logs only when
   the value contains a per-run canary (one canary per source, never reused):
   ```python
   HOOK = """(()=>{const C=%r,L=(s,v)=>console.log('MYTHOS-SINK:'+s+':'+String(v).slice(0,160));
   for(const n of ['innerHTML','outerHTML']){const d=Object.getOwnPropertyDescriptor(Element.prototype,n);
     Object.defineProperty(Element.prototype,n,{...d,set(v){if(String(v).includes(C))L(n,v);d.set.call(this,v)}})}
   for(const [o,n] of [[Element.prototype,'insertAdjacentHTML'],[document,'write'],[window,'eval'],[window,'setTimeout']]){
     const f=o[n];o[n]=function(...a){if(a.some(x=>typeof x==='string'&&x.includes(C)))L(n,a.join('|'));return f.apply(this,a)}}
   window.addEventListener('message',e=>{if(String(JSON.stringify(e.data)).includes(C))L('message<-'+e.origin,e.data)},true)})()""" % canary
   ctx.add_init_script(HOOK); page.on('console', lambda m: m.text.startswith('MYTHOS-SINK') and print(m.text))
   ```
2. Drive each source with the canary: `/#<canary>`, `?q=<canary>`, `window.name`, a `postMessage`
   (below), a stored value you wrote as your own user. A log line = the sink is reachable from
   that source. Navigation sinks (`location=`, `a.href`) are read from `page.url` and the DOM.
3. List message handlers by also wrapping `EventTarget.prototype.addEventListener` for
   `'message'` and logging `fn.toString()`; read each for `event.origin` / `event.source` checks.
4. `dalfox --dom`-style output and DOM Invader hits are candidates until step "confirm" passes.

## How to confirm (non-destructive)
Sink reached is not execution. Execution proof reuses `skills/stored-xss-oast/SKILL.md`: mint a
token with `xss-verify token --point 'GET /page#hash'`, put the matching payload (HTML,
attribute, JS-string or URL variant) in the source, load it in a real browser context, and take
the `MYTHOS-XSS:<token>` console line or an OAST hit on `<oast>/<token>` as the oracle.
- **postMessage**: host a page on a different origin you control (`python3 -m http.server 9001`
  in the toolbox, lab net) containing
  `<script>w=open('<TARGET>');setTimeout(()=>w.postMessage('<canary or token payload>','*'),3000)</script>`.
  A sink hit or token fire from that foreign origin proves the handler lacks an origin check.
  Negative controls: the same message with the wrong shape (handler ignores it) and, if the
  handler checks `origin`, a message from the allowed origin (expected path works, foreign does not).
- **DOM clobbering**: needs HTML injection that survives the sanitizer (ids/names usually do).
  Probe: inject `<a id=mythosX><a id=mythosX name=mythosY href=//<oast>/<token>>`, then in the page
  evaluate `window.mythosX.mythosY` (an anchor collection gives the `href` string). Then find the
  gadget: code such as `window.config || {}` or `document.getElementById(...)` feeding `script.src`
  or `innerHTML`. Proof is the OAST fetch of `<oast>/<token>` triggered by the clobbered value.
- **Client-side prototype pollution**: sources are `?__proto__[mythosM]=1`,
  `#__proto__[mythosM]=1`, `?constructor[prototype][mythosM]=1`, JSON in a web message. Read back
  `page.evaluate("({}).mythosM")`. `'1'` = pollution; the negative control is the same URL without
  the parameter returning `undefined`. A gadget (a property the page then reads into a sink) is
  needed for a finding; set the gadget property to a token payload only. The pollution lives in
  the page's JS realm: reload the tab to discard it, do nothing server-side.
- **CSP**: read the effective policy (`Content-Security-Policy`, meta tag, report-only). A bypass
  claim needs the canary to execute under the enforced policy: nonce + `strict-dynamic` with a
  clobbered `script.src` (PortSwigger, 2023-06-05), allowed JSONP/open-redirect/AngularJS hosts in
  `script-src`, `base-uri` missing. `require-trusted-types-for 'script'` turns sinks into
  `TypeError`s: check `window.trustedTypes` and any `default` policy before calling a sink safe.
- **Mutation XSS**: if input passes through DOMPurify/sanitizer then `innerHTML`, record the
  library version from the bundle and test only the canary payload against that version's known
  bypasses; a bypass that executes the token in a browser is the proof. Version alone is a candidate.
- **CSS injection / exfiltration**: injectable `<style>` or `style=` without script. Oracle: a
  selector rule on your own canary attribute/text that fetches `<oast>/<token>-hit` only when the
  condition holds, plus a selector that must not match (negative control). Test against your own
  secret-bearing element only (a canary value you placed), never real user tokens. Where CSP
  blocks external requests, the click-based variant needs a user action and is out of scope for
  unattended runs.
- **Client-side path traversal**: a source concatenated into a `fetch()` path
  (`fetch('/api/' + id)`), `id=..%2f..%2fother`. Proof = the request URL observed in the
  network log resolves to a different endpoint than intended and returns your own data of
  another type; a 404 or an error page does not count.
- **Open-redirect chains**: `?next=//<oast>/<token>`; a redirect alone is low. It becomes a finding
  only when chained (OAuth `redirect_uri`, `javascript:` href sink, `script.src` allow-listed host).

## What does NOT count
A sink hook line without execution, an alert in the toolbox's headless context that never reached a
victim-equivalent page, a reflected string in view-source, a `__proto__` write that is never read,
a CSP with `unsafe-inline` reported as XSS, a library version match, a message handler without an
origin check whose data never reaches a sink.

## Remediation
Safe sinks (`textContent`, `setAttribute` allow-list), Trusted Types enforced, strict
nonce-based CSP with `base-uri 'none'`, origin and `source` checks on every `message` handler,
`Object.create(null)` or `Map` for merged config, `Object.freeze(Object.prototype)`,
sanitizer kept current, unique ids not reachable from user HTML.

## Sources
- PortSwigger Research, "Bypassing CSP via DOM clobbering", Gareth Heyes (2023-06-05)
- PortSwigger, Top 10 web hacking techniques of 2024 (2025-02-04): #5 "Exploring the DOMPurify
  library: Bypasses and Fixes" (Mizu), mutation XSS primitives
- PortSwigger Web Security Academy, client-side prototype pollution and DOM-based vulnerabilities (undated)
- Gareth Heyes, webmail CSS injection research, Black Hat USA 2026 (2026-08-06), as reported by The
  Hacker News (2026-08); primary paper title not retrieved, so only the technique class is used here
- Related: `xss.md`, `headers-cors.md`, `skills/stored-xss-oast/SKILL.md`
