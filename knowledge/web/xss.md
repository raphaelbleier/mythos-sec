# Cross-Site Scripting (XSS)

**Class:** injection / client-side  **Updated:** 2026-11-13

## What it is
Attacker-controlled input is rendered in a page without context-aware encoding, executing script in
victims' browsers. Variants and where each is handled:
- **Reflected**: input comes back in the response of the same request. This note.
- **Stored / blind**: input is saved and rendered later to another user or an admin queue:
  `skills/stored-xss-oast/SKILL.md` (token per injection point, browser canary or OAST hit).
- **DOM**: the page's own JS moves input into a sink; the server response is clean:
  `client-side-dom.md` (sinks, postMessage, clobbering, prototype pollution).
- **Mutation XSS (mXSS)**: sanitized markup mutates into executable markup when re-parsed. Below.
- **Delivery through model output** (chat markdown, agent answers): `llm-output-handling.md`.

## How Mythos detects it
- Engine: reflected-XSS probe injects a unique marker with `<svg/onload>` and raw quotes, flags only
  when reflected unencoded in an HTML context (encoded reflection is not flagged, FP guard).
- First step by hand: send a harmless alphanumeric token (`mythosq7x`) and read **where** it lands:
  HTML body, attribute value (quoted or not), `<script>` string, URL attribute (`href`/`src`),
  `<style>`, HTML comment, JSON in a `<script>` block, or inside a framework template. The context
  picks the payload; a payload from a list without that step is the main source of false positives.
- Tools: `dalfox` (payload verification, DOM mode), the Playwright **mythos-browser** agent for
  DOM, stored and auth-gated pages.

| context | what must survive to execute | encoded reflection means |
|---|---|---|
| HTML body | `<` and `>` raw | not exploitable here |
| quoted attribute | the quote char, then `onfocus=`/`autofocus` | not exploitable unless unquoted |
| unquoted attribute | a space | |
| `<script>` JS string | the quote or `</script>` | `<` escaping stops it |
| URL attribute | `javascript:` scheme allowed | scheme filter or encoding stops it |
| template literal / `{{ }}` | engine syntax: that is `ssti.md` / client-side template injection | |

## How to confirm (non-destructive)
1. Mint a token for the injection point and take the payload for the observed context:
   ```
   scripts/mythos python3 skills/stored-xss-oast/scripts/xss_verify.py token \
     --map engagements/<dir>/scan/xss-tokens.jsonl --point 'GET /search q' --oast <oast base>
   ```
   The payload logs `MYTHOS-XSS:<token>` and loads `<oast>/<token>`; it carries no cookie theft.
2. Open the single PoC URL in a real browser context (`xss_verify.py verify --url ... --state ...`
   or the browser agent). Evidence = the console line or OAST hit carrying the token, plus the
   screenshot and the reflection context. A scanner "V" line, a payload visible in view-source
   or a 200 does not execute anything.
3. **Negative control:** the same request with the token but without the markup characters
   (`mythosq7x` plain) must show no execution; and the request as sent through the encoder the app
   applies (for example, a different parameter that is correctly encoded) stays inert.
4. A reflected finding is user-interaction-based: record whether it needs the victim to open a
   crafted link (`GET`) or a form post (`POST`, usually needs CSRF-style delivery), and whether
   the cookie has `HttpOnly` (reduces session theft, not script execution).

### CSP and Trusted Types interaction
Read `Content-Security-Policy` (header or `<meta>`) before judging severity.
- Execution blocked by CSP but markup injected: report the HTML injection as `candidate` and say what
  the policy blocks (`script-src 'self'`, nonces, `object-src`, `base-uri`). Then check known
  policy bypasses only with the canary: JSONP or open redirect on an allowed host, a missing
  `base-uri`, nonce reuse across responses, DOM clobbering of an allowed `script.src`
  (`client-side-dom.md`; PortSwigger 2023-06-05).
- `unsafe-inline` or `unsafe-eval` in `script-src` is not an XSS finding by itself.
- `require-trusted-types-for 'script'` makes string-to-sink assignments throw: the DOM payload
  must go through a policy. A permissive `default` policy that returns its input is a finding in
  its own right only when a token then executes.
- `Content-Security-Policy-Report-Only` does not block; execution under it proves the bug, not a bypass.

### Mutation XSS
When input is sanitized (DOMPurify, a server-side allow-list) and the result is put in `innerHTML`,
test only the canary payload against the library version from the bundle. DOMPurify bypasses
based on browser parsing quirks (node flattening, the stack of open elements, namespace confusion)
were the #5 entry of PortSwigger's Top 10 web hacking techniques of 2024 (2025-02-04, Mizu).
Proof = the token executes in a browser for the pinned sanitizer version; the sanitizer's output
string looking odd does not count. Check the target's own sanitizer settings (`ALLOWED_TAGS`,
`ADD_ATTR`, `FORBID_*`): a permissive config is a cheaper bug than a parser bypass.

## What does NOT count
Encoded reflection, reflection in a non-executing context (`<textarea>`, JSON response with
`application/json` and `nosniff`, a download), `alert` on a page the victim cannot reach, self-XSS
(only you can inject and view), a missing CSP or `HttpOnly` flag alone, a header-injection that does
not render. A payload that executes only in the toolbox browser because you disabled the CSP.

## Remediation
Context-aware output encoding at the sink; a strict nonce-based Content-Security-Policy with
`base-uri 'none'` and `object-src 'none'`; Trusted Types for DOM sinks; keep the sanitizer updated
and sanitize last, right before `innerHTML`; no re-parsing of sanitized HTML.

## Sources
- OWASP WSTG-INPV-01/02; PortSwigger Web Security Academy, XSS and DOM-based vulnerabilities (2026-10)
- PortSwigger Research, "Bypassing CSP via DOM clobbering", Gareth Heyes (2023-06-05)
- PortSwigger, Top 10 web hacking techniques of 2024 (2025-02-04), #5 "Exploring the DOMPurify
  library: Bypasses and Fixes"
- Related: `client-side-dom.md`, `llm-output-handling.md`, `ssti.md`, `skills/stored-xss-oast/SKILL.md`
