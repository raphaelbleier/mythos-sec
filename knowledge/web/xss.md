# Cross-Site Scripting (XSS)

**Class:** injection / client-side  **Updated:** 2026-10-25

## What it is
Attacker-controlled input is rendered in a page without context-aware encoding, executing script in victims' browsers. Variants: reflected, stored, DOM.

## How Mythos detects it
- Engine: reflected-XSS probe injects a unique marker with `<svg/onload>` and raw quotes, flags only when reflected unencoded in an HTML context (encoded reflection is not flagged — FP guard).
- Tools: `dalfox` (payload verification, DOM), Playwright browser agent for DOM/stored XSS and auth-gated pages.

## How to confirm (non-destructive)
A single PoC URL that pops a harmless marker (e.g. `alert(document.domain)`), not a real payload against real users. Capture the reflection context.

## Remediation
Context-aware output encoding; a strict Content-Security-Policy; Trusted Types for DOM sinks.

## Sources
- OWASP WSTG-INPV-01/02; PortSwigger — XSS (2026-10).
