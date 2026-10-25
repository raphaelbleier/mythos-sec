# Server-Side Request Forgery (SSRF)

**Class:** server-side  **Updated:** 2026-10-25

## What it is
The server fetches a URL the attacker controls, reaching internal services, cloud metadata (169.254.169.254) or otherwise unreachable hosts.

## How Mythos detects it
- Engine: out-of-band check. The OAST listener issues a unique callback URL on url/fetch/redirect-like params; a received callback confirms SSRF (confidence: certain).
- Tools: `interactsh-client` for OOB on remote engagements; `nuclei` SSRF templates.

## How to confirm (non-destructive)
Point the parameter at your own collaborator host and observe the inbound request. For impact, demonstrate reading a benign internal endpoint, not sensitive data.

## Remediation
Allowlist outbound hosts; block internal ranges and the metadata IP; re-validate after redirects; disable unused URL schemes.

## Sources
- OWASP WSTG-INPV-19; PortSwigger — SSRF (2026-10).
