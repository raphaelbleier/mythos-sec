# Security Headers, Cookies & CORS

**Class:** configuration  **Updated:** 2026-10-25

## How Mythos detects it
Engine passive checks: missing CSP/HSTS/X-Frame-Options/X-Content-Type-Options; cookies without HttpOnly/Secure/SameSite; CORS that reflects an arbitrary Origin with credentials (high) or wildcard-with-credentials (medium).

## How to confirm
CORS: send `Origin: https://evil.example` and observe it reflected in `Access-Control-Allow-Origin` together with `Access-Control-Allow-Credentials: true`.

## Remediation
Deploy CSP and HSTS; set secure cookie flags; validate Origin against an allowlist; never pair a reflected/`*` ACAO with credentials.

## Sources
- OWASP Secure Headers Project; WSTG-CLNT-07.
