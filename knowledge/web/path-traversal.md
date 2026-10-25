# Path Traversal (CWE-22) & Arbitrary File Write

**Class:** server-side  **Updated:** 2026-10-25

## What it is
File path parameters that break out of the app root via `../` sequences,
encodings (`%2e%2e%2f`, double-encoded `%252e`, UTF overlong), or absolute
paths (`/etc/passwd`, `C:\Windows\win.ini`). Three impact levels:
read → write/delete → RCE (webshell drop). KEV-real in 2026: Fortinet
CVE-2025-61624 (path traversal, authenticated admin → arbitrary file
write/delete via CLI), KEV October 2026.

## How Mythos detects it
- Engine: parameter mutation lists for `file`, `path`, `download`, `template`,
  `doc`, `attachment`, `report`, `img`, `lang`, `include`-like parameters;
  canary traversals (nested `....//`, client-side normalization chew) and LFI
  oracles (`root:.*:0:0` in /etc/passwd, `[fonts]` in win.ini).
- Upload angle: when `filename` is server-side joined → `shell.php%00.jpg`,
  `..\..\` Windows backslash mixing, Zip-Slip on extraction.
- Tools: ffuf with a traversal wordlist through `run_tool`; nuclei LFI
  templates.

## How to confirm (non-destructive)
Read-only oracle files without secrets (passwd header lines, win.ini) or an
OAST callback via URL-fetchable parameters. NO write proof on production
targets — writes only in the lab.

## Remediation
Indirection (file IDs instead of paths), normalize + prefix allowlist,
chroot/container FS boundaries, watch Windows/Unix dual encodings.

## Sources
- CISA KEV CVE-2025-61624 (2026-10); PortSwigger File Path Traversal Academy (2026-10)
