# Unrestricted File Upload → RCE

**Class:** server-side  **Updated:** 2026-10-25

## What it is
Upload functionality that accepts webshell-suited files/extensions or validates
content type/extension only on the client or only at the filename level. Chain
potential: RCE via PHP/JSP/cgi extensions, `.htaccess`/`web.config`
overwrite, polyglot images (EXIF shell), Zip-Slip on extraction (CWE-22
related).

## How Mythos detects it
- Engine: detect upload forms (multipart/enctype), then test a matrix:
  double extensions (`shell.php.jpg`, `shell.jpg.php`), case tricks (`.pHp`,
  `.PHP5`, shtml/svc), legacy null bytes, MIME tampering (`Content-Type` vs
  magic bytes), SVG with `<script>` (XSS vector), `.htaccess` handler probe.
- Retrieval oracle: after upload, fetch the upload URL with a query marker —
  lab targets only for execution proof; on real targets demonstrate the
  validation bypass with harmless content only.

## How to confirm (non-destructive)
Lab: upload a marker file `<?php echo "MYTHOS-" . (1+1); ?>`, prove it is
served and executes; then repeat against the patched validation → the marker
must be rejected. Production: proof of validation bypass stops at fetching a
harmless file, never shellcode.

## Remediation
Server-side extension + magic byte check, storage outside webroot,
randomized filenames, forced `Content-Disposition` download, MIME consistency,
no `.htaccess` parseability in upload dirs.

## Sources
- OWASP WSTG; PortSwigger File Upload Academy (2026-10)
