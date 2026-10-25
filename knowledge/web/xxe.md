# XXE / XML External Entity Injection (CWE-611)

**Class:** server-side  **Updated:** 2026-10-25

## What it is
XML parsers that resolve DTDs/entities: `SYSTEM file:///etc/passwd` → file
read, `SYSTEM http://oast` → OOB/SSRF, billion laughs → DoS. Modern contexts:
SAML signature processing, SOAP endpoints, SVG uploads (document/image
parsers), DOCX/XLSX import (OOXML is a ZIP full of XML), RSS/webhook import.
2026 context: XXE in KEV appliances often acts as an *auth-bypass precursor*
(SAML XXE → assertion forgery).

## How Mythos detects it
- Engine: OOB via interactsh: fuzz XML parameters with a generic entity
  wrapper (`<!DOCTYPE x [ <!ENTITY % a SYSTEM "http://OAST"> %a; ]>`);
  error-based analysis where the server echoes entity content.
- Format awareness: SOAP action bodies, `SAMLResponse` (Base64 inflate),
  `.docx`/`.svg` uploads (OOXML cascade), RSS importers.

## How to confirm (non-destructive)
OOB callback (DNS-only) as proof — no file exfiltration on real targets;
error-based reads only in the lab.

## Remediation
Parser configuration: disable DTD/external entities per language (e.g.
`setFeature(DISABLE_DOCTYPE)`), harden SAML/DOCX parsers, size/depth limits
against entity expansion.

## Sources
- OWASP WSTG-INPV-07; PortSwigger XXE Academy (2026-10); CISA KEV 2026 appliance patterns
