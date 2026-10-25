# Unsafe Deserialization → RCE

**Class:** server-side  **Updated:** 2026-10-25

## What it is
An application deserializes untrusted data (Java `ObjectInputStream`, .NET
`BinaryFormatter`/`ViewState`/`TypeNameHandling`, PHP `unserialize`, Python
`pickle`, Ruby `Marshal`) with an attacker-summonable gadget object → code
execution. KEV-real in 2026: SharePoint CVE-2026-58644 (deserialization → RCE,
KEV July 2026); a recurring stereotype of appliance CVEs (Fortinet, Ivanti,
VMware).

## How Mythos detects it
- Engine signatures: `__VIEWSTATE` parameter without MAC validation; Java
  stream marker (`rO0AB`); PHP object (`O:<len>:`); Ruby (`--- !ruby/object`);
  Python pickle markers in Base64 blobs; .NET `TypeNameHandling` in JSON
  (`$type` key).
- Fingerprint: product + version → `cve_lookup` (appliance deserialization
  CVEs are mostly unauthenticated and dominate KEV).
- Tools: ysoserial / ysoserial.net in the toolbox container (via `docker exec`).

## How to confirm (non-destructive)
- DNS/OOB-only payload (ysoserial `URLDNS` gadget): a single callback through
  your own collaborator proves the sink without executing code.
- On lab targets: harmless command marker (`id` echo, marker file in tmp).

## Remediation
Avoid deserializing untrusted input entirely; otherwise: MAC/integrity checks
(ASP.NET `enableViewStateMac`), pin versions, prefer type-safe formats (JSON
without `$type`, forbid `pickle`).

## Sources
- CISA KEV, CVE-2026-58644 (2026-07); OWASP Deserialization Cheat Sheet (2026-10)
