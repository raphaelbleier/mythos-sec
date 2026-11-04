# Mythos knowledge base

Per-bug-class notes the Mythos agents read at runtime to pick confirmation
steps and cut false positives. Add new notes with the `research-ingest` skill
(`/cybersecurity research <topic>`). One fact per file; keep them short, dated
and sourced.

## Web
- [SQL Injection](web/sql-injection.md)
- [Cross-Site Scripting](web/xss.md)
- [Server-Side Request Forgery](web/ssrf.md)
- [Broken Access Control (IDOR/BOLA/BFLA)](web/access-control.md)
- [Server-Side Template Injection](web/ssti.md)
- [JWT / OAuth / Session](web/jwt-oauth.md)
- [Security Headers, Cookies & CORS](web/headers-cors.md)
- [Unsafe Deserialization → RCE](web/deserialization.md)
- [OS Command Injection (CWE-78)](web/command-injection.md)
- [Path Traversal & Arbitrary File Write](web/path-traversal.md)
- [Unrestricted File Upload → RCE](web/file-upload.md)
- [XXE / XML External Entity Injection](web/xxe.md)
- [GraphQL & Modern API Testing](web/graphql-api.md)
- [Race Conditions](web/race-conditions.md)
- [Mass Assignment (BOPLA)](web/mass-assignment.md)
- [Web Cache Poisoning & Deception](web/cache-poisoning.md)
- [HTTP Request Smuggling](web/request-smuggling.md)

## Techniques
Cross-cutting methodology used by the `cve-deep-dive` skill.
- [CVE Triage 2026 (KEV/EPSS pipeline)](techniques/cve-triage-2026.md)
- [Patch Diffing](techniques/patch-diffing.md)
- [Exploit Chaining](techniques/exploit-chaining.md)
