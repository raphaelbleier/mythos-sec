# Server-Side Template Injection (SSTI)

**Class:** injection  **Updated:** 2026-10-25

## How Mythos detects it
Engine sends engine-specific arithmetic probes (`{{1337*1337}}`, `${...}`, `#{...}`, `<%= %>`); a rendered product (1787569) that is not the literal payload confirms evaluation. Distinct primes avoid confusion with reflected literals.

## How to confirm (non-destructive)
Escalate the arithmetic proof to an engine identification payload only; stop before RCE. Note the engine (Jinja2, Twig, Freemarker, Velocity) for the report.

## Remediation
Never render user input as a template; pass user data only as bound variables; sandbox the engine.

## Sources
- PortSwigger — SSTI (2026-10); James Kettle, "Server-Side Template Injection".
