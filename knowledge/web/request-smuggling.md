# HTTP Request Smuggling (CL.TE, TE.CL, H2 downgrade)

**Class:** server-side / infrastructure  **Updated:** 2026-11-04

## What it is
Front-end and back-end disagree on where a request ends (`Content-Length` vs
`Transfer-Encoding`, or HTTP/2 downgraded to HTTP/1.1), so the attacker's
trailing bytes become the prefix of the next request on that backend
connection: bypass of front-end controls, response queue poisoning, capture of
other users' requests.

## How Mythos detects it
- `smuggler.py` (defparam): timing-based CL.TE / TE.CL probes, configs
  `default`/`doubles`/`exhaustive`. README warns of false positives and
  negatives, especially on large providers. Candidates only.
- Needs a proxy chain (CDN, load balancer, reverse proxy) to apply at all;
  single-server targets are `n/a`.

## How to confirm (non-destructive)
Differential pair sent by the agent itself, lab or explicit permission only:
attack request smuggling `GET /mythos-<token>`, then a normal request; the
normal request receiving the `/mythos-<token>` response (twice) is the proof,
the same pair without the conflicting length headers is the negative control.
Recipe in `skills/deep-server/SKILL.md`. Never leave a poisoned backend socket
on a live target.

## Remediation
Normalize or reject ambiguous requests at the front end (both CL and TE,
obfuscated TE), use HTTP/2 end to end, disable backend connection reuse where
it cannot be made consistent.

## Sources
- defparam/smuggler README (2026-10)
- PortSwigger Research, HTTP desync attacks (2019) and HTTP/2 desync (2021)
