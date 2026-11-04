# Web Cache Poisoning and Cache Deception

**Class:** server-side / infrastructure  **Updated:** 2026-11-04

## What it is
Poisoning: an input the cache does not key on (header, parameter, fat GET body)
changes the response, which is then stored and served to everyone on that key.
Deception: a private page is cached as static because of a path trick
(`/account/x.css`, `;.css`, `%2f..%2fstatic`), then readable anonymously.

## How Mythos detects it
- `wcvs` (Hackmanit Web-Cache-Vulnerability-Scanner): 10 poisoning techniques
  (unkeyed header/param, parameter cloaking, fat GET, response splitting,
  smuggling, HHO/HMC/HMO, param pollution) and deception checks. Candidates only.
- Cache indicators: `X-Cache`, `Age`, `CF-Cache-Status`, `Vary`.

## How to confirm (non-destructive)
Always add a cache buster (`?cb=<token>`) so only the agent's own key is
poisoned. Poison with the unkeyed input, then fetch the same `cb` clean from a
fresh connection: injected value plus a cache-hit indicator = proof; a different
`cb` stays clean (negative control). Deception: userA fetches the trick URL,
then anonymous fetch shows userA's marker with a cache hit.

## Remediation
Key the cache on every input that changes the response or strip it at the edge;
cache only by explicit content type and path rules, not by extension.

## Sources
- Hackmanit/Web-Cache-Vulnerability-Scanner README (2026-10)
- PortSwigger Web Security Academy, web cache poisoning / deception
