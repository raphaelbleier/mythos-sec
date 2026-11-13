# Parser Differentials (probe each layer, compare)

**Class:** technique  **Updated:** 2026-11-13

## What it is
Two components read the same bytes and disagree about what they mean. The
security check runs in one parser, the action in the other. This is the
shared mechanism under request smuggling (`knowledge/web/request-smuggling.md`),
cache deception and poisoning (`knowledge/web/cache-poisoning.md`), path
traversal (`knowledge/web/path-traversal.md`), gateway bypass
(`knowledge/web/gateway-bypass.md`), Unicode normalization, JSON/YAML
duplicate-key bugs and SAML signature wrapping. PortSwigger's Top 10 web
hacking techniques of 2025 (published 2026-02-05) lists "Parser
Differentials: When Interpretation Becomes a Vulnerability" (joernchen) at #10
and "Lost in Translation: Exploiting Unicode Normalization" (Ryan and Isabella
Barnett, Black Hat USA 2025) at #4.

## How Mythos detects it
Build the layer list from recon: CDN or WAF, reverse proxy, framework router,
application code, database, downstream services (a second HTTP client, an
XML/JSON/YAML parser, a template engine). Then send one input and observe
what each layer did with it. You need an observation point per layer:
- edge: `Server`, `Via`, `X-Cache`, block pages, WAF reaction;
- proxy/framework: which route ran (a distinct marker in the response);
- app: a reflected or logged form of the value (what string it saw);
- database: the stored value read back (truncation, case folding, collation);
- downstream fetchers: an OAST hit showing the host the second parser chose.

## Probe set (one input, compare per layer)
Use harmless values and your own test objects; add a cache buster.

```
path:     /a/..%2fb   /a/%2e%2e/b   /a;x/../b   //a   /a/./b   /a%00.png   /a\b
query:    ?a=1&a=2   ?a[]=1   ?a=1;a=2   ?a=%u0041   (duplicate key: first, last or joined?)
header:   duplicated Host / Content-Length, obs-fold, a header name with _ vs -
body:     JSON {"a":1,"a":2}   YAML with anchors/duplicate keys   charset=ibm037 vs utf-8
url host: http://good.example@evil.example/   http://good.example#@evil.example/   http://evil.example\@good.example/
unicode:  U+FF07 (fullwidth ') , U+212A (Kelvin K), U+0131 (dotless i), ligatures, U+2024
email:    a@b.com@evil.com   "a@b.com"@evil.com   a@b.com%0d%0a
```

Reading the results:
- Different value or route per layer = a differential. It is a candidate only.
- It becomes a finding when the differential crosses a security decision:
  the checker saw a safe value, the consumer used a dangerous one.

## How to confirm (non-destructive)
Choose the decision that the differential could cross, then build the pair:
check-layer sees X, use-layer sees Y. Examples and the oracle for each:
- path: ACL layer allows `/public/..;/admin`, origin serves `/admin`. Oracle:
  admin-only marker in the body (see `gateway-bypass.md`).
- Unicode: a filter blocks `'` or `<script`, a later layer normalizes (NFKC)
  `U+FF07` or `U+FF1C` into the blocked character. Oracle: the normalized
  form appears in the sink (a reflected or stored value) after the filter
  allowed the original. Order of normalization versus validation decides the
  bug: validate after normalizing, not before (Barnett, Black Hat USA 2025).
  Also account collisions: register with a Kelvin-sign or dotless-i variant of
  an email you own and see whether it maps onto your other account (own
  accounts only).
- URL host: a validator and the fetcher disagree on the host of
  `good@evil` forms. Oracle: OAST hit on the host the fetcher chose
  (`knowledge/web/ssrf.md`).
- duplicate keys: validator reads the first `role`, the binder reads the last.
  Oracle: durable state on the agent's own object (`mass-assignment.md`).
- cross-component identity: a shared identity pool that splits a username on
  `_` while the sub contains `_` yields different identities per component
  (Doyensec, Cognito multi-SSO, 2026-05-05).

Negative control: the same probe with the variant removed gets the expected
single interpretation in every layer. Proof = the two observations side by
side (what the check saw, what the use did) plus the security effect.

Does NOT count: a response that merely differs in length or status between
layers; a normalization that the application also rejects in the second
layer; an encoding that the target echoes but no consumer decodes.

## Remediation
One canonical parse per value, validated after normalization and used in its
canonical form; reject ambiguous inputs (duplicate keys, mixed encodings,
raw backslashes in paths); route and authorize on the same representation
that the origin uses.

## Sources
- PortSwigger Research, "Top 10 web hacking techniques of 2025" (2026-02-05).
- joernchen, "Parser Differentials: When Interpretation Becomes a
  Vulnerability", OffensiveCon 2025 (abstract only; no whitepaper).
- Ryan and Isabella Barnett, "Lost in Translation: Exploiting Unicode
  Normalization", Black Hat USA 2025.
- Orange Tsai, "Breaking Parser Logic", Black Hat USA 2018-08-08.
- Doyensec, "The Danger of Multi-SSO AWS Cognito User Pools" (2026-05-05).
