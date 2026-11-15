# Web Cache Poisoning and Cache Deception

**Class:** server-side / infrastructure  **Updated:** 2026-11-15

## What it is
Poisoning: an input the cache does not key on (header, parameter, fat GET body)
changes the response, which is then stored and served to everyone on that key.
Deception: a private page is cached as static because of a path trick
(`/account/x.css`, `;.css`, `%2f..%2fstatic`), then readable anonymously.
Underneath both sits one defect: **the cache and the origin disagree about what
the request said**, so the key written is not the resource served.

## Why this class is different from every other one here
In every other class the proof touches only the tester. Here the proof *is* the
harm: an entry you store is served to every real user who asks for that key,
for as long as it lives, and no apology retracts it. A finding that poisoned a
live key is a finding with an incident attached.

So the method is built around four rules, and `scripts/cache` enforces all four
in code rather than in prose:

1. **Only a key the operator isolated.** A unique cache-buster parameter
   (`?cb=<token>`) on every key anything is stored under, so the poisoned entry
   is one nobody will ever request. The bare key — the one real users hit — is
   refused unless `--i-own-this-cache` is passed, which belongs on your own lab
   and nowhere else.
2. **The marker is inert.** `[A-Za-z0-9._-]{4,64}`, under the reserved
   `.invalid` TLD when it must look like a host. Never a redirect target, a
   script, a CRLF, or the name of a real third party. If the finding would only
   be interesting with an executable payload, the payload is *described* as
   unexecuted impact.
3. **Bust the entry and verify the bust.** A client revalidation
   (`Cache-Control: no-cache, no-store, max-age=0` plus `Pragma: no-cache`)
   replaces the poisoned entry with a fresh clean one, and a second read must
   show the marker gone. The cleanup is part of the evidence, not an afterthought.
4. **A failed cleanup is collateral, loudly.** `scripts/cache` exits 5, names
   the key and says to disclose it. The programme gets the key, the marker and
   the time, and nothing else on that host is poisoned until it is purged.

Note the tension rule 3 creates: once the entry is clean and fresh, replaying
the recorded prime against the same key does **not** re-poison it, because the
cache answers the replay from the clean entry without reaching the origin. The
stored bytes are therefore for inspection and byte-level diffing, and
reproduction is the same subcommand on a new buster key. Safety wins that
trade, and the finding should say so rather than pretend the replay re-proves
it.

## Why `X-Cache: HIT` is not an oracle
It is the most-cited and least load-bearing line in this class, for six
reasons:

- **The origin can set it.** `X-Cache`, `Age`, `X-Cache-Hits` and friends are
  ordinary response headers. An application, a framework or a middlebox nobody
  told you about can emit any of them. Only `Cache-Status` (RFC 9211) has a
  specified meaning, and it is still just a header.
- **It describes the wrong hop.** In a chain of caches the header you see may
  be a hit at a tier that is not the one storing your entry, and a hit at a
  parent can sit behind a miss at a child.
- **A hit does not say *what* was stored.** It confirms a cache answered, not
  that the response carries your input. A hit on a clean entry looks the same.
- **`Age: 0` is ambiguous by construction.** A store and a hit within the same
  second are indistinguishable, and plenty of edges round down.
- **Some vendors report HIT for a stale-while-revalidate serve, a private
  per-client cache, or a hit on a different variant** chosen by a `Vary` you
  cannot see.
- **It is the one signal an attacker-controlled input can influence** on the
  very targets where unkeyed-input poisoning works at all.

So the oracle is always **content**: our inert marker appears in a response to
a request that did not carry it, with a negative control on a key that was
never primed, and for deception an owner-only string reaching a client with no
session. The cache signal is *reported* — the verdict says which signal it
rests on and whether that signal is `explicit`, `weak` or worth nothing — and
it supports the content oracle without ever replacing it. Where the signal is
missing or contradictory, the verdict is `inconclusive`, which in this class is
the common and honest answer.

## How Mythos detects it
`scripts/cache` (skill: `cache-poisoning`), five subcommands, every request
written byte-exact on a fresh socket and recorded as a `kind: "raw"` traffic
record so a validator can read and diff the exact bytes:

- `keys` — cacheability of one busted key first, then one input at a time:
  a curated header list, the query parameters, and the key's *shape* (the port
  in `Host`, path case, trailing slash, path parameter, trailing `%0a`, a
  static-looking suffix). Each classified `unkeyed-and-reflected`, `unkeyed`,
  `keyed`, `ignored` or `inconclusive`, with the signal named.
- `poison` — prime an isolated key through the unkeyed input, read it as a
  second independent client, control on an unprimed key, bust, verify.
- `deception` — nine path variants against a private page, the owner's own
  session as the victim role and an anonymous context as the reader.
- `fatget` — a GET with a body, `X-HTTP-Method-Override`, `X-Method-Override`,
  `X-HTTP-Method`, `?_method=` and a `_method=` form body. Overrides to PUT,
  PATCH and DELETE are refused in code.
- `normdiff` — `%2f`, dot segments encoded and plain, double-encoded dots,
  double slash, path parameter, trailing dot, `/..;/`, duplicate parameters,
  obs-fold, and ambiguous framing.

`wcvs` (Hackmanit Web-Cache-Vulnerability-Scanner) remains in the toolbox for
breadth — ten poisoning techniques including parameter cloaking, response
splitting, HHO/HMC/HMO — and its output is a candidate list, never a finding.

## Normalization is the bug, not a bypass
Everything in `normdiff` is a parsing-difference question. The finding is
"the edge and the origin disagree about what these bytes say", which is a
defect whether or not anything was blocked anywhere: a WAF that parses
differently from the thing it protects is the same defect seen from one side.
Nothing here is scored by whether it got past a filter, there is no
bypass-signature library, and framing it as detection evasion would be both
wrong and useless to a triager — the fix is "normalize once, then route and
key on the normalized form", and that fix is what the report asks for.

Three oracle shapes, because a status difference alone proves nothing:

- **path**: the edge stored an entry under the unresolved target while the
  response is the one for the resolved path, with a control at a path that
  does not exist, to show the shape is being *resolved* and not ignored by a
  catch-all route.
- **cloak** (duplicate parameters): `?x=A&x=B` primed, then `?x=A` alone served
  from cache carrying B's effect. The edge keyed the first occurrence, the
  origin read the last.
- **fold** (obs-fold, deprecated by RFC 7230 and still accepted here and
  there): the same folded bytes answered differently at the edge and at the
  origin. This one needs the origin's own answer; without it, `inconclusive`.

Ambiguous framing (`Content-Length` beside `Transfer-Encoding`, or two
`Content-Length` headers) accepted rather than rejected is recorded as a
normalization fact and **never promoted to a candidate here**. The
baseline/trigger pair on fresh connections belongs to
`knowledge/web/request-smuggling.md` and `skills/desync`, which own the
transport for it. The probes this script does send are self-terminating, so no
tier is ever left waiting for bytes that are not coming — that is the line
between a parsing question and a denial of service, and it is not crossed.

## How to confirm (non-destructive)
1. Establish that the key caches: two reads of one busted key, and a signal
   that says hit.
2. Vary one input. Keep the key, change nothing else.
3. Read the same key as a second client: fresh connection, its own User-Agent,
   no cookies, and none of the inputs the prime carried.
4. Control on a key that was never primed. If the marker shows up there too,
   the target reflects it unconditionally and this is not a cache finding.
5. Bust and verify. Report the cleanup state.
6. Verdict `candidate` with the recorded byte-exact pairs, or `inconclusive`.
   Never `confirmed`: a validator on a different model decides that.

Deception: owner primes the trick URL, the anonymous reader fetches it, the
oracle is an owner-only string, and `not cached` is itself a result worth
reporting — the origin served the private page under a static-looking path and
only the cache rule stood between that and the full bug.

## Does NOT count
A cache signal with no content oracle. A marker the reading request carried
itself — that is a reflection of the key, not the cache serving something a
client never sent. A response that differs because the path differs (a
different path legitimately has a different answer; the oracle must name the
*resolved* path). An unkeyed header that changes nothing observable: a cache
cannot key on what makes no difference, and there is nothing to poison with. A
`Vary`-keyed input mistaken for an unkeyed one because `Vary` was not read.

## Remediation
Key the cache on every input that changes the response, or strip it at the
edge. Cache only by explicit content-type and path rules, never by extension,
and never a response the origin marked `private` or `no-store`. Normalize the
request once, then route *and* key on the normalized form. Reject ambiguous
paths (`;`, encoded slashes, dot segments, backslashes) and ambiguous framing
at the edge rather than forwarding them. Ignore method-override headers unless
a documented API needs them, and never cache a response produced by one.

## Sources
- PortSwigger Web Security Academy, web cache poisoning and web cache
  deception.
- James Kettle, "Practical Web Cache Poisoning" (2018) and "Web Cache Entanglement"
  (2020): unkeyed inputs, cache-key normalization, parameter cloaking, fat GET.
- Omer Gil, "Web Cache Deception Attack" (Black Hat USA 2017), and the 2022
  delimiter/normalization follow-up work on `;`, `%0a`, `%3f` and `%23`.
- RFC 9211, the `Cache-Status` header: the only cache signal with a specified
  meaning, and still only a header.
- RFC 7230 §3.2.4, obs-fold deprecated; RFC 2606, `.invalid` reserved.
- Hackmanit/Web-Cache-Vulnerability-Scanner README (2026-10).
- Orange Tsai, "Breaking Parser Logic" (Black Hat USA 2018), for the
  path-normalization half; see also `knowledge/web/gateway-bypass.md` and
  `knowledge/techniques/parser-differentials.md`.
- Not verified here: which specific CDNs honour a client revalidation as an
  eviction. The cleanup step measures it per target instead of assuming it,
  which is why a failed cleanup is a reported outcome rather than an
  impossibility.
