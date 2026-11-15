# HTTP Request Smuggling and Desync (CL.TE, TE.CL, 0.CL, CL.0, Expect, H2.TE, CRLF)

**Class:** server-side / infrastructure  **Updated:** 2026-11-14

## What it is
Front end and back end disagree on where a request ends, so the attacker's
trailing bytes become the prefix of the next request on that backend
connection: bypass of front-end controls, response queue poisoning, capture of
other users' requests. The disagreement can come from `Content-Length` versus
`Transfer-Encoding` (CL.TE, TE.CL), from one tier ignoring a length header
entirely (0.CL, CL.0), from `Expect` handling, from an HTTP/2 request
downgraded to HTTP/1.1 (H2.TE, H2.0), or from a CRLF injected into a header
value or a path. It needs a proxy chain (CDN, load balancer, reverse proxy) to
apply at all; a single-server target is `n/a`.

## The variants

| variant | the disagreement |
|---|---|
| CL.TE | front end uses `Content-Length`, back end uses `Transfer-Encoding` |
| TE.CL | the reverse |
| TE.0 | front end honours `Transfer-Encoding`, back end ignores it (reported in Google Cloud Load Balancer; session-token leakage and zero-click account takeover) |
| 0.CL | front end ignores `Content-Length`, back end honours it. Normally deadlocks the upstream; solved with an early-response gadget, and converts to CL.0 with a double desync, which is what makes victim-facing attacks possible |
| CL.0 | front end honours `Content-Length`, back end treats the body as the next request. The classic browser-powered case |
| Expect-based | four published classes: 0.CL with a vanilla `Expect: 100-continue`, 0.CL with an obfuscated one (`Expect: y 100-continue`), CL.0 vanilla, CL.0 obfuscated. `Expect` also makes some chains emit a second response header block, bypassing front-end header removal |
| H2.TE / H2.0 | HTTP/2 to the front end, downgraded upstream, with framing taken from a header the downgrade should have rejected. H2.TE bypassed AWS Desync Guardian |
| CRLF-powered | an injected `Transfer-Encoding` beside the real `Content-Length` gives CL.TE with no double CRLF at all; a CRLF in the path splits the request outright |

**Early-response gadgets** are what make 0.CL workable: a tier that answers
before reading the body. IIS answers `/con` or `/nul` inside a mapped folder;
nginx answers a static-file request early; a server-level redirect works
elsewhere. No viable gadget was found for Apache, which closes the connection
on error.

**Where CRLF gets injected**, in the wild: custom upstream headers such as
`X-Original-Url`, a reflected session cookie, and `$uri` in an nginx
`proxy_pass` (so OpenResty and Tengine are on the candidate list). Most
variants are browser-triggerable through `fetch` or a navigation, including
connection-locked 0.CL (`window.open` plus a navigation lands both requests on
one connection).

## How Mythos detects it
Detection moved from timing to a **baseline-versus-trigger comparison on clean
requests**, and this is the standard now: send a known-good request, send the
same request with exactly one discrepancy introduced, compare the two
responses. Timing detection is heavily WAF-fingerprinted and produces both
false positives and false negatives.

| trigger | a vulnerable chain answers |
|---|---|
| injected version `HTTP/13.37` in a split request line | `505` |
| injected `Transfer-Encoding: x` | `501` |
| injected `Expect: asdf` | `417` with `Connection: close` |
| header visible to one tier, hidden from the other | a response that differs from the normal-`Host`, omitted-`Host` and masked-header baselines |
| two matching `Content-Length` headers, or a bare `\n\n` as header terminator | a response the baseline did not produce |
| connection-locked 0.CL: two requests on one keep-alive connection | `200` then `400` |

- `skills/desync` owns the procedure and the `raw` tool (byte-exact writes,
  half-close control, a fresh connection per probe, its own recorder). The
  recording proxy cannot carry these probes: it is an HTTP/1.1 parser that
  re-frames what it forwards, advertises only `http/1.1` in ALPN, and
  deadlocks on a 0.CL probe whose body is withheld on purpose.
- `smuggler.py` (defparam) still generates CL.TE / TE.CL timing candidates and
  is documented as misfiring on large providers. Treat its output as a hint and
  confirm with the differential, never with its timing.
- Public tooling worth knowing about, none of it headless: HTTP Request
  Smuggler v3.0 and Turbo Intruder (Burp), `t0xodile/crlf-powered-desync-scanner`,
  and the `turtlesec-software/crlf-desyncs` nuclei templates.
- Fingerprint the tiers first; the variant follows from them. Upstream HTTP/2
  is the fix, so the targets worth testing are the ones that downgrade: it was
  confirmed for HAProxy, F5 BIG-IP, Google Cloud, Imperva and Cloudflare
  (internal HTTP/1 only), experimental in Apache, absent in nginx, Akamai,
  CloudFront and Fastly.

## How to confirm (non-destructive)
A differential pair the agent sends itself, on its own fresh connection. The
pair is the proof and the removal of the discrepancy is the control:

1. Baseline: the request without the discrepancy, on a fresh connection.
2. Trigger: the same bytes with the one discrepancy, on a fresh connection.
   The smuggled prefix is a read of a path that does not exist,
   `GET /mythos-<token>`, never a write and never a method with side effects.
3. Proof: a status code, body or header block the baseline did not produce, and
   `traffic replay` of the stored sequence producing it again.
4. Negative control: the same sequence with the framing discrepancy removed and
   nothing else changed, behaving normally.
5. Repeat the trigger once more on a second fresh connection. Twice, or it
   stays a candidate.

**Rule out pipelining and plain connection reuse before calling anything a
hit.** Both fooled a published agentic harness into reporting vulnerabilities
that were not there; the discriminator is step 4.

**Never leave a poisoned connection behind.** One probe, one connection, closed
when the probe ends, never from a pool another client could be served from. A
socket abandoned in a desynced state is a live trap for the next real user of
that backend.

**No response queue poisoning against a live target, and no victim attacks.**
RQP and the socket-capture variants serve the agent's prefix to somebody else's
request. Kettle's own tooling avoids them and the PortSwigger write-up on
automating header injection rejected RQP as too dangerous to real users; one
published RQP demonstration needed about 500 connections for twenty minutes
against real traffic, which is a denial of service with a finding attached. The
classes provable on the agent's own connection — 0.CL, CL.0, the Expect
variants, H2.TE, CRLF splitting — are the ones to run. State the rest as impact
and say why it was not demonstrated.

## Reported impact, for severity
A Cloudflare-internal H2.0 desync exposed over 24 million sites (patched within
hours, $7,000). Akamai CVE-2025-32094, CL.0 via an obfuscated `Expect`, took 65
days and paid 74 bounties totalling $221,000. CRLF-powered desync paid $500 to
$20,000 per report with no CVEs assigned. AWS chose not to patch the ALB-with-IIS
case; the mitigation there is
`routing.http.drop_invalid_header_fields.enabled` plus
`routing.http.desync_mitigation_mode = strictest`. Several of these are the
provider's bug and not the site's: say whose it is in the finding.

## Remediation
Upstream HTTP/2 end to end is the only durable fix. Short of that: normalize or
reject ambiguous requests at the front end (both CL and TE present, obfuscated
TE, duplicate CL, a bare `\n` terminator, CRLF in a header value or path),
never build an upstream URI from a request-controlled variable such as nginx's
`$uri`, and disable backend connection reuse where consistency cannot be
guaranteed.

## Sources
- PortSwigger Research, James Kettle, "HTTP desync attacks" (2019) and "HTTP/2 desync" (2021)
- PortSwigger Research, James Kettle, "HTTP/1.1 must die: the desync endgame" (2025-08-06, updated 2025-10-17); Black Hat USA 2025 slides; the 0.CL Web Security Academy lab
- PortSwigger Research, "CRLF-Powered Desync Attacks: Beheading HTTP Streams" (2026-08-05)
- PortSwigger Research, "Can AI do novel security research?" — the HTTP Terminator, Black Hat USA 2026 / DEF CON 34 (2026-08-05): a multipart/byteranges trigger affecting 200+ sites, dual matching `Content-Length` headers, a dangling-byte RQP enhancement, Shared-Parser Confusion, and **CVE-2026-63078 in Apache Traffic Server**
- PortSwigger Research, "Making header injection critical with one prompt" (2026-11-04)
- Bugcrowd, "Unveiling TE.0 HTTP request smuggling" (Google Cloud Load Balancer)
- defparam/smuggler README (2026-10)
