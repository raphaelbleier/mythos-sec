# Server-Side Request Forgery (SSRF)

**Class:** server-side  **Updated:** 2026-11-13

## What it is
The server fetches a URL the attacker influences, reaching internal services,
cloud metadata (169.254.169.254) or hosts the tester cannot reach. Sinks: url,
callback, webhook, avatar-by-URL, import, PDF/screenshot renderers, link
unfurlers, XML/SVG fetchers, and URLs a model emits that a server then fetches
(`llm-output-handling.md`). Webhook target URLs are the same sink
(`webhooks.md`).

## How Mythos detects it
- OAST first: a unique callback URL per parameter (`http://<token>.<oast>/`);
  an inbound request carrying the token is the signal. Record the source IP,
  `User-Agent` and HTTP method of the hit: they show which component fetched
  (a library UA, a headless browser, a PDF engine) and whether it sent headers.
- Blind (no response shown): the OAST hit is the oracle. Without egress, use a
  timing pair: a closed port on your own OAST host vs an open one, repeated 3
  times; only a stable difference counts.
- `nuclei` SSRF templates and `interactsh-client` are candidate generators.

## Probes (all against hosts you control)
1. Plain: `url=http://<token>.<oast>/a`. Hit = the server makes requests.
2. Redirect following: your OAST host answers `302 Location: http://<token2>.<oast>/b`.
   A second hit on `/b` proves redirects are followed, with no internal host
   touched. Repeat with `307` (method kept) and a redirect to another scheme.
3. Filter bypass, each with a negative control (the same form pointing at your
   OAST host must be allowed, otherwise you are testing an allowlist, not a bug):
   - numeric forms of one host: `http://2130706433/`, `http://0x7f000001/`,
     `http://0177.0.0.1/`, `http://127.1/`
   - `http://[::ffff:127.0.0.1]/`, `http://[::1]/`
   - userinfo and fragment tricks: `http://allowed.example@<oast>/`,
     `http://<oast>#@allowed.example/`, `http://allowed.example.<oast>/`
   - DNS name you control that resolves to a private address (OAST resolves to
     your own address; use a rebinding service only against your own sink)
   - scheme and handler: `file://`, `gopher://`, `dict://`, `ftp://` (only
     check whether the scheme is accepted, via an OAST hit for `ftp://`)
   - URL parser differential: the validator and the fetcher parse the same
     string differently (backslash, `\@`, encoded dot, `//` vs `/`). See
     `techniques/parser-differentials.md`.
4. Redirect-loop SSRF (PortSwigger Top 10 2025 #3, shubs, Searchlight Cyber,
   2025-06-23): a blind SSRF that follows redirects may return the final
   response body if your server loops redirects with an increasing status code,
   because some clients only surface the body once a redirect limit is hit.
   Test only against your own redirector first; the aim is to learn whether the
   target returns upstream bodies, using an OAST-hosted marker page.

## Cloud reality
A plain GET SSRF usually cannot read cloud credentials:
- AWS IMDSv2: `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds`,
  then `X-aws-ec2-metadata-token` on GET; PUTs with `X-Forwarded-For` are
  rejected; default response hop limit is 1. IMDSv1 (no headers) is still the
  default unless an instance is set to token-required. (AWS EC2 User Guide)
- GCP: every request needs `Metadata-Flavor: Google`, else it is denied.
- Azure IMDS: needs `Metadata: true` and must not carry `X-Forwarded-For`.
So the finding states what the primitive controls: method, headers, body. A
GET-only SSRF against IMDSv2 or GCP/Azure is internal-network reach, not
credential theft. Needing header or method control is part of the report.

## How to confirm (non-destructive)
- Proof: an OAST hit with the token, mapped to one parameter, plus the
  negative control (token not sent, or the parameter set to an allowed host,
  gives no hit). For impact: one benign internal response (a health page you
  can identify as internal), never credentials or tokens.
- Probe 169.254.169.254 or other metadata hosts only if the program allows
  it; report the reachable path and status code. Do not read or store IAM
  credentials, do not use them. Do not scan internal ranges; one or two named
  hosts at most, inside `rules.max_requests`.
- Does NOT count: the parameter appearing in a redirect, a 200 from your own
  host, a validator error message, a DNS-only hit from a resolver the target
  does not control (check the source IP is plausibly the target's).

## Remediation
Allowlist destinations after resolving DNS and pin the resolved IP for the
connection; re-validate every redirect hop or disable redirects; block
link-local, loopback and private ranges incl. IPv4-mapped IPv6; allow only
http(s); require IMDSv2 and disable unused metadata; egress filtering.

## Sources
- OWASP WSTG-INPV-19; PortSwigger Web Security Academy, SSRF (2026-10)
- PortSwigger Top 10 Web Hacking Techniques of 2025 (2026-02-05): #3 "Novel SSRF Technique Involving HTTP Redirect Loops"
- Searchlight Cyber, same title (2025-06-23)
- AWS EC2 User Guide, "How Instance Metadata Service Version 2 works"
- Google Compute Engine docs, "Query instance metadata"; Microsoft Learn, "Azure Instance Metadata Service" (updated 2026-05)
