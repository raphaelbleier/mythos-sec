# Subdomain Takeover (dangling CNAME, NS, A)

**Class:** infrastructure  **Updated:** 2026-11-13

## What it is
A DNS record of an in-scope name points at a third-party resource that no longer exists or was
never claimed (deleted bucket, removed PaaS app, expired domain, dead nameserver zone). Whoever
registers that resource then serves content under the target's name: phishing on a trusted host,
cookie access for the parent domain, an allow-listed CSP or CORS origin, OAuth `redirect_uri`
hosts, script hosts (see `client-side-supply-chain.md`).

## How Mythos detects it
Subdomain input is the `recon` output (`subfinder`; `amass` is in the toolbox image). Keep only
names that `scope.yaml` covers.
```
scripts/mythos sh 'while read h; do dig +noall +answer "$h" CNAME; done < recon/subs.txt'   # dnsx is not in the image
scripts/mythos sh 'nuclei -l recon/live.txt -t http/takeovers/ -rl 10'      # fingerprint templates
```
Flag, in order of strength:
1. **CNAME to a provider whose target does not resolve** (NXDOMAIN on the CNAME target).
2. **CNAME to a provider that resolves** and the HTTP body is the provider's "unclaimed" page
   (GitHub Pages "There isn't a GitHub Pages site here.", S3 `NoSuchBucket`, Heroku "no such app",
   Azure/Fastly/Shopify and similar). The canonical fingerprint list is `can-i-take-over-xyz`, which
   marks each service as Vulnerable or Edge case; Edge case means a claim may be blocked by the
   provider (domain verification), so fingerprint alone is weaker.
3. **NS delegation to a dead zone**: `dig NS sub.<domain>` returns nameservers that answer
   `REFUSED`/`SERVFAIL` or whose own domain is unregistered (RDAP, GET). Highest impact, rare.
4. **A record to an IP** the target no longer owns (cloud elastic IP): only a candidate, since the
   claim is probabilistic and needs allocating addresses; do not attempt it.
Tools (only nuclei is in the toolbox image; install `dnsReaper` and `subjack` on demand): nuclei `takeovers` templates (`http/takeovers/` in projectdiscovery/nuclei-templates),
`dnsReaper` (Punk Security, signature-based, exits non-zero on a possible takeover), `subjack`
(haccer). None is the proof. Run them one at a time (toolbox RAM limit).

## How to confirm (non-destructive)
Proof is read-only and **stops there**:
1. DNS trace: `dig +trace <host>` or the CNAME/NS answers plus the NXDOMAIN or `REFUSED` line.
2. Provider fingerprint: `curl -sI https://<host>/` and the body excerpt that matches the
   `can-i-take-over-xyz` entry (and the provider status check, for example RDAP "not found" for a
   CNAME target domain).
3. The negative control: a neighbouring in-scope host on the same provider that serves normal
   content, or the same host's fingerprint absent after a retry (providers flap).
Closure state `reproduced`. Raise to `validated` with the same stored `dig`/`curl` file re-run.

**Claiming** the resource (creating the bucket, app or domain) is out of bounds unless the program
text explicitly permits proof-of-takeover. If it does, the only allowed artifact is a static page
with a unique token and a contact line, no login, no form, no script, no cookies set, served only
long enough for triage and removed afterwards. Never register an expired domain. Without that
permission, report the dangling record with the DNS trace and fingerprint and say it is unclaimed.

**Impact check without acting:** read the parent's cookie scope from responses you already have
(`Set-Cookie: Domain=.example.com` means a taken subdomain reads and sets session cookies),
`Access-Control-Allow-Origin` and CSP allow-lists that list the subdomain, and OAuth redirect
allow-lists. Do not set cookies or make the host answer.

## What does NOT count
A CNAME to a provider that is still claimed by the target, a 404 from the origin, a fingerprint
matched on an `Edge case` entry without a second signal, a scanner line without the DNS trace,
an `A` record to a cloud IP, `NXDOMAIN` on the host itself with no record at all (nothing to take).

## Remediation
Delete DNS records when the resource is removed, claim the provider-side domain verification
before pointing DNS, inventory DNS against cloud assets, monitor for NXDOMAIN CNAME targets.

## Sources
- OWASP WSTG, Test for Subdomain Takeover (WSTG-CONF-10): confirm the fingerprint and that the
  resource is unclaimed, do not claim it (undated, current guide)
- EdOverflow, can-i-take-over-xyz fingerprint list (GitHub, continuously maintained)
- projectdiscovery/nuclei-templates `http/takeovers/`; punk-security/dnsReaper; haccer/subjack
  (tool READMEs; signature counts not verified)
- Related: `client-side-supply-chain.md`, `headers-cors.md`, `ssrf.md` (dangling hosts allow-listed server-side)
