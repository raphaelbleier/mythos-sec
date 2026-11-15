---
name: takeover
description: Subdomain and dangling-resource takeover for a Mythos engagement - a CNAME or ALIAS pointing at an unclaimed cloud or PaaS name, an NS delegation nobody serves, a zone the registry has let go, buckets and PaaS hosts referenced from HTML, CSS, JS, CSP, preconnect and source maps, third-party script hosts that no longer resolve with their SRI coverage, and dead domains in CSP report-uri, form-action, SPF include: and OAuth redirect allowlists - each judged against a fingerprint table that states separately what the provider's unclaimed page looks like and whether claiming the name is actually possible today. Nothing is ever claimed. Use when recon maps a CNAME to a provider, an external script or bucket reference, a CSP, or a subdomain list.
---

# Takeover: the reference still points somewhere, and nobody is there

A takeover finding is three facts, and scanner output usually carries one.

1. **A reference that still points somewhere.** A CNAME, an NS delegation, a
   `<script src>`, a CSP source, an SPF `include:`, an OAuth redirect entry.
2. **A destination that is unclaimed.** The provider's own "there is nothing
   here" response, or NXDOMAIN on the record's target.
3. **A claim path that is open today.** This is the part that is almost always
   missing, and the part that decides whether anything is a finding. Providers
   added domain verification: GitHub Pages, Vercel, Netlify, Shopify and Azure
   App Service all ask, in some configuration, for proof that the domain is
   yours before they will serve it. A perfect fingerprint on one of those is
   not a takeover.

So this skill's output is `candidate` at its strongest, `inconclusive` wherever
the fingerprint or the claimability is ambiguous, and `dead-reference` where
the name is dangling but the provider will not hand it over. `confirmed` belongs
to the validate phase (AGENTS.md), and `takeover` never writes it.

## The line, and why it is where it is

**Never claim the resource.** Do not register a domain, create a bucket, add a
PaaS app, reserve a tunnel or package name, or change a DNS record — not to
prove the finding, not "just a static page", not on a lab-looking target. The
script refuses in code: `takeover claim`, `takeover register`, `takeover
occupy` and every other spelling exit 3 with the refusal and do nothing.

The reasons, in order of how much they cost when ignored:

- Claiming **is** the attack. It takes control of a name third parties still
  trust, and from that moment every visitor's browser is talking to the
  operator's infrastructure under the target's name.
- It is not reversible from the target's side. They cannot un-ring it; they can
  only delete the record and hope nobody looked.
- It puts the operator into a contract with a cloud provider over a name they
  do not own, under a bounty programme that usually forbids exactly that by
  name.
- And it is unnecessary. The evidence a triager needs — the DNS answer, the
  provider's unclaimed-host response, and the written claim path — is entirely
  read-only, and `takeover` produces all three.

Whether to take the last step is the **operator's** decision on a real
engagement, read against that programme's own text, in an editor, outside a
run. It is not a decision an unattended agent gets to make, because the agent
cannot read the contract, cannot own the consequence and cannot undo it. If the
programme does permit proof-of-takeover in writing, `knowledge/web/subdomain-takeover.md`
says what the only acceptable artifact looks like — and a human still does it.

## Scope, in two halves

`engagements/<dir>/scope.yaml` is the authorization boundary and is never
widened, by this skill or anything in it. The halves differ:

- **DNS is free.** Reading a public CNAME, NS, TXT or SOA record is not
  touching a host. `takeover` resolves any name you give it.
- **HTTP is gated.** A dangling name usually resolves *outside* scope — that is
  the nature of the bug — and fingerprinting it means sending a request to a
  third party's server. Every HTTP fingerprint is scope-checked, refused rather
  than sent, and the refused destination is **reported** in the result
  (`refused` in `--json`, a section in the text output) so the gap is visible
  instead of silent. A refused fingerprint downgrades the verdict to
  `inconclusive`; it never invents one.

If an engagement genuinely needs the provider fingerprinted, the operator adds
that provider host to `in_scope` in an editor before the run. Never from inside
one, and never to silence a warning.

No brute force. `takeover cname --wordlist` exists, is off unless asked for,
caps at `--max-names` (default 50) and paces every lookup by
`rules.rate_limit_rps`. Recon's subdomain list is the intended input; the
sweep is a fallback, not a discovery strategy.

## 1. Read the table before you read a result

```
script: name "takeover", args ["fingerprints"]
```

It prints the table version, which services can reach `candidate` at all
(`claimable: yes` **and** `confidence` high or medium), which entries are stale
(`confidence: low`, carried from a published list and not corroborated), and a
shape check. `--full` prints the whole table; `--json` for the machine form.
The data lives in `knowledge/web/takeover-fingerprints.json`.

Today only four services can produce a `candidate` from a fingerprint alone:
`aws-s3`, `gcs`, `azure-blob`, `azure-trafficmanager`. Everything else is an
edge case, a verified-domain provider, or a stale entry. That ratio is the
honest state of this class, not a gap in the table.

A match on a stale entry is still worth a line in the report: it is a lead for
a human who can read the provider's current documentation. It is never a
candidate.

## 2. Mine the references out of what recon already fetched

```
script: name "takeover", args ["dangling", "--url", "https://app.test/"]
script: name "takeover", args ["dangling", "--url", "https://app.test/static/app.js.map"]
script: name "takeover", args ["dangling", "--file", "engagements/<dir>/loot/bundle.js"]
```

`dangling` takes exactly one input: `--url` (fetched, scope-checked), `--file`
(a local HTML, CSS, JS or `.map`), or `--stdin` with `--kind html|css|js|sourcemap`.
`--origin` resolves relative references in a file. It mines:

- `<script src>`, `<link href>` of every `rel` including `preconnect` and
  `dns-prefetch`, `<img>`/`<iframe>`/`<video>`/`<source>`/`<embed>` sources
- a `Content-Security-Policy` meta tag, split per directive
- a source map's `sourceRoot`, `sources` and `sourcesContent`
- **bare provider hostnames anywhere in the text**, which is the case a regex
  over `src=` attributes misses: `var B = "legacy.s3.eu-west-1.amazonaws.com"`
  is a bucket reference that never appears as a URL
- path-style bucket URLs (`https://s3.amazonaws.com/<bucket>/…`), with the
  bucket name extracted

By default only hosts that match a service in the table are reported;
`--all-hosts` adds the rest, which is how you find a dangling vendor domain
that is not a cloud provider at all.

Run it on the pages that matter separately. A dangling script on `/checkout` is
not the same finding as one on `/about`.

## 3. Judge the DNS records recon found

```
script: name "takeover", args ["cname", "assets.app.test", "docs.app.test"]
script: name "takeover", args ["cname", "--hosts-file", "engagements/<dir>/recon/subs.txt"]
script: name "takeover", args ["cname", "--surface", "engagements/<dir>/surface.json"]
```

`cname` reads the CNAME chain with `dig` (falling back to `host`, and saying so
when neither is installed), matches the chain's last target against the table's
CNAME suffixes, and judges. `--no-http` makes it DNS-only, so nothing at all is
sent to the destination — and then every live host comes back `inconclusive`,
never `not-dangling`, because nothing was read.

`--cname HOST=TARGET` substitutes a CNAME answer instead of asking DNS, for
replaying a stored `dig` answer and for the lab. `--map HOST=URL` fingerprints
a host by fetching URL instead, which is how the lab stand-in is used; the
scope check then applies to URL, which is the truth of what was sent.

**An A record to a cloud address is deliberately not a candidate here.**
Claiming an address means allocating addresses until one comes back, which is
probabilistic, noisy and an action this script will not take. It is reported as
`not-dangling` with that reason, and belongs in the report as a note.

## 4. The script hosts, with their SRI coverage

```
script: name "takeover", args ["scripts", "--url", "https://app.test/checkout"]
```

A `script-src` takeover is stored XSS on every page that loads it, which is why
this subcommand reports resolution and SRI in one table: SRI is the one control
that survives the takeover. The verdicts follow from that, and the distinction
is the point:

| host | `integrity=` | verdict |
|---|---|---|
| does not resolve | absent | `candidate` — script execution in every visitor's session |
| does not resolve | present | `dead-reference` — a changed body fails the hash, so the page breaks and nothing executes |
| does not resolve, non-executing tag (`preconnect`, `img`) | — | `dead-reference` |
| resolves, on a table service | — | judged by the fingerprint, scope permitting |

`sri_coverage` in the result is `covered/external`: the denominator is
third-party resources only, because SRI on a same-origin script buys nothing.
Report the fraction next to the finding; a payment page is where it matters
(`knowledge/web/client-side-supply-chain.md` has the PCI DSS 6.4.3 / 11.6.1
angle).

Each dangling script host's next read-only step is printed with it: whether its
registrable domain is registered at all, which is step 6.

## 5. The references nobody looks at

```
script: name "takeover", args ["records", "--url", "https://app.test/"]
script: name "takeover", args ["records", "app.test", "--spf-depth", "3"]
script: name "takeover", args ["records", "--csp", "report-uri https://r.old.test/x; form-action https://pay.old.test/"]
script: name "takeover", args ["records", "--redirect-uri", "https://legacy.partner.test/cb"]
```

`records` checks four kinds of reference that no takeover scanner reads:

- **CSP `report-uri` / `report-to`** — a dead host here receives every
  violation report, which carries URLs, blocked sources and sometimes
  parameters from the victim's session.
- **CSP `form-action`, `frame-ancestors`, `base-uri`** — a dead `form-action`
  host is where a form the browser already allows will post.
- **SPF `include:` and `redirect=`**, followed to `--spf-depth` (default 3).
  Whoever controls a dead include decides who may send mail as the target. The
  liveness test here is **NXDOMAIN, not "has no A record"**: an include target
  normally has only a TXT record, so judging it by address lookup calls every
  healthy mail provider dangling.
- **OAuth redirect allowlists** that the app discloses, one `--redirect-uri`
  per entry. A dead host in that list receives authorization codes.

For a dead name the result says plainly whether the name *is* a registrable
domain (anyone may register it) or a subdomain of a domain somebody else still
owns (a dangling reference, and a takeover only for whoever controls that
zone). Those are different findings and the distinction is where this class is
usually overstated.

## 6. The delegation, and the zone itself

```
script: name "takeover", args ["ns", "legacy.app.test"]
script: name "takeover", args ["ns", "legacy.app.test", "--rdap"]
```

`ns` reads the delegation and asks each nameserver for the zone's SOA with
`dig … +norecurse`, then classifies:

- `authoritative` — answers with the `aa` flag set.
- `lame` — REFUSED, SERVFAIL, unreachable, or the nameserver's own hostname
  does not resolve.
- `non-authoritative` — answers NOERROR **without** `aa`. Counted with `lame`:
  a server giving a referral is not serving the zone.

**Every** nameserver lame is a `candidate`, and the rarest, highest-impact case
in this class: nobody is serving the zone, so whoever can make one of those
nameserver hostnames answer serves all of it. Some lame and some authoritative
is `inconclusive` — resolution fragility, worth reporting, not a takeover.

`--rdap` additionally asks an RDAP service whether the registrable domain is
registered, or in `pendingDelete` / `redemptionPeriod` / `clientHold`. An
unregistered or dropping domain is a `candidate` with the claim path stated and
not taken. It is **off by default**, because RDAP is HTTP to a third party:
scope.yaml must name that host, and when it does not the lookup is refused and
reported, not sent. `--rdap-base` changes the service.

A name with no NS records is not a delegation, and `ns` says so — but it still
runs the `--rdap` step when asked, because an undelegated name under a
registrable domain that fell out of the registry is the strongest finding here.

## 7. Write the finding

Each candidate needs, in the engagement directory:

1. The reference, with where it came from: the `dig` answer for a record, or
   the page and the tag/directive/source-map field for a reference.
2. The destination's state: the NXDOMAIN line, or the provider's unclaimed-host
   response with the status and the matched string.
3. The negative control. A neighbouring in-scope host on the same provider that
   serves normal content, or the `/fp/live`-shaped case: the same matcher
   saying `not-dangling` on a claimed host. Providers flap, so re-run the
   fingerprint once after a pause and record both answers.
4. The claim path from the table — **and the sentence that it was not taken.**
5. The impact, read from traffic you already have and never by acting: a
   `Set-Cookie: Domain=.app.test` means a taken subdomain reads session
   cookies; a CSP or CORS allow-list naming the dangling host means script
   execution on the parent; an OAuth redirect allowlist means codes.
6. For an `inconclusive`, what would settle it: which provider's documentation
   says whether the claim is open, or which second signal is missing.

Exit codes let the driver read the result without parsing: `0` nothing
dangling, `1` at least one candidate, `2` usage, `3` a refused claim verb, `4`
neither `dig` nor `host` installed.

## 8. The lab

`lab/takeoverlab` is the fixture, on `127.0.0.1:5030`. `/` is a victim page
with a CSP header, an SRI-less third-party script, a dangling bucket in a
`preconnect`, a GCS image host, a bucket name built in a JS string, a dead
`form-action` and a dead `report-uri`; `/static/app.js.map` has a second bucket
in its `sourceRoot`; `/api/config` discloses an OAuth allowlist with a dead
entry. `/fp/s3`, `/fp/github-pages` and `/fp/heroku` serve those providers' own
unclaimed-host responses, and `/fp/live` is the negative control.

```
python3 lab/takeoverlab/app.py                 # or the compose service
script: name "takeover", args ["dangling", "--url", "http://127.0.0.1:5030/",
        "--map", "takeoverlab-legacy-assets.s3.amazonaws.com=http://127.0.0.1:5030/fp/s3"]
script: name "takeover", args ["cname", "docs.takeoverlab.test",
        "--cname", "docs.takeoverlab.test=takeoverlab-gone.github.io",
        "--map", "takeoverlab-gone.github.io=http://127.0.0.1:5030/fp/github-pages"]
```

The second one is the pair worth seeing: the same clean fingerprint produces
`candidate` for S3 and `inconclusive` for GitHub Pages, because the table knows
one name is first-come and the other may be held by domain verification.

Every fake credential in the fixture is the string `MYTHOS_LAB_CANARY`, and
every hostname on its pages is either `.invalid` or a nonsense label under a
real provider suffix, so nothing there resolves and nothing there can be
claimed by accident.

## Read next

- `knowledge/web/subdomain-takeover.md` — the confirmation playbook, what does
  not count, and the one acceptable artifact if a programme permits a claim in
  writing.
- `knowledge/web/client-side-supply-chain.md` — SRI, lapsed script origins, tag
  managers, payment pages.
- `knowledge/web/headers-cors.md` — which allow-lists turn a taken subdomain
  into script execution on the parent.
