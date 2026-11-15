# Subdomain Takeover (dangling CNAME, NS, A)

**Class:** infrastructure  **Updated:** 2026-11-15

## What it is
A DNS record of an in-scope name points at a third-party resource that no longer exists or was
never claimed (deleted bucket, removed PaaS app, expired domain, dead nameserver zone). Whoever
registers that resource then serves content under the target's name: phishing on a trusted host,
cookie access for the parent domain, an allow-listed CSP or CORS origin, OAuth `redirect_uri`
hosts, script hosts (see `client-side-supply-chain.md`).

## How Mythos detects it
`scripts/takeover` is the deterministic pass; `skills/takeover/SKILL.md` has the step order and
the exact subcommand signatures. In short: `takeover fingerprints` first (what the table can and
cannot conclude), then `dangling` on the pages recon fetched, `cname` on the names it found,
`scripts` for the external script hosts and their SRI coverage, `records` for CSP reporting, SPF
and OAuth allowlists, and `ns` for the delegation and the zone itself. Its strongest verdict is
`candidate`; it writes `inconclusive` wherever the fingerprint or the claimability is ambiguous,
and it never claims (see **The claim decision** below).

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
### Three facts, not one
A finding here is a reference that still points somewhere, a destination that is unclaimed, **and a
claim path that is open today**. Published lists carry the first two and are routinely stale on the
third: GitHub Pages, Vercel, Netlify, Shopify and Azure App Service have each added some form of
domain verification, so a textbook-perfect fingerprint on one of them can be unclaimable. The
repository's table (`knowledge/web/takeover-fingerprints.json`) therefore records `fingerprint`,
`claimable` (`yes` / `edge` / `no` / `unknown`) and `confidence` (`high` / `medium` / `low`, with
`stale: true` on every entry carried from a list and not corroborated) as three separate fields, and
`scripts/takeover` reaches `candidate` only for `claimable: yes` at confidence medium or better.
At the time of writing that is four services — S3, GCS, Azure Blob, Azure Traffic Manager — and
that ratio is the honest state of the class, not a hole in the table. Re-checking an entry means
reading the provider's current documentation, not copying another list; set `checked` and raise
`confidence` when you do.

### Lame delegation, precisely
A nameserver in the delegation is not serving the zone when it answers REFUSED or SERVFAIL, is
unreachable, has a hostname that does not resolve, **or answers NOERROR without the `aa` flag**.
The last one is the easy miss: a referral looks like an answer. `dig @<ns> <zone> SOA +norecurse`
and read the flags. *Every* nameserver lame is the takeover; some lame and some authoritative is
resolution fragility and worth reporting as that.

### The references nobody reads
Beyond CNAME and NS, the same dangling name appears where no takeover scanner looks, and the
consequence differs per place:
* CSP `report-uri` / `report-to` — a dead host receives every violation report, with URLs and
  blocked sources from the victim's session.
* CSP `form-action` — where a form the browser already allows will post.
* SPF `include:` / `redirect=` — whoever controls a dead include decides who may send mail as the
  target. Judge these by **NXDOMAIN, not by the absence of an A record**: an include target
  normally has only a TXT record, so an address lookup calls every healthy mail provider dangling.
* OAuth `redirect_uri` allowlists the app discloses — a dead entry receives authorization codes.
* Source maps — `sourceRoot` and `sources` name buckets the shipped bundle does not.
* A bucket name concatenated at runtime (`"https://" + BUCKET + "/"`), which a regex over `src=`
  attributes never sees.

### SRI changes the verdict, not just the severity
A third-party script host that no longer resolves is script execution in every visitor's session —
unless the tag carries `integrity=`, in which case a changed body fails the hash and the page
simply breaks. Dead host plus no SRI is the candidate; dead host plus SRI is a dead reference and
an availability problem. Report SRI coverage as third-party-covered over third-party-total; SRI on
a same-origin script buys nothing.

### Dangling names and scope
A dangling name resolves outside scope by its nature. Reading its DNS is not touching a host and
needs no permission; sending HTTP to it does, and `scope.yaml` governs that half. `scripts/takeover`
gates every fingerprint request on the scope check, reports the destination it refused, and
downgrades the verdict to `inconclusive` rather than inventing one. Adding a provider host to
`in_scope` is a human action in an editor before the run.

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

### The claim decision
**Claiming** the resource — creating the bucket, adding the PaaS app, registering the domain,
reserving the tunnel or package name — is out of bounds unless the programme text explicitly
permits proof-of-takeover, and then it is a **human** who does it. `scripts/takeover` refuses in
code: `takeover claim`, `register`, `occupy` and every other spelling exit 3 and do nothing, and
there is no flag that changes that.

Why the decision belongs to the operator and not to the agent, in order of what it costs when
ignored:
* Claiming **is** the attack, not a demonstration of it. From that moment every visitor's browser
  is talking to the tester's infrastructure under the target's name.
* It is not reversible from the target's side. They can delete the record; they cannot un-serve
  what was served.
* It puts the tester into a contract with a cloud provider over a name they do not own, under a
  programme that usually forbids exactly that by name — a legal exposure an unattended run cannot
  evaluate and cannot carry.
* An agent cannot read the contract, cannot own the consequence and cannot undo it. The programme
  text is a human-readable agreement; reading it and accepting its terms is what an operator is.
* And it is unnecessary: the DNS answer, the provider's own unclaimed-host response and a written
  claim path are all read-only, and together they are what a triager actually replays.

If the programme does permit it in writing, the only allowed artifact is a static page with a
unique token and a contact line — no login, no form, no script, no cookies set — served only long
enough for triage and removed afterwards. Never register an expired domain. Without that
permission, report the dangling record with the DNS trace and fingerprint and say it is unclaimed.

**Impact check without acting:** read the parent's cookie scope from responses you already have
(`Set-Cookie: Domain=.example.com` means a taken subdomain reads and sets session cookies),
`Access-Control-Allow-Origin` and CSP allow-lists that list the subdomain, and OAuth redirect
allow-lists. Do not set cookies or make the host answer.

## What does NOT count
A CNAME to a provider that is still claimed by the target, a 404 from the origin, a fingerprint
matched on an `Edge case` entry without a second signal, a scanner line without the DNS trace,
an `A` record to a cloud IP, `NXDOMAIN` on the host itself with no record at all (nothing to take),
a fingerprint on a provider that verifies domain ownership (Vercel, WordPress.com, Zendesk,
Statuspage) — that is a dead reference and DNS hygiene, not a takeover — a dead SPF `include:`
judged by a missing A record rather than NXDOMAIN, a missing `integrity=` on a host that still
resolves and is not takeover-able, and a dangling subdomain of a domain somebody else still owns
reported as if registering the parent were available.

## Remediation
Delete DNS records when the resource is removed, claim the provider-side domain verification
before pointing DNS, inventory DNS against cloud assets, monitor for NXDOMAIN CNAME targets.

## Sources
- OWASP WSTG, Test for Subdomain Takeover (WSTG-CONF-10): confirm the fingerprint and that the
  resource is unclaimed, do not claim it (undated, current guide)
- EdOverflow, can-i-take-over-xyz fingerprint list (GitHub, continuously maintained)
- projectdiscovery/nuclei-templates `http/takeovers/`; punk-security/dnsReaper; haccer/subjack
  (tool READMEs; signature counts not verified)
- Provider documentation for the claimability column: GitHub Pages custom-domain verification,
  Azure `asuid` custom-domain verification, Vercel domain verification, AWS S3 and GCS bucket
  naming (globally unique), Azure storage-account naming. Each entry's `source` field names its
  own; `checked: null` means nobody re-read it for this repository yet
- Tooling in this repository: `scripts/takeover`,
  `knowledge/web/takeover-fingerprints.json`, `skills/takeover/SKILL.md`, `lab/takeoverlab`
- Related: `client-side-supply-chain.md`, `headers-cors.md`, `ssrf.md` (dangling hosts allow-listed server-side)
