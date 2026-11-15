# Dependency Confusion and Typosquatting (registry side)

**Class:** supply chain / dependency resolution  **Updated:** 2026-11-15

This is the registry half of the supply chain. The client-side half — third-party `<script src>`,
missing SRI, lapsed script domains, tag managers — is `client-side-supply-chain.md` and does not
repeat here. The two share one absolute rule, stated in both: *the proof is the attack, so the
proof is not taken.*

## What it is

Every package manager resolves a name through an ordered list of registries. When a name exists
only in a company's private registry, and the installer can also see a public one, the public
answer can win:

* **npm** merges the public registry with any `@scope:registry` mapping. A scope with no mapping,
  or a mapping that only some of the build hosts have, resolves from `registry.npmjs.org`.
* **pip** treats `--index-url` and `--extra-index-url` as one flat namespace and takes the
  **highest version** it finds across all of them, with no preference for the internal index.
  This is the worst of the ecosystems and it is documented behaviour, not a bug.
* **Maven** and **NuGet** walk their repository list in order, so a public repository listed first,
  or a group/feed with no upstream filter, resolves first.

So an attacker who learns an internal package name publishes that name publicly, at a version
higher than the internal one, and waits for a build to install it. It executes as the build, in
the network the build runs in. The class was named and demonstrated by Alex Birsan in February
2021 against 35 companies including Apple, Microsoft, PayPal, Shopify, Netflix, Yelp, Uber and
Tesla, with over $130,000 in bounties; he read most of the names out of published JavaScript
bundles and leaked `package.json` files, which is exactly the path below.

**Typosquatting** is the same payload with a different delivery: a package named one edit away
from a real one (`lodahs`, `python-dateutil` vs `python3-dateutil`, `electorn`), installed by a
human typing or a generated manifest. For a target engagement it matters in one direction only:
is the *target* installing a squat, or is a squat of the target's own public package sitting there
waiting for the target's users.

## What the target tells you, and where

`scripts/supplychain extract <url>` collects all of this in one pass and records where each name
came from, which is what the finding needs:

| Source | What it yields |
|---|---|
| JS bundle / chunk | `node_modules/<name>` in webpack module ids and `/*!*** ***/` comments; bare `require()`/`import` specifiers |
| `.js.map` | `sources[]` keeps the whole `node_modules` tree, including packages the bundle inlined |
| `/package.json`, `/package-lock.json`, `/yarn.lock` | names, the declared **range**, and the registry each one was **resolved from** |
| `/composer.json`, `/requirements.txt`, `/pom.xml`, `/Gemfile.lock`, `/Cargo.toml` | the same for PHP, Python, Java, Ruby, Rust |
| `/.npmrc`, `/.yarnrc.yml`, `/pip.conf`, `/nuget.config` | the internal registry host, the scope it serves, and often a token |
| third-party CDN script URLs | `unpkg.com/<name>@<version>` names a public package and its version |

A reachable `.npmrc` is two findings at once: the registry URL (an internal host name, often the
only thing between the tester and an internal service) and, on the line below, `_authToken`. Report
the token as **exposed**, never as valid: do not authenticate to the registry with it.

## Internal or public, and why it matters

A private name is the whole precondition. `supplychain extract` marks a name internal only on a
signal the target emitted, and prints the signal next to the name:

1. the scope is mapped to a non-public registry in a config the target served
   (`@acme-internal:registry=https://nexus.corp…`);
2. the lockfile resolved it from a non-public registry;
3. the name carries a non-public token (`internal`, `private`, `corp`, `intranet`, …);
4. the scope or prefix is the target's own organisation label.

"It sounds internal" alone is signal 3 and the weakest of the four. A scoped name with none of the
four is **not** reported as internal: `@babel/core` is scoped and public, and a tool that calls
every scope private produces a report of nothing.

## The amplifiers

A private name on its own is trivia. `supplychain amplifiers` looks for the conditions that make
an installer actually reach a public registry for it:

* **unclaimed internal name** — the public registry returns 404 for it. The window is open.
* **private scope resolved from a public registry** — the lockfile itself shows
  `@acme-internal/telemetry` fetched from `registry.npmjs.org`. No speculation needed: the build
  already does the wrong thing.
* **mixed registry configuration** — the reachable config names both a public and a private
  registry, so a name missing from the private one falls through.
* **private registry with no scope binding** — which registry serves a name depends on lookup
  order rather than on configuration.
* **a version range a higher public release would win** — `^`, `~`, `>=` or `*`, which is the
  mechanism pip's highest-version rule and npm's range resolution both ride on.

## How to confirm (non-destructive)

Confirmation here stops earlier than in every other class in this repository, and the stopping
point is the point.

A read-only existence lookup is allowed: one GET per name at the public registry, which asks
whether a package of that name exists and who owns it. `supplychain claimable` does exactly that,
behind `--contact-registries`, rate-limited, sending the package name and nothing else — no target
host name, no engagement data, no session. Public registries are third-party infrastructure that
`scope.yaml` cannot authorize, which is why the flag exists and why the scope file is never
widened to cover them.

**Everything beyond that lookup is refused.** The remaining proof — publishing a package under the
unclaimed name — is the attack:

* it executes code on **every** machine in the world that resolves that name, not only the
  target's, including the target's suppliers and customers;
* npm, PyPI and crates.io treat a name as taken permanently; unpublishing is restricted and does
  not restore the prior state;
* a canary package is still a published package, and "it only phoned home" is a statement about
  this version of it, not about the name.

So the verdict is `candidate`, with: the origin URL and the exact line the name came from, the
registry lookup URL and its status code, the signals that made the name internal, the amplifier
that makes it reachable, and the sentence that the remaining proof was refused. `scripts/supplychain`
cannot write `confirmed` — no input to it produces that word, and any `publish`, `register`,
`reserve` or `unpublish` spelling on its command line exits 3 — and neither may a validator invent
it. A validator re-reads the recorded evidence: it re-runs the lookup, checks the 404 still holds
and that the name's internal signals are in the recorded bytes. That is the whole validation.

Claiming the name is a decision only the human operator can take, only with the programme's
written agreement, and outside a run.

Typosquatting confirms differently and more cheaply, because the squat already exists:
`supplychain typosquat <name> --check` reports which neighbours exist and who owns them. A
neighbour owned by the same maintainer is an alias, not a finding. A `candidate` needs three
things together: a different owner, a recent first publish, and either the victim's name in the
metadata or install-time code (`postinstall`, `setup.py`). And a squat is only the *target's*
finding if the target installs it — which the target's own lockfile either shows or does not.

## What does NOT count

A scoped name with no internal signal; a name that is simply absent from a registry with no
amplifier behind it (a build that never asks a public registry cannot be confused); a name
recovered from a private source the engagement did not authorize; "npm shows 404" with no record
of which name or when; a typosquat neighbour owned by the same author; a token found in `.npmrc`
reported as valid rather than exposed; and any claim about a name that was tested by publishing it.

## Remediation

Pin scope-to-registry mappings for every private scope and set `always-auth`; use a single
registry endpoint that proxies the public one with upstream filtering (Artifactory/Nexus virtual
repository, CodeArtifact, Azure Artifacts upstream) so no installer ever sees two namespaces; pin
exact versions through a committed lockfile and `npm ci` / `pip install --require-hashes`;
pre-register the organisation's private scopes and name prefixes publicly as placeholders — that
is the only legitimate way the name gets claimed; stop serving `.npmrc`, `pip.conf`, lockfiles and
source maps from the web root; rotate the token that was published next to the registry URL.

## Sources

- Alex Birsan, "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other
  Companies" (2021-02-09)
- pip documentation on `--extra-index-url` and version selection across indexes
- npm documentation on scoped packages and `@scope:registry`
- Related: `client-side-supply-chain.md` (the script and SRI half), `client-side-dom.md`
