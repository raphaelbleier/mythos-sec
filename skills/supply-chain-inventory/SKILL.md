---
name: supply-chain-inventory
description: Build a component inventory of what the target serves — JS/CSS/wasm libraries and their versions from bundle markers and published source maps, server-side products from the probe's headers — emit CycloneDX 1.6 with per-row evidence, hand it to `scripts/cvefeed` for a ranked candidate list, check SRI coverage and CDN trust, and diff two SBOMs on a re-engagement. Use when the target serves third-party JavaScript, publishes a source map, or leaks a product version in a header. Drives `scripts/sbom`, `scripts/cvefeed` and `scripts/probe`.
---

# Supply-chain inventory — what is deployed, how well you know it, and what would resolve it

The target tells you its dependency list for free: banner comments, runtime
version assignments, bundler module paths, `node_modules/<pkg>/package.json`
inside a published source map, CSS framework banners, a wasm `producers`
section, and `Server`/`X-Powered-By`. This skill collects that into one
inventory where **every row names the request that proved it**, and then refuses
to call any of it a finding.

The failure mode this skill exists to prevent: reporting "jQuery 1.12.4,
therefore CVE-X" — the single most common false positive in this class, because
vendors backport without bumping versions and bundlers mangle past the marker.
Read `knowledge/web/sbom-known-cves.md` before writing anything up; it carries
what the published literature says about version-only matching. SRI and lapsed
third-party origins are the neighbouring class and live in
`knowledge/web/client-side-supply-chain.md`.

Triage selects this skill when the surface shows external scripts, a published
`.js.map`, or a versioned product in a header (`skills/registry.yaml`). It
drives `scripts/sbom` and, through it, `scripts/cvefeed`.

## 0. Authorization

- `engagements/<dir>/scope.yaml` is the boundary and is never widened. A
  cross-origin CDN script is **recorded from the HTML attribute and not
  fetched**; `scripts/sbom` refuses a host the scope does not authorize and
  exits 3. `--fetch-external` only lifts that for a host already in scope.
- The vulnerability databases are third parties. `sbom cves` is offline by
  default and reads only the disk cache and `knowledge/cve/snapshot.json`.
  `--allow-feeds` permits a refresh; the hosts it then contacts are listed in
  `scripts/sbom --help`. Only `name@version` pairs leave the machine — never the
  target's hostname, URLs, headers or the engagement directory.
- GET only. No payloads, no brute force, no DoS.

## Steps

1. **Take the server-side half from the probe, do not fingerprint it again.**
   Recon already fetched the entry point, the common paths and the headers it
   keeps, and its `technology` list is exactly the product/version pairs this
   inventory needs:

       scripts/probe <url> --depth 2 --json out: surface.json
       scripts/sbom inventory <url> --from-probe surface.json --json

   Each server row's evidence points at the probe page that carried the header
   (`probe:<url>`), so the inventory stays traceable without re-sending the
   request. Exit 1 means no component marker was found at all — a result, not
   an error: write it down as "the target leaks no identifiable component".

2. **Read the inventory's confidence column before anything else.** Every row
   carries the marker that produced it:

   | confidence | score | marker |
   |---|---|---|
   | strong | 0.9 | `hash` — sha256 matches a release hash you supplied |
   | moderate | 0.6 | `sourcemap-manifest` — a `package.json` in `sourcesContent` |
   | moderate | 0.5 | `banner`, `runtime`, `header` |
   | weak | 0.3 | `filename`, `module-path` |
   | name-only | 0.1 | the library is present, no version is readable |

   `--json` exposes `confidence`, `confidence_score`, `marker_kind`, `marker`,
   `technique`, `caveat`, `evidence.request` and `also_seen` (the weaker markers
   that agreed). Nothing above 0.6 is reachable from the outside without a hash
   table you built yourself:

       scripts/sbom inventory <url> --hashes release-hashes.json --json

   where the file is `{"<sha256>": "pkg@version"}` from artifacts you downloaded
   and hashed. No corpus ships with the tool on purpose.

3. **Emit the document, and let it validate.**

       scripts/sbom cyclonedx surface-sbom.json --out engagements/<dir>/sbom.json
       scripts/sbom cyclonedx surface-sbom.json --spdx > engagements/<dir>/sbom.spdx

   The CycloneDX 1.6 output carries the confidence in the spec's own
   `evidence.identity[].confidence`, the marker in `methods[].technique`, and
   the request id in both the method value and a `mythos:evidence:request`
   property. The command exits 1 if the document fails the required-field
   checks, including the invariant that every component's evidence names a
   request the document declares. A non-zero exit here is a bug in the tool, not
   something to work around.

4. **Hand the inventory to the CVE feed. Offline first.**

       scripts/sbom cves surface-sbom.json --json
       scripts/sbom cves surface-sbom.json --allow-feeds --json   # only if the cache is empty/stale

   `cvefeed` does the ranking (KEV, then EPSS band, then version-match
   confidence, then whether a check exists). A hash match is handed over as
   `--fingerprint`, every other version as `--banner`, and a version-less row as
   `--product`, so the feed's own confidence never claims more than the marker
   earned. Each output row carries `state: candidate`, the `weakest_link` (the
   inventory row's marker and its caveat) and `resolve`: the exact live check.
   If the feed has no data at all the command exits 1 and says so — do not
   silently continue as if the inventory were clean.

5. **Resolve each candidate by behaviour, never by re-reading the version.**
   Follow the `resolve` line. For a client-side library that means the
   `browser` tool exercising the API the fix changed; for a server product the
   advisory's own request/response pair, or
   `scripts/mythos nuclei -id <cve-id> -u <target>` when the row carries a
   template — after reading the template's matcher, because a banner matcher
   would make the proof circular. Then write
   `verdicts/<slug>.md` with `state: candidate` and the traffic record of the
   behavioural proof, or `state: tested` naming what you checked. You may not
   write `confirmed`; the validate phase does that.

6. **Check SRI coverage and which CDN hosts the page trusts.**

       scripts/sbom sri <url> --json

   Reports every script/stylesheet/preload with its `integrity` and
   `crossorigin`, the coverage ratio over cross-origin script resources, the
   hosts the CSP trusts for script, and the two mismatches that matter: trusted
   but never loaded, and loaded but never named in the CSP. An `integrity`
   without `crossorigin` is reported too — the browser skips the check, so the
   attribute is inert. Severity discipline and the lapsed-origin follow-up are
   in `client-side-supply-chain.md`: missing SRI alone is a low hardening note,
   and it becomes a candidate only if the eTLD+1 is takeover-able or the path is
   user-writable. The eTLD+1 column is the last two labels, not a public-suffix
   lookup, and nothing rests on it.

7. **On a re-engagement, diff.**

       scripts/sbom diff engagements/<old>/sbom.json engagements/<new>/sbom.json

   Exits 1 when anything changed. A version change and a new component land on
   the `retest` list; a row that only changed confidence changed how well it is
   known, not necessarily what is deployed, and the output says so. This pairs
   with `scripts/watch`, which answers the same question about the surface.

8. **Write it up as an inventory, not as findings.** Attach the CycloneDX
   document as an artifact. Each unresolved match goes in the report as a
   candidate with its marker, request id, confidence, the feed row and the check
   it would have needed. For a payment page, note the PCI DSS v4.0.1 6.4.3
   inventory/authorization gap next to the technical rows and leave the
   compliance verdict to the assessor.

## Stop conditions

- The target serves a single inlined bundle with no banners, no source map and
  no module paths: say the inventory is empty and why. An empty inventory is not
  an empty dependency list, and claiming otherwise is the failure this skill
  guards against.
- No CVE data (`sbom cves` exits 1 and names the reason) and no network
  authorization: report the inventory, mark the CVE pass not run, and say that
  `scripts/cvefeed refresh` with network would complete it.
- A version match that cannot be resolved behaviourally within the engagement
  stays a candidate, with the check named. Do not promote it on confidence.

## Self-test

`python3 scripts/sbom selftest` runs the marker asserts, the CycloneDX
validation (including thirteen deliberately malformed documents that must each
be rejected), the privacy invariant on the feed argv, and one live round trip
against a loopback server it starts itself. Run it after changing the script.
The ground-truth fixture is `lab/sbomlab/` (`GET /__inventory` serves the right
answers).
