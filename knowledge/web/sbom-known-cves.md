# Outside-in SBOM and known-CVE matching (why a version match is a candidate)

**Class:** supply chain / inventory  **Updated:** 2026-11-15
**Tool:** `scripts/sbom`  **Skill:** `skills/supply-chain-inventory/SKILL.md`
**Related:** `client-side-supply-chain.md` (SRI, lapsed origins), `skills/cve-deep-dive`,
`knowledge/techniques/cve-triage-2026.md`

## What it is

A black-box target publishes most of its dependency list without meaning to:
banner comments in bundles (`/*! jQuery v1.12.4 */`), runtime version
assignments (`angular.version.full`), bundler module paths
(`./node_modules/moment/moment.js`), `node_modules/<pkg>/package.json` inside a
published source map's `sourcesContent`, framework banners in CSS, a
`producers` custom section in a wasm module, and a `Server` or `X-Powered-By`
header naming a product and a version. Collected, that is a software bill of
materials built from the outside. Matched against KEV/EPSS/NVD/GHSA/OSV it is a
list of aim points — and nothing more, which is the whole point of this note.

## How Mythos detects it

1. `scripts/sbom inventory <url>` — markers above, each row carrying the request
   id that proved it and a confidence tied to the marker.
2. `scripts/sbom cyclonedx <inventory.json>` — CycloneDX 1.6, confidence in the
   spec's own `evidence.identity[].confidence` and the marker in
   `methods[].technique`, so a downstream consumer sees the same judgement.
3. `scripts/sbom cves <inventory.json>` — hands `name@version` pairs to
   `scripts/cvefeed`, which does the ranking. Offline by default.
4. `scripts/sbom diff a.json b.json` — what changed since the last engagement.

## Why a version-only match is weak evidence

Four mechanisms break it, in rough order of how often they bite:

**Backporting.** A distribution or vendor applies the upstream fix without
changing the version string the software reports. Red Hat, Debian, Ubuntu and
SUSE all ship patched builds whose upstream version is the vulnerable one and
whose package release is not; this is why distributions publish their own
advisory streams and tell scanners to compare the *package release*, not the
upstream version. Against a `Server: nginx/1.18.0` header you cannot see the
package release at all, so a CVE affecting "< 1.20" is a question, never an
answer.

**Banner-versus-build.** A banner comment is a comment. A build that vendored a
patched copy, or that applied a local patch, keeps the banner of whatever it
started from. The inverse also happens: a bundle re-exports a *newer* library
under an old banner left in a concatenated header block.

**Bundler mangling.** Minification, tree-shaking, module concatenation and
transpilation remove whole functions and rewrite identifiers. A library whose
vulnerable code path was shaken out is reported as present and vulnerable; a
library inlined without its banner is not reported at all. The same mechanism
breaks hash matching: there is no release artifact to compare against, because
the bytes on the wire never existed in any release.

**Operator-settable headers.** `Server`, `X-Powered-By` and friends are
configuration. A reverse proxy, a WAF, a `server_tokens` setting or a
deliberately misleading banner all change them, in both directions.

### What the published literature says

These are the findings that matter here. Treat the sources as pointers to
re-read before quoting a number in a report; the claims below are stated
qualitatively on purpose.

- **SCA tools disagree with each other.** Imtiaz et al., *A Comparative Study
  of Vulnerability Reporting by Software Composition Analysis Tools* (ESEM
  2021), ran nine SCA tools over the same projects and found substantial
  disagreement in what each reported — vulnerabilities reported by one tool and
  not the others were common, and no tool's output was a superset. If nine
  purpose-built tools with manifest access disagree, an outside-in inventory
  with no manifest is not the stronger signal.
- **The naive "vulnerable dependency" count is inflated.** Pashchenko et al.,
  *Vuln4Real: A Methodology for Counting Actually Vulnerable Dependencies*
  (IEEE TSE 2020/2022), showed that counting vulnerable dependencies without
  accounting for development-only dependencies, non-deployed artifacts and
  halo/sub-dependency effects substantially overestimates the real exposure.
- **Repackaging and rebundling defeat scanners.** Dann et al., *Identifying
  Challenges for OSS Vulnerability Scanners — A Study and Test Suite* (IEEE TSE
  2022), built a test suite of real-world library-modification patterns
  (shading, rebundling, repackaging, backports) and showed that mainstream
  scanners both miss vulnerable code and flag code that is not there. This is
  the Java equivalent of what a JavaScript bundler does to a front end.
- **NVD's own affected-version data has quality problems.** Anwar et al.,
  *Cleaning the NVD* (IEEE TDSC 2021) and later NVD-quality work document
  missing, inconsistent and over-broad CPE entries. `scripts/cvefeed` already
  encodes two scars from this: a CPE's vendor field is not the product (a
  `python:pillow:*` hint matched a target that merely ran python), and a version
  is only evidence against a range for the same package.
- **Reachability is a separate question again.** Vendor research (Veracode,
  Snyk, Datadog, Endor Labs reports from 2022 onward) consistently claims that
  only a minority of known-vulnerable dependency versions have the vulnerable
  code on a reachable path — the published figures range widely and are
  vendor-measured, so take the direction and not the number: *present* is not
  *reachable*, and *reachable* is not *exploitable*.

The practical consequence: a client-side version match belongs in a report as a
candidate with its marker named, or as an inventory/hardening observation, and
never as a vulnerability finding on its own.

## How to confirm (non-destructive)

A version match is resolved by **behaviour**, not by reading the version again.

- **Client-side library.** Re-GET the asset (the inventory row's evidence URL)
  to confirm the marker is still there, then exercise the behaviour the fix
  changed in the `browser` tool: call the affected API with a benign input and
  observe whether the patched or the unpatched path runs. Example shape: a
  sanitizer bypass is confirmed by the sanitizer's own output for a known
  payload, with a canary and no navigation — not by `$.fn.jquery`.
- **Server-side product.** Use the behavioural check from the advisory. If the
  `cvefeed` row carries a `nuclei_template`, `scripts/mythos nuclei -id <cve-id>
  -u <target>` is that check already written; read the template's matcher before
  trusting it, because some templates match on the banner and would be circular
  here.
- **Hash match.** The one marker worth calling `strong`, and only against a
  release artifact you downloaded and hashed yourself (`sbom inventory
  --hashes`). No hash corpus ships with the tool: an unverified hash table is
  worse than none, because it manufactures confidence.
- **Source-map manifest.** A `package.json` in `sourcesContent` is the build's
  own statement of what it resolved. It is the strongest non-hash marker and
  still does not prove that the resolved code is what shipped, since the bundle
  may have been patched after resolution.

## What does NOT count

A `Server` banner plus a CVE id. A banner comment plus an advisory. "Retire.js
flagged it". A version read from a filename or a CDN URL path (that is what was
requested, not what was served). A CycloneDX document presented as a finding —
an SBOM is an inventory artifact, and its rows are candidates. Anything where
the proof and the detection are the same observation.

## Reporting

Report the inventory as an artifact (attach the CycloneDX document), and report
each unresolved version match as a candidate with: the marker, the request id,
the confidence, the feed row it matched, and the live check that would resolve
it. If the engagement ends without that check, the row stays a candidate in the
report and says what it would have needed — which is a result, not a gap.

PCI DSS v4.0.1 requirement 6.4.3 wants an inventory and written authorization of
every script on a payment page; an outside-in inventory of a payment page is
directly useful evidence for that gap (dates and wording:
`client-side-supply-chain.md`, which took them from vendor summaries).

## Sources

- CycloneDX 1.6 specification (`bomFormat`, `specVersion`, `components[].type`,
  `evidence.identity[].methods[].technique`)
- SPDX 2.3 tag-value specification
- Imtiaz, Thorn, Williams, *A Comparative Study of Vulnerability Reporting by
  Software Composition Analysis Tools*, ESEM 2021
- Pashchenko, Plate, Ponta, Sabetta, Massacci, *Vuln4Real*, IEEE TSE
- Dann, Plate, Hermann, Ponta, Bodden, *Identifying Challenges for OSS
  Vulnerability Scanners*, IEEE TSE 2022
- Anwar, Abusnaina, Chen, Li, Mohaisen, *Cleaning the NVD*, IEEE TDSC 2021
- Distribution backporting policies (Red Hat, Debian security FAQ) for the
  version-string-versus-package-release problem
- `knowledge/techniques/cve-triage-2026.md`, `scripts/cvefeed --help`
