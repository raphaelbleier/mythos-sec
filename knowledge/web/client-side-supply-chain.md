# Client-Side Supply Chain (third-party scripts, SRI, lapsed domains)

**Class:** supply chain / client-side  **Updated:** 2026-11-13

## What it is
Every `<script src>`, stylesheet, dynamic loader (`createElement('script')`, `import()`, tag
manager) hands code execution on the page to another origin. If that origin is compromised, or its
domain lapses and is re-registered by someone else, the attacker runs script in every visitor's
session. This is one of the two supply-chain families a black-box tester can check without source
access. Case: Polyfill.io, where a widely embedded `cdn.polyfill.io` script was served with
malicious redirects after the domain and project changed hands (reported 2024-06-25; sources
disagree on when the malicious behaviour began, so no earlier date is claimed here).

## How Mythos detects it
1. Collect every external resource: the HTML (`<script>`, `<link rel=stylesheet|modulepreload>`),
   the **mythos-browser** network log (`page.on('request')` for `script`/`stylesheet`/`font`
   types, after the SPA settled and after login), and strings in JS bundles that build script
   URLs. Include responses from `/checkout`, `/login`, `/account` separately: the risky page is
   the one with the session or payment form.
2. For each record store: URL, host, eTLD+1, same-origin or cross-origin, `integrity=` present,
   `crossorigin=` present, loaded by (HTML / loader / tag manager).
   ```
   scripts/mythos sh "curl -s <URL> | grep -oE '<(script|link)[^>]*>'      # read src/href, integrity, crossorigin"
   ```
3. For each cross-origin eTLD+1 check that it still resolves and is registered (GET only):
   ```
   dig +short NS <etld1>; dig +short A <host>
   curl -s https://rdap.org/domain/<etld1>          # 404 / "not found" = unregistered candidate
   ```
   NXDOMAIN on the host alone is not enough (the subdomain may just be removed); the **registered
   domain** must be absent from RDAP, or its RDAP record show `pendingDelete`/`redemptionPeriod`.
4. CSP `script-src` (header or meta): list host sources and wildcards. Flag broadly writable
   origins that allow user-uploaded or arbitrary JS (`*.s3.amazonaws.com`, `raw.githubusercontent.com`,
   `*.cloudfront.net`, `cdn.jsdelivr.net/npm/*` without a path, `unpkg.com`, `*.appspot.com`,
   JSONP endpoints). Pointer: `client-side-dom.md` for the bypass confirmation.
5. Tag managers (GTM, Tealium, Adobe Launch): fetch the container JS (`gtm.js?id=GTM-...`) and list
   the custom HTML tags and the third-party URLs they inject; the container's editors are a trust
   boundary the target controls, not you.

## How to confirm (non-destructive)
- **Missing SRI on a third-party script**: report as a hardening note with severity low. It is a
  `candidate` of value only if the host's eTLD+1 is takeover-able or the script is user-writable.
- **Lapsed or unregistered origin**: severity high. Proof = the page request that loads the URL
  (HAR line or `view-source`), the DNS answers (`NXDOMAIN` or no NS), and the RDAP response that
  shows the registered domain is not registered. Closure state `reproduced`, then stop.
- **Dangling third-party subdomain used as script host** (`cdn.<org>.com` CNAME to a deleted
  bucket): same, handled by `subdomain-takeover.md`.
- **Writable wildcard CSP host**: show that the CSP allows the host and that the host serves
  content you can place under your own account (an object you uploaded to your own bucket on that
  provider), executing only a canary through `skills/stored-xss-oast/SKILL.md` on a page you own.

**Absolute rule:** state that a domain appears available to register and **never register it**,
never buy it, never point it at a server, never claim a bucket or package name that a live page
loads. Registering is the attack; the DNS and RDAP lines are the proof. If the program wants the
claim demonstrated it must say so in writing and the user decides.

## What does NOT count
Missing `integrity` on a script served by a major CDN under the target's own contract, a script
that merely 404s, a CDN host that is registered by the CDN vendor, absence of CSP, a wildcard
`*.googleapis.com` in `script-src` with no demonstrated writable path, any claim based on a
crawler's "unregistered" output without the RDAP line.

## Payment pages
PCI DSS v4.0.1 (published 2024-06-11) requirement 6.4.3 asks for an inventory, written
justification and authorization of every script on a payment page plus integrity assurance;
11.6.1 asks for change and tamper detection of payment-page scripts and security-impacting HTTP
headers. Both became mandatory on 2025-03-31. A payment page with unauthorized or lapsed
third-party scripts and no SRI/CSP is a compliance gap worth stating next to the technical
finding; scope for outsourced checkout varies, so leave the compliance verdict to the assessor.
The standard text was not retrieved here: the dates and wording come from vendor summaries.

## Remediation
Self-host or pin versions and use `integrity` plus `crossorigin="anonymous"`, a path-specific CSP
allow-list instead of wildcard CDNs, remove scripts from lapsed vendors, restrict tag-manager
publish rights, monitor payment-page scripts (6.4.3, 11.6.1).

## Sources
- Sansec and press coverage of the Polyfill.io supply-chain attack (2024-06-25; BleepingComputer,
  SecurityWeek, Sonatype)
- PCI DSS v4.0.1 (2024-06-11), requirements 6.4.3 and 11.6.1 (via vendor summaries, e.g. Report URI)
- W3C Subresource Integrity (SRI) specification
- Related: `subdomain-takeover.md`, `client-side-dom.md`, `headers-cors.md`
