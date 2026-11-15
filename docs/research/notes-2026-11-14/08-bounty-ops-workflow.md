# Operational workflow around automated web red teaming (bounty ops, scope, reporting, ASM, legal, collaboration) - as of November 2026

Research budget was ~20 tool calls; coverage of Immunefi, YesWeHack and Intigriti API internals is thin (see Gaps). Many platform pages are primary; several items come from search summaries and are flagged.

## 1. Program and scope integration (platform APIs, machine-readable scope, enforcement)

### Takeaway
Only HackerOne has an official, documented, researcher-facing structured-scope API plus a report-submission endpoint. Intigriti has a beta token API; YesWeHack and Bugcrowd have no documented researcher scope API, so tools rely on community scrapers or the hourly bounty-targets-data dump. Scope from every source is lossy (wildcards with exclusions, free-text instructions), so it must be imported as a draft into `scope.yaml` and confirmed by a human, not trusted as-is.

### Cited Findings
- HackerOne Hacker API: HTTP Basic auth (API username + token); `GET /hackers/programs`, `GET /hackers/programs/{handle}`, `/scope_exclusions`, `/weaknesses`. — [HackerOne API docs](https://api.hackerone.com/hacker-resources/)
- HackerOne `GET /hackers/programs/{handle}/structured_scopes` returns `asset_type`, `asset_identifier`, `eligible_for_bounty`, `eligible_for_submission`, free-text `instruction` (nullable), `max_severity`, CIA requirements, `created_at`/`updated_at`; filters `filter[id__gt]`, `created_at__gt`, `updated_at__gt`; max 10,000 scopes per pagination walk. — [HackerOne API docs](https://api.hackerone.com/hacker-resources/)
- HackerOne structured-scopes endpoint is limited to 50 requests/minute (per HackerOne's Oct 2026 researcher update). — [What's New for HackerOne Researchers](https://www.hackerone.com/blog/whats-new-for-hackerone-researchers)
- HackerOne `POST /hackers/reports` requires `team_handle`, `title`, `vulnerability_information`, `impact`; optional `severity_rating` (none..critical), `weakness_id` (CWE-linked weakness), `structured_scope_id`. — [HackerOne API docs](https://api.hackerone.com/hacker-resources/)
- HackerOne added 35,000+ in-scope assets (+45%) in the 12 months to 30 June 2026, so scope churn is high and re-polling matters. — [What's New for HackerOne Researchers](https://www.hackerone.com/blog/whats-new-for-hackerone-researchers)
- Intigriti Researcher API is REST, token-authenticated, labelled "V1 (BETA)", lets you query programs and program activity. Tokens come from account settings "API Tokens". — [Intigriti KB](https://kb.intigriti.com/en/articles/8529303-intigriti-researcher-api); search summary of [Intigriti Quick Scope](https://github.com/intigriti/iqs)
- Intigriti endpoint paths seen in third-party code disagree (`/external/researcher/v1/programs` vs `/core/researcher/programs/{company}/{handle}` with a `domains` field using numeric type codes); treat as unverified. — [bbscope Intigriti docs](https://beta.pkg.go.dev/github.com/se1wan/bbscope/pkg/platforms/intigriti)
- YesWeHack: no official developer docs for scope found. DefectDojo's YesWeHack connector uses a Personal Access Token (read access to programs is enough); community scrapers call `api.yeswehack.com/programs/{slug}` with a bearer JWT, and some need TOTP for 2FA. — [DefectDojo YesWeHack connector](https://docs.defectdojo.com/connectors/toolreference/yeswehack/); [ScopesExtractor](https://www.rubydoc.info/gems/scopes_extractor/0.8.0/YesWeHack/Scopes)
- Bugcrowd API (docs.bugcrowd.com) is customer-side (submissions, filtering, pagination); new API version V1.1.0 listed May 5 2026. No researcher scope API found. — [Bugcrowd API usage](https://docs.bugcrowd.com/api/usage); [API changelog](https://docs.bugcrowd.com/api/changelog)
- arkadiyt/bounty-targets-data publishes raw JSON for Bugcrowd, HackerOne, Federacy, Intigriti, YesWeHack plus `domains.txt` and `wildcards.txt`; repo says hourly update. Caveat in repo: wildcard in scope may have excluded subdomains, so check program rules. — [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data); crawler in [bounty-targets](https://www.github.com/arkadiyt/bounty-targets)
- rix4uni/scope and sw33tLie/bbscope split in/out-of-scope per platform (third-party; update interval claims unverified). — [rix4uni/scope](https://github.com/rix4uni/scope); [bbscope](https://sw33tlie.github.io/bbscope/print.html)
- security.txt (RFC 9116, April 2022) at `/.well-known/security.txt` is a contact/discovery mechanism; it does not grant testing permission. — [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116); practitioner note in [bug-bounties.as93.net](https://bug-bounties.as93.net/learn/security-txt-guide-for-researchers)
- disclose.io dioterms defines partial vs full safe-harbor tiers for VDPs; Bugcrowd grants partial safe harbor to programs that do not meet all requirements. — [disclose.io](https://disclose.io/framework/terms/safe-harbor/); [Bugcrowd safe harbor docs](https://docs.bugcrowd.com/researchers/disclosure/disclose-io-and-safe-harbor/)
- Immunefi: scope and PoC requirements are per program; only listed impacts are in scope; PoC should fork a local chain, any Mainnet/Testnet activity to validate is prohibited. — [Immunefi rules](https://immunefi.com/rules/)
- Intigriti CoC: scanners/automated tests allowed but some programs ban or rate-limit them; testing must not be disproportionate or degrade service; Burp Collaborator-style pingback allowed unless program forbids; unapproved third-party pentest tools that process personal data or repro info are not allowed; write operations/data manipulation need explicit permission. — [Intigriti CoC](https://kb.intigriti.com/en/articles/5247238-community-code-of-conduct)
- HackerOne: no published numeric rate limit for automated testing found; the blog tells programs that restrict "automated testing" to rephrase it toward finding quality, i.e. many existing policies still say "no automated testing". — [HackerOne hackbot blog](https://www.hackerone.com/blog/ai-hackbots-security-testing-update)

### Inferences
- Minimum viable import: HackerOne via structured_scopes (respect 50 rpm, use `updated_at__gt` for incremental sync); everything else via bounty-targets-data JSON as read-only fallback; always emit a `scope.yaml` draft with `source`, `fetched_at`, `eligible_for_submission`, `max_severity`, and the raw `instruction` text kept for human review.
- Free-text instructions (rate limits, "no automated scanners", "no testing of payments") are not machine-readable anywhere; the guard needs a per-program `rules:` block filled by a human or LLM-extracted and human-confirmed (an LLM-parsed policy must never silently widen scope).
- Out-of-scope entries and `eligible_for_submission=false` must map to `block`, not `warn`; wildcard-with-exclusion needs explicit deny-list precedence.
- Check security.txt/VDP only for reporting contact and policy URL; it must never produce an authorization.

### Gaps
- Official Intigriti API endpoint list/schema and rate limits (KB page fetched only via search summary).
- Any official YesWeHack researcher API docs and Immunefi machine-readable scope/API (Immunefi data seen only as web pages).
- HackerOne and Bugcrowd per-program automated-scanning rate limits; found no platform-wide numbers.
- Bugcrowd researcher-facing scope data format (brief JSON) not verified.

## 2. AI-submission policy in 2026

### Takeaway
No platform bans AI assistance, but all of them put full accountability on the human submitter, require validated reproduction, and now throttle or suspend accounts for unvalidated automated volume. Immunefi explicitly prohibits AI-generated or scanner reports lacking impact. Fully autonomous submission without human validation is a policy blocker on Bugcrowd (30-day suspension path), Intigriti (disclosure and personal verification required), Immunefi (ban), and a risk on HackerOne (CoC bans large-scale unverified submissions; hackbots allowed only under special rules and where the program permits).

### Cited Findings
- HackerOne Code of Conduct update (dated April 2026 in HackerOne's post): researchers remain responsible for validating AI-assisted output; bans "large-scale submission of low-signal or unverified reports" and "AI-assisted testing that results in unsafe or prohibited activity". — [What's New for HackerOne Researchers](https://www.hackerone.com/blog/whats-new-for-hackerone-researchers)
- HackerOne welcomed hackbots in Feb 2025 "under a special set of rules" (rules not enumerated on the page); programs are told to check whether their policy permits hackbots. — [HackerOne hackbot update, 26 Jun 2025](https://www.hackerone.com/blog/ai-hackbots-security-testing-update)
- HackerOne agentic validation can auto-close reports as Duplicate/Informative/Spam/N-A or request more info at high confidence; researchers can reopen; triage prioritization uses "researcher signal". — [What's New for HackerOne Researchers](https://www.hackerone.com/blog/whats-new-for-hackerone-researchers)
- HackerOne says it does not train generative models on researcher submissions or customer data (CEO statement, Feb 2026). — [The Register](https://www.theregister.com/2026/02/18/hackerone_ai_policy/)
- HackerOne 2026 Responsible AI: by default its agents cannot do sensitive actions such as bounty payouts or scope changes without human oversight. — [Responsible AI at HackerOne](https://www.hackerone.com/blog/responsible-ai) (via search snippet)
- Bugcrowd (10 Mar 2026): permanent ban for "submission farming"; 10+ consecutive invalid reports triggers review, and if tied to automated/AI activity without pre-submission validation, a 30-day suspension; 10+ invalid (non-consecutive) requires identity verification; automation to claim common findings at launch ("launch squatting") violates standards; rate controls updated, no numbers. — [Bugcrowd policy changes](https://www.bugcrowd.com/blog/bugcrowd-policy-changes-to-address-ai-slop-submissions/)
- Bugcrowd ToS: third parties may not train AI on customer/researcher data. — [Bugcrowd (search summary)](https://www.bugcrowd.com/blog/bugcrowd-policy-changes-to-address-ai-slop-submissions/)
- Intigriti CoC: AI allowed if used responsibly; you must personally verify and understand the vulnerability; no invented endpoints, placeholder text or generic exploit templates; you must disclose when and how AI was used; unverified-looking AI output may be closed without response, get longer validation, or lead to removal; sanctions are warnings, invitation, payment or platform restrictions, appealable every 30 days. — [Intigriti CoC](https://kb.intigriti.com/en/articles/5247238-community-code-of-conduct)
- Intigriti Triage Assist flags duplicates and checks consistency with past decisions; triagers cannot work with speculative attack vectors. — [Intigriti triager perspective](https://www.intigriti.com/blog/business-insights/the-ai-impact-a-triagers-perspective)
- Immunefi prohibits "AI-generated or automated scanner reports" lacking impact information; spam leads to ban. — [Immunefi rules](https://immunefi.com/rules/)
- YesWeHack published a Claude Code plugin ("Claude Kit") with rules against invented target facts and theoretical impact; no formal YWH policy on AI reports found. — [YesWeHack Claude Kit](https://www.yeswehack.com/learn-bug-bounty/triager-grade-reports-claude-code)
- curl ended its bug bounty effective 31 Jan 2026 citing AI slop. — [Daniel Stenberg](https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty); [The Register](https://www.theregister.com/2026/01/21/curl_ends_bug_bounty/)
- Ars Technica (May 2026): submissions up 76% YoY to March; share of valid reports steady ~25%; some programs suspended. — [Ars Technica mirror](https://hn.jakechampion.name/reader/https://arstechnica.com/ai/2026/05/bug-bounty-businesses-bombarded-with-ai-slop/) (secondary)
- Single secondary claim: HackerOne program templates now let programs add rules like mandatory AI disclosure or "no fully autonomous submissions". — [decryptiondigest](https://www.decryptiondigest.com/blog/bug-bounty-programs-ai-era-hackerone-bugcrowd-2026) (unverified)

### Inferences
- Safe design: Mythos produces a submission-ready draft + evidence bundle; a named human clicks submit after replaying the PoC. Add an `ai_disclosure` field to every report (Intigriti makes it mandatory; good practice elsewhere).
- A pre-submit gate should enforce: reproduced N times from clean state, in-scope per `scope.yaml`, no unverified claims (every host/endpoint in the report traced to recorded traffic), and a per-program/day submission cap to stay far below the Bugcrowd "10 invalid" tripwire.
- Automated scanner-only findings without demonstrated impact are an explicit out-of-scope/ban class on Immunefi and common in program exclusion lists.

### Gaps
- HackerOne's "special set of rules" for hackbots and the exact CoC text; the pwnkit-docs audit (claims only ~0.34% of 590 public H1 programs explicitly allow automated scanning, CoC "silence is not consent") is self-published and I could not verify it, and its dating (May) differs from HackerOne's own "April" — [pwnkit audit](https://pwnkit-docs.pages.dev/research/2026-05-06-h1-ai-readiness/).
- Triage SLAs per platform: HackerOne page states none; not found for others.
- Reputation/signal formulas (H1 Signal, Bugcrowd priority) not found in detail.
- A Pinggy post claims curl stopped taking reports in July 2026; uncorroborated.

## 3. Reporting standards

### Takeaway
All three big platforms now support CVSS 4.0 alongside 3.1, but defaults differ (Intigriti configurable per company, Bugcrowd per program, HackerOne standard 3.1 and 4.0 calculators with asset-level max severity caps). Reports that triage fast contain exact repro, impact tied to the asset, and the platform's weakness taxonomy (HackerOne weakness_id/CWE; Bugcrowd VRT).

### Cited Findings
- HackerOne supports a CVSS 4.0 calculator and standard 3.1/4.0 implementations; if the asset has a `max_severity` the calculator caps the score. — [HackerOne CVSS 4.0](https://docs.hackerone.com/en/articles/10502498-cvss-4-0); [HackerOne severity](https://docs.hackerone.com/organizations/severity.html)
- Bugcrowd calculator supports 3.1 and 4.0 base metrics; admins enable 4.0 per program; separate VRT pre-fills priority. — [Bugcrowd CVSS v4](https://docs.bugcrowd.com/changelog/customers/cvss-v4/); [Managing CVSS](https://docs.bugcrowd.com/customers/submission-management/cvss/)
- Intigriti: CVSS 4.0 available, version set by company admin for all programs. — [Intigriti KB](https://kb.intigriti.com/en/articles/11463887-using-the-cvss-calculator-incl-4-0-on-intigriti); [Intigriti blog](https://www.intigriti.com/blog/business-insights/adoption-of-cvss-v4-vulnerability-assessment-calculator)
- Intigriti: only reports submitted through the platform count; PoC files attach on-platform; do not submit placeholder reports to claim duplicates. — [Intigriti CoC](https://kb.intigriti.com/en/articles/5247238-community-code-of-conduct)
- HackerOne Report Assistant suggests edits without rewriting unless asked; severity/asset/weakness fields remain editable. — [What's New for HackerOne Researchers](https://www.hackerone.com/blog/whats-new-for-hackerone-researchers)
- Immunefi: some programs reject reports without runnable PoC code; explanations are not PoC. — [Immunefi rules](https://immunefi.com/rules/)
- DefectDojo dedup uses per-parser algorithms (Unique ID from tool, Hash Code over configured fields; service field always appended); reimport has its own matching settings; REST `POST /api/v2/import-scan/` and `/reimport-scan/` (endpoint names from community pages). — [DefectDojo dedup](https://docs.defectdojo.com/triage_findings/finding_deduplication/about_deduplication/); [reimport](https://docs.defectdojo.com/import_data/import_intro/reimport/)

### Inferences (from general knowledge, not fetched this session)
- Add CVSS 4.0 vector (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`) as primary where the target platform/program uses it, keep 3.1 in parallel; emit vector not just score so the platform calculator can recompute; respect asset `max_severity` cap.
- SARIF 2.1.0 is useful for DefectDojo/GitHub code-scanning ingestion, not for bounty submission; CycloneDX VEX and OSCAL matter for enterprise/compliance clients (VEX for "not affected" statements on retests, OSCAL assessment-results for audit packages), low priority for bounty.
- Duplicate pre-check can be built from: own fingerprint DB of prior submissions + HackerOne public disclosed reports/Hacktivity + program's disclosed-reports feed + platform responses; no platform exposes a "would this be a dup" API to researchers (not found).
- Evidence bundle: HAR (sanitised), request/response pairs, a standalone PoC script with expected output, screenshots/video, timestamps, tool version, scope.yaml hash.

### Gaps
- No platform duplicate-check API for researchers found.
- Severity-negotiation norms not sourced (only platform calculators).
- Platform report templates beyond HackerOne's required API fields not retrieved.
- SARIF/CycloneDX/VEX/OSCAL claims not verified this session.

## 4. Continuous / ASM side

### Takeaway
CTEM is a loop (scope, discover, prioritize, validate, mobilize) and commercial ASM sells discovery + change alerts + ticketing. Open-source equivalents already cover scheduled runs, diff alerts and Slack/Discord; Mythos's `scripts/watch` covers only the retest slice.

### Cited Findings
- CTEM five stages, cyclic: mobilization feeds back into scoping; Gartner introduced it in 2022; scoping defines what matters rather than inventorying everything. — [Kroll](https://www.kroll.com/en/publications/cyber/what-is-continuous-threat-exposure-management); [Cymulate whitepaper](https://cymulate.com/uploaded-files/2024/11/Continuous-Threat-Exposure-Management-CTEM-Whitepaper.pdf) (vendor sources; Gartner doc not retrieved)
- ProjectDiscovery Cloud: scheduled daily or hourly-ish scans, real-time scans when new Nuclei templates ship, alerting (Slack, Teams, email, webhook) incl. new-vulnerability alerts on rescans, ticketing (Jira, GitHub, GitLab, Linear) with optional two-way sync. Continuous (back-to-back) scanning is Enterprise-only. — [PD alerting/integrations](https://docs.projectdiscovery.io/cloud/integrations); [PD scans](https://docs.projectdiscovery.io/cloud/scanning/createscans); [real-time scans](https://docs.projectdiscovery.io/cloud/scanning/real-time-scans)
- reNgine: periodic and clocked scans with Slack/Discord/Telegram notifications for new subdomains/vulns/changes. — [reNgine repo mirrors / Intigriti tool post](https://intigriti.com/researchers/blog/hacking-tools/hacker-tools-rengine) (secondary; hosted-product claims from HailBytes are marketing)
- HackerOne's agentic PTaaS (Jan 2026) and YesWeHack Agentic Pentest (Jun 2026) are commercial continuous/autonomous testing offerings. — [The Register](https://www.theregister.com/2026/02/18/hackerone_ai_policy/); [YesWeHack](https://www.businesswire.com/news/home/20260625181000/en)

### Inferences
- Gap analysis against Mythos: no asset-discovery loop feeding scope (must only add assets that match `scope.yaml` wildcards and were confirmed in program scope), no diff of recon state (new host, new port, new tech, cert change), no scheduler, no alerts. Open-source building blocks: subfinder/amass/asnmap/dnsx/httpx/naabu + CT log monitoring (crt.sh/certstream), nuclei templates scheduled via cron/systemd timer, `anew`-style diffing.
- Re-test of fixed bugs: tie each submitted finding fingerprint to platform report ID and state; on "Resolved", schedule `watch` retest and file a regression note; this is the one ASM feature most compatible with bounty rules since it targets a known in-scope issue.
- Axiom, Trickest, nemesis not researched (see Gaps).

### Gaps
- Axiom, Trickest, nemesis, OWASP Amass specifics (not searched).
- Cost/rate-limit courtesy of passive sources not covered.
- CVE-driven "real-time" rescans on new templates is only sourced from PD docs, no independent evidence.

## 5. Legal / safety operating rules

### Takeaway
Authorization comes only from the program policy/safe-harbor and signed engagement paperwork, never from discovery artifacts. Platforms explicitly restrict write operations, load, and third-party tools that process vulnerability data.

### Cited Findings
- Intigriti: write operations/data manipulation need explicit permission; keep invasive commands minimal; report if your testing slows the service; OAST pingback (Collaborator) allowed unless the program forbids; third-party tools that handle personal or repro data must be approved. — [Intigriti CoC](https://kb.intigriti.com/en/articles/5247238-community-code-of-conduct)
- Immunefi: no Mainnet/Testnet activity to validate; use local forks. — [Immunefi rules](https://immunefi.com/rules/)
- HackerOne: ban on AI-assisted testing causing unsafe or prohibited activity. — [What's New for HackerOne Researchers](https://www.hackerone.com/blog/whats-new-for-hackerone-researchers)
- disclose.io safe harbor tiers; security.txt is not authorization (see section 1).
- Bugcrowd and HackerOne state platform data must not be used to train third-party AI. — [Bugcrowd](https://www.bugcrowd.com/blog/bugcrowd-policy-changes-to-address-ai-slop-submissions/); [The Register](https://www.theregister.com/2026/02/18/hackerone_ai_policy/)

### Inferences
- Sending program data (PoC, repro, PII) to a third-party LLM API may itself violate platform ToS (Intigriti: unapproved third-party tools processing personal/repro info). Mythos needs a "data egress" note and ideally local/approved model option; this is a real policy exposure for an LLM-driven tool.
- Needed controls: append-only audit log (who/what/when/request IDs), global kill switch honored by all workers, redirect/SSRF re-check (every followed hop and every OAST callback target re-validated against scope; blocked when a redirect leaves scope), PII minimisation (hash/redact in evidence, stop at proof), OAST on operator-owned domain with per-engagement tokens and teardown, and authorization artifact referenced in `scope.yaml` (program URL + retrieved policy hash/date, or SoW/RoE ID and window).
- PTES/OSSTMM/NIST SP 800-115 rules-of-engagement expectations and CREST/firm requirements were not retrieved; list these as expected rather than sourced.

### Gaps
- Not sourced: PTES, OSSTMM, NIST 800-115 text, CREST/reputable-firm operational requirements, CFAA/Austrian §118a StGB legal analysis, DOJ 2022 CFAA good-faith policy.
- OAST hygiene guidance (interactsh) not searched.

## 6. Collaboration and multi-operator use

### Takeaway
DefectDojo is the de-facto findings DB with REST import/reimport and dedup; SysReptor (reptor CLI) and Ghostwriter (GraphQL) are the report generators. Mythos has none of these hooks.

### Cited Findings
- DefectDojo supports engagements, import-scan and reimport-scan APIs with dedup and `auto_create_context`; reimport dedup config is separate and not retroactive (needs `dedupe` management command). — [DefectDojo dedup](https://docs.defectdojo.com/triage_findings/finding_deduplication/about_deduplication/); search summary of [reimport docs](https://docs.defectdojo.com/import_data/import_intro/reimport/)
- SysReptor `reptor` CLI can upload findings from JSON/TOML and export findings as JSON; Ghostwriter has a GraphQL API; reptor's Ghostwriter importer handles finding templates, not project findings; PwnDoc-ng to SysReptor is only community scripts. — [reptor docs](https://docs.sysreptor.com/cli/getting-started); [reptor on GitHub](https://github.com/syslifters/reptor); [Ghostwriter GraphQL docs](https://docs.specterops.io/ghostwriter-docs/home.md)
- ProjectDiscovery Cloud ticketing integrates Jira/GitHub/GitLab/Linear with two-way sync, as the reference model. — [PD integrations](https://docs.projectdiscovery.io/cloud/integrations)

### Inferences
- Cheapest high-value path: emit DefectDojo-importable SARIF or Generic Findings JSON with stable `unique_id_from_tool` = Mythos fingerprint, then call reimport-scan on each run; this gives dedup, status, Jira push and team UI for free. Faraday/Dradis exports not researched; SysReptor via reptor JSON upload.
- Multi-operator needs: operator identity in the audit log, a shared findings store (SQLite is single-writer; DefectDojo or Postgres otherwise), claim/lock on a target to avoid two operators hitting the same host (also a rate-limit courtesy issue), and a webhook notifier (Slack incoming webhook) for findings and kill-switch events.

### Gaps
- Faraday, Dradis, PwnDoc API specifics not researched.
- SysReptor finding-creation payload schema not confirmed.
- DefectDojo SARIF/CycloneDX parser page failed to load; parser support not verified here.
