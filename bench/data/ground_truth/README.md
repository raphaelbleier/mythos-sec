# Ground truth for flagless targets

The XBOW sweep (`bench/run.py`) scores by random flag capture. The four real
vulnerable apps below ship no flag, so scoring is **recall against the upstream
documentation** — every JSON here is the documented vulnerability list, verbatim
in structure, filled from the upstream challenge docs.

| File | Target | Upstream source | License |
|---|---|---|---|
| `crapi.json` | OWASP crAPI | `docs/challenges.md` (18 disclosed + 3 secret) | Apache-2.0 |
| `vulnbank.json` | Vuln Bank (Commando-X) | README "Implemented Vulnerabilities" (11 categories) | MIT |
| `dvga.json` | Damn Vulnerable GraphQL Application | README "Scenarios" (23, incl. 2 recon milestones) | MIT |
| `vampi.json` | VAmPI | README "List of Vulnerabilities" (9) | MIT |

Framework/runner status (which arms exist) lives one level up in
`../frameworks.json`; PentestGPT and CAI are recorded there as
`interactive_only`/`harness: false` and are refused by `bench/run.py` before any
target starts.

## Schema

- `target_id`, `name`, `kind: "flagless"`, `license`
- `upstream` — repo URL, exact challenge-doc URL, `retrieved` date
- `deploy` — canonical run command, ports, endpoint paths, and run-relevant
  caveats (MailHog for crAPI, XSS TTL for Vuln Bank, compose secure/insecure
  split for VAmPI)
- `scoring.protocol` — how recall/precision are computed for this target
- `vulns[]` — one entry per documented vulnerability/scenario:
  - `id` — stable (`crapi-01`, `vb-01`, `dvga-01`, `vampi-01`)
  - `title` — upstream wording, minimally compressed
  - `class` — canonical class keyword for grouping (not used for matching)
  - `bench_tag` — one of the tags in `bench/score.py` ALIASES, or `null`
    when no XBEN tag corresponds; reused if real-app detection matching is
    wired into scoring later
  - `scored` — `false` marks entries excluded from the recall denominator
    (undisclosed crAPI secrets, LLM-provider confounders, duplicate bullets,
    recon milestones)
  - `notes` — proof rules and caveats (destructive-class constraints: DoS,
    brute force, races are demonstrated lightly or by absence, never run hard)
- `exclusions[]` — ids plus the reason they are out of the denominator
- `false_positive_control` — fixture giving a non-vulnerable twin (VAmPI
  secure instance), or `null`

## Editing rules

Ground-truth files may only change when the upstream doc changes (append the new
`retrieved` date). `scored: false→true` flips are metric choices: never make
them to make a run look better; record the reason in `notes`.
