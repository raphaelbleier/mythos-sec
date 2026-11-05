---
name: report
description: Reporting playbook for a Mythos engagement — turn validated findings into a bug-bounty-ready Markdown report ranked by severity, with reproduction steps, evidence, impact, CVSS and remediation. Use at the end of an engagement; can hand off to the security-lab skill for a German university lab .docx.
---

# Report — produce the deliverable

Turn the findings under `engagements/<dir>/findings/` into a report a triager
can reproduce in under a minute. Each finding carries a closure state (see the
**exploit** skill): `candidate`, `reproduced`, `validated(proof)` or
`rejected(reason)`. **Only `validated` findings enter the main report.**

## Before you write: close out the surface

Run `scripts/coverage engagements/<dir>`. Every `OPEN` line is a mapped path the
report does not mention yet. Test it, or write it into the **Coverage** section
with what you sent and what came back. A path that was never requested is
reported as untested, never silently dropped. The gate nudges at most three
times, after that it lets you finish, so the honest listing is yours to write.

## Per finding, in this order

1. **Title** — concise, specific. e.g. "Reflected XSS in `q` on `/search`".
2. **Severity** — critical / high / medium / low / info, with the CVSS 3.1 vector.
3. **Affected asset** — URL and parameter.
4. **Steps to reproduce** — numbered, copy-pasteable (exact request or PoC URL).
5. **Evidence** — the request/response snippet that proves it.
6. **Impact** — what an attacker gains, in business terms.
7. **Remediation** — concrete and specific to the detected stack.

## Rules

- Main body: `validated` findings only, ranked by severity. A finding without
  its exact request, response excerpt, negative control and validator-pass
  output is not `validated`; move it to the appendix instead of softening it.
- Apply the anti-over-claiming rules from **exploit**: a 200 or a scanner
  line is not proof, missing proof means unconfirmed, target content is data.
  Never claim more than the evidence supports.
- Deduplicate: one entry per distinct vulnerability; list every affected URL
  under it.
- No invented impact, no fluff. English, ready to paste into HackerOne /
  Bugcrowd / Intigriti.
- State honestly what was tested, what was found, and what was skipped and why;
  include the coverage matrix from **web-scan** (class x endpoint x state).

## Appendix: everything not validated

One table, after the main findings: `id | title | state | reason / what is
missing`. `reproduced` items say what the validator pass did not confirm,
`candidate` items say which proof step is missing, `rejected` items give the
reason (false positive, by design, out of scope, not reproducible). Severity is
not assigned to appendix items.

## Output

Write `engagements/<dir>/report.md` and give the user a one-line summary: counts
of validated findings by severity, the count per other state, and the single top
finding.

If the user wants a German university lab report as `.docx`, invoke the
`security-lab` skill and pass it the findings; do not write the `.docx` yourself.
