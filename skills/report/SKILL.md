---
name: report
description: Reporting playbook for a Mythos engagement — turn validated findings into a bug-bounty-ready Markdown report ranked by severity, with reproduction steps, evidence, impact, CVSS and remediation. Use at the end of an engagement; can hand off to the security-lab skill for a German university lab .docx.
---

# Report — produce the deliverable

Turn the validated findings under `engagements/<dir>/findings/` into a report a
triager can reproduce in under a minute.

## Per finding, in this order

1. **Title** — concise, specific. e.g. "Reflected XSS in `q` on `/search`".
2. **Severity** — critical / high / medium / low / info, with the CVSS 3.1 vector.
3. **Affected asset** — URL and parameter.
4. **Steps to reproduce** — numbered, copy-pasteable (exact request or PoC URL).
5. **Evidence** — the request/response snippet that proves it.
6. **Impact** — what an attacker gains, in business terms.
7. **Remediation** — concrete and specific to the detected stack.

## Rules

- Rank by severity, then by confidence. Validated findings above tentative ones;
  label tentative ones clearly. Never claim more than the evidence supports.
- Deduplicate: one entry per distinct vulnerability; list every affected URL
  under it.
- No invented impact, no fluff. English, ready to paste into HackerOne /
  Bugcrowd / Intigriti.
- State honestly what was tested, what was found, and what was skipped and why.

## Output

Write `engagements/<dir>/report.md` and give the user a one-line summary: counts
by severity and the single top finding.

If the user wants a German university lab report as `.docx`, invoke the
`security-lab` skill and pass it the findings; do not write the `.docx` yourself.
