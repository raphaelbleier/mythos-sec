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

## The engagement layout, exactly

A live run wrote its whole report into `findings/report.md`, which left nothing
machine-readable and produced one bogus finding with no class. The layout is
not a suggestion:

```
engagements/<dir>/
  report.md            the deliverable, at the ROOT, never inside findings/
  findings/<id>.md     one file per finding, front matter + evidence
  findings.json        written by scripts/findings, do not hand-write it
  scope.yaml           the authorization boundary
```

Each `findings/<id>.md` carries `id`, `title`, `class` (a knowledge-base class
name, so the CWE maps), `status`, `asset`, `param`, `severity`, `cvss`, `proof`,
`negative_control`, and `reason` for a rejected one. Write these before the
prose, not after: the prose is assembled from them, and `scripts/findings`
refuses to run without them with exit code 3.

## Machine-readable output

Run `scripts/findings engagements/<dir>` before you write the prose. It reads
the front matter of every `findings/<id>.md` and writes `findings.json`:

```bash
scripts/findings engagements/<dir> --sarif engagements/<dir>/findings.sarif
```

Do not skip this and do not hand-write the JSON. The script does four things
you must not do by eye:

- **It computes the CVSS 3.1 base score from the vector** instead of trusting
  the severity word. If it reports `severity says critical but the vector
  computes medium (6.1)`, fix one of the two before writing the report. A
  severity nobody can derive from the vector is an inflated report.
- **It deduplicates** on class plus endpoint template plus parameter, with
  numeric and UUID path segments collapsed, so the same flaw on `/users/1`
  and `/users/9823` is one finding with two affected assets. Use its merged
  list as the report's structure.
- **It redacts credentials** out of the evidence: cookies, bearer tokens,
  JWTs, API keys, passwords. `findings.json` leaves the engagement directory
  and must not carry a session.
- **It refuses to let `validated` stand without a proof path and a negative
  control**, and lists every such finding under `problems`. Resolve all of
  them: either supply the evidence or drop the state back.

A retest against a previous engagement compares the two runs:

```bash
scripts/findings engagements/<dir> --diff <previous>/findings.json
```

That prints fixed, still present and new, keyed by fingerprint, which is what
a program's retest request actually asks for. `--fail-on high` exits non-zero
when a validated finding is high or above, for a CI gate.

## Output

Write `engagements/<dir>/report.md` and give the user a one-line summary: counts
of validated findings by severity, the count per other state, and the single top
finding. `findings.json` and, when asked for, `findings.sarif` sit beside it.

The front matter each finding needs for all of this: `id`, `title`, `class`
(the knowledge-base class name, so the CWE maps), `status`, `asset`, `param`,
`severity`, `cvss`, `proof`, `negative_control`, and `reason` for a rejected
one. A class with no CWE mapping is reported as a problem rather than guessed;
add it to the table in `scripts/findings` if the class is real.

If the user wants a German university lab report as `.docx`, invoke the
`security-lab` skill and pass it the findings; do not write the `.docx` yourself.
