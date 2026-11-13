# Continuous testing with `scripts/watch`

An engagement is a snapshot of one day. The target keeps changing after it: a
route ships that nobody tested, a framework is upgraded, a CVE lands on the
KEV list for the stack, a fixed bug comes back. Mythos has no schedule of its
own and nothing here changes that. `scripts/watch` is the piece a cron job or
a CI step calls between engagements. It sends a few dozen GET requests, calls
no model, and prints a prioritized work list. The `continuous` skill is what
an agent does with that list.

> **Authorization warning.** A scheduled job keeps testing after you stop
> looking. If the bug-bounty program pauses, closes, drops the asset or
> changes its rules, a job that is still running is unauthorized access, and
> "the scope file said so" is not a defense. Before you schedule anything,
> and again at least every 30 days, you must check on the program's own page:
> that the program is live and accepting reports, that every asset in
> `scope.yaml` is still listed and nothing new is excluded, that automated
> traffic is allowed at your rate, and that any required header, account or
> testing window is still the one you configured. `scripts/watch` cannot see
> that page. What it does is force you to look: it records your confirmation
> (`init --confirm-authorization`), and if the scope file changes or the
> confirmation is older than `--reconfirm-days` (default 30), it sends no
> request to the target and exits 3 until you confirm again. Use a smaller
> `--reconfirm-days` for programs that change often. Scheduling a job on a
> target you do not own and have not re-confirmed is the failure this feature
> is most likely to cause.

## quick start

```
export MYTHOS_SCOPE="$PWD/engagements/<dir>/scope.yaml"      # never guessed, always pinned
scripts/watch init  https://app.example.com --confirm-authorization 'h1.example/program, 2026-11-14' \
                    --from engagements/<dir>                 # seed from the finished engagement
scripts/watch check https://app.example.com                  # the cheap daily check
scripts/watch retest https://app.example.com                  # which stored proofs to replay
```

`--from` takes the engagement's `findings/`, `surface.json` and
`cve-candidates.json`, which `report` and `recon` already write. Without it the
first `check` stores what it sees as the baseline and reports nothing.

After an agent has worked the list:

```
scripts/watch record <url> engagements/<new-dir>   # new findings, fixed, regressions; moves the baseline
scripts/watch verify <url> <fingerprint> --fixed --evidence replay.txt
scripts/watch ack    <url> --note 'reviewed, harmless'
```

## what it checks

| signal | cost to the target | what it reports |
|---|---|---|
| `surface` | up to about 56 GETs (`probe --depth 2`) | new and removed routes, new parameters on known routes, changed authentication mechanism, a gated route that opened, a new or changed technology, new hosts |
| `cve` | none | CVE ids that were not known at the last engagement and match the stored fingerprint, through `scripts/cvefeed match` |
| `findings` | none | stored proofs to replay: gone since the last engagement, regressed, on a changed route, or not replayed for `--retest-days` |

`--signals cve,findings` runs the two signals that send nothing to the target.
The diffing of findings is not re-implemented: `record` calls
`scripts/findings --diff` and keeps a registry per fingerprint on top of it.

## the work list

`check --json` prints one document. Its shape, shortened:

```json
{
  "target": "https://app.example.com",
  "exit": {"code": 1, "meaning": "outstanding work, queue it"},
  "cost": {"requests_to_target": 19, "refused_by_scope": 0, "model_calls": 0},
  "signals": {"surface": {"status": "ok", "diff": {"new_routes": ["GET /export"]}},
              "cve": {"status": "ok", "data_age": "41m old", "stale": false},
              "findings": {"status": "ok", "registry": 3}},
  "work": [{
    "id": "new-endpoint:/export",
    "kind": "new-endpoint",
    "priority": 2, "priority_label": "high",
    "summary": "new endpoint GET/POST /export",
    "why": "untested by construction: nothing in the last engagement covered it",
    "handled_by": {"skill": "web-scan", "also": ["business-logic"], "run": null},
    "touches_target": true, "held": false,
    "first_seen": "2026-11-14T05:23:04Z"
  }],
  "not_queued": [{"host": "cdn.other.example", "in_scope": false, "reason": "..."}],
  "do_not_rerun": [{"what": "...", "why": "..."}],
  "notes": []
}
```

- `priority` 1 is a human now, 2 an agent run today, 3 the next scheduled run,
  4 hygiene. `kind` is one of `new-cve`, `new-endpoint`, `new-parameter`,
  `auth-change`, `status-change`, `stack-change`, `new-host`, `removed-routes`,
  `retest`, `blocked`.
- `handled_by` names the skill that does the work and any extra skills the
  parameter names point at. `run` is a ready command when one exists, such as a
  paced `nuclei -id` for a CVE with a template.
- `held: true` means authorization is not current. The item must not be acted
  on.
- `not_queued` lists hosts the target pointed at that are outside the pinned
  scope. They were reported and never requested.
- `do_not_rerun` is what an agent should leave alone: recon on mapped routes,
  classes already rejected, CVE ids already assessed.
- `first_seen` ages an item. An unhandled item keeps its date, so a list that
  has been red for nine days says so.

## exit codes

| code | meaning | a job should |
|---|---|---|
| 0 | nothing outstanding | do nothing |
| 1 | outstanding work. The same state returns 1 again until `record` or `ack` consumes it | queue the work list for an agent or a human |
| 2 | error or refusal: no pinned scope, no state, target unreachable, feed unusable | alert the operator. An unreachable target is not "fixed" |
| 3 | a human is needed now: a KEV entry newly matches the stack (once per CVE), or scope or authorization is out of date and traffic is held | page |

3 wins over 2, and 2 wins over 1. The output is printed in every case with
whatever was computed. KEV pages only for a fingerprint read off the product
(`exact`) or a banner whose matched package is the product itself. A banner
match on an unrelated package (a Python banner against a KEV row for node.js,
seen in testing) is priority 2, not a page.

## how scope is enforced

Under an agent host, `hooks/scope-guard.py` and `hooks/budget-guard.py` see the
agent's Bash calls. They do not see the requests a script makes internally, and
a cron job or CI step has no hook at all. So `watch` calls the same two modules
for every request it sends, redirects included: a request to a host or port
outside the pinned scope is refused before it is sent, and each request is
paced through the budget guard's token bucket at `rules.rate_limit_rps`
(0.2 seconds apart when the scope sets none). `rules.allow_active: false`
skips the surface signal. A host that drift discovers is never requested: in
scope it becomes a recon item, out of scope it goes under `not_queued`. A
missing `MYTHOS_SCOPE` is a refusal; there is no fallback to the newest
`engagements/*/scope.yaml`.

## state layout

State is per target, because the point is continuity across runs:

```
engagements/.watch/<host>_<port>/
  state.json         authorization, scope hash, fingerprint, known CVE ids, finding registry, first-seen dates
  surface.json       the baseline map (probe output, cookie values dropped) and its hash
  last-surface.json  the map from the latest check; what `ack` adopts
  findings.json      the last recorded findings.json (scripts/findings --all)
  last-check.json    the latest work list
```

It lives under `engagements/` because it holds target data (routes, finding
titles, redacted evidence) and that directory is already git-ignored, so it is
never committed. It is written only by this host-side tool: the toolbox mounts
the repo read-only and never needs it. An engagement directory would be wrong,
since several engagements share one target, and `~/.mythos` would be wrong,
since `lessons` keeps only a salted hash of a target there on purpose. Override
with `--state DIR` or `MYTHOS_WATCH_STATE`. There is no locking: do not run two
checks of one target at once (`flock` in cron, `concurrency` in Actions).

A finding in the registry is `open`, `unverified_gone`, `fixed` or
`regressed`. `unverified_gone` is what a validated finding becomes when a later
engagement does not re-find it. It means "not reproducible today". Only
`verify --fixed` with a saved replay of the proof turns it into `fixed`.

## cron

```sh
#!/bin/sh
# /usr/local/bin/mythos-watch  (adapt: paths, target, notification)
cd /opt/mythos-sec || exit 2
export MYTHOS_SCOPE=/srv/bounty/example/scope.yaml
TARGET=https://app.example.com
OUT=/var/lib/mythos/example-$(date -u +%Y%m%dT%H%MZ).json

scripts/watch check "$TARGET" --json "$@" > "$OUT"
case $? in
  0) ;;
  1) echo "work queued in $OUT" | mail -s "mythos: work for $TARGET" you@example.org ;;
  3) echo "see $OUT" | mail -s "mythos: URGENT $TARGET" you@example.org ;;
  *) echo "see $OUT" | mail -s "mythos: watch error for $TARGET" you@example.org ;;
esac
```

```
# crontab: the signals that send nothing every 6 hours, the surface once a day
7 */6 * * *   flock -n /tmp/watch-example.lock mythos-watch --signals cve,findings
23 5 * * *    flock -n /tmp/watch-example.lock mythos-watch
```

The job only produces the list. Acting on it is an agent session started on
purpose, with `MYTHOS_SCOPE` pinned to the same file, told to follow the
`continuous` skill on `last-check.json`.

## GitHub Actions

This is an example, not a finished workflow. Adapt it before use: the target
and scope come from secrets you create, the cadence is yours, and it assumes a
private repository, because the cached state holds target data. It is written
in the style of the other workflows here (actions pinned to a full SHA, least
privilege, inputs through `env` and never interpolated into `run:`). The
state is restored and saved explicitly, with the save under `always()`,
because a job that exits 1 or 3 on purpose must still save what it learned,
including which KEV id it already announced. Authorization is confirmed only by
a person, through a manual dispatch with a note. A scheduled run never
confirms it for you, and a run with no state fails instead of re-baselining.

```yaml
name: watch

on:
  schedule:
    - cron: '23 5 * * *'
  workflow_dispatch:
    inputs:
      authorization_note:
        description: 'Confirms authorization: where and when you re-checked the program page and scope'
        required: false

permissions:
  contents: read

concurrency:
  group: watch
  cancel-in-progress: false

jobs:
  watch:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false

      - name: Restore the watch state
        uses: actions/cache/restore@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
        with:
          path: engagements/.watch
          key: watch-${{ github.run_id }}
          restore-keys: |
            watch-

      - name: Pin the scope
        env:
          WATCH_SCOPE: ${{ secrets.WATCH_SCOPE }}
        run: |
          printf '%s\n' "$WATCH_SCOPE" > "$RUNNER_TEMP/scope.yaml"
          echo "MYTHOS_SCOPE=$RUNNER_TEMP/scope.yaml" >> "$GITHUB_ENV"

      - name: Selftest
        run: python3 scripts/watch --selftest

      - name: Confirm authorization (manual dispatch with a note only)
        if: github.event_name == 'workflow_dispatch' && github.event.inputs.authorization_note != ''
        env:
          TARGET: ${{ secrets.WATCH_TARGET }}
          NOTE: ${{ github.event.inputs.authorization_note }}
        run: python3 scripts/watch init "$TARGET" --confirm-authorization "$NOTE"

      - name: Check
        id: check
        env:
          TARGET: ${{ secrets.WATCH_TARGET }}
          WATCH_HEADER: ${{ secrets.WATCH_HEADER }}
        run: |
          args=()
          if [ -n "$WATCH_HEADER" ]; then args+=(--header "$WATCH_HEADER"); fi
          set +e
          python3 scripts/watch check "$TARGET" "${args[@]}" --json > "$RUNNER_TEMP/work.json"
          echo "code=$?" >> "$GITHUB_OUTPUT"

      - name: Save the watch state
        if: always()
        uses: actions/cache/save@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
        with:
          path: engagements/.watch
          key: watch-${{ github.run_id }}

      - name: Keep the work list
        if: always()
        uses: actions/upload-artifact@65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08 # v4.6.0
        with:
          name: watch-work
          path: ${{ runner.temp }}/work.json
          if-no-files-found: ignore
          retention-days: 14

      - name: Branch on the exit code
        env:
          CODE: ${{ steps.check.outputs.code }}
        run: |
          case "$CODE" in
            0) echo "nothing outstanding" ;;
            1) echo "::warning::watch found work. The list is in the watch-work artifact." ;;
            *) echo "::error::watch exit $CODE: a human is needed. See the watch-work artifact."; exit 1 ;;
          esac
```

Two things this example does not do for you. GitHub evicts a cache entry
after seven days without access, so a pause longer than that loses the state
and the next run fails until you dispatch it with a note again; that is the
safe direction. And a runner's IP address changes, so a program that
allow-lists source addresses or requires a specific header needs the header
(`WATCH_HEADER`) and, for the address, a runner you control.

## cost and cadence

What one run costs, from this repository's own numbers:

| run | requests to the target | model calls | wall time at 5 req/s |
|---|---|---|---|
| `watch check`, surface | at most 40 pages + 15 common paths + 1 GraphQL probe, so about 56. Measured: 19 on a 3-page site, 28 on DVGA | 0 | 4 to 12 seconds plus latency |
| `watch check --signals cve,findings` | 0 | 0 | seconds |
| replaying one stored proof | 2 (the proof and its negative control), by the protocol in the skill | one small agent session for all due proofs, not measured | seconds |
| a full engagement | thousands. `hooks/budget-guard.py` estimates one default invocation at 2000 (nuclei), 5000 (ffuf), 500 each (katana, arjun), 1500 (sqlmap) and 1000 (dalfox), about 10,500 for those six. These are the guard's over-estimates, not measured counts | many | about 35 minutes of wire time |

Model cost is the number that matters and the one this repository cannot give
for a real target. The README's benchmark section measures $0.27 to $0.77 per
run on DVGA, a single small lab app. A real target with several hosts and
authenticated areas costs more, and that figure is not measured here.

Thirty daily checks send at most about 1,700 requests and cost no model calls.
One full re-run sends several times that and costs model tokens on top, to
re-find mostly what the last engagement already found. That is the argument
against a monthly full re-run: the code that did not change gives the same
findings, so most of the spend buys "still present". The cheap check
concentrates the spend on the one thing that is untested by construction, the
code that changed.

Recommended cadence:

| what | how often | why |
|---|---|---|
| `check --signals cve,findings` | every 6 hours | It touches no target, and `cve-snapshot.yml` refreshes the feed on the same 6 hours. Langflow-class flaws have been exploited within hours of disclosure, and this signal is the only one for which a day is too slow. |
| `check` (surface, plus the above) | daily; weekly if the program is sensitive to automated traffic or the target rarely ships | Surface drift is the highest-value signal and about 56 requests is below any sane rate limit. Daily means a new endpoint is a day old when it is flagged. |
| replay due stored proofs | weekly (`--retest-days 7`), and at once for any finding whose route drifted | Two requests per finding. This is the free retest competitors sell: fixes verified, regressions caught. |
| targeted run on a `new-endpoint` or `new-parameter` item | when the list says so, scoped to that route | The agent tests what changed, not the whole target. |
| full re-engagement | not on a calendar. On a major version change, a large batch of new routes, a confirmed urgent CVE, or scope growth. Quarterly at most as a deliberate backstop | See the limits: the check cannot see everything. |

## limits

- It sees what `probe` sees: pages and forms reachable by links, the OpenAPI
  document and GraphQL introspection when present. A client-rendered SPA gives
  a near-empty map and drift only in the shell page; the recon skill hands
  those to the browser agent, and `watch` does not. A target larger than 40
  pages is mapped partially, and which pages fall inside the cut can vary.
- It cannot see a behavior change behind an unchanged URL, a new backend
  parameter that no form, link or spec shows, or a logic bug introduced in an
  existing handler. "No change" is not "no new vulnerability". That is why a
  periodic full run stays as a backstop.
- An authenticated map is only as good as the header you pass. An expired
  token looks like removed routes and a changed login flow. An authenticated
  and an unauthenticated run do not compare, and `watch` skips the diff when
  it notices.
- CVE matching inherits `cvefeed`'s precision. A banner such as `python/3.14`
  or `nginx/1.18` is matched loosely, so expect priority 2 rows that are not
  real. Only an exact fingerprint, or a banner whose matched package is the
  product, pages a human. Data older than seven days is flagged stale in the
  output, and a quiet `cve` signal on stale data means little.
- Finding drift needs a recorded engagement. `check` alone never learns that a
  bug was fixed; it can only list the proofs to replay. `verify --fixed` checks
  that the evidence file exists and is not empty. It cannot check that the file
  shows a failed proof, so it is an audit trail and not a proof checker.
- The scope pin detects that the local file changed. It does not know the
  program changed. The confirmation interval is the only control for that, and
  it is as good as the person who answers it.
- Pacing is a token bucket shared through `.budget` in the scope file's
  directory, so it is shared with an agent session using the same scope file,
  not with another machine or another job.
- It sends no payloads and reports nothing it has not seen in a response. Whether a
  new route is vulnerable is the agent's work, under the proof standard in
  **exploit**.
- A scheduled agent session is a long unattended run. The single human gate of
  an engagement is the scope confirmation, and for this mode that confirmation
  is the one you renew every 30 days.
