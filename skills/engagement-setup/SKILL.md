---
name: engagement-setup
description: Set up a new Mythos engagement workspace and scope. Use at the start of a /cybersecurity run, or whenever the user wants to begin testing a new target, define scope, or import a bug-bounty program's rules before any scanning.
---

# Engagement setup

Create a clean, scoped workspace before any traffic reaches the target. Scope
is the authorization boundary; nothing runs until it is written down.

## Steps

1. **Identify the target** and the authorization. Ask the user which program /
   client this is and confirm they are authorized to test it. If they cannot
   confirm authorization, stop.

2. **Create the workspace**:
   `engagements/<target-host>-<YYYYMMDD>/` with subdirs `recon/`, `scan/`,
   `findings/`. Everything about the engagement stays here (it is git-ignored).

3. **Write `scope.yaml`** directly in the engagement dir (template below),
   then edit it to match the program exactly:

   ```yaml
   target: https://target.example
   in_scope:
     - target.example # only hosts/CIDRs the program lists; *.example.com for wildcards
   out_of_scope: [] # every excluded host the program names
   rules:
     rate_limit_rps: 5
     ports: [80, 443] # the ports the program authorizes
     allow_active: true # false only if the program forbids active scanning
     allow_exploit: true # false only if the program forbids PoC exploitation
     allow_publish: false # never publish a package to a public registry
     allow_claim_resources: false # never claim a dangling subdomain or bucket
     allow_secret_verification: false # never use a credential you found
   source: "" # optional: path to a source tree the program authorized you to read
   identities: [] # optional: two accounts for BOLA/IDOR testing
   notes: "" # paste the program's testing rules verbatim
   ```

   Field rules:
   - `in_scope`: only the hosts/CIDRs the program lists. Use `*.example.com`
     for wildcard programs. An empty list authorizes nothing, and the guard
     treats it that way rather than as "allow everything".
   - `out_of_scope`: every excluded host the program names.
   - `rules.rate_limit_rps`: the program's rate limit, enforced by
     `hooks/budget-guard.py`. Single-shot calls are paced by sleeping, and a
     batch tool invoked without its own pacing flag is refused with the flag
     to add. There is no request ceiling: a volume cap only ever stops the run
     before the finding. If a program states a request limit, put it in
     `notes` and watch it yourself.
   - `rules.ports`: the ports the program authorizes. A request to another
     port on an in-scope host is reported as out of scope.
   - `rules.allow_active` and `rules.allow_exploit`: both default to true,
     because this is a pentesting suite and exploitation is the work. Set
     either to false only when the program's text forbids it. An explicit
     `allow_exploit: false` makes the guard repeat the rule back once when
     exploitation tooling runs; honoring it is your judgement, not a block.
   - `rules.allow_publish`, `rules.allow_claim_resources`,
     `rules.allow_secret_verification`: keep all three false unless the
     program's text explicitly authorizes that action. They cover publishing a
     package to a public registry (dependency-confusion testing), claiming a
     dangling subdomain or bucket, and using a credential you discovered.
     Each of those affects a third party, not just the target.
   - `source`: a local path, only when the program or client gave you the code. Having
     the source does not widen the scope: the live target is still bounded by
     `in_scope`, and reading a repository you were not given is out of scope. Leave it
     empty for a black-box engagement.
   - `notes`: paste the program's testing rules (e.g. "no DoS, no automated
     testing of the login form, no social engineering").

4. **Pin the scope file** so nothing else can become the authorization
   boundary:

   ```bash
   echo "engagements/<dir>/scope.yaml" > .mythos-scope
   export MYTHOS_SCOPE="$PWD/engagements/<dir>/scope.yaml"
   ```

   Both lines, and the file matters more than the export. A PreToolUse hook
   runs as its own process in the host's environment, not in your shell, so an
   `export` inside a tool call never reaches the guards: a measured run pinned
   the scope exactly as instructed and the guards still fell back to the newest
   `engagements/*/scope.yaml` by modification time, which is the fallback the
   pin exists to avoid. The file is read by both guards. The export is still
   worth setting, because `scripts/probe`, `scripts/verify` and `scripts/watch`
   are children of your shell and read it for the rate limit.

   Without the pin, a leftover directory from an older engagement can silently
   authorize this one. Confirm it took effect:

   ```bash
   python3 hooks/scope-guard.py --check 'curl https://example.invalid/'
   ```

   The `scope` field in that output must be the file you just wrote.

5. **Start the recorder.** `scripts/traffic start`, then mark each phase with
   `scripts/traffic phase recon|scan|exploit|report`, and run host requests as
   `scripts/traffic exec -- curl ...`.

   This is not optional bookkeeping. `engagements/<dir>/audit.jsonl` logs a
   command's argv and exit code, not its requests, so without the recorder
   there is no record of what was actually sent. It is also what makes the
   coverage gate mean something: with a traffic record, a mapped path counts as
   covered only when a request went to it, and without one the gate falls back
   to looking for the path's name in the report, which a run can satisfy by
   listing the paths it did not test.

5. **Read the history** for this target and stack, if there is any:

   ```bash
   scripts/lessons seen --target <target-host>
   scripts/lessons prior            # after recon fingerprints the stack
   ```

   A class this target previously had rejected does not get re-reported
   without new evidence. With an empty ledger this prints nothing useful and
   the default phase order stands.

6. **Read the scope back** to the user in one line and get a nod before
   starting recon. This is the single human gate of an engagement. A scope
   file passed with `--scope` counts as that confirmation (non-interactive
   runs); after it, the phases run through to the report. Do not start the
   toolbox here: it starts on first real need (see the **toolbox** skill), and
   hand-reading the target needs only the host's `curl`.

## Bug-bounty program import

If the user pastes a program's scope page, extract in-scope and out-of-scope
assets, the rate limit, and any forbidden techniques into `scope.yaml`. When in
doubt, exclude rather than include. Record the program name and URL in `notes`.

## What the scope file actually controls

> **The guards do not run under `--dangerously-skip-permissions`.** Confirmed
> 14 November 2026: that flag disables a plugin's PreToolUse hooks, so with it
> the scope guard, the rate limiting, the exploitation notice and the
> non-destructive denylist are all inert. Everything in the table below holds
> in an interactive session and in any unattended run that does not use the
> flag. It does not hold in the benchmark harness, which uses it on every cell.
> See `docs/research/2026-11-14-known-defects.md`, defect 0.


The scope file is the authorization boundary, and two hooks read it on every
Bash and WebFetch call. Knowing which rule is enforced and which is only
advice matters, because the two failure modes are different:

| Rule | Enforced by | On a violation |
|---|---|---|
| in_scope / out_of_scope / ports | `hooks/scope-guard.py` | **Warns, does not block.** The request has already gone out by the time you read the warning. Treat it as a slip that happened: stop, report it, do not repeat it. `MYTHOS_SCOPE_ENFORCE=ask` or `block` is the only way to prevent the call. |
| rate_limit_rps | `hooks/budget-guard.py` | Single-shot calls are paced by sleeping. A batch tool without its own pacing flag is refused, with the flag to add. |
| non-destructive, no brute force, no DoS | `hooks/budget-guard.py` | Refused outright, in every mode. No scope rule makes these acceptable, and a run already deleted another user's data once. |
| allow_exploit: false | `hooks/budget-guard.py` | Warns once when exploitation tooling runs. Not a block: exploitation is the job. |
| allow_active, allow_publish, allow_claim_resources, allow_secret_verification | nothing | Your judgement. Honor them as written; the relevant knowledge notes state the non-destructive alternative for each. |
| request volume | nothing, by design | There is no ceiling. Spend what the finding needs. |

Beyond that, the file is the reference you must honor in every tool
invocation: target only in-scope hosts, stay under the rate limit, and exploit
only when `allow_exploit` is true.
