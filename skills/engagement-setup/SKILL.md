---
name: engagement-setup
description: Write and check the scope file for a Mythos engagement. Use before a run against a new target, when importing a bug-bounty program's rules, and to look up what the scope file actually controls.
---

# Engagement setup

Scope is the authorization boundary, and it is settled before any traffic
reaches the target. `mythos -t <url>` generates the narrowest file it can, that
host and that port and nothing else, in `engagements/<host>[-<port>]-<date>/`.
For a real program that is not enough: write the file by hand and pass it with
`--scope <file>`. Nothing in a run widens it, and no agent may edit it.

Triage never selects this skill: scope is settled by a human before any traffic
reaches the target, and no agent may edit it. It drives no script, and its
entry in `skills/registry.yaml` carries no triggers for that reason.

## Steps

1. **Identify the target** and the authorization: which program or client this
   is, and that testing it is permitted. Without that, there is no engagement.
   This is a decision made before the run, not a question asked during one.

2. **The workspace** is `engagements/<target-host>-<YYYYMMDD>/`. The CLI creates
   it, the driver adds `findings/` and `verdicts/`, and everything about the
   engagement stays inside it (it is git-ignored).

3. **Write `scope.yaml`** in the engagement dir, from this template, edited to
   match the program exactly:

   ```yaml
   target: https://target.example
   in_scope:
     - target.example # only hosts/CIDRs the program lists; *.example.com for wildcards
   out_of_scope: [] # every excluded host the program names
   ports: [80, 443] # the ports the program authorizes
   rules:
     rate_limit_rps: 5
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
   - `ports`: the ports the program authorizes. A request to another port on an
     in-scope host is reported as out of scope. Keep this key at the top level:
     the guard also accepts it under `rules`, the CLI does not.
   - `rules.rate_limit_rps`: the program's rate limit, enforced by
     `hooks/budget-guard.py`. Single-shot calls are paced by sleeping, and a
     batch tool invoked without its own pacing flag is refused with the flag
     to add. There is no request ceiling: a volume cap only ever stops the run
     before the finding. If a program states a request limit, put it in
     `notes` and watch it yourself.
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
     testing of the login form, no social engineering"). They reach every agent
     in the run through the system prompt.

4. **Check the file resolves** before the run. Both guards read `MYTHOS_SCOPE`,
   and the CLI sets it to this run's file for every guard call and every tool,
   so a leftover directory cannot authorize the engagement. Run by hand, the
   guards fall back to the newest `engagements/*/scope.yaml` by modification
   time, so pin it yourself:

   ```bash
   MYTHOS_SCOPE="$PWD/engagements/<dir>/scope.yaml" \
     python3 hooks/scope-guard.py --check 'curl https://example.invalid/'
   ```

   The `scope` field in that output must be the file you just wrote. The same
   export is what `scripts/probe`, `scripts/verify` and `scripts/watch` read
   for the rate limit when you run them outside a run.

5. **Read the history** for this target and stack, if there is any:

   ```bash
   scripts/lessons seen --target <target-host>
   scripts/lessons prior            # after recon fingerprints the stack
   ```

   A class this target previously had rejected does not get re-reported
   without new evidence. With an empty ledger this prints nothing useful and
   the default phase order stands.

The traffic recorder needs nothing from you: the driver starts it before the
first phase and stops it after the last. `engagements/<dir>/audit.jsonl` logs a
command's argv and exit code, not its requests, so the recorder is the only
account of what was actually sent, and `scripts/coverage` uses it to decide
whether a mapped path was reached at all rather than merely named in the report.

## Bug-bounty program import

If the user pastes a program's scope page, extract in-scope and out-of-scope
assets, the rate limit, and any forbidden techniques into `scope.yaml`. When in
doubt, exclude rather than include. Record the program name and URL in `notes`.

## What the scope file actually controls

Both guards are called with `--check '<command>'` from inside every tool that
can reach the target, by `cli/src/agent/guards.ts`. There is no configuration in
which they do not run: a tool reaches the network by going through that module,
and a guard that cannot run refuses the call instead of sending it. They used to
be host plugin hooks, which is how every benchmark cell ran with its scope
guard, rate limiter and destructive denylist inert without saying so.

Knowing which rule is enforced and which is only advice matters, because the two
failure modes are different:

| Rule | Enforced by | On a violation |
|---|---|---|
| in_scope / out_of_scope / ports | `hooks/scope-guard.py` | **Warns, does not block.** The request has already gone out by the time you read the warning. Treat it as a slip that happened: stop, report it, do not repeat it. |
| rate_limit_rps | `hooks/budget-guard.py` | Single-shot calls are paced by sleeping. A batch tool without its own pacing flag is refused, with the flag to add. |
| non-destructive, no brute force, no DoS | `hooks/budget-guard.py` | Refused outright, in every mode. No scope rule makes these acceptable, and a run already deleted another user's data once. `MYTHOS_DESTRUCTIVE=warn` downgrades it for a throwaway lab, nowhere else. |
| allow_exploit: false | `hooks/budget-guard.py` | Warns once when exploitation tooling runs. Not a block: exploitation is the job. |
| allow_active, allow_publish, allow_claim_resources, allow_secret_verification | nothing | Your judgement. Honor them as written; the relevant knowledge notes state the non-destructive alternative for each. |
| request volume | nothing, by design | There is no ceiling. Spend what the finding needs. |

Beyond that, the file is the reference you must honor in every tool
invocation: target only in-scope hosts, stay under the rate limit, and exploit
only when `allow_exploit` is true.
