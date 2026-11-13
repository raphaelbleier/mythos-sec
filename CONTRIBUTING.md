# Contributing

Issues and pull requests are welcome. Mythos is research code for authorized
security testing, so a few rules are not negotiable.

## Before you open a pull request

**Edit the canonical file, not the generated one.** The orchestrator, the
sub-agents and the `/cybersecurity` command live under `.opencode/`. The files
in `agents/` and `commands/`, and `CLAUDE.md`, are generated from them. Change
the source, then run:

```bash
python3 scripts/build-hosts.py
python3 scripts/build-hosts.py --check   # exits 1 if anything still drifts
```

A pull request that hand-edits `agents/*.md` or `commands/*.md` will be asked to
redo the change in `.opencode/`.

**Run the self-test.** It needs Docker and takes a few minutes:

```bash
scripts/mythos up
scripts/selftest.sh
```

The test asserts that the lab app's seeded vulnerabilities are still found, that
the negative controls stay clean, and that the scope guard refuses what it should.
If your change touches a skill, a script or the guard, say in the pull request
whether the self-test passed.

**Keep the diff small.** One change per pull request. No reformatting of code you
did not otherwise touch.

## What belongs here

New bug-class playbooks under `knowledge/`, new capability skills, better tool
invocations and benchmark work all fit. So do corrections to the benchmark
numbers in `README.md`, as long as the run that produced them is reproducible
from the repo.

## What does not

Anything that only helps against targets you are not allowed to test. Mythos is
built for bug-bounty programs in scope, systems you own and lab targets, and
that boundary is the point of the project rather than a disclaimer on top of it.
Concretely, no denial-of-service or brute-force tooling, no detection evasion,
no data exfiltration beyond the minimal proof a finding needs, and nothing that
widens the scope guard's boundary on its own.

## Engagement data

Everything under `engagements/` is git-ignored. Check twice that no scope file,
tool log, screenshot or finding from a real target ends up in a commit. The same
goes for the lab: commit the seeded vulnerability, not the output of a run
against someone else's host.

## Style

Match what is already in the file. Commit messages follow
[Conventional Commits](https://www.conventionalcommits.org/).
