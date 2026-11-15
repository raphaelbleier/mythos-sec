# Security policy

## Reporting a vulnerability in Mythos itself

Use GitHub's private vulnerability reporting:
[report a vulnerability](https://github.com/raphaelbleier/mythos-sec/security/advisories/new).
It is enabled on this repository. The report stays private until a fix is
published. Please do not open a public issue for it.

What is useful in a report: the version or commit, what an attacker can do, and
the smallest way to reproduce it. A patch is welcome but not required.

Expect a first reply within a week. This is a research project maintained by
one person, so there is no formal response-time commitment beyond that.

## What counts as a vulnerability here

Mythos is a CLI that drives security tools against hosts the operator declared
in scope. Things worth reporting:

- A way to make the scope guard pass a host that the engagement's `scope.yaml`
  does not allow, or to have it miss a request entirely. The guards are called
  from `cli/src/agent/guards.ts`, which shells out to
  `hooks/scope-guard.py --check` and `hooks/budget-guard.py --check` from
  inside every tool that can reach the target. A code path that reaches the
  network without going through that call is a bug in this class, and so is a
  command shape the guard's parsing does not see.
- A way past the destructive denylist in `hooks/budget-guard.py`: data
  destruction, brute force or denial of service that it does not refuse.
- Code execution on the operator's machine through engagement input, for
  example through a crafted HTTP response, a tool's output, a page the headless
  browser loads, or a scope file.
- A secret, cookie, session token or API key leaking out of `engagements/` or
  out of the operator's credential store into logs, reports, the terminal
  transcript or the repository.
- Container escape from the `mythos-toolbox` image, or a way to make the
  container write outside `engagements/`.

Things that are documented behaviour, not vulnerabilities:

- The scope guard warns and does not refuse. `cli/src/agent/guards.ts` pins it
  to warn, so an out-of-scope request is reported after it has already gone
  out, and the warning reaches the agent together with the tool result. Scope
  is a judgement about authorization that the operator owns, and a run that
  refuses on its own reading of a scope file would be making that judgement
  for them. Run the engagement against a scope file you have checked.
  Set `MYTHOS_SCOPE_ENFORCE=ask` or `block` to have the call refused instead.
  A run is unattended, so `ask` is treated as `block`: nothing can ask you
  mid-run, and refusing is the safe reading of "not without me".
- The pacing guard also warns rather than refusing, and honors
  `rules.rate_limit_rps` by sleeping. There is no request ceiling. Data
  destruction, brute force and denial of service are the exception: those are
  refused, and no scope rule turns that off.
- The toolbox ships offensive security tools and the agent is allowed to run
  them. That is the purpose of the project.
- Mythos sends target data and tool output to whichever model provider the
  operator configured. Pick the provider accordingly.

## How the toolbox is confined

`scripts/mythos up` starts the container with `--cap-drop ALL --cap-add
NET_RAW --security-opt no-new-privileges`, which leaves it the raw sockets a
SYN scan needs and nothing else. The repository is mounted read-only at
`/repo`; only `engagements/` is writable, and `engagements/audit.jsonl` inside
it is mounted read-only so the container cannot rewrite its own audit trail. On
Linux the container runs as the host user's uid and gid, and it gets no access
to the Docker socket. The host, not the container, executes `hooks/`,
`scripts/` and `skills/`.

By default the container is bridged and reaches the host only through
`host.docker.internal`. `MYTHOS_NET=host` puts it in the host's network
namespace instead, which removes that isolation: the container then sees every
service bound to the host's loopback, including ones no engagement authorized.
It exists because a target bound to `127.0.0.1` is not reachable from a bridged
container at all, and it is for a local lab target and nothing else. The CLI
sets it only when the target's host is a loopback address. For a routable
target the bridge is correct and stays.

## Reporting a vulnerability you found *with* Mythos

Report it to the affected program or vendor, not here. If Mythos produced a
wrong or unverifiable finding, that is a bug in Mythos and belongs in a normal
issue.
