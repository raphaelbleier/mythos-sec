# Security policy

## Reporting a vulnerability in Mythos itself

Use GitHub's private vulnerability reporting:
[report a vulnerability](https://github.com/raphaelbleier/mythos-sec/security/advisories/new).
It is enabled on this repository. The report stays private until a fix is
published. Please do not open a public issue for it.

What is useful in a report: the version or commit, what an attacker can do, and
the smallest way to reproduce it. A patch is welcome but not required.

Expect a first reply within a week. This is a research project maintained by one
person, so there is no formal response-time commitment beyond that.

## What counts as a vulnerability here

Mythos drives security tools against hosts that the operator says are in scope.
Things worth reporting:

- A way to make the scope guard pass a host that the engagement's `scope.yaml`
  does not allow, or to have it miss a request entirely.
- Code execution on the operator's machine through engagement input, for example
  through a crafted HTTP response, a tool's output, or a scope file.
- A secret, cookie or session token from an engagement leaking out of
  `engagements/` into logs, reports or the repository.
- Container escape from the `mythos-toolbox` image.

Things that are documented behaviour, not vulnerabilities:

- The scope guard defaults to warn-only. It reports an out-of-scope request
  after it has already gone out. Set `MYTHOS_SCOPE_ENFORCE=ask` or `block` if a
  single out-of-scope request is unacceptable. `README.md` states this, and the
  measurement behind it is in `docs/poster/`.
- The toolbox ships offensive security tools, and the host agent is allowed to
  run them. That is the purpose of the project.
- `opencode.json` grants the host broad permissions by default. Tighten it for
  your own setup.

## Reporting a vulnerability you found *with* Mythos

Report it to the affected program or vendor, not here. If Mythos produced a
wrong or unverifiable finding, that is a bug in Mythos and belongs in a normal
issue.
