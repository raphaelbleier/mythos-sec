---
name: toolbox
description: How to run real security tools inside the Mythos Kali toolbox container. Use whenever an engagement needs nuclei, sqlmap, dalfox, ffuf, katana, subfinder, httpx, nikto, commix, interactsh-client, jwt_tool or any other Kali tool — the recon/web-scan/exploit skills all drive tools through this.
---

# Toolbox — run real tools in Docker

Security tools run inside the `mythos-toolbox` Kali container. The `shell` tool
is a shell pipeline in that container, and the `request` tool is a single curl
in it, so everything below is what those two tools execute. The driver runs
`scripts/mythos up` before the first phase, so the container is already started
when you get your first turn.

Triage never selects this skill; every phase that runs a tool reads it on
demand. It drives no script of its own: `scripts/mythos` is what the `shell`
tool wraps. Its entry in `skills/registry.yaml` carries no triggers for that
reason.

## Commands

```
scripts/mythos up                  pull or build the image, start the container
scripts/mythos tools               list the key tools + versions (sanity check)
scripts/mythos run <tool> [args]   run one tool in the toolbox
scripts/mythos <tool> [args]       shorthand for `run`
scripts/mythos sh '<shell cmd>'    run a shell pipeline in the toolbox
scripts/mythos down                stop + remove the container
```

The repo is mounted read-only at `/repo` (the container's working dir) and the
engagement directory is writable, so anything a tool writes under
`engagements/` appears on the host.

**Reading the command lines in these skills.** They write tool invocations as
`scripts/mythos <tool> ...`, which is the operator's form on the host. Inside
the `shell` tool you are already in the container: drop that prefix and send
`<tool> ...`, or the pipeline itself. `scripts/mythos` itself does not work from
inside the container at all. A line that calls another `scripts/<name>` is the
`script` tool, which runs it on the host; inside a `shell` pipeline the same
script is `python3 /repo/scripts/<name>`.

## Everything in here is recorded

The driver starts the recording proxy before the first phase and
`scripts/mythos` injects the proxy variables into every exec, so a plain `curl`
in the container is recorded and replayable. Do not start a proxy of your own,
and do not wrap commands in `scripts/traffic exec`: that form is for a command
run on the host, not in the toolbox. `scripts/traffic summary` prints what was
captured, including the tools whose traffic it never saw (see the **traffic**
skill).

## Cost

Every `scripts/mythos <tool>` call pays a `docker exec` round trip on top of
the tool's own runtime. On a small target that latency can outweigh the whole
check, so prefer one aimed `request` or a `script` call where that answers the
question. `probe` and `verify` run on the host through the `script` tool and
cost one process, not a container round trip: use them before reaching for a
scanner.

## Reaching the target

- **Public / in-scope host:** use its real hostname or URL. The container is
  bridged and the host itself is reachable as `host.docker.internal`.
- **A target bound to the host's loopback** (the bundled `lab/` apps, anything
  on `127.0.0.1:PORT`): the CLI sets `MYTHOS_NET=host` for a loopback target,
  which puts the container in the host's own network namespace. The target then
  keeps its `127.0.0.1:PORT` address inside the container, and
  `host.docker.internal` does not exist there. A bridged container cannot reach
  the host's loopback at any address, which is why this exists.
- `MYTHOS_NET=<docker network name>` keeps the bridge and also attaches the
  toolbox to that network, for a lab that runs in Docker itself.

The system prompt states the target's address inside the container. Use it
rather than working it out again.

## Tool belt (web / API focus)

Verified against the built image, not from memory: `toolbox/tools.txt` is the
list, `docs/toolbox-inventory.md` says which of them anything actually calls,
and `scripts/mythos tools` prints what the running container really has.

Recon: `whatweb`, `httpx`, `wafw00f`, `subfinder`, `katana`, `gau`, `arjun`,
`ffuf`, `gobuster`, `feroxbuster`, `dirsearch`, `wfuzz`.
Scanning: `nuclei`, `dalfox`, `sqlmap`, `nikto`, `commix`, `wpscan`, `wcvs`,
`crlfuzz`.
Auth/OOB/misc: `jwt_tool`, `interactsh-client` (OOB collaborator for blind
SQLi/SSRF/RCE/XXE), `qsreplace`, `curl`, `jq`, `gitleaks` (offline, over
a tree you already have), `ysoserial` and `phpggc` (offline gadget chains).
`gf` is on PATH but ships no patterns, so it prints nothing.
Browser (DOM XSS / SPA): use the `browser` tool, which drives a real Chromium
and reports the console and the request log.

**Not in the image**, whatever a playbook elsewhere says: `waybackurls`
(use `gau`), `gospider` (use `katana`), `anew` (use `sort -u -o f f`),
`unfurl`, `semgrep`, `trufflehog`, `kiterunner`, `clairvoyance`, `InQL`.

## Seven tools are wired, not just present: `scripts/tools`

A binary on PATH is reachable; it is not paced, capped, scope-checked or
parsed. `scripts/tools` is the wrapper that does those four things, and where
one of its subcommands covers what you want, prefer it over the bare tool:

```
scripts/tools fuzz    <URL with FUZZ>   ffuf, capped by -n, -rate from scope
scripts/tools params  <URL>             arjun, capped by -n, --rate-limit from scope
scripts/tools crlf    <URL>             crlfuzz, CRLF / header injection
scripts/tools jwt     <TOKEN>           jwt_tool, offline unless --target
scripts/tools secrets <PATH>            gitleaks over a tree, sends nothing
scripts/tools gadget  {list|java|php}   ysoserial / phpggc, sends nothing
scripts/tools hosts   <DOMAIN>          subfinder, every name marked out of scope
```

`--json` on all of them. Exit 0 nothing, 1 at least one candidate, 2 usage,
3 refused (out of scope, or destructive), 4 the tool is not in the image. No
verdict it writes is ever `confirmed`: a tool's own "VULNERABLE" line is one
response's worth of evidence.

## Discipline

- The host is RAM-limited (~3.7 GB). Do **not** run nuclei + sqlmap + a browser
  simultaneously; scope nuclei by `-tags`, run heavy tools one at a time.
- Honor `scope.yaml`: rate limits (`-rl`/`-rate`/`-t`) and the in-scope host
  list. The scope guard runs inside the tool and warns after the request has
  gone out, so staying in scope is still yours to get right.
- A tool missing from a given Kali snapshot is skipped at build time, never
  fatal — pick an equivalent (`gobuster`↔`ffuf`↔`feroxbuster`, `gau`↔`katana`).
- **stdin is always a pipe.** Every exec is `docker exec -i`, so a tool that
  takes a target on the command line *and* accepts a list on stdin may read the
  empty pipe and ignore your `-u`. That is exactly what `crlfuzz -u <URL>` did:
  it sent nothing and exited 0. Redirect `< /dev/null` for such a tool;
  `scripts/tools` already does.
- `hydra`, `john`, `hashcat`, `masscan` and `msfconsole` are in the image (the
  last pulled in as a `commix` dependency) and **none of them may be run**:
  `hooks/scope-guard.py` refuses brute force, mass scanning and denial of
  service in every mode, and no scope rule overrides that. Their presence is an
  artefact of Kali packaging, not an allowlist.
