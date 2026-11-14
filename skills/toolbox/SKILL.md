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

Recon: `whatweb`, `httpx`, `wafw00f`, `subfinder`, `katana`, `gau`,
`waybackurls`, `arjun`, `ffuf`, `gobuster`, `feroxbuster`, `gospider`.
Scanning: `nuclei`, `dalfox`, `sqlmap`, `nikto`, `commix`, `wpscan`.
Auth/OOB/misc: `jwt_tool`, `interactsh-client` (OOB collaborator for blind
SQLi/SSRF/RCE/XXE), `qsreplace`, `gf`, `anew`, `curl`, `jq`.
Browser (DOM XSS / SPA): use the `browser` tool, which drives a real Chromium
and reports the console and the request log.

## Discipline

- The host is RAM-limited (~3.7 GB). Do **not** run nuclei + sqlmap + a browser
  simultaneously; scope nuclei by `-tags`, run heavy tools one at a time.
- Honor `scope.yaml`: rate limits (`-rl`/`-rate`/`-t`) and the in-scope host
  list. The scope guard runs inside the tool and warns after the request has
  gone out, so staying in scope is still yours to get right.
- A tool missing from a given Kali snapshot is skipped at build time, never
  fatal — pick an equivalent (`gobuster`↔`ffuf`↔`feroxbuster`, `gau`↔`waybackurls`).
