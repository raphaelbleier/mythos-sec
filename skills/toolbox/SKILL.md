---
name: toolbox
description: How to run real security tools inside the Mythos Kali toolbox container from Claude Code. Use whenever an engagement needs nuclei, sqlmap, dalfox, ffuf, katana, subfinder, httpx, nikto, commix, interactsh-client, jwt_tool or any other Kali tool — the recon/web-scan/exploit skills all drive tools through this.
---

# Toolbox — run real tools in Docker

Mythos is skill-driven: **you (Claude Code) are the agent**, and you run real
security tools inside the `mythos-toolbox` Kali container through the
`scripts/mythos` shim. No Python engine, no second LLM.

## Commands

```
scripts/mythos up                  # build image on first run, start the container
scripts/mythos tools               # list the key tools + versions (sanity check)
scripts/mythos run <tool> [args]   # run one tool in the toolbox
scripts/mythos <tool> [args]       # shorthand for `run`
scripts/mythos sh '<shell cmd>'    # run a shell pipeline in the toolbox
scripts/mythos down                # stop + remove the container
```

The repo is mounted at `/repo` (the container's working dir), so anything a tool
writes under `engagements/` appears on the host.

## Start it lazily

`scripts/probe` is not a toolbox tool: it is stdlib Python on the host, so it
costs one process, not a container round trip. Use it before anything here.

Do **not** start the container at the beginning of an engagement. Plain HTTP
requests — fetching pages, reading headers, probing a parameter — run on the
host's own `curl`. Run `scripts/mythos up` the first time you actually need a
tool that only exists in the container (nuclei, sqlmap, dalfox, katana, ffuf,
subfinder, jwt_tool, ...).

Every `scripts/mythos <tool>` call pays a `docker exec` round trip on top of
the tool's own runtime. On a small target that latency can outweigh the whole
check: prefer a host `curl` where one answers the question.

## Reaching the target

- **Public / in-scope host:** use its real hostname/URL.
- **Local lab on the host** (e.g. the bundled `lab/` apps on `localhost:3000`):
  from inside the container use `http://host.docker.internal:3000`. The shim
  adds the `host.docker.internal` mapping automatically.

## Tool belt (web / API focus)

Recon: `whatweb`, `httpx`, `wafw00f`, `subfinder`, `katana`, `gau`,
`waybackurls`, `arjun`, `ffuf`, `gobuster`, `feroxbuster`, `gospider`.
Scanning: `nuclei`, `dalfox`, `sqlmap`, `nikto`, `commix`, `wpscan`.
Auth/OOB/misc: `jwt_tool`, `interactsh-client` (OOB collaborator for blind
SQLi/SSRF/RCE/XXE), `qsreplace`, `gf`, `anew`, `curl`, `jq`.
Browser (DOM XSS / SPA): Playwright + Chromium — prefer the **mythos-browser**
agent / the Playwright MCP for DOM work.

## Discipline

- The WSL host is RAM-limited (~3.7 GB). Do **not** run nuclei + sqlmap + a
  browser simultaneously; scope nuclei by `-tags`, run heavy tools one at a time.
- Honor `scope.yaml`: rate limits (`-rl`/`-rate`/`-t`), request budget, and the
  in-scope host list. The scope-guard hook warns on out-of-scope hosts; you must
  still not target them.
- A tool missing from a given Kali snapshot is skipped at build time, never
  fatal — pick an equivalent (`gobuster`↔`ffuf`↔`feroxbuster`, `gau`↔`waybackurls`).

```

```
