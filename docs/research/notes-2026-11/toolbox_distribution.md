# Packaging and distributing a Kali-based toolbox container for a pentest agent (status Nov 2026)

> **Working notes, not documentation.** This file belongs to the research
> trail behind Mythos. It records what was true when it was written and is not
> kept in sync with the code. For maintained documentation see `README.md`,
> `AGENTS.md` and `docs/architecture.md`.

Method note: ~20 tool calls. Many doc pages did not contain the details asked for (marked in Gaps). Snippets under "Inferences" are my own design recommendations built on the cited facts, not copied from a source, and are untested.

## 1. Image build (base, multi-arch, size, pinning, browser, non-root)

### Takeaway
Use `kalilinux/kali-rolling` (multi-arch incl. arm64, ~50 MB compressed bare) as base, install a curated tool list rather than a `kali-linux-*` metapackage, compile Go tools in a builder stage, and strip docs/locales. Strix's own sandbox Dockerfile is the closest working template (Kali rolling, two-stage, non-root user, apt Chromium).

### Cited Findings
- Official Kali images: `kalilinux/kali-rolling` (main, tracks rolling), `kali-last-release` (no updates until next release), `kali-bleeding-edge`, `kali-experimental`, `kali-dev`; updated weekly; none include the default metapackage, install e.g. `kali-linux-headless` yourself. Bleeding-edge etc. only for "very special cases" — [Kali docs](https://www.kali.org/docs/containers/official-kalilinux-docker-images/)
- `kalilinux/kali-rolling:latest` bare image is published for linux/386, amd64, arm/v7 and arm64; compressed size amd64 50.55 MB, arm64 49.92 MB — [Docker Hub](https://hub.docker.com/r/kalilinux/kali-rolling/tags)
- Strix sandbox Dockerfile: base `kalilinux/kali-rolling:latest`; two-stage (`gobuilder` compiles Go tools, runtime stage copies binaries only); non-root user `pentester` with passwordless sudo, workdir `/workspace`; nmap given raw-socket caps via `setcap`; tools: nmap, naabu, subfinder, httpx, katana, gospider, sqlmap, nuclei, ffuf, wapiti, arjun, dirsearch, wafw00f, interactsh-client, trufflehog (pinned 3.99.2), gitleaks, trivy, semgrep, bandit, retire, jwt_tool, caido-cli 0.56.0 (+ Python SDK venv), gdb, jq, ripgrep; custom `ENTRYPOINT docker-entrypoint.sh`; no EXPOSE — [Strix Dockerfile](https://raw.githubusercontent.com/usestrix/strix/main/containers/Dockerfile)
- Strix size tricks: drop apt lists, `autoremove/autoclean`, purge non-English locales, `rm -rf /usr/share/doc/* /usr/share/man/*`, clean npm cache, symlink duplicate binaries; nuclei templates are updated at build time; generates a CA cert added to system trust store; pins Debian brotli packages because Kali still shipped a vulnerable version — same source
- Strix browser: Chromium from **apt** (not Playwright download), `agent-browser` npm pkg 0.26.0 pointed at it via `AGENT_BROWSER_EXECUTABLE_PATH`, env also written to `/etc/profile.d/agent-browser.sh` — same source
- ProjectDiscovery `pdtm`: `-i <tool>` / `-ia`, default bin dir `$HOME/.pdtm/go/bin`, `-bp` custom path; docs show no version-pinning, no Docker note, no arm64 note ("only on platforms for which binaries have been published") — [pdtm README](https://raw.githubusercontent.com/projectdiscovery/pdtm/main/README.md)
- vxcontrol/kali-linux-image (PentAGI base): multi-stage Dockerfile with targets base/systemd/test/mcp, built via `docker buildx bake`, linux/amd64+arm64, `WITH_BURP=false` skips ~700 MB layer; CI runs Trivy, attaches provenance, publishes SBOMs as workflow artifacts — [repo](https://github.com/vxcontrol/kali-linux-image)

### Inferences
- Sizes: bare Kali ~50 MB compressed; a "200+ tool" Kali image is ~14.6-16 GB (vxcontrol) so a curated image must avoid `kali-linux-large/everything`. A web-pentest-only list (nmap, sqlmap, ffuf, nuclei, httpx, katana, dalfox, etc.) is likely low single-digit GB uncompressed; I found no measured number for Strix's image (gap).
- `kali-last-release` gives weekly-stable but stale tools; `kali-rolling` gives fresh tools but non-reproducible builds. Reproducibility compromise: build on `kali-rolling`, pin Go tools by version (`go install pkg@vX.Y.Z`), pin digest of base in `FROM kalilinux/kali-rolling@sha256:...` and let Dependabot/Renovate bump it weekly; tag images by date.
- Go tools via `go install` in a builder stage (multi-arch for free, version-pinnable) beats pdtm (no pinning documented) and beats apt for fast-moving tools (nuclei, httpx, ffuf). Use apt only for tools with heavy native deps (nmap, sqlmap, hydra, chromium).
- Nuclei templates: bake a snapshot at build time (`nuclei -update-templates` in a RUN) so image is reproducible offline; weekly scheduled rebuild gives freshness; allow runtime `-ut` only if egress to GitHub is permitted. (The nuclei doc page I fetched did not cover update flags — verify.)
- Chromium: apt `chromium` is the proven path in Kali (Strix); Playwright's bundled browser downloads are Ubuntu/Debian-targeted and `playwright install-deps` assumes apt names that may differ on Kali; use `executable_path=/usr/bin/chromium` with `--no-sandbox` when non-root in container (needs `--cap-add SYS_ADMIN` or seccomp profile otherwise). Untested here.
- Non-root: copy Strix pattern (user + setcap on nmap) so `nmap -sS` works without `--privileged`; add `--cap-add NET_RAW --cap-add NET_ADMIN` at run time only if needed.

Skeleton:
```dockerfile
# syntax=docker/dockerfile:1.7
FROM golang:1.24-bookworm AS gobuilder
ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build \
    GOBIN=/out go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.x.y && \
    GOBIN=/out go install github.com/projectdiscovery/httpx/cmd/httpx@v1.x.y && \
    GOBIN=/out go install github.com/ffuf/ffuf/v2@v2.x.y

FROM kalilinux/kali-rolling@sha256:<pinned>
ENV DEBIAN_FRONTEND=noninteractive
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      nmap sqlmap chromium python3-pip jq curl ca-certificates libcap2-bin && \
    setcap cap_net_raw,cap_net_admin+eip "$(readlink -f /usr/bin/nmap)" && \
    rm -rf /var/lib/apt/lists/* /usr/share/doc/* /usr/share/man/*
COPY --from=gobuilder /out/ /usr/local/bin/
RUN nuclei -update-templates -ud /opt/nuclei-templates
RUN useradd -m -u 1000 pentester
USER pentester
WORKDIR /repo
```

### Gaps
- No measured size/build-time for Strix's published sandbox image, Exegol variants (docs page said sizes/arm64 exist but gave no numbers), or a curated web-pentest Kali image.
- Playwright-on-Kali specifics and Kali `chromium` arm64 behavior not sourced.
- Nuclei template update flags and `go install` build times on arm64 under QEMU not sourced.

## 2. Publishing (GHCR, CI, tags, signing, SBOM)

### Takeaway
Build each arch on a native runner (`ubuntu-24.04-arm` for arm64, free for public repos), push by digest, merge with `docker buildx imagetools create`; enable `provenance` + `sbom` in build-push-action; sign by digest with cosign keyless.

### Cited Findings
- Multi-arch pattern: per-arch jobs push by digest, upload digests as artifacts, a merge job assembles a manifest list (`docker buildx imagetools create`); arm64 can use native runner label `ubuntu-24.04-arm` instead of QEMU; free-tier private repos cannot use the public arm64 runners — [sredevopsorg guide](https://sredevopsorg.github.io/multi-arch-docker-github-workflow), [oneuptime guide](https://oneuptime.com/blog/post/2025-12-20-multi-platform-docker-builds-github-actions/view)
- Docker's official alternative: reusable workflow `docker/github-builder/.github/workflows/build.yml@v1` with `platforms: linux/amd64,linux/arm64`, `push: true`, `meta-images`, which "splits the build into one platform per runner" (permissions `contents: read`, `id-token: write`) — [Docker docs](https://docs.docker.com/build/ci/github-actions/multi-platform/)
- build-push-action v4+: provenance on by default (`mode=max` public repos, `min` private); SBOM only with `sbom: true`; attestations require `push: true` (not `load`); default provenance includes build-arg values so use secret mounts — [Docker docs](https://docs.docker.com/build/ci/github-actions/attestations/)
- Per-arch builds sometimes set `provenance: false` so the digest is a plain image, then attest after merging — [cloud-pi-native workflow](https://github.com/cloud-pi-native/console/actions/runs/10124602724/workflow)
- vxcontrol CI: Trivy scan + provenance + SBOM artifacts — [repo](https://github.com/vxcontrol/kali-linux-image)

### Inferences
- Tag scheme: `:vX.Y.Z` (matches agent release), `:X.Y`, `:latest`, `:YYYYMMDD` (weekly rebuild), plus `:sha-<short>`. Agent should pin to the version it was released with, not `latest`.
- Cosign keyless (OIDC, `id-token: write`): `cosign sign --yes ghcr.io/ORG/toolbox@${DIGEST}` after merge; users verify with `cosign verify --certificate-identity-regexp ... --certificate-oidc-issuer https://token.actions.githubusercontent.com`. Not verified against current cosign docs in this session.
- GHCR pull limits: I found no sourced numbers; public GHCR images are widely reported as anonymous-pullable without Docker Hub-style limits, but treat as unverified. Base `kalilinux/*` pulls hit Docker Hub rate limits in CI (anonymous 100/6h per IP) — mitigate via `docker/login-action` with Hub creds (unverified number).
- Workflow sketch:
```yaml
on: { push: { tags: ['v*'] }, schedule: [{ cron: '0 3 * * 1' }], workflow_dispatch: {} }
jobs:
  build:
    strategy: { matrix: { include: [ {p: linux/amd64, r: ubuntu-24.04}, {p: linux/arm64, r: ubuntu-24.04-arm} ] } }
    runs-on: ${{ matrix.r }}
    permissions: { contents: read, packages: write, id-token: write }
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with: { registry: ghcr.io, username: ${{ github.actor }}, password: ${{ secrets.GITHUB_TOKEN }} }
      - id: b
        uses: docker/build-push-action@v6
        with:
          context: toolbox
          platforms: ${{ matrix.p }}
          outputs: type=image,name=ghcr.io/${{ github.repository_owner }}/toolbox,push-by-digest=true,name-canonical=true,push=true
          cache-from: type=gha,scope=${{ matrix.p }}
          cache-to: type=gha,mode=max,scope=${{ matrix.p }}
          provenance: false
      - run: mkdir -p /tmp/d && touch "/tmp/d/${{ steps.b.outputs.digest#sha256: }}"   # then upload-artifact
  merge:
    needs: build
    runs-on: ubuntu-24.04
    permissions: { packages: write, id-token: write }
    steps:
      # download-artifact merge-multiple -> /tmp/d ; docker/metadata-action for tags
      - run: docker buildx imagetools create $(jq -cr '.tags|map("-t "+.)|join(" ")' <<<"$DOCKER_METADATA_OUTPUT_JSON") $(printf 'ghcr.io/ORG/toolbox@sha256:%s ' *)
      - uses: sigstore/cosign-installer@v3
      - run: cosign sign --yes ghcr.io/ORG/toolbox@${DIGEST}
```
  (the `${…#sha256:}` expression is shell-style pseudo-code; do it in a shell step.) Caveat: with `provenance:false` per-arch you lose BuildKit provenance; alternatively use Docker's `github-builder` reusable workflow which handles this.
- CI cache: `type=gha` per-platform scope; separate Go build-cache mounts; weekly cron rebuild refreshes Kali packages and nuclei templates.

### Gaps
- Exact build times, GHCR pull-rate limits, and cosign command syntax not confirmed from primary docs.
- Exegol's registry/signing and Strix's published image tag/registry (Docker Hub vs GHCR) not found.

## 3. Host-container execution model

### Takeaway
Existing projects split: Strix runs a tool server inside the sandbox (caido-cli + Python SDK, custom entrypoint); vxcontrol offers an `:mcp` variant exposing ~15 stdio MCP servers behind an authenticated agentgateway on 8081; Exegol ships an MCP server so the AI never touches the host OS. For a simple agent, a thin `docker exec` shim into one long-lived container is the lowest-complexity option.

### Cited Findings
- vxcontrol `:mcp` image: agentgateway on port 8081, refuses to start without `MCP_GATEWAY_TOKEN`; ~15 stdio MCP servers (nmap, metasploit, nuclei, sqlmap, ffuf, hashcat, tshark, Chromium) — [repo](https://github.com/vxcontrol/kali-linux-image)
- vxcontrol `:test` image (docker client + curl, ~170 MB) exists to verify agents reach a Docker daemon "that refuses host-escape requests", i.e. PentAGI talks to Docker via an API (socket/proxy) and hardens it — same source
- Exegol MCP: "lets an AI client orchestrate containers and run tools inside them without access to the host OS"; Exegol Sentinel records interactive commands on the host for audit (Enterprise) — [Exegol docs](https://docs.exegol.com/)
- Strix's image has a custom entrypoint and no EXPOSE (no published ports) — [Strix Dockerfile](https://raw.githubusercontent.com/usestrix/strix/main/containers/Dockerfile)

### Inferences (design recommendation, uncited)
| Model | Pros | Cons |
|---|---|---|
| `docker run --rm` per command | clean isolation, no state | ~0.3-1 s startup; loses browser/session state; nuclei template cache cold |
| long-lived container + `docker exec` | simple, stdout/stderr/exit code natively, `--user`, `-w`, `timeout` wrapper, concurrency = parallel execs | one shared FS/network state; must handle container lifecycle |
| HTTP/MCP server in container | structured results, streaming, no docker CLI needed on host | more code, auth, port exposure; HexStrike-style servers widen attack surface |
| docker.sock mount | agent-in-container orchestrates | root-equivalent on host; avoid for public tool |
Recommendation: one long-lived container `mythos-toolbox` started by the shim (`docker run -d --name ... --init --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges -v "$ENGAGEMENT":/repo`), commands via `docker exec -i --user 1000 -w /repo/... toolbox timeout --signal=TERM --kill-after=5 $T cmd...`. Shim should be one Python (stdlib) or Go CLI instead of bash+ps1 to avoid Windows quoting: pass argv as list (no shell), convert paths via `pathlib`, set `MSYS_NO_PATHCONV=1` for Git Bash (it mangles `/repo` arguments), and quote Windows bind-mount paths as `C:\path:/repo`. Linux file ownership: `--user $(id -u):$(id -g)` (Docker Desktop on Mac/Win remaps ownership via VM file sharing automatically; WSL2 bind mounts from `/mnt/c` are slow, prefer repo inside WSL filesystem). Docker's own docs note that on Windows/WSL2, file sharing is done by the WSL2 kernel and is invisible from host ([Docker Desktop networking docs](https://docs.docker.com/desktop/features/networking/)).
Concurrency: each `docker exec` is independent; cap parallel execs with a semaphore in the shim and `--pids-limit`/`--memory`/`--cpus` on the container.

### Gaps
- HexStrike architecture not fetched; no sourced timing numbers for exec vs run; Git Bash/PowerShell quirks above are from general knowledge, not a fetched source.

## 4. Networking (lab targets, OOB)

### Takeaway
Use `host.docker.internal` on Desktop and `--add-host=host.docker.internal:host-gateway` on Linux; for compose labs, attach the toolbox to the lab's network; for OOB, a self-hosted interactsh-server needs a domain with NS records, public IP and port 53, so for local labs prefer a custom listener container on the lab network.

### Cited Findings
- Docker Desktop NATs container egress via a virtual adapter (typically 192.168.65.3); `-p` publishes on 0.0.0.0 by default (can be restricted) — [Docker Desktop networking](https://docs.docker.com/desktop/features/networking/)
- `--network host` works on Linux; on Docker Desktop only from 4.34+, opt-in in Settings > Resources > Network, L4 only (TCP/UDP), containers cannot bind host IPs, incompatible with Enhanced Container Isolation — [Docker host driver docs](https://docs.docker.com/engine/network/drivers/host/)
- interactsh-server self-host needs: a domain you control, `ns1`/`ns2` hostnames pointing to server IP and domain NS set to them, a small always-on VPS, inbound all traffic allowed; default ports DNS 53 TCP/UDP, HTTP 80, HTTPS 443, SMTP 25/587/465, LDAP 389 (optional FTP 21, FTPS 990, SMB 445); flags `-domain`, `-ip`, `-listen-ip`, `-token`/`-auth`, `-eviction` (default 30 days), `-skip-acme`, `-http-port`; installed by `go install` — no Docker docs for the server — [interactsh README](https://raw.githubusercontent.com/projectdiscovery/interactsh/main/README.md)
- Client: `interactsh-client -server host -token XXX`; default public servers "can change/rotate/down at any time" — [ProjectDiscovery docs](https://docs.projectdiscovery.io/opensource/interactsh/running)

### Inferences
- Lab on same host: `docker network connect <lab_net> mythos-toolbox` (or compose `networks: { lab: { external: true, name: xbow_default } }`), then target by service name. This avoids host.docker.internal entirely.
- Linux run flag: `--add-host=host.docker.internal:host-gateway`; Docker Desktop provides the name natively (stated widely; the Desktop page I fetched did not cover it — unverified in session).
- Local OOB without DNS: run interactsh-server with `-skip-acme` on lab network and use IP-based callbacks (HTTP only), or a trivial HTTP/DNS catcher container in the compose; public oast servers (oast.pro etc.) require the target to have internet egress, which offline labs lack.
- Admin-bot for stored-XSS proof: add a Playwright/Chromium container (same image, apt chromium) on the lab network that logs in as the victim and visits a URL on demand; expose it as `docker exec toolbox visit-as-admin URL`.

### Gaps
- interactsh-server `-skip-acme`/no-DNS behaviours (what works without NS delegation) not documented in fetched page; XBOW compose network names not researched.

## 5. Safety and budget enforcement in the shim

### Takeaway
Layered: (1) shim-level argv allowlist, scope check and per-tool rate flag injection, (2) all HTTP(S) forced through an in-container proxy that enforces scope and counts requests, (3) iptables egress rules, (4) append-only command log. Tool flags alone cannot give a global request budget.

### Cited Findings
- nuclei: `-rl` global requests/sec (default 150), `-rlm` per minute (mutually exclusive with -rl), `-c` template concurrency (25), `-bs` bulk size (25), `-timeout` 10 s — [ProjectDiscovery docs](https://docs.projectdiscovery.io/opensource/nuclei/mass-scanning-cli#rate-limiting)
- mitmproxy: `--allow-hosts` (regex on `host:port`) makes it ignore (pass through uninspected) all other traffic; in regular proxy mode explicit HTTP requests are never ignored, only CONNECT; in transparent mode matching uses IP and SNI — [mitmproxy docs](https://docs.mitmproxy.org/stable/howto/ignore-domains/). Note: allow/ignore is about interception, not blocking; blocking needs an addon (not found in docs fetched).
- Strix embeds `caido-cli` in the sandbox (proxy for all traffic and recording) — [Strix Dockerfile](https://raw.githubusercontent.com/usestrix/strix/main/containers/Dockerfile)
- Exegol Sentinel (Enterprise) records commands on the host for audit — [Exegol docs](https://docs.exegol.com/)

### Inferences
- Per-tool flags (from general knowledge, verify): ffuf `-rate N`, sqlmap `--delay/--threads`, nmap `--max-rate`, httpx `-rl`, katana `-rl`, nuclei `-rl`. Shim table `tool -> flag` appended if user omitted it; reject tools without a known flag unless proxied.
- Strong option: set `HTTP_PROXY/HTTPS_PROXY` (many tools honor `-proxy`) to a mitmdump addon in the container: `def request(flow): if host not in SCOPE or counter>=BUDGET: flow.kill()`; `counter` persisted to `/repo/.budget.json`. Non-proxy-aware tools (nmap, raw sockets) are covered only by iptables and their own rate flags.
- iptables in container (needs NET_ADMIN, applied by entrypoint then drop cap): `iptables -P OUTPUT DROP; -A OUTPUT -o lo -j ACCEPT; -A OUTPUT -d <target CIDR> -j ACCEPT; -A OUTPUT -d <interactsh IP> -j ACCEPT; -A OUTPUT -p udp --dport 53 -d <resolver> -j ACCEPT`. DNS allowlist is weak against DNS tunneling; hostname-based allowlist needs resolving at start.
- Audit: shim writes JSONL `{ts, argv, cwd, exit, duration, bytes_out, budget_delta}` to `<engagement>/.audit/commands.jsonl` before and after each exec (pre-record guarantees logging of crashing commands).

### Gaps
- No source found for a ready-made scope-enforcing mitmproxy addon; sqlmap/ffuf/nmap flag names not fetched from docs here; interaction of budget counting with HTTP/2 and keep-alive not researched.

## 6. Reuse vs build

### Takeaway
Reuse a Kali base and curate your own thin image for the agent's toolset; adopt Strix's Dockerfile structure; do not depend on Exegol (account/plan model, heavy) or PentAGI's 14-16 GB image for a one-pull UX.

### Cited Findings
- vxcontrol/kali-linux-image: MIT, multi-arch (amd64, arm64), 200+ tools, full image 14.6 GB (README also says ~16 GB), has a lean `test` variant (~170 MB) — [repo](https://github.com/vxcontrol/kali-linux-image); PentAGI default pentest image is `vxcontrol/kali-linux`, customizable via `DOCKER_DEFAULT_IMAGE_FOR_PENTEST`, base entrypoint `/usr/local/bin/container-entrypoint` — [PentAGI guide](https://raw.githubusercontent.com/vxcontrol/pentagi/main/examples/guides/openvas-custom-image.md)
- Exegol: suite of Workstation (Docker-based, wrapper creates containers, resources at `/opt/resources`), Studio, Sentinel, MCP, Dashboard; plans Community/Pro/Team/Enterprise; Dockerfiles for variants (full, ad, light, osint, web) in repo — [Exegol docs](https://docs.exegol.com/), [Exegol-images](https://github.com/ThePorgs/Exegol-images)
- Kali: images do not include any default metapackage; `kali-linux-headless` is the documented install — [Kali docs](https://www.kali.org/docs/containers/official-kalilinux-docker-images/)

### Inferences
- Recommended: own image `FROM kalilinux/kali-rolling`, ~20 curated tools, structure copied from Strix; optionally offer `:full` variant built `FROM vxcontrol/kali-linux` for AD/crypto work. Exegol `web` variant is the closest drop-in alternative but licensing/plan and account requirements for current images are unverified.

### Gaps
- Exegol image sizes, arm64 support and registry: docs page referenced them but gave no details.
- Licensing of Strix Dockerfile reuse (license not checked).
