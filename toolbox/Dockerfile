# syntax=docker/dockerfile:1.7
# Mythos toolbox: Kali-based image with a curated web red-team tool belt. Mythos
# is skill-driven — Claude Code is the agent and runs these tools via the
# scripts/mythos shim; the image ships no engine.
#
#   build:  docker build -t mythos-toolbox -f toolbox/Dockerfile .   (context = repo root)
#   run:    scripts/mythos up  (cap-drop ALL + NET_RAW, no docker.sock)
#
# Stage 1 compiles pinned Go tools (multi-arch for free); stage 2 is Kali with
# apt tools. Every install must succeed: a failed or yanked install would
# otherwise ship, sign and publish a smaller image. Only the optional apt extras
# are best-effort (and say so loudly). Metasploit is opt-in (large).
#
# Both base images are pinned by digest for reproducibility. Dependabot (docker
# ecosystem, .github/dependabot.yml) proposes new digests as PRs; by hand:
#   docker buildx imagetools inspect <image>:<tag> | grep Digest

# ---------------------------------------------------------------- go builder
FROM golang:1.26-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS gobuilder
# Versions: see toolbox/tools.txt.
RUN set -eu; \
    for pkg in \
        github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1 \
        github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0 \
        github.com/projectdiscovery/katana/cmd/katana@v1.8.0 \
        github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0 \
        github.com/ffuf/ffuf/v2@v2.3.0 \
        github.com/hahwul/dalfox/v2@v2.13.0 \
        github.com/projectdiscovery/interactsh/cmd/interactsh-client@v1.4.1 \
        github.com/lc/gau/v2/cmd/gau@v2.2.4 \
        github.com/tomnomnom/qsreplace@v0.0.3 \
        github.com/tomnomnom/gf@v0.0.0-20200618134122-dcd4c361f9f5 ; do \
      GOBIN=/out go install "$pkg"; \
    done; \
    # wcvs: upstream tag 2.0.0 has no "v" prefix (invalid for go), so pin the commit.
    GOBIN=/tmp/wcvs go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@75159ea557772447a7760184e1f08e3cc3395090 \
      && mv /tmp/wcvs/Web-Cache-Vulnerability-Scanner /out/wcvs; \
    ls /out

# ------------------------------------------------------------------- runtime
FROM kalilinux/kali-rolling:latest@sha256:7997e0581c4f5c185cfe6773d5cae8fcc7c6b79798726ccaabf843af4bcd2013

ARG INSTALL_METASPLOIT=false
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    MYTHOS_IN_TOOLBOX=1 \
    HOME=/home/pentester \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    CHROME_BIN=/usr/bin/chromium \
    PATH=/usr/local/bin:$PATH

# --- core (must succeed) -----------------------------------------------
# default-jre-headless and php-cli are core: the ysoserial and phpggc wrappers
# are useless without them.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap nikto whatweb sqlmap gobuster wfuzz dirb dirsearch \
        curl wget jq git ca-certificates dnsutils unzip openssl \
        python3 python3-pip python3-venv seclists wordlists chromium \
        default-jre-headless php-cli \
    && rm -rf /var/lib/apt/lists/*

# --- optional extras: per-package so a name missing from a Kali snapshot ----
# (testssl.sh is today) does not kill the rest. The only best-effort layer.
RUN apt-get update && for p in \
        commix dotdotpwn xsser sslscan testssl.sh wpscan amass masscan feroxbuster \
        hydra john hashcat nbtscan enum4linux; do \
      apt-get install -y --no-install-recommends "$p" || echo "WARNING: optional apt package $p SKIPPED, not in this Kali snapshot" >&2; \
    done && rm -rf /var/lib/apt/lists/*

# --- metasploit (opt-in) -----------------------------------------------
RUN if [ "$INSTALL_METASPLOIT" = "true" ]; then \
      apt-get update && apt-get install -y --no-install-recommends metasploit-framework && \
      rm -rf /var/lib/apt/lists/* ; \
    fi

# --- pinned Go binaries ------------------------------------------------
COPY --from=gobuilder /out/ /usr/local/bin/

# --- Python belt (hash-pinned, see toolbox/requirements.in) ------------
# --ignore-installed: Kali's apt Python packages ship no RECORD file, so pip
# cannot uninstall them; the /usr/local copies shadow them instead.
COPY toolbox/requirements.txt /tmp/requirements.txt
RUN pip3 install --break-system-packages --no-cache-dir --require-hashes --ignore-installed \
        -r /tmp/requirements.txt

# --- git-clone / jar tools: jwt_tool, smuggler, phpggc, graphw00f, ysoserial.
# Clones pinned to a commit, see tools.txt. graphw00f is cloned, not pip-installed:
# the PyPI name "graphw00f" is an inert placeholder, not the real tool. ----
RUN set -eu; \
    pin() { d=/opt/$1; git init -q "$d" && git -C "$d" fetch -q --depth 1 "$2" "$3" && git -C "$d" checkout -q FETCH_HEAD && rm -rf "$d/.git"; } ; \
    wrap() { printf '#!/bin/sh\nexec %s "$@"\n' "$2" > "/usr/local/bin/$1" && chmod +x "/usr/local/bin/$1"; } ; \
    pin jwt_tool https://github.com/ticarpi/jwt_tool 3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b; \
    wrap jwt_tool "python3 /opt/jwt_tool/jwt_tool.py"; \
    pin smuggler https://github.com/defparam/smuggler 2be871e6151ce85167a277fab21c74c851d8b20b; \
    wrap smuggler.py "python3 /opt/smuggler/smuggler.py"; \
    pin phpggc https://github.com/ambionics/phpggc f8aebde3a1abb88b02042fd12a71b4c61d6cfe2c; \
    wrap phpggc "php /opt/phpggc/phpggc"; \
    pin graphw00f https://github.com/dolevf/graphw00f 1fc956a956eeaeea74fd8038780fd118f4876ae9; \
    wrap graphw00f "python3 /opt/graphw00f/main.py"; \
    mkdir -p /opt/ysoserial; \
    curl -fsSL -o /opt/ysoserial/ysoserial-all.jar https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar; \
    echo "2c9bddd6a1a4ec66c1078ea97dacb61eb66d1c41aec7b6d21e3c72214ce170f1  /opt/ysoserial/ysoserial-all.jar" | sha256sum -c -; \
    wrap ysoserial "java -jar /opt/ysoserial/ysoserial-all.jar"

# --- non-root user. nmap runs unprivileged (-sT); file caps are useless under
# no-new-privileges. For raw scans: scripts/mythos with `docker exec -u 0` (NET_RAW is granted).
RUN useradd -m -u 1000 -s /bin/bash pentester \
    && mkdir -p /work /repo && chown pentester:pentester /work

# nuclei templates baked at a release tag, not whatever upstream main holds at
# build time. Cloned as root: /home/pentester predates useradd (pip's cache lives
# there), so it is root-owned. World-writable home so the shim can run the
# container as the host uid.
RUN git clone -q --depth 1 --branch v10.5.2 https://github.com/projectdiscovery/nuclei-templates /home/pentester/nuclei-templates \
    && rm -rf /home/pentester/nuclei-templates/.git
RUN chmod -R a+rwX /home/pentester \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /usr/share/doc/* /usr/share/man/* /root/.cache /tmp/* \
    && find /usr/share/locale -mindepth 1 -maxdepth 1 ! -name 'en*' ! -name locale.alias -exec rm -rf {} +

# Chromium as non-root in a container: launch with --no-sandbox (Playwright:
# executable_path="/usr/bin/chromium", args=["--no-sandbox"]).
ENV MYTHOS_WORDLIST=/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

USER pentester
WORKDIR /work
ENTRYPOINT ["sleep", "infinity"]
