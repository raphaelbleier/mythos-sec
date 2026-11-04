# syntax=docker/dockerfile:1.7
# Mythos toolbox: Kali-based image with a curated web red-team tool belt. Mythos
# is skill-driven — Claude Code is the agent and runs these tools via the
# scripts/mythos shim; the image ships no engine.
#
#   build:  docker build -t mythos-toolbox -f toolbox/Dockerfile .   (context = repo root)
#   run:    scripts/mythos up  (cap-drop ALL + NET_RAW, no docker.sock)
#
# Stage 1 compiles pinned Go tools (multi-arch for free); stage 2 is Kali with
# apt tools. Extra layers are best-effort: a package missing from a given Kali
# snapshot is skipped, never fatal. Metasploit is opt-in (large).

# Base pinned by digest for reproducibility. Refresh weekly (CI does this on
# rebuild; do it by hand with):
#   docker buildx imagetools inspect kalilinux/kali-rolling | grep Digest
ARG KALI_DIGEST=sha256:7997e0581c4f5c185cfe6773d5cae8fcc7c6b79798726ccaabf843af4bcd2013

# ---------------------------------------------------------------- go builder
FROM golang:1.26-bookworm AS gobuilder
# Versions: see toolbox/tools.txt. Each install is independent, a failure is non-fatal.
RUN for pkg in \
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
      GOBIN=/out go install "$pkg" || echo "skip $pkg"; \
    done; \
    # wcvs: upstream tag 2.0.0 has no "v" prefix (invalid for go), so pin the commit.
    GOBIN=/tmp/wcvs go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@75159ea557772447a7760184e1f08e3cc3395090 \
      && mv /tmp/wcvs/Web-Cache-Vulnerability-Scanner /out/wcvs || echo "skip wcvs"; \
    ls /out

# ------------------------------------------------------------------- runtime
FROM kalilinux/kali-rolling@${KALI_DIGEST}

ARG INSTALL_METASPLOIT=false
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    MYTHOS_IN_TOOLBOX=1 \
    HOME=/home/pentester \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    CHROME_BIN=/usr/bin/chromium \
    PATH=/usr/local/bin:$PATH

# --- core (must succeed) -----------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap nikto whatweb sqlmap gobuster wfuzz dirb dirsearch \
        curl wget jq git ca-certificates dnsutils unzip openssl \
        python3 python3-pip python3-venv seclists wordlists chromium \
    && rm -rf /var/lib/apt/lists/*

# --- extras: per-package so one missing name never kills the rest ------
RUN apt-get update && for p in \
        commix dotdotpwn xsser sslscan testssl.sh wpscan amass masscan feroxbuster \
        hydra john hashcat nbtscan enum4linux default-jre-headless php-cli; do \
      apt-get install -y --no-install-recommends "$p" || echo "skip apt:$p"; \
    done && rm -rf /var/lib/apt/lists/*

# --- metasploit (opt-in) -----------------------------------------------
RUN if [ "$INSTALL_METASPLOIT" = "true" ]; then \
      apt-get update && apt-get install -y --no-install-recommends metasploit-framework && \
      rm -rf /var/lib/apt/lists/* ; \
    fi

# --- pinned Go binaries ------------------------------------------------
COPY --from=gobuilder /out/ /usr/local/bin/

# --- Python belt (best-effort, each independent) -----------------------
RUN for pkg in arjun wafw00f semgrep==1.183.0 graphw00f h2spacex==1.2.2 playwright; do \
      pip3 install --break-system-packages --no-cache-dir "$pkg" || echo "skip pip:$pkg"; \
    done

# --- git-clone / jar tools: jwt_tool, smuggler, phpggc, ysoserial (one layer,
# each independent and non-fatal; clones pinned to a commit, see tools.txt) ----
RUN pin() { d=/opt/$1; git init -q "$d" && git -C "$d" fetch -q --depth 1 "$2" "$3" && git -C "$d" checkout -q FETCH_HEAD && rm -rf "$d/.git"; } ; \
    wrap() { printf '#!/bin/sh\nexec %s "$@"\n' "$2" > "/usr/local/bin/$1" && chmod +x "/usr/local/bin/$1"; } ; \
    { pin jwt_tool https://github.com/ticarpi/jwt_tool 3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b && \
      pip3 install --break-system-packages --no-cache-dir termcolor cryptography pycryptodomex requests && \
      wrap jwt_tool "python3 /opt/jwt_tool/jwt_tool.py"; } || echo "jwt_tool skipped"; \
    { pin smuggler https://github.com/defparam/smuggler 2be871e6151ce85167a277fab21c74c851d8b20b && \
      wrap smuggler.py "python3 /opt/smuggler/smuggler.py"; } || echo "smuggler skipped"; \
    { pin phpggc https://github.com/ambionics/phpggc f8aebde3a1abb88b02042fd12a71b4c61d6cfe2c && \
      wrap phpggc "php /opt/phpggc/phpggc"; } || echo "phpggc skipped"; \
    { mkdir -p /opt/ysoserial && \
      curl -fsSL -o /opt/ysoserial/ysoserial-all.jar https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar && \
      wrap ysoserial "java -jar /opt/ysoserial/ysoserial-all.jar"; } || echo "ysoserial skipped"

# --- non-root user. nmap runs unprivileged (-sT); file caps are useless under
# no-new-privileges. For raw scans: scripts/mythos with `docker exec -u 0` (NET_RAW is granted).
RUN useradd -m -u 1000 -s /bin/bash pentester \
    && mkdir -p /work /repo && chown pentester:pentester /work

# nuclei templates baked at build (best-effort; needs network at build time).
# World-writable home so the shim can run the container as the host uid.
USER pentester
RUN nuclei -update-templates || echo "nuclei templates skipped (fetched on first use)"
USER root
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
