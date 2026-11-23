# syntax=docker/dockerfile:1.7
# Mythos toolbox: Kali-based image with a curated web red-team tool belt. The
# agent (cli/) runs these tools through the scripts/mythos shim; the image ships
# no agent and no model of its own.
#
#   build:  docker build -t mythos-toolbox -f toolbox/Dockerfile .   (context = repo root)
#   run:    scripts/mythos up  (cap-drop ALL + NET_RAW, no docker.sock)
#
# Stage 1 compiles pinned Go tools (multi-arch for free); stage 2 is Kali with
# apt tools. Every install must succeed: a failed or yanked install would
# otherwise ship, sign and publish a smaller image. Only the optional apt extras
# are best-effort (and say so loudly).
#
# INSTALL_METASPLOIT is a no-op in practice: `commix`, in the best-effort list,
# Depends on metasploit-framework, so msfconsole (654 MB) is in every image
# whatever the ARG says. Verified 2026-11-15 against the built image. Nothing in
# the repo invokes it and nothing may -- an exploitation framework that fires
# payloads at a host is off the allowlist (docs/toolbox-inventory.md).
#
# Both base images are pinned by digest for reproducibility. Dependabot (docker
# ecosystem, .github/dependabot.yml) proposes new digests as PRs; by hand:
#   docker buildx imagetools inspect <image>:<tag> | grep Digest

# ---------------------------------------------------------------- go builder
FROM golang:1.27-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS gobuilder
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
        github.com/tomnomnom/gf@v0.0.0-20200618134122-dcd4c361f9f5 \
        github.com/fullstorydev/grpcurl/cmd/grpcurl@v1.9.4 \
        github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@v1.4.1 \
        github.com/zricethezav/gitleaks/v8@v8.30.1 ; do \
      GOBIN=/out go install "$pkg"; \
    done; \
    # wcvs: upstream tag 2.0.0 has no "v" prefix (invalid for go), so pin the commit.
    GOBIN=/tmp/wcvs go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@75159ea557772447a7760184e1f08e3cc3395090 \
      && mv /tmp/wcvs/Web-Cache-Vulnerability-Scanner /out/wcvs; \
    ls /out

# ------------------------------------------------------------------- runtime
FROM kalilinux/kali-rolling:latest@sha256:7997e0581c4f5c185cfe6773d5cae8fcc7c6b79798726ccaabf843af4bcd2013

ARG INSTALL_METASPLOIT=false

# ysoserial builds its gadget chains by reflecting into java.base internals,
# which the module system has closed since JDK 16. On this image's JRE a plain
# `java -jar ysoserial-all.jar URLDNS ...` fails with
# InaccessibleObjectException and prints nothing usable -- so the tool was in
# the image, on PATH, named by skills/deep-server, and could not generate the
# one chain that is safe to send (URLDNS, a DNS lookup, no code execution).
# These are the --add-opens ysoserial's own README requires; the wrapper in
# /usr/local/bin/ysoserial passes them and the build asserts URLDNS works.
ENV YSO_OPENS="--add-opens=java.base/java.util=ALL-UNNAMED \
--add-opens=java.base/java.util.concurrent=ALL-UNNAMED \
--add-opens=java.base/java.lang=ALL-UNNAMED \
--add-opens=java.base/java.lang.reflect=ALL-UNNAMED \
--add-opens=java.base/java.net=ALL-UNNAMED \
--add-opens=java.base/java.io=ALL-UNNAMED \
--add-opens=java.base/java.security=ALL-UNNAMED \
--add-opens=java.base/java.text=ALL-UNNAMED \
--add-opens=java.base/javax.net.ssl=ALL-UNNAMED \
--add-opens=java.base/sun.security.x509=ALL-UNNAMED \
--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED"
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
# does not kill the rest. The only best-effort layer. As of 2026-11-15 every
# name below installs; testssl.sh does too (its binary is `testssl`), so the old
# "testssl.sh is today missing" note here was stale.
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
    pin graphql-cop https://github.com/dolevf/graphql-cop 17560b0827373797ffd7ada19be7d447b7d67662; \
    wrap graphql-cop "python3 /opt/graphql-cop/graphql-cop.py"; \
    mkdir -p /opt/ysoserial; \
    curl -fsSL -o /opt/ysoserial/ysoserial-all.jar https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar; \
    echo "2c9bddd6a1a4ec66c1078ea97dacb61eb66d1c41aec7b6d21e3c72214ce170f1  /opt/ysoserial/ysoserial-all.jar" | sha256sum -c -; \
    wrap ysoserial "java $YSO_OPENS -jar /opt/ysoserial/ysoserial-all.jar"

# --- non-root user. nmap runs unprivileged (-sT); file caps are useless under
# no-new-privileges. For raw scans: scripts/mythos with `docker exec -u 0` (NET_RAW is granted).
RUN useradd -m -u 1000 -s /bin/bash pentester \
    && mkdir -p /work /repo && chown pentester:pentester /work

# --- jwt_tool: two things it cannot do for itself in this image -------------
# 1. On first run it writes ~/.jwt_tool/jwtconf.ini, and it stores its inline
#    comments as configparser keys (allow_no_value=True). Those comment strings
#    contain ":", and Python 3.14's configparser.write() now refuses a key that
#    contains a delimiter, so jwt_tool died with InvalidWriteError on EVERY
#    first invocation -- which is every fresh container. Five skills and
#    cli/src/agent/tools.ts name this tool. Building the parser with "=" as the
#    only delimiter makes the keys valid again; the file it writes is still
#    readable by the default reader.
# 2. createConfig() ends in exit(1), so even once it succeeds the first real
#    call fails. And a `--help` run never reaches it (argparse exits first), so
#    the config has to be primed with a real token. Done here, at build time, so
#    the first call an engagement makes is the one that works.
#    Before this, the partial file configparser left behind was missing its
#    [argvals] section, so the SECOND call died with KeyError('argvals') too.
# 3. Its generated default is proxy = 127.0.0.1:8080, an explicit proxy that
#    overrides the recording proxy scripts/mythos injects and points at nothing.
#    Set to False, jwt_tool falls back to the HTTP(S)_PROXY variables, which is
#    exactly where Mythos wants its traffic to go.
RUN set -eu; \
    sed -i "s/configparser.ConfigParser(allow_no_value=True)/configparser.ConfigParser(allow_no_value=True, delimiters=('=',))/" \
        /opt/jwt_tool/jwt_tool.py; \
    export HOME=/home/pentester; \
    rm -rf /home/pentester/.jwt_tool; \
    python3 /opt/jwt_tool/jwt_tool.py eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0. \
        >/dev/null 2>&1 || true; \
    test -f /home/pentester/.jwt_tool/jwtconf.ini \
      || { echo "FATAL: jwt_tool did not write its config" >&2; exit 1; }; \
    sed -i 's|^proxy = 127.0.0.1:8080$|proxy = False|' /home/pentester/.jwt_tool/jwtconf.ini; \
    grep -q '^proxy = False$' /home/pentester/.jwt_tool/jwtconf.ini; \
    python3 /opt/jwt_tool/jwt_tool.py eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0. \
        | grep -q 'alg' \
      || { echo "FATAL: jwt_tool still cannot decode a token" >&2; exit 1; }

# --- ysoserial must actually produce a payload, not an InaccessibleObjectException
RUN ysoserial URLDNS 'http://build-check.invalid/' | wc -c | grep -qvw 0 \
      || { echo "FATAL: ysoserial cannot generate URLDNS; check YSO_OPENS" >&2; exit 1; }

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
