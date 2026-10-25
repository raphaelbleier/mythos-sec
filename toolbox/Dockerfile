# Mythos toolbox: Kali-based image with a broad web red-team tool belt plus the
# Mythos engine. The belt is the union of what CAI, Strix, HexStrike and
# PentestGPT drive, focused on web and API testing.
#
#   build:  docker build -t mythos-toolbox -f toolbox/Dockerfile .   (context = repo root)
#   run:    kept alive by the compose service; exec tools into it per command.
#
# Extra tool layers are best-effort: a package missing from a given Kali
# snapshot is skipped, never fatal. Metasploit is opt-in (large).
FROM kalilinux/kali-rolling

ARG INSTALL_METASPLOIT=false
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    MYTHOS_IN_TOOLBOX=1 \
    GOBIN=/usr/local/bin \
    PATH=/usr/local/bin:/root/go/bin:$PATH

# --- core (must succeed) -----------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap nikto whatweb sqlmap ffuf gobuster wfuzz dirb dirsearch \
        curl wget jq git ca-certificates dnsutils unzip \
        python3 python3-pip python3-venv pipx golang-go seclists wordlists \
    && rm -rf /var/lib/apt/lists/*

# --- recon / scanning: proven-good group (one atomic install) ----------
RUN apt-get update && apt-get install -y --no-install-recommends \
        nuclei subfinder katana dnsx naabu dalfox amass masscan feroxbuster \
    && rm -rf /var/lib/apt/lists/*

# --- extras: per-package so one missing name never kills the rest ------
RUN apt-get update && for p in \
        wafw00f commix dotdotpwn xsser sslscan testssl.sh wpscan \
        hydra john hashcat nbtscan enum4linux hakrawler httpx-toolkit; do \
      apt-get install -y --no-install-recommends "$p" || echo "skip apt:$p"; \
    done && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery httpx binary (kali's package name varies; ensure `httpx`)
RUN set -e; \
    if ! command -v httpx >/dev/null 2>&1; then \
      (command -v httpx-toolkit >/dev/null 2>&1 && ln -sf "$(command -v httpx-toolkit)" /usr/local/bin/httpx) || \
      (GOBIN=/usr/local/bin go install github.com/projectdiscovery/httpx/cmd/httpx@latest) || \
      echo "httpx unavailable"; \
    fi; command -v httpx || true

# --- Go belt (best-effort; small, high-value url/param tools) ----------
RUN for pkg in \
        github.com/tomnomnom/waybackurls@latest \
        github.com/tomnomnom/anew@latest \
        github.com/tomnomnom/qsreplace@latest \
        github.com/tomnomnom/gf@latest \
        github.com/lc/gau/v2/cmd/gau@latest \
        github.com/jaeles-project/gospider@latest \
        github.com/tomnomnom/assetfinder@latest \
        github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest ; do \
      GOBIN=/usr/local/bin go install "$pkg" 2>/dev/null || echo "skip $pkg"; \
    done; rm -rf /root/go/pkg || true

# --- Python belt (best-effort, each independent) -----------------------
RUN for pkg in arjun wafw00f semgrep graphw00f paramspider; do \
      pip3 install --break-system-packages --no-cache-dir "$pkg" || echo "skip pip:$pkg"; \
    done

# --- git-clone tools (jwt_tool) ----------------------------------------
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null && \
    pip3 install --break-system-packages --no-cache-dir termcolor cryptography pycryptodomex requests 2>/dev/null && \
    printf '#!/bin/sh\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool && \
    chmod +x /usr/local/bin/jwt_tool || echo "jwt_tool skipped"

# --- secrets / SCA (best-effort) ---------------------------------------
RUN apt-get update && (apt-get install -y --no-install-recommends trufflehog 2>/dev/null; \
    GOBIN=/usr/local/bin go install github.com/zricethezav/gitleaks/v8@latest 2>/dev/null; \
    true) && rm -rf /var/lib/apt/lists/*

# --- metasploit (opt-in) -----------------------------------------------
RUN if [ "$INSTALL_METASPLOIT" = "true" ]; then \
      apt-get update && apt-get install -y --no-install-recommends metasploit-framework && \
      rm -rf /var/lib/apt/lists/* ; \
    fi

# nuclei templates (best-effort; needs network at build time)
RUN nuclei -update-templates 2>/dev/null || true

# --- headless browser for DOM-XSS / SPA testing (built as root, no sudo) ---
RUN pip3 install --break-system-packages --no-cache-dir playwright \
    && (playwright install --with-deps chromium \
        || (apt-get update && apt-get install -y --no-install-recommends chromium \
            && rm -rf /var/lib/apt/lists/*) \
        || echo "browser install best-effort")

# --- Mythos engine ------------------------------------------------------
WORKDIR /opt/mythos-engine
COPY engine/ /opt/mythos-engine/
RUN pip3 install --break-system-packages --no-cache-dir -e . && mythos --version

ENV MYTHOS_WORDLIST=/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

WORKDIR /work
ENTRYPOINT ["sleep", "infinity"]
