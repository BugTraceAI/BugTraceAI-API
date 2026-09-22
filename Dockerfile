# BugTraceAI-API Dockerfile
# Fully automated API testing platform

FROM debian:bookworm-slim

LABEL maintainer="BugTraceAI Team"
LABEL description="Fully automated API security testing platform (Kiterunner, x8, Schemathesis, OFFAT, vulnapi)"
ARG APP_VERSION=1.4.4-beta
LABEL version="${APP_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# ── System deps ────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    wget \
    ca-certificates \
    unzip \
    p7zip-full \
    git \
    && rm -rf /var/lib/apt/lists/*

# ── Kiterunner binary ──────────────────────────────────────────────────────
ARG KR_VERSION=1.0.2
RUN wget -q \
    "https://github.com/assetnote/kiterunner/releases/download/v${KR_VERSION}/kiterunner_${KR_VERSION}_linux_amd64.tar.gz" \
    -O /tmp/kr.tar.gz \
    && tar -xzf /tmp/kr.tar.gz -C /tmp \
    && mv /tmp/kr /usr/local/bin/kr \
    && chmod +x /usr/local/bin/kr \
    && rm /tmp/kr.tar.gz


# ── x8 binary ──────────────────────────────────────────────────────────────
ARG X8_VERSION=4.3.0
RUN wget -q \
    "https://github.com/Sh1Yo/x8/releases/download/v${X8_VERSION}/x86_64-linux-x8.gz" \
    -O /tmp/x8.gz \
    && gunzip /tmp/x8.gz \
    && install -m755 /tmp/x8 /usr/local/bin/x8 \
    && rm -f /tmp/x8 \
    || echo "[WARN] x8 binary download/extract failed, tool will be unavailable"

# ── vulnapi binary ─────────────────────────────────────────────────────────
ARG VULNAPI_VERSION=0.8.10
RUN set +e; \
    wget -q \
      "https://github.com/cerberauth/vulnapi/releases/download/v${VULNAPI_VERSION}/vulnapi_Linux_x86_64.tar.gz" \
      -O /tmp/vulnapi.tar.gz \
    && tar -xzf /tmp/vulnapi.tar.gz -C /tmp \
    && install -m755 /tmp/vulnapi /usr/local/bin/vulnapi \
    && rm -f /tmp/vulnapi.tar.gz; \
    true

# ── Wordlists ──────────────────────────────────────────────────────────────
RUN mkdir -p /opt/kiterunner/wordlists /opt/wordlists /opt/params

# routes-small.kite (non-fatal: CDN may be unavailable)
RUN wget -q --timeout=30 \
    "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz" \
    -O /tmp/routes-small.tar.gz \
    && tar -xzf /tmp/routes-small.tar.gz -C /opt/kiterunner/wordlists \
    && rm /tmp/routes-small.tar.gz \
    || echo "[WARN] routes-small.kite download failed, kiterunner will use text wordlists"

# SecLists API wordlists — comprehensive API endpoint discovery
RUN wget -q --timeout=30 "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt" -O /opt/wordlists/api-endpoints-seclists.txt \
    || touch /opt/wordlists/api-endpoints-seclists.txt
RUN wget -q --timeout=30 "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/actions.txt" -O /opt/wordlists/actions.txt \
    || touch /opt/wordlists/actions.txt
RUN wget -q --timeout=30 "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-seen-in-wild.txt" -O /opt/wordlists/api-seen-in-wild.txt \
    || touch /opt/wordlists/api-seen-in-wild.txt
RUN wget -q --timeout=30 "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/objects.txt" -O /opt/wordlists/api-objects.txt \
    || touch /opt/wordlists/api-objects.txt
RUN wget -q --timeout=30 "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" -O /opt/wordlists/raft-medium-directories.txt \
    || touch /opt/wordlists/raft-medium-directories.txt
RUN wget -q --timeout=30 "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/swagger.txt" -O /opt/wordlists/swagger.txt \
    || touch /opt/wordlists/swagger.txt

# FuzzDB API paths — alternative to Assetnote
RUN wget -q --timeout=30 "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-small-directories.txt" -O /opt/wordlists/fuzzdb-dirs.txt \
    || touch /opt/wordlists/fuzzdb-dirs.txt

# Assetnote API-specific wordlists (text, not .kite format)
RUN wget -q --timeout=30 "https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2024_11_28.txt" -O /opt/wordlists/assetnote-apiroutes.txt \
    || echo "[WARN] Assetnote API routes unavailable" && touch /opt/wordlists/assetnote-apiroutes.txt

# Merge all API wordlists into one unified file for kiterunner brute mode
RUN cat /opt/wordlists/api-endpoints-seclists.txt \
        /opt/wordlists/api-seen-in-wild.txt \
        /opt/wordlists/api-objects.txt \
        /opt/wordlists/actions.txt \
        /opt/wordlists/swagger.txt \
        /opt/wordlists/assetnote-apiroutes.txt \
    2>/dev/null | sort -u > /opt/wordlists/api-endpoints.txt \
    || touch /opt/wordlists/api-endpoints.txt

# x8 parameters
RUN wget -q --timeout=30 "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt" -O /opt/params/burp-parameter-names.txt \
    || wget -q --timeout=30 "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -O /opt/params/burp-parameter-names.txt \
    || touch /opt/params/burp-parameter-names.txt
RUN wget -q --timeout=30 "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-seen-in-wild.txt" -O /opt/params/api-seen-in-wild.txt \
    || touch /opt/params/api-seen-in-wild.txt

# ── Python Environment ─────────────────────────────────────────────────────
RUN python3 -m venv /opt/api-venv
ENV PATH="/opt/api-venv/bin:$PATH"

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ── Application ────────────────────────────────────────────────────────────
WORKDIR /opt/bugtrace-api
COPY . .

# ── Environment ────────────────────────────────────────────────────────────
ENV KR_BIN=/usr/local/bin/kr
ENV X8_BIN=/usr/local/bin/x8
ENV VULNAPI_BIN=/usr/local/bin/vulnapi
ENV WORDLISTS_DIR=/opt/kiterunner/wordlists
ENV TEXT_WORDLISTS_DIR=/opt/wordlists
ENV PARAMS_DIR=/opt/params
# ── Entrypoint ────────────────────────────────────────────────────────────
RUN chmod +x /opt/bugtrace-api/entrypoint.sh
ENTRYPOINT ["/opt/bugtrace-api/entrypoint.sh"]
CMD ["mcp", "--sse"]
