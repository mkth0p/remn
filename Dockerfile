# REMN in one container: the built frontend served by the Python API (backend/run.py, waitress).
#
#   docker build -t remn .                                                  # core
#   docker build --build-arg EXTRA_PIP="yara-python libpff-python" -t remn .  # full: YARA and PST support
#   docker run --rm -p 8000:8000 -v remn-data:/app/backend/data remn
#
# Python packages are installed in a build stage that has a compiler (libpff builds from source) and
# copied into a runtime image that has neither a compiler nor pip. GeoLite2 and the offline lists are
# data the operator downloads: mount them under /app/backend/data. The Claude Code connector needs the
# claude command line on the host, so it is not available here.

# base images pinned by digest; dependabot proposes the bumps (see .github/dependabot.yml)
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS python-build
ENV PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get -y --no-install-recommends install build-essential && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --upgrade pip
COPY backend/requirements.txt /tmp/requirements.txt
# extra packages go in here, e.g. --build-arg EXTRA_PIP="yara-python libpff-python"
ARG EXTRA_PIP=""
RUN /opt/venv/bin/pip install -r /tmp/requirements.txt \
    && if [ -n "$EXTRA_PIP" ]; then /opt/venv/bin/pip install $EXTRA_PIP; fi \
    && /opt/venv/bin/python -m pip uninstall -y pip

# Hayabusa: Sigma over EVTX as a detection engine, pinned by version and by the release
# archive's SHA-256 so a substituted download fails the build. HAYABUSA=0 builds without it.
FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS hayabusa
ARG TARGETARCH
ARG HAYABUSA=1
ARG HAYABUSA_VERSION=4.0.0
RUN mkdir -p /opt/hayabusa \
    && if [ "$HAYABUSA" = "1" ]; then \
        apt-get update && apt-get -y --no-install-recommends install ca-certificates curl unzip && rm -rf /var/lib/apt/lists/* \
        && case "$TARGETARCH" in \
            amd64) asset=lin-x64-gnu; sum=1137e27c795e83f8837c962f2136cf1634a67a655d7ba8efa8b2d38a33ba09b4 ;; \
            arm64) asset=lin-aarch64-gnu; sum=e41e9ecac3197f59874e47b8d982ec0557e2686d68f172a9d99f4ca7ac3ae594 ;; \
            *) echo "no Hayabusa build for $TARGETARCH" >&2; exit 1 ;; \
        esac \
        && curl -fsSL -o /tmp/hayabusa.zip "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-${asset}.zip" \
        && echo "${sum}  /tmp/hayabusa.zip" | sha256sum -c - \
        && unzip -q /tmp/hayabusa.zip -d /opt/hayabusa \
        && mv "/opt/hayabusa/hayabusa-${HAYABUSA_VERSION}-${asset}" /opt/hayabusa/hayabusa \
        && chmod 0755 /opt/hayabusa/hayabusa && test -d /opt/hayabusa/rules \
        && rm -f /tmp/hayabusa.zip; \
    fi

FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:$PATH"
# Debian's security updates as of the build (the base tag lags them by days); no package manager stays behind
RUN apt-get update && apt-get -y --no-install-recommends upgrade && rm -rf /var/lib/apt/lists/* \
    && python -m pip uninstall -y pip && rm -rf /usr/local/lib/python3.*/ensurepip/_bundled /root/.cache
COPY --from=python-build /opt/venv /opt/venv
COPY --from=hayabusa /opt/hayabusa /opt/hayabusa
ENV HAYABUSA_PATH=/opt/hayabusa/hayabusa
WORKDIR /app
COPY backend/ backend/
COPY rules/ rules/
COPY tools/ tools/
COPY LICENSE THIRD_PARTY_NOTICES.md ./
COPY --from=frontend /src/frontend/dist frontend/dist
# nothing from the build machine's cases, uploads or caches
RUN rm -rf backend/data/cases backend/tmp backend/data/claude-cwd && mkdir -p backend/data/cases backend/tmp \
    && useradd --create-home --uid 1000 remn && chown -R remn:remn /app
USER remn
VOLUME ["/app/backend/data", "/app/backend/tmp"]
EXPOSE 8000
# the container's own name is what browsers reach it by; add yours in FORENSIC_ALLOWED_HOSTS
ENV FORENSIC_ALLOWED_HOSTS=localhost,127.0.0.1 FORENSIC_TMP_DIR=/app/backend/tmp
CMD ["python", "backend/run.py", "--host", "0.0.0.0", "--port", "8000"]
