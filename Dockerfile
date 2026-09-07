# REMN in one container: the built frontend served by the Python API (backend/run.py, waitress).
#
#   docker build -t remn .
#   docker run --rm -p 8000:8000 -v remn-data:/app/backend/data remn
#
# Optional pieces (PST support via libpff, YARA) are not in the image; see docs/setup.md.
# The Claude Code connector needs the claude command line on the host, so it is not available here.

FROM node:22-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install -r backend/requirements.txt
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
