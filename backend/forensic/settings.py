"""
Django settings for the forensic backend.

The server is deliberately stateless: no database, no sessions, no auth.
It parses uploaded evidence in memory / temp files, streams results to the
browser (which stores everything in IndexedDB) and proxies Ollama and the
optional reputation providers.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent  # backend/
ROOT_DIR = BASE_DIR.parent  # project root

load_dotenv(ROOT_DIR / ".env")


def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, "1" if default else "0").strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# stateless server (no sessions, no signed cookies): a per-process random key when none is configured
SECRET_KEY = os.environ.get("FORENSIC_SECRET_KEY") or secrets.token_urlsafe(48)
DEBUG = _env_bool("FORENSIC_DEBUG", False)

# Comma-separated extra hosts for remote/home-server deployments, e.g.
# FORENSIC_ALLOWED_HOSTS=remn.example.com,100.64.0.12
ALLOWED_HOSTS = ["127.0.0.1", "localhost"] + [h.strip() for h in os.environ.get("FORENSIC_ALLOWED_HOSTS", "").split(",") if h.strip()]

# Shared access token for remote deployments. When set, every /api request must
# send it as the X-Forensic-Client header value; when unset (local use), the
# header only needs to be present (cookie-less CSRF protection).
FORENSIC_AUTH_TOKEN = os.environ.get("FORENSIC_AUTH_TOKEN", "").strip()

# Browser-only ingestion mode, for an instance open to people you do not know: the server parses
# evidence and returns rows, and keeps nothing. The server store, chunked uploads, jobs, reputation
# lookups and the server-side model transports answer 403. See docs/security.md.
FORENSIC_BROWSER_ONLY = _env_bool("FORENSIC_BROWSER_ONLY", False)
# Behind a reverse proxy the peer address is the proxy's; with this on, the client address is the
# first X-Forwarded-For entry. Only set it when a proxy you control is the only way in.
FORENSIC_TRUST_PROXY = _env_bool("FORENSIC_TRUST_PROXY", False)
# Requests a minute per client address on the heavy paths (parsing, correlation, conversion,
# lookups, models, store writes). 0 turns the budget off.
FORENSIC_RATE_LIMIT_PER_MIN = _env_int("FORENSIC_RATE_LIMIT_PER_MIN", 0)

INSTALLED_APPS = ["api"]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "forensic.middleware.ApiClientHeaderMiddleware",
    "forensic.middleware.ModeGuardMiddleware",
    "forensic.middleware.RateLimitMiddleware",
    "forensic.middleware.SecurityHeadersMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django.middleware.common.CommonMiddleware",
]

ROOT_URLCONF = "forensic.urls"
WSGI_APPLICATION = "forensic.wsgi.application"

TEMPLATES: list = []

# No database at all: evidence never touches the server disk beyond the
# request-scoped upload temp file.
DATABASES: dict = {}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True

# ---------------------------------------------------------------------------
# Uploads
# ---------------------------------------------------------------------------
FILE_UPLOAD_TEMP_DIR = Path(os.environ.get("FORENSIC_TMP_DIR", BASE_DIR / "tmp"))
FILE_UPLOAD_TEMP_DIR.mkdir(parents=True, exist_ok=True)
FILE_UPLOAD_MAX_MEMORY_SIZE = 2_621_440  # 2.5 MB, above that Django streams to FILE_UPLOAD_TEMP_DIR
# Our handler creates temp files that can be re-opened by path on Windows (see forensic/uploads.py)
FILE_UPLOAD_HANDLERS = [
    "django.core.files.uploadhandler.MemoryFileUploadHandler",
    "forensic.uploads.ForensicTemporaryFileUploadHandler",
]
DATA_UPLOAD_MAX_MEMORY_SIZE = 64 * 1024 * 1024  # JSON bodies (AI tool results can be large)
DATA_UPLOAD_MAX_NUMBER_FIELDS = 10_000

# Application-level cap checked against Content-Length before parsing (single multipart request).
FORENSIC_MAX_UPLOAD_MB = _env_int("FORENSIC_MAX_UPLOAD_MB", 2048)
# Chunked uploads (large evidence): per-file cap and chunk size.
FORENSIC_MAX_CHUNKED_GB = _env_int("FORENSIC_MAX_CHUNKED_GB", 64)
FORENSIC_CHUNK_MB = _env_int("FORENSIC_CHUNK_MB", 16)

# The staging area holds evidence only while it is being parsed, but an abandoned upload holds
# disk until something removes it. An instance open to strangers keeps that window short.
FORENSIC_UPLOAD_MAX_AGE_S = _env_int("FORENSIC_UPLOAD_MAX_AGE_S", 1800 if FORENSIC_BROWSER_ONLY else 6 * 3600)
# How often the sweeper runs. 0 disables the periodic sweep (it still runs at startup).
FORENSIC_UPLOAD_SWEEP_S = _env_int("FORENSIC_UPLOAD_SWEEP_S", 300)
# How long one ingest request may parse before its stream is ended with what it has. The rate
# limiter shapes arrivals, not concurrent work, and the server cannot reap a request already in
# flight, so without this a handful of slow parses hold every worker thread for as long as they
# like. Off on a private instance; an instance open to strangers gets thirty minutes.
FORENSIC_INGEST_MAX_S = _env_int("FORENSIC_INGEST_MAX_S", 1800 if FORENSIC_BROWSER_ONLY else 0)
# Total bytes the staging area may hold. A new upload is refused above it, after a sweep, so a
# stream of abandoned uploads cannot fill the disk however short the lifetime is.
FORENSIC_TMP_MAX_GB = _env_int("FORENSIC_TMP_MAX_GB", 4)
# Advisory threshold (MB) above which the UI suggests the server store instead of IndexedDB.
FORENSIC_STORE_THRESHOLD_MB = _env_int("FORENSIC_STORE_THRESHOLD_MB", 150)
# Files smaller than this are handled fully in memory by the parsers.
FORENSIC_IN_MEMORY_MB = _env_int("FORENSIC_IN_MEMORY_MB", 256)

# ---------------------------------------------------------------------------
# Frontend (Vite build output)
# ---------------------------------------------------------------------------
FRONTEND_DIST = ROOT_DIR / "frontend" / "dist"

# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "gemma4-hauhaucs:latest")
OLLAMA_NUM_CTX = _env_int("OLLAMA_NUM_CTX", 32768)
OLLAMA_TIMEOUT = _env_int("OLLAMA_TIMEOUT", 600)
# Claude Code connector: the server runs the local "claude" command line as the analyst model
# (evidence excerpts leave the machine for Anthropic). Operators can switch it off.
# Hayabusa, Sigma over EVTX, as an optional detection engine. Found on PATH or at HAYABUSA_PATH,
# with its rules beside the binary or at HAYABUSA_RULES. Every ingested event log is handed to
# it when present; HAYABUSA_ENABLED=0 keeps it out of ingest without uninstalling it.
HAYABUSA_ENABLED = _env_bool("HAYABUSA_ENABLED", True)
HAYABUSA_PATH = os.environ.get("HAYABUSA_PATH", "").strip()
HAYABUSA_RULES = os.environ.get("HAYABUSA_RULES", "").strip()
HAYABUSA_MIN_LEVEL = os.environ.get("HAYABUSA_MIN_LEVEL", "low").strip() or "low"
HAYABUSA_MAX_S = _env_int("HAYABUSA_MAX_S", 300)
# Memory one engine run may reach before it is killed, and how many may run at once. Size the
# product of the two under the container's memory limit with room for the parser itself.
HAYABUSA_MAX_MB = _env_int("HAYABUSA_MAX_MB", 1536)
HAYABUSA_CONCURRENCY = _env_int("HAYABUSA_CONCURRENCY", 1)
# How long an ingest waits for a free slot before carrying on without the engine.
HAYABUSA_WAIT_S = _env_int("HAYABUSA_WAIT_S", 20)
# Replaces the option set wholesale for a release whose flags moved; see services/analysis/hayabusa.py
HAYABUSA_ARGS = os.environ.get("HAYABUSA_ARGS", "").strip()
CLAUDE_CODE_ENABLED = _env_bool("CLAUDE_CODE_ENABLED", True)
CLAUDE_CODE_BIN = os.environ.get("CLAUDE_CODE_BIN", "").strip()
CLAUDE_CODE_TIMEOUT = _env_int("CLAUDE_CODE_TIMEOUT", 600)

# ---------------------------------------------------------------------------
# Reputation providers (all optional, all opt-in from the UI)
# ---------------------------------------------------------------------------
REPUTATION_KEYS = {
    "abusech": os.environ.get("ABUSECH_AUTH_KEY", ""),  # URLhaus + MalwareBazaar
    "virustotal": os.environ.get("VIRUSTOTAL_API_KEY", ""),
    "abuseipdb": os.environ.get("ABUSEIPDB_API_KEY", ""),
    "greynoise": os.environ.get("GREYNOISE_API_KEY", ""),
    "ipinfo": os.environ.get("IPINFO_TOKEN", ""),
    "spamhaus_dqs": os.environ.get("SPAMHAUS_DQS_KEY", ""),
    "safebrowsing": os.environ.get("GOOGLE_SAFEBROWSING_KEY", ""),
}
REPUTATION_TIMEOUT = _env_int("REPUTATION_TIMEOUT", 15)
REPUTATION_CACHE_TTL = _env_int("REPUTATION_CACHE_TTL", 6 * 3600)

# Local data (offline block lists, YARA rules, GeoLite2 database)
DATA_DIR = Path(os.environ.get("FORENSIC_DATA_DIR", BASE_DIR / "data"))
OFFLINE_LISTS_DIR = DATA_DIR / "lists"
YARA_RULES_DIR = DATA_DIR / "yara"
# Server-side case stores (DuckDB, one folder per case) for gigabyte-scale evidence.
CASES_DIR = Path(os.environ.get("FORENSIC_CASES_DIR", DATA_DIR / "cases"))

# Bundled detection rules (YAML)
RULES_DIR = ROOT_DIR / "rules"

# ---------------------------------------------------------------------------
# Logging: never log evidence content, only operational messages.
# ---------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"std": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "std"}},
    "root": {"handlers": ["console"], "level": os.environ.get("FORENSIC_LOG_LEVEL", "INFO")},
    "loggers": {
        "django.request": {"level": "WARNING"},
        "httpx": {"level": "WARNING"},
        "httpcore": {"level": "WARNING"},
    },
}

# Browser hardening for the served app (also applied when the Vite dev server proxies /api)
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "no-referrer"
X_FRAME_OPTIONS = "DENY"
