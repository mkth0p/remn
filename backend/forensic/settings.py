"""
Django settings for the forensic backend.

The server is deliberately stateless: no database, no sessions, no auth.
It parses uploaded evidence in memory / temp files, streams results to the
browser (which stores everything in IndexedDB) and proxies Ollama and the
optional reputation providers.
"""
from __future__ import annotations

import os
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


SECRET_KEY = os.environ.get("FORENSIC_SECRET_KEY", "local-forensic-tool-no-sessions")
DEBUG = _env_bool("FORENSIC_DEBUG", False)

# Comma-separated extra hosts for remote/home-server deployments, e.g.
# FORENSIC_ALLOWED_HOSTS=remn.example.com,100.64.0.12
ALLOWED_HOSTS = ["127.0.0.1", "localhost"] + [
    h.strip() for h in os.environ.get("FORENSIC_ALLOWED_HOSTS", "").split(",") if h.strip()
]

# Shared access token for remote deployments. When set, every /api request must
# send it as the X-Forensic-Client header value; when unset (local use), the
# header only needs to be present (cookie-less CSRF protection).
FORENSIC_AUTH_TOKEN = os.environ.get("FORENSIC_AUTH_TOKEN", "").strip()

INSTALLED_APPS = ["api"]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "forensic.middleware.ApiClientHeaderMiddleware",
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
