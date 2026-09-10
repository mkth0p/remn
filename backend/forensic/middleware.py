"""
Minimal CSRF-style protection for a cookie-less local API.

Every request under /api/ must carry the custom header ``X-Forensic-Client``.
A third-party web page cannot add a custom header without a CORS preflight,
and this server never answers preflights, so drive-by requests from other
origins are rejected with 403.

When ``FORENSIC_AUTH_TOKEN`` is set (remote/home-server deployments), the
header value must equal the token; a wrong value gets 401 with code "auth"
so the frontend can prompt for the token.
"""

from __future__ import annotations

import hmac
import re
import threading
import time

from django.conf import settings
from django.http import JsonResponse

HEADER_NAME = "HTTP_X_FORENSIC_CLIENT"


def client_address(request) -> str:
    """The client's address: the first X-Forwarded-For entry when the proxy in front is trusted, else the peer."""
    if settings.FORENSIC_TRUST_PROXY:
        first = request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
        if first:
            return first
    return request.META.get("REMOTE_ADDR", "") or "?"


class ApiClientHeaderMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith("/api/"):
            if request.method == "OPTIONS":
                return JsonResponse({"error": "preflight not supported"}, status=403)
            value = request.META.get(HEADER_NAME, "")
            if not value:
                return JsonResponse({"error": "missing X-Forensic-Client header"}, status=403)
            token = settings.FORENSIC_AUTH_TOKEN
            if token and not hmac.compare_digest(value, token):
                return JsonResponse({"error": "invalid access token", "code": "auth"}, status=401)
        return self.get_response(request)


# What the built index.html declares in its <meta> tag, plus frame-ancestors (header only).
CSP = (
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' http: https:; worker-src 'self' blob:; "
    "frame-src 'self' blob: data: about:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


class SecurityHeadersMiddleware:
    """Hardening headers on every response: no framing, no MIME sniffing, no referrer leaks,
    a Content Security Policy for the app pages, and no cross-origin embedding of API bodies."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        resp = self.get_response(request)
        resp.setdefault("X-Content-Type-Options", "nosniff")
        resp.setdefault("Referrer-Policy", "no-referrer")
        resp.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        resp.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        resp.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        ct = str(resp.get("Content-Type", ""))
        if request.path.startswith("/api/"):
            # API bodies are data: nothing in them may run, embed or be framed
            resp.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
        elif ct.startswith("text/html") or ct.startswith("text/javascript") or ct.startswith("application/javascript"):
            # the app pages, and the scripts: a web worker takes its policy from its own script's response,
            # so the hashing and ingest workers must get the page's policy (wasm, connect-src), not the API one
            resp.setdefault("Content-Security-Policy", CSP)
        return resp


# Paths that keep state on the server, reach out to third parties or run a model on the server's
# account: closed in browser-only mode. Parsing, correlation, rule conversion, rule packs and the
# prompt bundle for the browser-direct model stay open.
# /api/ingest/package is closed here even though it keeps no state: reconciling a collection is
# quadratic in attacker-controlled inputs and each native member spawns a decoder subprocess, so
# it is a costly path served to strangers. Collection packages are an operator workflow.
#
# /api/upload is NOT closed. A browser-store case has to get its evidence to the parser somehow,
# and the alternative is one request carrying the whole file, which proxies refuse well before the
# server's own limit. The chunked path writes the same transient bytes the multipart path already
# writes to the temp directory, bounded by FORENSIC_MAX_UPLOAD_MB in this mode, rate limited on
# init, and swept after 24 hours.
BROWSER_ONLY_CLOSED = (
    "/api/store",
    "/api/jobs",
    "/api/reputation",
    "/api/ingest/package",
    "/api/ai/chat",
    "/api/ai/query",
    "/api/ai/models",
    "/api/ai/claude",
)


class ModeGuardMiddleware:
    """Browser-only mode: the server answers 403 with code "browserOnly" on every stateful or costly path."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if settings.FORENSIC_BROWSER_ONLY and request.path.startswith(BROWSER_ONLY_CLOSED):
            return JsonResponse({"error": "not available on this server: browser-only mode", "code": "browserOnly"}, status=403)
        return self.get_response(request)


# The heavy paths: parsing, correlation, enrichment, conversion, lookups, models, store writes and
# queries that run rules or SQL. Health, meta, rule packs, chunk PUTs and plain store reads are not budgeted.
BUDGETED = re.compile(
    r"^/api/(ingest/|analyze/|chains/|relationships/|enrich/|rules/convert/|reputation/|ai/|upload/init$|store/[^/]+/(ingest|import|export|rules/run|sql|reputation)$)"
)


class RateLimitMiddleware:
    """A token bucket per client address over the heavy paths: FORENSIC_RATE_LIMIT_PER_MIN requests a
    minute, refilled continuously. Over budget gets 429 with a Retry-After. 0 turns it off."""

    _lock = threading.Lock()
    _buckets: dict[str, tuple[float, float]] = {}

    def __init__(self, get_response):
        self.get_response = get_response

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._buckets.clear()

    def __call__(self, request):
        limit = int(settings.FORENSIC_RATE_LIMIT_PER_MIN or 0)
        if limit > 0 and BUDGETED.match(request.path):
            addr = client_address(request)
            now = time.monotonic()
            with self._lock:
                tokens, last = self._buckets.get(addr, (float(limit), now))
                tokens = min(float(limit), tokens + (now - last) * limit / 60.0)
                if tokens < 1.0:
                    self._buckets[addr] = (tokens, now)
                    resp = JsonResponse({"error": "too many requests from this address, try again shortly", "code": "rate"}, status=429)
                    resp["Retry-After"] = str(int((1.0 - tokens) * 60.0 / limit) + 1)
                    return resp
                self._buckets[addr] = (tokens - 1.0, now)
                if len(self._buckets) > 10_000:
                    for k in [k for k, (_, t) in self._buckets.items() if now - t > 600]:
                        del self._buckets[k]
        return self.get_response(request)
