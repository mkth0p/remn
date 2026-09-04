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

from django.conf import settings
from django.http import JsonResponse

HEADER_NAME = "HTTP_X_FORENSIC_CLIENT"


class ApiClientHeaderMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith("/api/"):
            if request.method == "OPTIONS":
                return JsonResponse({"error": "preflight not supported"}, status=403)
            value = request.META.get(HEADER_NAME, "")
            if not value:
                return JsonResponse(
                    {"error": "missing X-Forensic-Client header"}, status=403
                )
            token = settings.FORENSIC_AUTH_TOKEN
            if token and not hmac.compare_digest(value, token):
                return JsonResponse(
                    {"error": "invalid access token", "code": "auth"}, status=401
                )
        return self.get_response(request)
