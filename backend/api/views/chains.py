"""Cross-source attack chains from posted rows. A case's chains are built with its stories
(api/views/stories.py), from the rows the story build selects; this endpoint reads no case store."""

from __future__ import annotations

import json
import logging

from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_POST

from api.errors import failure
from forensic.access import permission
from services.analysis import chains as C

log = logging.getLogger(__name__)

_OPT_KEYS = ("seed_min_risk", "window_hours", "before_minutes", "collapse_minutes", "min_score", "max_chains")


def _opts(body: dict) -> dict:
    out = {}
    for k in _OPT_KEYS:
        v = body.get(k)
        if v is None:
            camel = "".join(p.capitalize() if i else p for i, p in enumerate(k.split("_")))
            v = body.get(camel)
        if v is not None:
            try:
                out[k] = float(v) if k in ("window_hours", "before_minutes", "collapse_minutes") else int(v)
            except (TypeError, ValueError):
                continue
    return out


@permission("signed-in")
@require_POST
def build(request: HttpRequest):
    """Body: {mails, events, findings, settings, ...opts}."""
    try:
        body = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
    if body.get("storeKey"):
        # a server case's chains come with its stories, which select its rows around every flag
        return JsonResponse({"error": "a server case's chains are built with its stories: POST /api/stories/build", "code": "storyBuild"}, status=400)
    settings = body.get("settings") or {}
    findings = body.get("findings") or []
    opts = _opts(body)
    try:
        result = C.build_chains(body.get("mails") or [], body.get("events") or [], findings, settings, **opts)
    except Exception as exc:  # noqa: BLE001
        return JsonResponse(failure("the chain build", exc, log), status=500)
    return JsonResponse(result)
