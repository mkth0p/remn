"""Stories: build them from a server case store, or from the rows a browser-stored case posts."""

from __future__ import annotations

import json
import logging

from django.conf import settings as django_settings
from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_POST

from services.analysis import stories as S
from services.store.casestore import registry

log = logging.getLogger(__name__)

_OPT_KEYS = {"gap_hours": float, "max_stories": int, "max_steps": int, "seed_min_risk": int}
# what a caller may ask for: a build's cost and its response grow with stories times steps, so both are held
# to a few times the defaults (200 stories, 400 steps); the gap from an hour to thirty days
_OPT_BOUNDS = {"gap_hours": (1.0, 720.0), "max_stories": (1, 1_000), "max_steps": (1, 2_000), "seed_min_risk": (0, 100)}


def _opts(body: dict) -> dict:
    out = {}
    for k, cast in _OPT_KEYS.items():
        camel = "".join(p.capitalize() if i else p for i, p in enumerate(k.split("_")))
        v = body.get(k, body.get(camel))
        if v is not None:
            try:
                x = cast(v)
            except (TypeError, ValueError, OverflowError):
                continue
            if x != x:  # NaN
                continue
            lo, hi = _OPT_BOUNDS[k]
            out[k] = min(max(x, lo), hi)
    return out


@require_POST
def build(request: HttpRequest):
    """Body: {storeKey, settings, findings, ...opts} for a server case, or {events, mails, findings, settings, ...opts}."""
    try:
        body = json.loads(request.body or b"{}")
        if not isinstance(body, dict):
            raise ValueError("expected a JSON object")
    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
    settings = body.get("settings") or {}
    findings = body.get("findings") or []
    if not isinstance(settings, dict) or not isinstance(findings, list):
        return JsonResponse({"error": "settings must be an object and findings a list"}, status=400)
    opts = _opts(body)
    try:
        if body.get("storeKey"):
            if django_settings.FORENSIC_BROWSER_ONLY:
                return JsonResponse({"error": "server stores are unavailable in browser-only mode", "code": "browserOnly"}, status=403)
            try:
                st = registry.get(str(body["storeKey"]), create=False)
            except (ValueError, FileNotFoundError):
                return JsonResponse({"error": "unknown case store"}, status=404)
            result = S.stories_for_store(st, settings, findings, **opts)
        else:
            events, mails = body.get("events") or [], body.get("mails") or []
            if not isinstance(events, list) or not isinstance(mails, list):
                return JsonResponse({"error": "events and mails must be lists"}, status=400)
            result = S.build_stories(events, mails, findings, settings, measures=S.rule_measures(), **{k: v for k, v in opts.items() if k != "seed_min_risk"})
    except Exception as exc:  # noqa: BLE001
        log.exception("story build failed")
        return JsonResponse({"error": str(exc)[:300]}, status=500)
    return JsonResponse(result)
