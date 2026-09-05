"""Cross-source attack chains: build from a server case store, or from rows posted by a browser-stored case."""
from __future__ import annotations

import json
import logging

from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_POST

from services.analysis import chains as C
from services.store.casestore import registry

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


@require_POST
def build(request: HttpRequest):
    """Body: {storeKey, settings, findings, ...opts} for a server case, or {mails, events, findings, settings, ...opts}."""
    try:
        body = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
    settings = body.get("settings") or {}
    findings = body.get("findings") or []
    opts = _opts(body)
    try:
        if body.get("storeKey"):
            try:
                st = registry.get(str(body["storeKey"]), create=False)
            except (ValueError, FileNotFoundError):
                return JsonResponse({"error": "unknown case store"}, status=404)
            result = C.chains_for_store(st, settings, findings, **opts)
        else:
            result = C.build_chains(body.get("mails") or [], body.get("events") or [], findings, settings, **opts)
    except Exception as exc:  # noqa: BLE001
        log.exception("chain build failed")
        return JsonResponse({"error": str(exc)[:300]}, status=500)
    return JsonResponse(result)
