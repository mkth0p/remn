from __future__ import annotations

import json

from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_GET, require_POST

from services.reputation.base import KINDS, registry, summarize

MAX_ITEMS = 200


@require_GET
def providers(request: HttpRequest):
    return JsonResponse({"providers": registry.list(), "cacheSize": len(registry.cache)})


@require_POST
def lookup(request: HttpRequest):
    try:
        body = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
    items_raw = body.get("items") or []
    if not isinstance(items_raw, list):
        return JsonResponse({"error": "items must be a list"}, status=400)
    if len(items_raw) > MAX_ITEMS:
        return JsonResponse({"error": f"at most {MAX_ITEMS} items per call"}, status=400)
    items: list[tuple[str, str]] = []
    for it in items_raw:
        if not isinstance(it, dict):
            continue
        kind = str(it.get("kind") or "").lower()
        value = str(it.get("value") or "").strip()
        if kind in KINDS and value:
            items.append((kind, value[:2048]))
    wanted = body.get("providers")
    if wanted is not None and not isinstance(wanted, list):
        return JsonResponse({"error": "providers must be a list"}, status=400)
    results = registry.lookup(items, providers=[str(p) for p in wanted] if wanted else None, deadline=float(body.get("deadline") or 60))
    return JsonResponse({"results": results, "summary": summarize(results)})
