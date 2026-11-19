from __future__ import annotations

import json

from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_GET, require_POST

from api.params import BadParameter, seconds
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
    try:
        deadline = seconds(body.get("deadline"), "deadline", 60)
    except BadParameter as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    names = [str(p) for p in wanted] if wanted else None
    # A lookup discloses the indicator to the provider, so it is the analyst's choice per case. The
    # page holds that choice and the server cannot read it, so the request has to state it: a
    # client that forgot to check, or never knew of the setting, gets a refusal and not a disclosure.
    external = [p.name for p in registry.providers.values() if p.external and (names is None or p.name in names)]
    if items and external and body.get("networkAllowed") is not True:
        return JsonResponse(
            {
                "error": "this lookup would send the indicators to external providers, and the request does not say that the case allows it "
                "(networkAllowed: true); allow reputation lookups for the case, or name only local providers",
                "code": "lookupsNotAllowed",
                "external": external,
            },
            status=403,
        )
    results = registry.lookup(items, providers=names, deadline=deadline)
    return JsonResponse({"results": results, "summary": summarize(results)})
