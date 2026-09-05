"""Enrichment passes: sender baselining + campaign clustering (server store, or rows posted by a browser case)."""
from __future__ import annotations

import json
import logging

from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_POST

from services.analysis import baseline
from services.store.casestore import registry

log = logging.getLogger(__name__)


@require_POST
def mails(request: HttpRequest):
    """Body: {storeKey, settings} -> summary; or {mails: [...], settings} -> {rows: [{id, senderPrevalence, ...}], summary}."""
    try:
        body = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
    settings = body.get("settings") or {}
    try:
        if body.get("storeKey"):
            try:
                st = registry.get(str(body["storeKey"]), create=False)
            except (ValueError, FileNotFoundError):
                return JsonResponse({"error": "unknown case store"}, status=404)
            return JsonResponse({"summary": baseline.enrich_store(st, settings)})
        rows = body.get("mails") or []
        if not isinstance(rows, list):
            return JsonResponse({"error": "mails must be a list"}, status=400)
        enrichment = baseline.enrich(rows, settings)
        return JsonResponse({"rows": [{"id": mid, **e} for mid, e in enrichment.items()], "summary": baseline.summarize(enrichment)})
    except Exception as exc:  # noqa: BLE001
        log.exception("enrichment failed")
        return JsonResponse({"error": str(exc)[:300]}, status=500)
