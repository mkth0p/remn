"""Enrichment passes: sender baselining + campaign clustering (server store, or rows posted by a browser case)."""

from __future__ import annotations

import json
import logging

from django.conf import settings as conf
from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_POST

from api.errors import failure
from api.jobs import manager
from api.views.store import REFUSED, _limit, _stopped, refused
from forensic.access import permission
from services.analysis import baseline
from services.analysis import rescore as calibration
from services.store.casestore import QueryStopped, TimeLimit, registry

log = logging.getLogger(__name__)

RESCORE_STOPPED = (
    "one read of the case was stopped after {seconds} s, the most FORENSIC_STORE_QUERY_MAX_S allows one query on a server store, "
    "so the mail scores were left as they were. Ask the operator to raise the limit."
)


def _read_limit() -> TimeLimit:
    """The time one read of a rescore job may take: a job has no request to answer 504, so it says the limit in its error."""
    return TimeLimit(conf.FORENSIC_STORE_QUERY_MAX_S, RESCORE_STOPPED)


@permission("write", case="body")
@require_POST
def rescore(request: HttpRequest):
    # Only the messages composed here are returned. An exception raised while the mails are scored
    # can quote a mail, so it is a server failure with a reference (JsonErrorsMiddleware).
    try:
        body = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
    if not isinstance(body, dict) or not isinstance(body.get("settings", {}), dict):
        return JsonResponse({"error": "expected an object and settings object"}, status=400)
    settings = body.get("settings") or {}
    if body.get("storeKey"):
        if conf.FORENSIC_BROWSER_ONLY:
            return JsonResponse({"error": "server stores are unavailable in browser-only mode", "code": "browserOnly"}, status=403)
        try:
            st = registry.get(str(body["storeKey"]), create=False)
        except ValueError:
            return JsonResponse({"error": "invalid case key"}, status=400)
        except FileNotFoundError:
            return JsonResponse({"error": "unknown case store"}, status=404)
        except REFUSED as exc:
            return refused(exc)
        if any(j["status"] in ("queued", "running") for j in manager.list(st.key)):
            return JsonResponse({"error": "Wait for this case's current jobs to finish before rescoring."}, status=409)
        account = getattr(request, "account", None)
        job = manager.submit(
            "rescore_mails", st.key, lambda j: calibration.store(st, settings, j, limit=_read_limit), "Rescore mails", account=account.name if account else None
        )
        return JsonResponse({"jobId": job.id}, status=202)
    rows = body.get("mails")
    if not isinstance(rows, list) or len(rows) > 200 or any(not isinstance(r, dict) or not isinstance(r.get("id"), int) for r in rows):
        return JsonResponse({"error": "mails must contain at most 200 rows with integer IDs"}, status=400)
    return JsonResponse(calibration.batch(rows, settings))


@permission("write", case="body")
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
            if conf.FORENSIC_BROWSER_ONLY:
                return JsonResponse({"error": "server stores are unavailable in browser-only mode", "code": "browserOnly"}, status=403)
            try:
                st = registry.get(str(body["storeKey"]), create=False)
            except (ValueError, FileNotFoundError):
                return JsonResponse({"error": "unknown case store"}, status=404)
            except REFUSED as exc:
                return refused(exc)
            try:
                with _limit():
                    summary = baseline.enrich_store(st, settings)
            except QueryStopped as exc:
                return _stopped(exc)
            return JsonResponse({"summary": summary})
        rows = body.get("mails") or []
        if not isinstance(rows, list):
            return JsonResponse({"error": "mails must be a list"}, status=400)
        enrichment = baseline.enrich(rows, settings)
        return JsonResponse({"rows": [{"id": mid, **e} for mid, e in enrichment.items()], "summary": baseline.summarize(enrichment)})
    except Exception as exc:  # noqa: BLE001
        return JsonResponse(failure("the enrichment", exc, log), status=500)
