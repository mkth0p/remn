"""Sanitized archive observations: real request times, synthetic service, no Windows IDs."""

import re

from services.parsers.collection import timestamp

VERSION = "ghost-archive/1"


def normalize(raw, index, context):
    if raw.get("schema") != VERSION or raw.get("syntheticService") is not True:
        raise ValueError("expected a ghost-archive/1 synthetic-service observation")
    ts = timestamp(raw.get("timestamp"))
    if ts is None:
        raise ValueError("deception observation requires a timezone-bearing timestamp")
    for name in ("episodeId", "exhibitId", "parentExhibitId"):
        value = raw.get(name)
        if value is not None and (not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value)):
            raise ValueError("invalid deception exhibit identifier")
    if not raw.get("exhibitId") or raw.get("scope") not in ("archive", "challenge", "unassigned"):
        raise ValueError("invalid deception scope or exhibit")
    for name in ("action", "result"):
        if not isinstance(raw.get(name), str) or not re.fullmatch(r"[a-z-]{1,48}", raw[name]):
            raise ValueError("invalid deception action or result")
    stage = raw.get("stage")
    if type(stage) is not int or not 0 <= stage <= 8:
        raise ValueError("invalid deception stage")
    # Explicit projection: raw transport bodies and arbitrary imported fields are not promoted.
    data = {k: raw[k] for k in ("schema", "timestamp", "scope", "action", "result", "stage", "syntheticService")}
    for name in (
        "episodeId",
        "exhibitId",
        "parentExhibitId",
        "responseSha256",
        "status",
        "durationMs",
        "bytes",
        "novelTransition",
        "suppressedEvents",
        "journalErrors",
    ):
        value = raw.get(name)
        if isinstance(value, (str, int, bool)) and (not isinstance(value, str) or len(value) <= 64):
            data[name] = value
    return {
        "recordKind": "event",
        "artifactType": "deception",
        "eventId": None,
        "ts": ts,
        "observedAt": timestamp(context.get("collectedAt")),
        "sourceIndex": index,
        "parserVersion": VERSION,
        "provider": "REMN Deception",
        "category": "deception:observed-request",
        "deceptionEpisodeId": raw.get("episodeId"),
        "deceptionExhibitId": raw["exhibitId"],
        "deceptionParentExhibitId": raw.get("parentExhibitId"),
        "deceptionScope": raw["scope"],
        "deceptionAction": raw["action"],
        "deceptionResult": raw["result"],
        "deceptionStage": stage,
        "summary": f"Synthetic archive / {raw['scope']}: {raw['action']} ({raw['result']})",
        "data": data,
    }
