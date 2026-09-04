"""
Chunked uploads for large evidence: init -> PUT chunks (append at offset) ->
complete (size check + SHA-256). Files live under FILE_UPLOAD_TEMP_DIR/uploads
until an ingestion consumes (and deletes) them.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_http_methods, require_POST

_ID = re.compile(r"^[a-f0-9]{32}$")
MAX_CHUNK = 64 * 1024 * 1024


def upload_dir() -> Path:
    d = Path(settings.FILE_UPLOAD_TEMP_DIR) / "uploads"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _paths(upload_id: str) -> tuple[Path, Path]:
    if not _ID.match(upload_id or ""):
        raise ValueError("bad upload id")
    d = upload_dir()
    return d / f"{upload_id}.part", d / f"{upload_id}.json"


def _meta(upload_id: str) -> dict[str, Any] | None:
    _, mp = _paths(upload_id)
    if not mp.exists():
        return None
    return json.loads(mp.read_text(encoding="utf-8"))


def _save_meta(upload_id: str, meta: dict[str, Any]) -> None:
    _, mp = _paths(upload_id)
    mp.write_text(json.dumps(meta), encoding="utf-8")


def get_upload(upload_id: str) -> tuple[Path, dict[str, Any]]:
    """Return (data path, meta) for a completed upload, or raise FileNotFoundError."""
    meta = _meta(upload_id)
    dp, _ = _paths(upload_id)
    if not meta or not dp.exists() or not meta.get("complete"):
        raise FileNotFoundError(upload_id)
    return dp, meta


def discard_upload(upload_id: str) -> None:
    try:
        dp, mp = _paths(upload_id)
    except ValueError:
        return
    for p in (dp, mp):
        try:
            p.unlink()
        except OSError:
            pass


def cleanup_stale(max_age_s: int = 24 * 3600) -> int:
    n = 0
    now = time.time()
    try:
        for p in upload_dir().iterdir():
            if p.suffix in (".part", ".json") and now - p.stat().st_mtime > max_age_s:
                p.unlink(missing_ok=True)
                n += 1
    except OSError:
        pass
    return n


@require_POST
def init(request: HttpRequest):
    try:
        body = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
    name = str(body.get("name") or "upload")[:255]
    size = int(body.get("size") or 0)
    limit = settings.FORENSIC_MAX_CHUNKED_GB * 1024 ** 3
    if size <= 0 or size > limit:
        return JsonResponse({"error": f"size must be between 1 byte and {settings.FORENSIC_MAX_CHUNKED_GB} GB"}, status=400)
    upload_id = uuid.uuid4().hex
    dp, _ = _paths(upload_id)
    dp.touch()
    _save_meta(upload_id, {"id": upload_id, "name": name, "size": size, "received": 0, "complete": False, "created": int(time.time() * 1000)})
    return JsonResponse({"uploadId": upload_id, "chunkSize": settings.FORENSIC_CHUNK_MB * 1024 * 1024})


@require_http_methods(["PUT", "POST"])
def chunk(request: HttpRequest, upload_id: str):
    try:
        meta = _meta(upload_id)
    except ValueError:
        return JsonResponse({"error": "bad upload id"}, status=400)
    if not meta:
        return JsonResponse({"error": "unknown upload"}, status=404)
    if meta.get("complete"):
        return JsonResponse({"error": "upload already completed"}, status=409)
    try:
        offset = int(request.GET.get("offset", meta["received"]))
    except ValueError:
        return JsonResponse({"error": "bad offset"}, status=400)
    if offset != meta["received"]:
        return JsonResponse({"error": "offset mismatch", "received": meta["received"]}, status=409)
    data = request.read()
    if len(data) > MAX_CHUNK:
        return JsonResponse({"error": "chunk too large"}, status=413)
    if meta["received"] + len(data) > meta["size"]:
        return JsonResponse({"error": "more bytes than announced"}, status=400)
    dp, _ = _paths(upload_id)
    with open(dp, "r+b" if dp.exists() else "wb") as fh:
        fh.seek(offset)
        fh.write(data)
    meta["received"] += len(data)
    _save_meta(upload_id, meta)
    return JsonResponse({"received": meta["received"], "size": meta["size"]})


@require_POST
def complete(request: HttpRequest, upload_id: str):
    try:
        meta = _meta(upload_id)
    except ValueError:
        return JsonResponse({"error": "bad upload id"}, status=400)
    if not meta:
        return JsonResponse({"error": "unknown upload"}, status=404)
    if meta["received"] != meta["size"]:
        return JsonResponse({"error": "incomplete upload", "received": meta["received"], "size": meta["size"]}, status=409)
    dp, _ = _paths(upload_id)
    h = hashlib.sha256()
    with open(dp, "rb") as fh:
        while True:
            b = fh.read(8 * 1024 * 1024)
            if not b:
                break
            h.update(b)
    meta["complete"] = True
    meta["sha256"] = h.hexdigest()
    _save_meta(upload_id, meta)
    return JsonResponse({"uploadId": upload_id, "sha256": meta["sha256"], "size": meta["size"], "name": meta["name"]})


@require_http_methods(["GET", "DELETE"])
def status(request: HttpRequest, upload_id: str):
    try:
        meta = _meta(upload_id)
    except ValueError:
        return JsonResponse({"error": "bad upload id"}, status=400)
    if request.method == "DELETE":
        discard_upload(upload_id)
        return JsonResponse({"ok": True})
    if not meta:
        return JsonResponse({"error": "unknown upload"}, status=404)
    return JsonResponse(meta)


def _unused() -> None:  # keep os imported for platforms where unlink semantics differ
    _ = os
