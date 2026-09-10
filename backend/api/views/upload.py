"""
Chunked uploads for large evidence: init -> PUT chunks (append at offset) ->
complete (size check + SHA-256). Files live under FILE_UPLOAD_TEMP_DIR/uploads
until an ingestion consumes (and deletes) them.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_http_methods, require_POST

log = logging.getLogger(__name__)
_ID = re.compile(r"^[a-f0-9]{32}$")
MAX_CHUNK = 64 * 1024 * 1024


def upload_dir() -> Path:
    d = Path(settings.FILE_UPLOAD_TEMP_DIR) / "uploads"
    d.mkdir(parents=True, exist_ok=True)
    # Evidence in transit is readable only by the account running the server. On a shared host this
    # is the difference between "briefly on disk" and "briefly readable by anyone on the box".
    try:
        d.chmod(0o700)
    except OSError:
        pass
    return d


def staged_bytes() -> int:
    """Everything the staging area currently holds, including Django's own multipart spool."""
    total = 0
    for directory in (upload_dir(), Path(settings.FILE_UPLOAD_TEMP_DIR)):
        try:
            for p in directory.iterdir():
                if p.is_file():
                    total += p.stat().st_size
        except OSError:
            continue
    return total


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


def cleanup_stale(max_age_s: int | None = None) -> int:
    """Remove staged evidence nothing is going to consume.

    Covers both the chunked staging area and Django's own multipart spool: a request that dies
    part-way through a large single-request upload leaves a .upload file behind there, which the
    original sweep never looked at.
    """
    if max_age_s is None:
        max_age_s = settings.FORENSIC_UPLOAD_MAX_AGE_S
    n = 0
    now = time.time()
    for directory, suffixes in ((upload_dir(), (".part", ".json")), (Path(settings.FILE_UPLOAD_TEMP_DIR), (".upload",))):
        try:
            for p in directory.iterdir():
                if not p.is_file() or p.suffix not in suffixes:
                    continue
                if now - p.stat().st_mtime > max_age_s:
                    p.unlink(missing_ok=True)
                    n += 1
        except OSError:
            continue
    return n


_sweeper: threading.Thread | None = None


def start_sweeper() -> bool:
    """Run cleanup_stale on a timer, so an abandoned upload clears without waiting for a restart.

    A daemon thread rather than an external timer: the container runs one process, and a sweep that
    depends on the operator having configured cron is a sweep that does not happen.
    """
    global _sweeper
    interval = int(settings.FORENSIC_UPLOAD_SWEEP_S or 0)
    if interval <= 0 or (_sweeper is not None and _sweeper.is_alive()):
        return False

    def loop() -> None:
        while True:
            time.sleep(interval)
            try:
                removed = cleanup_stale()
                if removed:
                    log.info("swept %d stale staged file(s)", removed)
            except Exception as exc:  # noqa: BLE001
                log.warning("upload sweep failed: %s", exc)

    _sweeper = threading.Thread(target=loop, name="remn-upload-sweeper", daemon=True)
    _sweeper.start()
    return True


@require_POST
def init(request: HttpRequest):
    try:
        body = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
    name = str(body.get("name") or "upload")[:255]
    size = int(body.get("size") or 0)
    limit = settings.FORENSIC_MAX_CHUNKED_GB * 1024**3
    if settings.FORENSIC_BROWSER_ONLY:
        # An instance open to strangers stages the same ceiling it accepts in one request, rather
        # than the operator-scale chunked ceiling: an unfinished upload holds disk until it is swept.
        limit = min(limit, settings.FORENSIC_MAX_UPLOAD_MB * 1024**2)
    if size <= 0 or size > limit:
        return JsonResponse({"error": f"size must be between 1 byte and {settings.FORENSIC_MAX_CHUNKED_GB} GB"}, status=400)
    # Refuse rather than accept an upload the disk cannot take. Sweep first, so a burst of
    # abandoned uploads does not lock out a legitimate one for the rest of the retention window.
    budget = settings.FORENSIC_TMP_MAX_GB * 1024**3
    if staged_bytes() + size > budget:
        cleanup_stale()
        if staged_bytes() + size > budget:
            return JsonResponse({"error": "the server is staging as much evidence as it can hold; try again shortly", "code": "staging-full"}, status=507)

    upload_id = uuid.uuid4().hex
    dp, _ = _paths(upload_id)
    dp.touch()
    try:
        dp.chmod(0o600)
    except OSError:
        pass
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
