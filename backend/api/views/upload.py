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
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_http_methods, require_POST

from api.params import BadParameter, whole_number
from services.ingest import staging
from services.ingest.staging import DIRECTORY_SUFFIXES, size_text, staged_bytes

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


def pending_bytes() -> int:
    """What the unfinished chunked uploads have announced but not yet sent. staged_bytes() only sees
    what is on disk, so without this a burst of inits each passes the budget before any chunk lands."""
    total = 0
    try:
        for p in upload_dir().glob("*.json"):
            try:
                meta = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not meta.get("complete"):
                total += max(0, int(meta.get("size", 0)) - int(meta.get("received", 0)))
    except OSError:
        pass
    return total


# init checks the budget and then records its reservation; two inits must not both pass on the same room
_reserve = threading.Lock()


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
    # .member, .decoded and .manifest are the parsers own staging. A parse releases them itself,
    # but a process killed mid-parse cannot, and nothing else reclaims them. Django's spool keeps
    # the uploaded file's extension after ".upload", so every suffix of the name is looked at.
    parser_temp = (".upload", ".member", ".decoded", ".manifest")
    for directory, suffixes in ((upload_dir(), (".part", ".json")), (Path(settings.FILE_UPLOAD_TEMP_DIR), parser_temp)):
        try:
            for p in directory.iterdir():
                if not p.is_file() or not set(p.suffixes) & set(suffixes):
                    continue
                if now - p.stat().st_mtime > max_age_s:
                    p.unlink(missing_ok=True)
                    n += 1
        except OSError:
            continue
    # The directories a parse creates, an expanded 7z and the event logs staged for an engine run,
    # go on the same age. A parse still reading an expanded archive touches it as it takes each
    # member, so the age is the time since it was last used.
    try:
        for p in Path(settings.FILE_UPLOAD_TEMP_DIR).iterdir():
            if p.is_dir() and not p.is_symlink() and p.name.endswith(DIRECTORY_SUFFIXES) and now - p.stat().st_mtime > max_age_s:
                shutil.rmtree(p, ignore_errors=True)
                n += 1
    except OSError:
        pass
    return n


def clear_leftovers() -> int:
    """At startup nothing is being parsed, so whatever a parse staged was left by a process that
    stopped in the middle of one: remove it whatever its age. Chunked uploads stay, since a client
    can resume one."""
    tmp = Path(settings.FILE_UPLOAD_TEMP_DIR)
    tmp.mkdir(parents=True, exist_ok=True)
    removed = 0
    for child in tmp.iterdir():
        try:
            if child.is_file() and child.suffix not in (".part", ".json"):
                child.unlink()
            elif child.is_dir() and not child.is_symlink() and child.name.endswith(DIRECTORY_SUFFIXES):
                shutil.rmtree(child)
            else:
                continue
            removed += 1
        except OSError:
            pass
    return removed


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
    try:
        size = whole_number(body.get("size"), "size", 0)
    except BadParameter as exc:
        return JsonResponse({"error": f"{exc} of bytes"}, status=400)
    limit = settings.FORENSIC_MAX_CHUNKED_GB * 1024**3
    if settings.FORENSIC_BROWSER_ONLY:
        # An instance open to strangers stages the same ceiling it accepts in one request, rather
        # than the operator-scale chunked ceiling: an unfinished upload holds disk until it is swept.
        limit = min(limit, settings.FORENSIC_MAX_UPLOAD_MB * 1024**2)
    if size <= 0 or size > limit:
        return JsonResponse({"error": f"size must be between 1 byte and {limit // 1024**2:,} MB"}, status=400)
    # Refuse rather than accept an upload the disk cannot take. Sweep first, so a burst of
    # abandoned uploads does not lock out a legitimate one for the rest of the retention window.
    # What is announced counts as taken: the room an upload will need is reserved when it starts.
    with _reserve:
        budget, decided_by = staging.capacity()
        if size > budget:
            # Larger than the staging area could hold even empty: waiting changes nothing, so the
            # answer says what does.
            return JsonResponse(
                {
                    "error": f"this file is {size_text(size)} and the staging area can hold at most {size_text(budget)} ({decided_by}); it cannot be accepted until that changes",
                    "code": "staging-too-small",
                },
                status=413,
            )
        if staged_bytes() + pending_bytes() + size > budget:
            cleanup_stale()
            held = staged_bytes() + pending_bytes()
            if held + size > budget:
                return JsonResponse(
                    {
                        "error": (
                            f"the staging area holds {size_text(held)} of other uploads and parses in progress and has room for "
                            f"{size_text(max(0, budget - held))} more; this file needs {size_text(size)}. The room frees as those are parsed, "
                            f"or after {settings.FORENSIC_UPLOAD_MAX_AGE_S // 60} minutes for an upload that was abandoned"
                        ),
                        "code": "staging-full",
                    },
                    status=507,
                )

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
    # Refuse an oversized chunk before reading it: request.read() is not bounded by Django's
    # DATA_UPLOAD_MAX_MEMORY_SIZE, so reading first would hold the whole body in memory.
    try:
        declared = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        return JsonResponse({"error": "bad content length"}, status=400)
    if declared > MAX_CHUNK:
        return JsonResponse({"error": "chunk too large"}, status=413)
    data = request.read(MAX_CHUNK + 1)
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
