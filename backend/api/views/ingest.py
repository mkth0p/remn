"""
Evidence ingestion for browser-stored cases. The server never stores anything:
the upload lives in a request-scoped temp file (or a completed chunked upload),
is hashed, parsed and streamed back as NDJSON.
"""

from __future__ import annotations

import io
import json
import logging
import os
import shutil
import tempfile
import time
from collections.abc import Iterator
from typing import Any

from django.conf import settings
from django.http import HttpRequest, JsonResponse, StreamingHttpResponse
from django.views.decorators.http import require_POST

from api.views.upload import discard_upload, get_upload
from services.analysis import hayabusa
from services.analysis.attachments.analyzer import analyze_attachment
from services.common import ndjson_line, sha256_chunks
from services.ingest.pipeline import EvtxSource, MailSource, detect_mail_format, iter_mbox_fileobj
from services.parsers.mail import pst as pst_mod
from services.parsers.mail.common import ParseContext

log = logging.getLogger(__name__)

NDJSON = "application/x-ndjson; charset=utf-8"
_iter_mbox_fileobj = iter_mbox_fileobj  # backwards-compatible alias (tests)


def _too_large(request: HttpRequest) -> JsonResponse | None:
    try:
        length = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    limit = settings.FORENSIC_MAX_UPLOAD_MB * 1024 * 1024
    if length > limit:
        return JsonResponse({"error": f"upload larger than {settings.FORENSIC_MAX_UPLOAD_MB} MB"}, status=413)
    return None


class _Source:
    """Either a multipart upload (request.FILES) or a completed chunked upload (uploadId)."""

    def __init__(self, request: HttpRequest) -> None:
        self.name = ""
        self.size = 0
        self.sha256 = ""
        self.path: str | None = None
        self.data: bytes | None = None
        self.upload_id: str | None = None
        self.error: JsonResponse | None = None
        upload_id = request.POST.get("uploadId") or request.GET.get("uploadId")
        if upload_id:
            try:
                path, meta = get_upload(upload_id)
            except (FileNotFoundError, ValueError):
                self.error = JsonResponse({"error": "upload not found or incomplete"}, status=404)
                return
            self.upload_id = upload_id
            self.name = str(request.POST.get("name") or meta.get("name") or "upload")
            self.size = int(meta.get("size") or 0)
            self.sha256 = str(meta.get("sha256") or "")
            self.path = str(path)
            return
        f = request.FILES.get("file")
        if f is None:
            self.error = JsonResponse({"error": "multipart field 'file' (or uploadId) is required"}, status=400)
            return
        self.name = f.name
        self.size = f.size
        self.sha256 = sha256_chunks(f.chunks(chunk_size=4 * 1024 * 1024))
        f.seek(0)
        if hasattr(f, "temporary_file_path"):
            try:
                self.path = f.temporary_file_path()
                return
            except Exception:  # noqa: BLE001
                pass
        self.data = f.read()

    def head(self, n: int = 4096) -> bytes:
        if self.data is not None:
            return self.data[:n]
        try:
            with open(self.path or "", "rb") as fh:
                return fh.read(n)
        except OSError:
            return b""

    def cleanup(self) -> None:
        if self.upload_id:
            discard_upload(self.upload_id)


DEADLINE_REASON = "parse stopped at the FORENSIC_INGEST_MAX_S limit; the rows already sent are kept and the result is marked incomplete"


def _deadline() -> float | None:
    """When this request must stop parsing, or None when no limit is configured."""
    limit = int(settings.FORENSIC_INGEST_MAX_S or 0)
    return time.monotonic() + limit if limit > 0 else None


def _expired(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() > deadline


def _engine_lines(src, tmp_dir: str, deadline: float | None) -> Iterator[bytes]:
    """Hayabusa over the staged event log, its detections as finding lines and one summary line."""
    remaining = max(1.0, deadline - time.monotonic()) if deadline else None
    target = src.path
    staged = None
    if target is None or not str(target).lower().endswith(".evtx"):
        # the engine picks files by extension, and an in-memory upload has no path at all
        fd, staged = tempfile.mkstemp(dir=tmp_dir, suffix=".evtx")
        with os.fdopen(fd, "wb") as out:
            if target is None:
                out.write(src.data or b"")
            else:
                with open(target, "rb") as fh:
                    shutil.copyfileobj(fh, out)
        target = staged
    try:
        findings, summary = hayabusa.run(target, tmp_dir, deadline_s=remaining)
    finally:
        if staged:
            try:
                os.unlink(staged)
            except OSError:
                pass
    for finding in findings:
        yield ndjson_line({"type": "finding", **finding})
    yield ndjson_line({"type": "engine", **summary})


def _stream(gen: Iterator[bytes]) -> StreamingHttpResponse:
    resp = StreamingHttpResponse(gen, content_type=NDJSON)
    resp["Cache-Control"] = "no-store"
    resp["X-Accel-Buffering"] = "no"
    return resp


def _ctx_from_request(request: HttpRequest) -> ParseContext:
    raw = request.POST.get("settings") or "{}"
    try:
        s = json.loads(raw)
    except ValueError:
        s = {}
    return ParseContext(
        internal_domains=[str(x) for x in (s.get("internalDomains") or []) if x],
        brands=[str(x) for x in (s.get("brands") or []) if x],
        vip_names=[str(x) for x in (s.get("vipNames") or []) if x],
        include_html=bool(s.get("includeHtml", True)),
        include_headers=bool(s.get("includeHeaders", True)),
        analyze_attachments=bool(s.get("analyzeAttachments", True)),
        trusted_senders=[str(x) for x in (s.get("trustedSenders") or s.get("trusted_senders") or []) if x],
    )


# ---------------------------------------------------------------------------
# EVTX (single file or zip/tar of EVTX files)
# ---------------------------------------------------------------------------
@require_POST
def ingest_evtx(request: HttpRequest):
    if (err := _too_large(request)) is not None:
        return err
    src = _Source(request)
    if src.error is not None:
        return src.error
    include_raw = request.POST.get("raw", "1") not in ("0", "false", "no")
    tmp_dir = str(settings.FILE_UPLOAD_TEMP_DIR)

    def gen() -> Iterator[bytes]:
        n = 0
        evsrc = EvtxSource(src.name, src.path, src.data, tmp_dir, include_raw=include_raw)
        engines = hayabusa.engines() if request.POST.get("engines", "1") != "0" else []
        yield ndjson_line({"type": "meta", "format": evsrc.format, "name": src.name, "size": src.size, "sha256": src.sha256, "includeRaw": include_raw, "engines": engines})
        deadline = _deadline()
        try:
            for row in evsrc:
                row["type"] = "event"
                yield ndjson_line(row)
                n += 1
                if _expired(deadline):
                    evsrc.stats.errors += 1
                    yield ndjson_line({"type": "error", "error": DEADLINE_REASON, "emitted": n})
                    break
            if engines:
                yield from _engine_lines(src, tmp_dir, deadline)
        except Exception as exc:  # noqa: BLE001
            log.exception("evtx ingestion failed")
            yield ndjson_line({"type": "error", "error": str(exc)[:300], "emitted": n})
        finally:
            stats = evsrc.stats.to_dict()
            stats["files"] = evsrc.files
            yield ndjson_line({"type": "done", "format": evsrc.format, "stats": stats, "emitted": n, "sha256": src.sha256})
            src.cleanup()

    return _stream(gen())


# ---------------------------------------------------------------------------
# Mail (eml, msg, mbox, pst, zip/tar corpora)
# ---------------------------------------------------------------------------
@require_POST
def ingest_mail(request: HttpRequest):
    if (err := _too_large(request)) is not None:
        return err
    src = _Source(request)
    if src.error is not None:
        return src.error
    ctx = _ctx_from_request(request)
    fmt = request.POST.get("format") or detect_mail_format(src.name, src.head())
    if fmt == "pst" and not pst_mod.available():
        src.cleanup()
        return JsonResponse({"error": "PST/OST support requires libpff-python (see backend/requirements-optional.txt)"}, status=501)
    tmp_dir = str(settings.FILE_UPLOAD_TEMP_DIR)

    def gen() -> Iterator[bytes]:
        yield ndjson_line(
            {
                "type": "meta",
                "format": fmt,
                "name": src.name,
                "size": src.size,
                "sha256": src.sha256,
                "settings": {"internalDomains": ctx.internal_domains, "brands": ctx.brands, "vipNames": ctx.vip_names},
            }
        )
        n = 0
        msrc = MailSource(src.name, src.path, src.data, ctx, tmp_dir)
        deadline = _deadline()
        try:
            for row in msrc:
                row["type"] = "mail"
                yield ndjson_line(row)
                n += 1
                if _expired(deadline):
                    msrc.stats.errors += 1
                    yield ndjson_line({"type": "error", "error": DEADLINE_REASON, "emitted": n})
                    break
        except Exception as exc:  # noqa: BLE001
            log.exception("mail ingestion failed")
            msrc.stats.errors += 1
            yield ndjson_line({"type": "error", "error": str(exc)[:300], "emitted": n})
        finally:
            yield ndjson_line({"type": "done", "format": msrc.format, "stats": msrc.stats.to_dict(), "emitted": n, "sha256": src.sha256})
            src.cleanup()

    return _stream(gen())


# ---------------------------------------------------------------------------
# Single attachment analysis (drag & drop a file to analyse it alone)
# ---------------------------------------------------------------------------
@require_POST
def analyze_single_attachment(request: HttpRequest):
    if (err := _too_large(request)) is not None:
        return err
    f = request.FILES.get("file")
    if f is None:
        return JsonResponse({"error": "multipart field 'file' is required"}, status=400)
    if f.size > 200 * 1024 * 1024:
        return JsonResponse({"error": "file too large for single-attachment analysis (200 MB max)"}, status=413)
    f.seek(0)
    data = f.read()
    result = analyze_attachment(f.name, data, f.content_type)
    return JsonResponse({"type": "attachment", "result": result})


def _unused() -> None:
    _ = io, Any


@require_POST
def ingest_package(request: HttpRequest):
    from services.ingest.package import PackageSource

    if (err := _too_large(request)) is not None:
        return err
    src = _Source(request)
    if src.error is not None:
        return src.error
    source_name = str(request.POST.get("sourceName") or src.name)[:2048]
    package = PackageSource(
        source_name, src.path, src.data, str(settings.FILE_UPLOAD_TEMP_DIR), _ctx_from_request(request), request.POST.get("raw", "1") != "0", src.sha256
    )

    package.engines = hayabusa.engines() if request.POST.get("engines", "1") != "0" else []

    def gen() -> Iterator[bytes]:
        rows = iter(package)
        deadline = _deadline()
        try:
            yield ndjson_line({"type": "meta", "format": package.format, "name": src.name, "size": src.size, "sha256": src.sha256, "engines": package.engines})
            for row in rows:
                yield ndjson_line(row)
                if _expired(deadline):
                    # Closing the iterator runs the package's own cleanup, which releases every
                    # artifact it was holding back for group decoding.
                    rows.close()
                    package.inventory_complete = False
                    yield ndjson_line({"type": "error", "error": DEADLINE_REASON})
                    break
            for finding in package.findings:
                yield ndjson_line({"type": "finding", **finding})
            for summary in package.engine_summaries:
                yield ndjson_line({"type": "engine", **summary})
            yield ndjson_line({"type": "done", "format": package.format, "stats": package.stats(), "sha256": src.sha256})
        except Exception as exc:  # noqa: BLE001
            yield ndjson_line({"type": "error", "error": str(exc)[:300]})
            package.inventory_complete = False
            yield ndjson_line({"type": "done", "format": package.format, "stats": package.stats(), "sha256": src.sha256})
        finally:
            rows.close()
            src.cleanup()

    return _stream(gen())
