"""
Evidence ingestion for browser-stored cases. The server never stores anything:
the upload lives in a request-scoped temp file (or a completed chunked upload),
is hashed, parsed in a process of its own (services/ingest/isolation.py) and
streamed back as NDJSON.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterator
from typing import Any

from django.conf import settings
from django.http import HttpRequest, JsonResponse, StreamingHttpResponse
from django.views.decorators.http import require_POST

from api.errors import failure
from api.views.upload import discard_upload, get_upload
from forensic.access import permission
from forensic.build import build_id
from services.analysis import hayabusa
from services.common import ndjson_line, sha256_chunks
from services.ingest import isolation, staging
from services.ingest.isolation import ParseStopped
from services.ingest.package import request_budget
from services.ingest.pipeline import DeadlineExceeded, detect_mail_format, iter_mbox_fileobj
from services.ingest.staging import member_ceiling
from services.parsers import m365
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
                path, meta = get_upload(upload_id, getattr(request, "account", None))
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


def _max_member() -> int:
    """The largest archive member copied out for parsing: never more than half the staging budget,
    so one member of a small upload cannot fill the area every other visitor's upload shares."""
    return member_ceiling()


def _members_line_stats(members: list[dict[str, Any]], limit: int = 2000) -> dict[str, Any]:
    """The member manifest for the done line, capped so a huge archive cannot make one huge line."""
    counts = {"parsed": 0, "skipped": 0, "error": 0}
    for m in members:
        key = str(m.get("status") or "parsed")
        counts[key] = counts.get(key, 0) + 1
    return {"members": members[:limit], "membersTotal": len(members), "memberCounts": counts}


def _stop_line(exc: Exception, what: str) -> dict[str, Any]:
    """The error line of a parse that ended early. A limit is said as it is, for the analyst; any
    other failure is logged under a reference and the client gets its type and the reference."""
    if isinstance(exc, DeadlineExceeded):
        return {"error": DEADLINE_REASON}
    if isinstance(exc, ParseStopped):
        return {"error": str(exc)}
    return failure(what, exc, log)


def _engine_lines(parse, result: dict[str, Any]) -> Iterator[bytes]:
    """Hayabusa's detections over the upload's event logs as finding lines, and its summary lines."""
    for finding in parse.findings:
        yield ndjson_line({"type": "finding", **finding})
    for summary in result.get("engineSummaries") or []:
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
        max_message_bytes=settings.FORENSIC_MAX_MESSAGE_MB * 1024 * 1024,
        trusted_arc_sealers=[str(x).lower() for x in (s.get("trustedArcSealers") or []) if x],
    )


def _dates(request: HttpRequest) -> tuple[dict[str, str] | None, JsonResponse | None]:
    """The date order and time zone the analyst set for the evidence (the "dates" field, JSON), for
    the cloud exports in it, or a 400 saying why it cannot be used."""
    try:
        setting = m365.date_setting(request.POST.get("dates"))
    except ValueError as exc:
        return None, JsonResponse({"error": str(exc)}, status=400)
    return (setting.to_dict() if setting is not None else None), None


# ---------------------------------------------------------------------------
# EVTX (single file or zip/tar of EVTX files)
# ---------------------------------------------------------------------------
@permission("work")
@require_POST
def ingest_evtx(request: HttpRequest):
    if (err := _too_large(request)) is not None:
        return err
    dates, err = _dates(request)
    if err is not None:
        return err
    src = _Source(request)
    if src.error is not None:
        return src.error
    include_raw = request.POST.get("raw", "1") not in ("0", "false", "no")
    tmp_dir = str(settings.FILE_UPLOAD_TEMP_DIR)

    def gen() -> Iterator[bytes]:
        n = 0
        deadline = _deadline()
        parse = None
        # The terminal line is yielded after the try, never inside a finally: a client that goes away
        # closes this generator at a yield, and a yield in a finally then aborts the cleanup below it.
        try:
            engines = hayabusa.engines() if request.POST.get("engines", "1") != "0" else []
            options = {"include_raw": include_raw, "max_member": _max_member(), "engines": bool(engines), "dates": dates}
            parse = isolation.start("evtx", name=src.name, path=src.path, data=src.data, tmp_dir=tmp_dir, options=options, deadline=deadline)
            yield ndjson_line(
                {
                    "type": "meta",
                    "format": parse.format,
                    "name": src.name,
                    "size": src.size,
                    "sha256": src.sha256,
                    "includeRaw": include_raw,
                    "engines": engines,
                    "parser": build_id(),
                }
            )
            error = None
            try:
                for row in parse:
                    row["type"] = "event"
                    yield ndjson_line(row)
                    n += 1
                    if _expired(deadline):
                        raise DeadlineExceeded()
                yield from _engine_lines(parse, parse.result())
            except Exception as exc:  # noqa: BLE001
                error = _stop_line(exc, "the parse of the event log")
            # a parse stopped here (the deadline, an error) reports what it had read before it ends
            parse.stop()
            if error is not None:
                yield ndjson_line({"type": "error", **error, "emitted": n})
            result = parse.result(error["error"] if error else None)
            yield ndjson_line({"type": "done", "format": parse.format, "stats": result["stats"], "emitted": n, "sha256": src.sha256, "parser": build_id()})
        finally:
            if parse is not None:
                parse.close()
            src.cleanup()

    return _stream(gen())


# ---------------------------------------------------------------------------
# Mail (eml, msg, mbox, pst, zip/tar corpora)
# ---------------------------------------------------------------------------
@permission("work")
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
        n = 0
        deadline = _deadline()
        parse = None
        # as for event logs: the terminal line is never yielded from a finally, so cleanup always runs
        try:
            options = {"ctx": ctx, "max_member": _max_member()}
            parse = isolation.start("mail", name=src.name, path=src.path, data=src.data, tmp_dir=tmp_dir, options=options, deadline=deadline)
            yield ndjson_line(
                {
                    "type": "meta",
                    "format": fmt,
                    "name": src.name,
                    "size": src.size,
                    "sha256": src.sha256,
                    "settings": {"internalDomains": ctx.internal_domains, "brands": ctx.brands, "vipNames": ctx.vip_names},
                    "parser": build_id(),
                }
            )
            error = None
            try:
                for row in parse:
                    row["type"] = "mail"
                    yield ndjson_line(row)
                    n += 1
                    if _expired(deadline):
                        raise DeadlineExceeded()
            except Exception as exc:  # noqa: BLE001
                error = _stop_line(exc, "the parse of the mail")
            parse.stop()
            if error is not None:
                yield ndjson_line({"type": "error", **error, "emitted": n})
            result = parse.result(error["error"] if error else None)
            stats = result["stats"]
            if result.get("members"):
                stats.update(_members_line_stats(result["members"]))
            yield ndjson_line({"type": "done", "format": parse.format, "stats": stats, "emitted": n, "sha256": src.sha256, "parser": build_id()})
        finally:
            if parse is not None:
                parse.close()
            src.cleanup()

    return _stream(gen())


# ---------------------------------------------------------------------------
# Single attachment analysis (drag & drop a file to analyse it alone)
# ---------------------------------------------------------------------------
@permission("work")
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
    # the analysers (oletools, pypdf, YARA, the archive readers) read the file in a process of its own
    parse = isolation.start(
        "attachment",
        name=f.name,
        path=None,
        data=data,
        tmp_dir=str(settings.FILE_UPLOAD_TEMP_DIR),
        options={"content_type": f.content_type},
        deadline=_deadline(),
    )
    try:
        for _row in parse:
            pass
    except DeadlineExceeded:
        return JsonResponse({"error": DEADLINE_REASON}, status=422)
    except ParseStopped as exc:
        return JsonResponse({"error": str(exc)}, status=422)
    finally:
        parse.close()
    return JsonResponse({"type": "attachment", "result": parse.result()["result"]})


@permission("work")
@require_POST
def ingest_package(request: HttpRequest):
    if (err := _too_large(request)) is not None:
        return err
    dates, err = _dates(request)
    if err is not None:
        return err
    src = _Source(request)
    if src.error is not None:
        return src.error
    source_name = str(request.POST.get("sourceName") or src.name)[:2048]
    engines = hayabusa.engines() if request.POST.get("engines", "1") != "0" else []
    options = {
        "ctx": _ctx_from_request(request),
        "include_raw": request.POST.get("raw", "1") != "0",
        "package_id": src.sha256,
        "engines": engines,
        "filesystem": request.POST.get("filesystem") == "1",
        "dates": dates,
    }
    tmp_dir = str(settings.FILE_UPLOAD_TEMP_DIR)

    def gen() -> Iterator[bytes]:
        deadline = _deadline()
        parse = None
        stopped = None
        budget = None
        try:
            budget = request_budget(claim=True)
            parse = isolation.start(
                "package", name=source_name, path=src.path, data=src.data, tmp_dir=tmp_dir, options={**options, "budget": budget}, deadline=deadline
            )
            yield ndjson_line({"type": "meta", "format": parse.format, "name": src.name, "size": src.size, "sha256": src.sha256, "engines": engines})
            try:
                for row in parse:
                    yield ndjson_line(row)
                    if _expired(deadline):
                        raise DeadlineExceeded()
            except (DeadlineExceeded, ParseStopped) as exc:
                stopped = _stop_line(exc, "the parse of the package")["error"]
            if stopped:
                # stopping the parse runs the package's own clean-up, which releases every artifact
                # it was holding back for group decoding
                parse.stop()
                yield ndjson_line({"type": "error", "error": stopped})
            result = parse.result(stopped)
            yield from _engine_lines(parse, result)
            yield ndjson_line({"type": "done", "format": parse.format, "stats": result["stats"], "sha256": src.sha256})
        except Exception as exc:  # noqa: BLE001
            line = failure("the parse of the package", exc, log)
            yield ndjson_line({"type": "error", **line})
            if parse is not None:
                parse.stop()
                yield ndjson_line({"type": "done", "format": parse.format, "stats": parse.result(stopped or line["error"])["stats"], "sha256": src.sha256})
        finally:
            if parse is not None:
                parse.close()
            if budget is not None:
                staging.release(budget["claim"])
            src.cleanup()

    return _stream(gen())
