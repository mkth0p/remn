"""
Server-store endpoints (DuckDB case store for gigabyte-scale cases): ingestion
jobs, bulk import, search / aggregate / timeline / facets / detail / pivot,
IOCs and reputation, rule runs, read-only SQL, deletion.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Iterator

from django.conf import settings
from django.http import HttpRequest, JsonResponse, StreamingHttpResponse
from django.views.decorators.http import require_GET, require_POST, require_http_methods

from api.jobs import Job, manager
from api.views.upload import discard_upload, get_upload
from services.common import ndjson_line
from services.ingest.pipeline import EvtxSource, MailSource, MailStats
from services.parsers import evtx_parser
from services.parsers.mail.common import ParseContext
from services.store import queries as Q
from services.store import rules as R
from services.store.casestore import registry
from services.store.sqlfilter import FilterError
from services.store.writers import EventWriter, MailWriter

log = logging.getLogger(__name__)


def _json(request: HttpRequest) -> dict[str, Any]:
    try:
        return json.loads(request.body or b"{}")
    except ValueError:
        return {}


def _store(key: str, create: bool = True):
    try:
        return registry.get(key, create=create), None
    except ValueError:
        return None, JsonResponse({"error": "invalid case key"}, status=400)
    except FileNotFoundError:
        return None, JsonResponse({"error": "unknown case store"}, status=404)


def _ctx_from(settings_obj: dict[str, Any] | None) -> ParseContext:
    s = settings_obj or {}
    return ParseContext(
        internal_domains=[str(x) for x in (s.get("internalDomains") or s.get("internal_domains") or []) if x],
        brands=[str(x) for x in (s.get("brands") or []) if x],
        vip_names=[str(x) for x in (s.get("vipNames") or s.get("vip_names") or []) if x],
        include_html=bool(s.get("includeHtml", True)),
        include_headers=bool(s.get("includeHeaders", True)),
        analyze_attachments=bool(s.get("analyzeAttachments", True)),
        trusted_senders=[str(x) for x in (s.get("trustedSenders") or s.get("trusted_senders") or []) if x],
    )


# ---------------------------------------------------------------------------
# listing / lifecycle
# ---------------------------------------------------------------------------
@require_GET
def list_stores(request: HttpRequest):
    return JsonResponse({"stores": registry.list(), "root": str(settings.CASES_DIR), "thresholdMb": settings.FORENSIC_STORE_THRESHOLD_MB})


@require_http_methods(["GET", "DELETE"])
def store_root(request: HttpRequest, key: str):
    if request.method == "DELETE":
        try:
            ok = registry.delete(key)
        except ValueError:
            return JsonResponse({"error": "invalid case key"}, status=400)
        return JsonResponse({"deleted": ok})
    st, err = _store(key, create=False)
    if err:
        return err
    return JsonResponse(Q.summary(st))


@require_http_methods(["DELETE"])
def delete_evidence(request: HttpRequest, key: str, evidence_id: int):
    st, err = _store(key, create=False)
    if err:
        return err
    return JsonResponse({"deleted": st.delete_evidence(int(evidence_id))})


# ---------------------------------------------------------------------------
# ingestion job (chunked upload -> parse -> DuckDB)
# ---------------------------------------------------------------------------
@require_POST
def ingest(request: HttpRequest, key: str):
    st, err = _store(key)
    if err:
        return err
    body = _json(request)
    upload_id = str(body.get("uploadId") or "")
    kind = str(body.get("kind") or "")
    evidence = body.get("evidence") or {}
    options = body.get("options") or {}
    if kind not in ("evtx", "mail"):
        return JsonResponse({"error": "kind must be evtx or mail"}, status=400)
    try:
        path, meta = get_upload(upload_id)
    except (FileNotFoundError, ValueError):
        return JsonResponse({"error": "upload not found or incomplete"}, status=404)
    try:
        evidence_id = int(evidence.get("id"))
    except (TypeError, ValueError):
        return JsonResponse({"error": "evidence.id is required"}, status=400)
    name = str(evidence.get("name") or meta.get("name") or "upload")
    sha_client = str(evidence.get("sha256Client") or "")
    ctx = _ctx_from(options.get("settings"))
    include_raw = bool(options.get("includeRaw", True))
    keep_bodies = bool(options.get("keepBodies", True))
    tmp_dir = str(settings.FILE_UPLOAD_TEMP_DIR)

    st.upsert_evidence({"id": evidence_id, "name": name, "kind": kind, "size": meta.get("size"), "sha256Client": sha_client or None,
                        "sha256Server": meta.get("sha256"), "count": 0, "stats": None, "addedAt": evidence.get("addedAt") or int(time.time() * 1000), "status": "parsing"})

    def run(job: Job) -> dict[str, Any]:
        job.update(rows=0, bytes=meta.get("size"), phase="parsing", name=name)
        t0 = time.time()
        count = 0
        last = 0.0
        try:
            if kind == "evtx":
                src = EvtxSource(name, str(path), None, tmp_dir, include_raw=include_raw)
                w = EventWriter(st, evidence_id, include_raw=include_raw)
                for row in src:
                    w.add(row)
                    count += 1
                    if time.time() - last > 0.5:
                        job.update(rows=count, format=src.format, files=len(src.files))
                        job.check()
                        last = time.time()
                w.flush()
                stats = src.stats.to_dict()
                stats["files"] = src.files
                fmt = src.format
            else:
                src2 = MailSource(name, str(path), None, ctx, tmp_dir)
                mw = MailWriter(st, evidence_id, keep_bodies=keep_bodies)
                for row in src2:
                    mw.add(row)
                    count += 1
                    if time.time() - last > 0.5:
                        job.update(rows=count, format=src2.format)
                        job.check()
                        last = time.time()
                mw.flush()
                stats = src2.stats.to_dict()
                fmt = src2.format
        except Exception:
            st.upsert_evidence({"id": evidence_id, "name": name, "kind": kind, "size": meta.get("size"), "sha256Client": sha_client or None,
                                "sha256Server": meta.get("sha256"), "count": count, "stats": None, "addedAt": evidence.get("addedAt"), "status": "error"})
            raise
        finally:
            discard_upload(upload_id)
        integrity = "verified" if (sha_client and sha_client == meta.get("sha256")) else ("mismatch" if sha_client else "pending")
        st.upsert_evidence({"id": evidence_id, "name": name, "kind": kind, "format": fmt, "size": meta.get("size"), "sha256Client": sha_client or None,
                            "sha256Server": meta.get("sha256"), "count": count, "stats": stats, "addedAt": evidence.get("addedAt"), "status": "done"})
        job.update(rows=count, phase="done", seconds=round(time.time() - t0, 1))
        return {"count": count, "stats": stats, "sha256Server": meta.get("sha256"), "integrity": integrity, "format": fmt, "evidenceId": evidence_id,
                "seconds": round(time.time() - t0, 1)}

    job = manager.submit("ingest", key, run, label=name)
    return JsonResponse({"jobId": job.id})


# ---------------------------------------------------------------------------
# bundle export (rows back out of DuckDB, in /import wire format)
# ---------------------------------------------------------------------------
def _nest_mail(r: dict[str, Any]) -> dict[str, Any]:
    """Reshape a flat mails-table row (+joined children) into the nested
    build_row shape that MailWriter.add (and therefore /import) consumes."""
    r = dict(r)
    r.pop("id", None)
    r["auth"] = {k: r.pop(k, None) for k in ("spf", "dkim", "dmarc", "compauth")}
    rt_list = r.pop("replyToList", None) or []
    rt_addr, rt_dom = r.pop("replyToAddr", None), r.pop("replyToDomain", None)
    if rt_list:
        r["replyTo"] = [{"addr": a, "domain": a.split("@", 1)[1] if isinstance(a, str) and "@" in a else None} for a in rt_list]
    elif rt_addr:
        r["replyTo"] = [{"addr": rt_addr, "domain": rt_dom}]
    else:
        r["replyTo"] = []
    for nm in ("to", "cc", "bcc"):
        r[nm] = [{"addr": a} for a in (r.pop(nm + "List", None) or [])]
    sa = r.pop("senderAddr", None)
    r["sender"] = {"addr": sa} if sa else None
    rw, roi = r.pop("reputationWorst", None), r.pop("reputationOriginIp", None)
    if rw or roi:
        r["reputation"] = {"worst": rw, "originIp": {"verdict": roi} if roi else None}
    return r


@require_GET
def export_rows(request: HttpRequest, key: str):
    """Stream every stored row as NDJSON in the exact format /import accepts:
    {"type":"evidence"|"event"|"mail", ...}. Event and mail lines keep their
    original evidenceId so the importer can regroup them per evidence."""
    st, err = _store(key)
    if err:
        return err

    def gen() -> Iterator[bytes]:
        cur = st.cursor()
        cur.execute("SELECT * FROM evidence ORDER BY id")
        for ev in Q.rows_to_dicts(cur, json_columns=("stats",)):
            yield ndjson_line({"type": "evidence", **ev})
        last = -1
        while True:
            cur.execute("SELECT * FROM events WHERE id > ? ORDER BY id LIMIT 5000", [last])
            rows = Q.rows_to_dicts(cur)
            if not rows:
                break
            last = rows[-1]["id"]
            for r in rows:
                if isinstance(r.get("data"), str):
                    try:
                        r["data"] = json.loads(r["data"])
                    except ValueError:
                        pass
                r.pop("id", None)
                yield ndjson_line({"type": "event", **r})
        last = -1
        while True:
            cur.execute("SELECT * FROM mails WHERE id > ? ORDER BY id LIMIT 500", [last])
            page = Q.rows_to_dicts(cur)
            if not page:
                break
            page = Q._parse_json_cols(page, "mails")
            last = page[-1]["id"]
            ids = [int(r["id"]) for r in page]
            ph = ", ".join("?" for _ in ids)
            cur.execute(f'SELECT * FROM attachments WHERE "mailId" IN ({ph}) ORDER BY id', ids)
            atts: dict[int, list] = {}
            for a in Q.rows_to_dicts(cur, json_columns=("details",)):
                atts.setdefault(int(a["mailId"]), []).append(a)
            cur.execute(f'SELECT * FROM urls WHERE "mailId" IN ({ph}) ORDER BY id', ids)
            urls: dict[int, list] = {}
            for u in Q.rows_to_dicts(cur):
                urls.setdefault(int(u["mailId"]), []).append(u)
            cur.execute(f'SELECT * FROM mail_bodies WHERE "mailId" IN ({ph})', ids)
            bodies = {int(b["mailId"]): b for b in Q.rows_to_dicts(cur)}
            for r in page:
                mid = int(r["id"])
                r["attachments"] = atts.get(mid, [])
                r["urls"] = urls.get(mid, [])
                b = bodies.get(mid) or {}
                for k in ("bodyText", "bodyHtml", "headersText", "visibleText"):
                    if r.get(k) is None:
                        r[k] = b.get(k)
                yield ndjson_line({"type": "mail", **_nest_mail(r)})

    resp = StreamingHttpResponse(gen(), content_type="application/x-ndjson")
    resp["Cache-Control"] = "no-store"
    resp["X-Accel-Buffering"] = "no"
    return resp


@require_POST
def import_rows(request: HttpRequest, key: str):
    """Bulk import of already-parsed rows (NDJSON body: {"type":"event"|"mail", ...}). Used to migrate a browser case to the server store."""
    st, err = _store(key)
    if err:
        return err
    try:
        evidence_id = int(request.GET.get("evidenceId", "0"))
    except ValueError:
        return JsonResponse({"error": "bad evidenceId"}, status=400)
    include_raw = request.GET.get("raw", "1") not in ("0", "false")
    ew = EventWriter(st, evidence_id, include_raw=include_raw)
    mw = MailWriter(st, evidence_id, keep_bodies=True)
    n_e = n_m = 0
    stats = evtx_parser.Stats()
    mstats = MailStats()
    while True:
        line = request.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        t = row.pop("type", None)
        if t == "event":
            ew.add(row)
            stats.add(row)
            n_e += 1
        elif t == "mail":
            mw.add(row)
            mstats.add(row)
            n_m += 1
        elif t == "evidence":
            st.upsert_evidence(row)
    ew.flush()
    mw.flush()
    return JsonResponse({"events": n_e, "mails": n_m, "eventStats": stats.to_dict() if n_e else None, "mailStats": mstats.to_dict() if n_m else None})


# ---------------------------------------------------------------------------
# queries
# ---------------------------------------------------------------------------
def _query(request: HttpRequest, key: str, fn):
    st, err = _store(key, create=False)
    if err:
        return err
    body = _json(request) if request.method == "POST" else {}
    try:
        return JsonResponse(fn(st, body), safe=False)
    except FilterError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    except Exception as exc:  # noqa: BLE001
        log.exception("store query failed")
        return JsonResponse({"error": str(exc)[:300]}, status=500)


@require_POST
def search(request: HttpRequest, key: str):
    return _query(request, key, lambda st, b: Q.search(st, str(b.get("source") or "events"), b.get("filter"), int(b.get("limit") or 2000), int(b.get("offset") or 0),
                                                       b.get("sort"), b.get("settings"), bool(b.get("full"))))


@require_POST
def count(request: HttpRequest, key: str):
    return _query(request, key, lambda st, b: {"count": Q.count(st, str(b.get("source") or "events"), b.get("filter"), b.get("settings"))})


@require_POST
def aggregate(request: HttpRequest, key: str):
    return _query(request, key, lambda st, b: Q.aggregate(st, str(b.get("source") or "events"), b.get("filter"), str(b.get("field") or "eventId"), int(b.get("limit") or 25), b.get("settings")))


@require_POST
def timeline(request: HttpRequest, key: str):
    return _query(request, key, lambda st, b: Q.timeline(st, str(b.get("source") or "events"), b.get("filter"), str(b.get("bucket") or "hour"), b.get("settings")))


@require_GET
def facets(request: HttpRequest, key: str):
    st, err = _store(key, create=False)
    if err:
        return err
    try:
        return JsonResponse(Q.facets(st, request.GET.get("source", "events"), request.GET.get("field", "eventId"), int(request.GET.get("limit", "50"))), safe=False)
    except FilterError as exc:
        return JsonResponse({"error": str(exc)}, status=400)


@require_GET
def row(request: HttpRequest, key: str):
    st, err = _store(key, create=False)
    if err:
        return err
    try:
        r = Q.get_row(st, request.GET.get("source", "events"), int(request.GET.get("id", "0")))
    except ValueError:
        return JsonResponse({"error": "bad id"}, status=400)
    if r is None:
        return JsonResponse({"error": "not found"}, status=404)
    return JsonResponse(r)


@require_POST
def pivot(request: HttpRequest, key: str):
    return _query(request, key, lambda st, b: Q.pivot(st, str(b.get("value") or "")))


@require_GET
def iocs(request: HttpRequest, key: str):
    st, err = _store(key, create=False)
    if err:
        return err
    g = request.GET
    return JsonResponse(Q.list_iocs(st, g.get("kind") or None, g.get("q") or None, g.get("bad") in ("1", "true"), g.get("unchecked") in ("1", "true"),
                                    int(g.get("limit", "500")), int(g.get("offset", "0")), g.get("sort", "verdict")))


@require_POST
def reputation(request: HttpRequest, key: str):
    st, err = _store(key, create=False)
    if err:
        return err
    body = _json(request)
    items = [it for it in (body.get("items") or []) if isinstance(it, dict) and it.get("kind") and it.get("value")]
    n = st.set_reputation(items)
    mirrored = st.mirror_reputation_to_mails()
    return JsonResponse({"stored": n, "mailsFlagged": mirrored})


@require_POST
def sql(request: HttpRequest, key: str):
    return _query(request, key, lambda st, b: Q.run_sql(st, str(b.get("sql") or ""), int(b.get("limit") or 200)))


@require_GET
def schema(request: HttpRequest, key: str):
    return JsonResponse({"schema": Q.SCHEMA_DOC})


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------
@require_POST
def rules_run(request: HttpRequest, key: str):
    st, err = _store(key, create=False)
    if err:
        return err
    body = _json(request)
    rules = [r for r in (body.get("rules") or []) if isinstance(r, dict) and r.get("id")]
    rule_settings = body.get("settings") or {}
    if not rules:
        return JsonResponse({"error": "rules are required"}, status=400)

    def run(job: Job) -> dict[str, Any]:
        job.update(index=0, total=len(rules))
        return R.run_rules(st, rules, rule_settings, progress=lambda p: job.update(**p), cancelled=lambda: job.cancelled)

    job = manager.submit("rules", key, run, label=f"{len(rules)} rules")
    return JsonResponse({"jobId": job.id})


# ---------------------------------------------------------------------------
# jobs
# ---------------------------------------------------------------------------
@require_GET
def jobs_list(request: HttpRequest):
    return JsonResponse({"jobs": manager.list(request.GET.get("case") or None)})


@require_http_methods(["GET", "DELETE"])
def job_detail(request: HttpRequest, job_id: str):
    job = manager.get(job_id)
    if not job:
        return JsonResponse({"error": "unknown job"}, status=404)
    if request.method == "DELETE":
        manager.cancel(job_id)
        return JsonResponse({"cancelled": True})
    return JsonResponse(job.to_dict(with_result=job.status in ("done", "error", "cancelled")))


@require_GET
def job_events(request: HttpRequest, job_id: str):
    """SSE stream of job progress (polling fallback: GET /api/jobs/<id>)."""
    job = manager.get(job_id)
    if not job:
        return JsonResponse({"error": "unknown job"}, status=404)

    def gen() -> Iterator[bytes]:
        last = None
        while True:
            d = job.to_dict(with_result=job.status in ("done", "error", "cancelled"))
            snap = json.dumps(d.get("progress")) + d["status"]
            if snap != last:
                yield f"data: {json.dumps(d)}\n\n".encode("utf-8")
                last = snap
            if d["status"] in ("done", "error", "cancelled"):
                break
            time.sleep(0.5)

    resp = StreamingHttpResponse(gen(), content_type="text/event-stream; charset=utf-8")
    resp["Cache-Control"] = "no-store"
    return resp


def _unused() -> None:
    _ = ndjson_line
