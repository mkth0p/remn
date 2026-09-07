"""Read queries over a case store: search, count, aggregate, timeline, facets, pivot, summary, detail, IOCs, raw SQL."""

from __future__ import annotations

import json
import re
import threading
from datetime import UTC
from typing import Any

import duckdb

from services.store.casestore import MAIL_JSON, CaseStore, q, rows_to_dicts
from services.store.sqlfilter import TEXT_FIELDS_EVENTS, Ctx, FilterError, compile_filter, order_by, resolve

HARD_CAP = 20000
EVENT_LIST_COLUMNS = [
    c
    for c in (
        "id",
        "evidenceId",
        "sourceFile",
        "recordId",
        "ts",
        "tsIso",
        "eventId",
        "level",
        "levelName",
        "provider",
        "channel",
        "computer",
        "category",
        "description",
        "summary",
        "targetUser",
        "targetDomain",
        "subjectUser",
        "subjectDomain",
        "logonType",
        "logonTypeName",
        "ipAddress",
        "ipPort",
        "workstation",
        "status",
        "subStatus",
        "statusText",
        "authPackage",
        "processName",
        "commandLine",
        "parentProcessName",
        "serviceName",
        "serviceFile",
        "taskName",
        "memberName",
        "groupName",
        "shareName",
        "relativeTargetName",
        "objectName",
        "scriptBlockText",
        "image",
        "parentImage",
        "destinationIp",
        "destinationPort",
        "query",
        "targetFilename",
        "targetObject",
        "threatName",
        "path",
        "message",
        "userSid",
        "processId",
        "threadId",
        "activityId",
        "keywords",
        "task",
        "opcode",
    )
]
MAIL_LIST_EXCLUDE = {"hops", "htmlInfo", "hiddenText", "references"}
BUCKET_MS = {"minute": 60_000, "hour": 3_600_000, "day": 86_400_000}
_SQL_FORBIDDEN = re.compile(
    r"(?i)\b(attach|detach|copy|export|import|install|load|pragma|set|reset|create|insert|update|delete|drop|alter|call|checkpoint|vacuum|force|read_csv|read_json|read_parquet|read_text|read_blob|glob|getenv)\b"
)


def _ctx(source: str, settings: dict[str, Any] | None) -> Ctx:
    if source not in ("events", "mails"):
        raise FilterError("source must be events or mails")
    return Ctx(source=source, settings=settings or {})


def _parse_json_cols(rows: list[dict[str, Any]], source: str) -> list[dict[str, Any]]:
    if source != "mails":
        return rows
    for r in rows:
        for k in MAIL_JSON:
            v = r.get(k)
            if isinstance(v, str):
                try:
                    r[k] = json.loads(v)
                except ValueError:
                    pass
    return rows


def search(
    store: CaseStore,
    source: str,
    flt: dict[str, Any] | None,
    limit: int = 2000,
    offset: int = 0,
    sort: dict[str, Any] | None = None,
    settings: dict[str, Any] | None = None,
    full: bool = False,
) -> dict[str, Any]:
    ctx = _ctx(source, settings)
    where = compile_filter(flt, ctx)
    order = order_by(sort or (flt or {}).get("sort"), ctx)
    limit = max(1, min(int(limit), HARD_CAP))
    if source == "events":
        cols = "*" if full else ", ".join(q(c) for c in EVENT_LIST_COLUMNS)
    else:
        from services.store.casestore import MAIL_COLUMNS

        cols = "*" if full else ", ".join(q(n) for n, _ in MAIL_COLUMNS if n not in MAIL_LIST_EXCLUDE)
    sql = f"SELECT {cols} FROM {source} WHERE {where} {order} LIMIT {limit + 1} OFFSET {int(offset)}"
    cur = store.cursor()
    cur.execute(sql, ctx.params)
    rows = rows_to_dicts(cur)
    truncated = len(rows) > limit
    rows = _parse_json_cols(rows[:limit], source)
    if source == "events" and full:
        for r in rows:
            if isinstance(r.get("data"), str):
                try:
                    r["data"] = json.loads(r["data"])
                except ValueError:
                    pass
    return {"rows": rows, "truncated": truncated, "offset": offset, "limit": limit}


def count(store: CaseStore, source: str, flt: dict[str, Any] | None, settings: dict[str, Any] | None = None) -> int:
    ctx = _ctx(source, settings)
    where = compile_filter(flt, ctx)
    cur = store.cursor()
    return int(cur.execute(f"SELECT count(*) FROM {source} WHERE {where}", ctx.params).fetchone()[0])


def _group_expr(source: str, field: str, ctx: Ctx) -> tuple[str, str]:
    """Return (from_clause_suffix, expression) handling list fields and virtual facets."""
    ts_field = "date" if source == "mails" else "ts"
    if source == "mails" and field == "riskBand":
        return "", "CASE WHEN risk >= 80 THEN 'critical' WHEN risk >= 60 THEN 'high' WHEN risk >= 40 THEN 'medium' WHEN risk >= 20 THEN 'low' ELSE 'clean' END"
    if source == "mails" and field == "attExt":
        return ", UNNEST(list_transform(coalesce(json_extract_string(attachments, '$[*].realExt'), []), x -> coalesce(nullif(x, ''), '?'))) AS _u(v)", "_u.v"
    e = resolve(field, ctx)
    if e.kind == "list":
        return f", UNNEST({e.sql}) AS _u(v)", "_u.v"
    _ = ts_field
    return "", f"CAST({e.sql} AS VARCHAR)"


def aggregate(store: CaseStore, source: str, flt: dict[str, Any] | None, field: str, limit: int = 25, settings: dict[str, Any] | None = None) -> dict[str, Any]:
    ctx = _ctx(source, settings)
    where = compile_filter(flt, ctx)
    ts_field = "date" if source == "mails" else "ts"
    suffix, expr = _group_expr(source, field, ctx)
    limit = max(1, min(int(limit), 5000))
    sql = (
        f"SELECT coalesce({expr}, '(empty)') AS value, count(*) AS count, min({q(ts_field)}) AS first, max({q(ts_field)}) AS last "
        f"FROM {source}{suffix} WHERE {where} GROUP BY 1 ORDER BY count DESC, value LIMIT {limit}"
    )
    cur = store.cursor()
    cur.execute(sql, ctx.params)
    groups = rows_to_dicts(cur)
    ctx2 = _ctx(source, settings)
    where2 = compile_filter(flt, ctx2)
    totals = cur.execute(f"SELECT count(*), count(DISTINCT {expr}) FROM {source}{suffix} WHERE {where2}", ctx2.params).fetchone()
    return {"field": field, "groups": groups, "total": int(totals[0]), "distinct": int(totals[1])}


def timeline(store: CaseStore, source: str, flt: dict[str, Any] | None, bucket: str = "hour", settings: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    ctx = _ctx(source, settings)
    where = compile_filter(flt, ctx)
    ts_field = "date" if source == "mails" else "ts"
    size = BUCKET_MS.get(bucket, BUCKET_MS["hour"])
    sql = f"SELECT ({q(ts_field)} // {size}) * {size} AS t, count(*) AS count FROM {source} WHERE {q(ts_field)} IS NOT NULL AND {where} GROUP BY 1 ORDER BY 1"
    cur = store.cursor()
    cur.execute(sql, ctx.params)
    return [{"t": int(t), "count": int(c)} for t, c in cur.fetchall()]


def facets(store: CaseStore, source: str, field: str, limit: int = 50) -> list[dict[str, Any]]:
    res = aggregate(store, source, None, field, limit)
    return [{"value": g["value"], "count": g["count"]} for g in res["groups"]]


def get_row(store: CaseStore, source: str, row_id: int) -> dict[str, Any] | None:
    cur = store.cursor()
    if source == "events":
        cur.execute("SELECT * FROM events WHERE id = ?", [int(row_id)])
        rows = rows_to_dicts(cur)
        if not rows:
            return None
        r = rows[0]
        if isinstance(r.get("data"), str):
            try:
                r["data"] = json.loads(r["data"])
            except ValueError:
                pass
        return r
    cur.execute("SELECT * FROM mails WHERE id = ?", [int(row_id)])
    rows = _parse_json_cols(rows_to_dicts(cur), "mails")
    if not rows:
        return None
    r = rows[0]
    cur.execute('SELECT * FROM attachments WHERE "mailId" = ? ORDER BY id', [int(row_id)])
    atts = rows_to_dicts(cur, json_columns=("details",))
    r["attachments"] = atts
    cur.execute('SELECT * FROM urls WHERE "mailId" = ? ORDER BY id', [int(row_id)])
    r["urls"] = rows_to_dicts(cur)
    cur.execute('SELECT * FROM mail_bodies WHERE "mailId" = ?', [int(row_id)])
    bodies = rows_to_dicts(cur)
    r["body"] = bodies[0] if bodies else None
    return r


def pivot(store: CaseStore, value: str) -> dict[str, Any]:
    needle = "%" + value.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    res: dict[str, Any] = {
        "value": value,
        "events": {"count": 0, "first": None, "last": None, "byEventId": {}, "fields": {}},
        "mails": {"count": 0, "first": None, "last": None, "fields": {}},
    }
    if not value.strip():
        return res
    cur = store.cursor()
    ev_fields = [f for f in TEXT_FIELDS_EVENTS if f != "raw"] + ["hashes", "memberName", "sourceIp", "hashes"]
    ev_fields = list(dict.fromkeys(ev_fields))
    hits = " OR ".join(f"lower({q(f)}) LIKE ? ESCAPE '\\'" for f in ev_fields)
    params = [needle] * len(ev_fields)
    cur.execute(f"SELECT count(*), min(ts), max(ts) FROM events WHERE {hits} OR lower(\"raw\") LIKE ? ESCAPE '\\'", params + [needle])
    c, first, last = cur.fetchone()
    res["events"].update({"count": int(c), "first": first, "last": last})
    if c:
        cur.execute(
            f'SELECT "eventId", count(*) FROM events WHERE {hits} OR lower("raw") LIKE ? ESCAPE \'\\\' GROUP BY 1 ORDER BY 2 DESC LIMIT 12', params + [needle]
        )
        res["events"]["byEventId"] = {str(k): int(v) for k, v in cur.fetchall()}
        for f in ev_fields:
            n = cur.execute(f"SELECT count(*) FROM events WHERE lower({q(f)}) LIKE ? ESCAPE '\\'", [needle]).fetchone()[0]
            if n:
                res["events"]["fields"][f] = int(n)
    m_fields = ["fromAddr", "fromName", "fromDomain", "subject", "originIp", "returnPath", "messageId", "textPreview", "replyToAddr"]
    mhits = " OR ".join(f"lower({q(f)}) LIKE ? ESCAPE '\\'" for f in m_fields)
    mparams = [needle] * len(m_fields)
    extra = (
        "OR EXISTS (SELECT 1 FROM urls u WHERE u.\"mailId\" = mails.id AND lower(u.url) LIKE ? ESCAPE '\\') "
        "OR EXISTS (SELECT 1 FROM attachments a WHERE a.\"mailId\" = mails.id AND (lower(a.sha256) = ? OR lower(a.md5) = ? OR lower(a.name) LIKE ? ESCAPE '\\'))"
    )
    v = value.strip().lower()
    cur.execute(f"SELECT count(*), min(date), max(date) FROM mails WHERE {mhits} {extra}", mparams + [needle, v, v, needle])
    c, first, last = cur.fetchone()
    res["mails"].update({"count": int(c), "first": first, "last": last})
    if c:
        for f in m_fields:
            n = cur.execute(f"SELECT count(*) FROM mails WHERE lower({q(f)}) LIKE ? ESCAPE '\\'", [needle]).fetchone()[0]
            if n:
                res["mails"]["fields"][f] = int(n)
    return res


def summary(store: CaseStore) -> dict[str, Any]:
    cur = store.cursor()
    counts = store.counts()
    ev = cur.execute("SELECT min(ts), max(ts) FROM events").fetchone()
    ml = cur.execute("SELECT min(date), max(date) FROM mails").fetchone()
    top_ids = cur.execute('SELECT "eventId", count(*) FROM events GROUP BY 1 ORDER BY 2 DESC LIMIT 15').fetchall()
    top_comp = cur.execute("SELECT computer, count(*) FROM events WHERE computer IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 10").fetchall()
    top_send = cur.execute(
        'SELECT "fromAddr", count(*) FROM mails WHERE "fromAddr" IS NOT NULL AND "fromAddr" <> \'\' GROUP BY 1 ORDER BY 2 DESC LIMIT 10'
    ).fetchall()
    top_flags = cur.execute("SELECT f, count(*) FROM mails, UNNEST(flags) AS t(f) GROUP BY 1 ORDER BY 2 DESC LIMIT 15").fetchall()
    evidence = rows_to_dicts(cur.execute("SELECT * FROM evidence ORDER BY id"), json_columns=("stats",))
    return {
        "counts": counts,
        "sizeBytes": store.size_bytes(),
        "eventsTimeRange": {"first": ev[0], "last": ev[1], "firstIso": _iso(ev[0]), "lastIso": _iso(ev[1])},
        "mailsTimeRange": {"first": ml[0], "last": ml[1], "firstIso": _iso(ml[0]), "lastIso": _iso(ml[1])},
        "topEventIds": [{"eventId": k, "count": int(v)} for k, v in top_ids],
        "topComputers": [{"computer": k, "count": int(v)} for k, v in top_comp],
        "topSenders": [{"from": k, "count": int(v)} for k, v in top_send],
        "topMailFlags": [{"flag": k, "count": int(v)} for k, v in top_flags],
        "evidence": evidence,
    }


def _iso(ms: Any) -> str | None:
    if ms is None:
        return None
    from datetime import datetime

    return datetime.fromtimestamp(int(ms) / 1000, tz=UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def list_iocs(
    store: CaseStore,
    kind: str | None = None,
    text: str | None = None,
    only_bad: bool = False,
    unchecked: bool = False,
    limit: int = 500,
    offset: int = 0,
    sort: str = "verdict",
) -> dict[str, Any]:
    params: list[Any] = []
    where = ["TRUE"]
    if kind:
        where.append("i.kind = ?")
        params.append(kind)
    if text:
        where.append("i.value LIKE ? ESCAPE '\\'")
        params.append("%" + text.lower().replace("%", "\\%").replace("_", "\\_") + "%")
    if only_bad:
        where.append("r.verdict IN ('malicious', 'suspicious')")
    if unchecked:
        where.append('r."checkedAt" IS NULL')
    order = {
        "verdict": "CASE r.verdict WHEN 'malicious' THEN 3 WHEN 'suspicious' THEN 2 WHEN 'clean' THEN 1 ELSE 0 END DESC, count DESC",
        "count": "count DESC",
        "first": '"firstSeen" ASC',
        "last": '"lastSeen" DESC',
        "value": "i.value ASC",
    }.get(sort, "count DESC")
    base = f"""
        FROM (SELECT kind, value, sum(count) AS count, min("firstSeen") AS "firstSeen", max("lastSeen") AS "lastSeen",
                     list_distinct(flatten(list(sources))) AS sources, list(DISTINCT "evidenceId") AS evidence
              FROM iocs GROUP BY kind, value) i
        LEFT JOIN ioc_reputation r ON r.kind = i.kind AND r.value = i.value
        WHERE {" AND ".join(where)}"""
    cur = store.cursor()
    total = int(cur.execute(f"SELECT count(*) {base}", params).fetchone()[0])
    limit = max(1, min(int(limit), 5000))
    cur.execute(
        f'SELECT i.kind, i.value, i.count, i."firstSeen", i."lastSeen", i.sources, i.evidence, r.verdict, r.tags, r.summary, r.verdicts, r."checkedAt" {base} ORDER BY {order} LIMIT {limit} OFFSET {int(offset)}',
        params,
    )
    rows = rows_to_dicts(cur, json_columns=("summary", "verdicts"))
    kinds = {k: int(v) for k, v in cur.execute("SELECT kind, count(*) FROM (SELECT DISTINCT kind, value FROM iocs) GROUP BY 1").fetchall()}
    return {"rows": rows, "total": total, "kinds": kinds, "offset": offset, "limit": limit}


def run_sql(store: CaseStore, sql: str, limit: int = 200, timeout_s: float = 30.0) -> dict[str, Any]:
    """Read-only SQL for the AI tool / power users: SELECT or WITH only, single statement, capped rows and time."""
    s = sql.strip().rstrip(";").strip()
    if ";" in s:
        raise FilterError("only one statement is allowed")
    head = s[:8].lower()
    if not (head.startswith("select") or head.startswith("with") or head.startswith("describe") or head.startswith("show")):
        raise FilterError("only SELECT / WITH queries are allowed")
    if _SQL_FORBIDDEN.search(s):
        raise FilterError("statement contains a forbidden keyword")
    limit = max(1, min(int(limit), 2000))
    wrapped = f"SELECT * FROM ({s}) AS _q LIMIT {limit + 1}" if head.startswith(("select", "with")) else s
    cur = store.cursor()
    timer = threading.Timer(timeout_s, cur.interrupt)
    timer.start()
    try:
        cur.execute(wrapped)
        rows = rows_to_dicts(cur)
    except duckdb.InterruptException as exc:
        raise FilterError(f"query cancelled after {timeout_s:.0f}s") from exc
    finally:
        timer.cancel()
    truncated = len(rows) > limit
    return {"rows": rows[:limit], "truncated": truncated, "columns": [d[0] for d in cur.description] if cur.description else []}


SCHEMA_DOC = """Tables (DuckDB, camelCase columns are quoted with double quotes):
  events(id, "evidenceId", "sourceFile", ts BIGINT epoch-ms, "tsIso", "eventId", provider, channel, computer, "levelName", category, description, summary,
         "targetUser", "targetDomain", "subjectUser", "subjectDomain", "logonType", "ipAddress", "ipPort", workstation, status, "subStatus", "statusText",
         "authPackage", "processName", "commandLine", "parentProcessName", "serviceName", "serviceFile", "taskName", "memberName", "groupName",
         "shareName", "relativeTargetName", "objectName", "scriptBlockText", image, "parentImage", "destinationIp", "destinationPort", query,
         "targetFilename", "targetObject", "threatName", path, message, data JSON-text, raw JSON-text)
  mails(id, "evidenceId", folder, subject, date BIGINT epoch-ms, "dateIso", "fromName", "fromNameNorm", "fromAddr", "fromDomain", "fromRegistrable",
        "replyToAddr", "replyToDomain", "toList" VARCHAR[], "returnPath", "messageId", "originIp", "hopCount", spf, dkim, dmarc, risk, flags VARCHAR[],
        "urlCount", "attachmentCount", "maxAttachmentRisk", "textPreview", "reputationWorst")
  attachments(id, "mailId", name, ext, "realExt", size, sha256, md5, risk, flags VARCHAR[], category)
  urls(id, "mailId", url, defanged, host, domain, flags VARCHAR[], text)
  mail_bodies("mailId", "bodyText", "bodyHtml", "headersText")
  iocs(kind, value, "evidenceId", count, "firstSeen", "lastSeen", sources VARCHAR[]) ; ioc_reputation(kind, value, verdict, tags, "checkedAt")
Helpers: to_timestamp(ts/1000) for dates, list_contains(flags, 'x'), regexp_matches(col, 'pattern', 'i'), time_bucket(INTERVAL '1 hour', to_timestamp(ts/1000))."""
