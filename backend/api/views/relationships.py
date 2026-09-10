"""Build the same relationship model from browser rows or a DuckDB case."""

import json

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_POST

from services.analysis.relationships import FIELDS, ROW_CAP, build
from services.store.casestore import EVENT_COLUMNS, MAIL_COLUMNS, q, registry, rows_to_dicts


@require_POST
def relationships(request):
    try:
        body = json.loads(request.body or b"{}")
        if not isinstance(body, dict):
            raise ValueError("expected a JSON object")
        evidence_id = body.get("evidenceId")
        if evidence_id is not None and (type(evidence_id) is not int or evidence_id <= 0):
            raise ValueError("evidenceId must be a positive integer")
        children_truncated = False
        options = body.get("options", {})
        if not isinstance(options, dict):
            raise ValueError("options must be an object")
        cursor = body.get("cursor", {})
        if not isinstance(cursor, dict) or any(type(cursor.get(k, 0)) is not int or cursor.get(k, 0) < 0 for k in ("events", "mails")):
            raise ValueError("cursor must contain non-negative event and mail IDs")
        page_size = body.get("pageSize", ROW_CAP)
        if type(page_size) is not int or not 1 <= page_size <= ROW_CAP:
            raise ValueError("invalid page size")
        next_cursor = None
        if body.get("storeKey"):
            if settings.FORENSIC_BROWSER_ONLY:
                return JsonResponse({"error": "server stores are unavailable in browser-only mode", "code": "browserOnly"}, status=403)
            try:
                store = registry.get(str(body["storeKey"]), create=False)
            except (ValueError, FileNotFoundError):
                return JsonResponse({"error": "unknown case store"}, status=404)
            cur = store.cursor()
            scope = ' AND "evidenceId" = ?' if evidence_id is not None else ""
            scope_params = [evidence_id] if evidence_id is not None else []
            batches = []
            try:
                process_names = ", ".join(q(n) for n, _ in EVENT_COLUMNS if n in FIELDS)
                process_context = rows_to_dicts(
                    cur.execute(f"SELECT {process_names} FROM events WHERE \"artifactType\" = 'process' {scope} ORDER BY id LIMIT {ROW_CAP + 1}", scope_params)
                )
                if len(process_context) > ROW_CAP:
                    children_truncated = True
                    options["resolveSnapshots"] = False
                    process_context = []
                for table, columns in (("events", EVENT_COLUMNS), ("mails", MAIL_COLUMNS)):
                    names = ", ".join(q(n) for n, _ in columns if n in FIELDS)
                    batches.append(
                        rows_to_dicts(
                            cur.execute(
                                f"SELECT {names} FROM {table} WHERE id > ? {scope} ORDER BY id LIMIT {page_size + 1}", [cursor.get(table, 0), *scope_params]
                            )
                        )
                    )
                events, mails = batches
                if len(events) > page_size or len(mails) > page_size:
                    next_cursor = {
                        table: rows[min(len(rows), page_size) - 1]["id"] if rows else cursor.get(table, 0) for table, rows in zip(("events", "mails"), batches)
                    }
                events, mails = events[:page_size], mails[:page_size]
                by_id = {m["id"]: m for m in mails[:ROW_CAP]}
                for mail in mails:
                    mail["attachments"] = []
                    mail["urls"] = []
                for table, fields, dest in (("attachments", '"mailId", "name", "sha256"', "attachments"), ("urls", '"mailId", "url", "normalized"', "urls")):
                    children = rows_to_dicts(
                        cur.execute(
                            f'SELECT {fields} FROM {table} WHERE "mailId" IN (SELECT id FROM mails WHERE id > ? {scope} ORDER BY id LIMIT {page_size}) ORDER BY id LIMIT 100001',
                            [cursor.get("mails", 0), *scope_params],
                        )
                    )
                    children_truncated |= len(children) > 100000
                    for child in children[:100000]:
                        by_id[child["mailId"]].setdefault(dest, []).append(child)
            finally:
                cur.close()
        else:
            events, mails = body.get("events", []), body.get("mails", [])
            process_context = body.get("processContext", [])
            if body.get("truncated"):
                options["resolveSnapshots"] = False
            for rows in (events, mails, process_context):
                if not isinstance(rows, list) or len(rows) > ROW_CAP + 1 or any(not isinstance(r, dict) for r in rows):
                    raise ValueError(f"events and mails must be arrays of at most {ROW_CAP + 1} records")
            for mail in mails:
                for field in ("urls", "attachments"):
                    if mail.get(field) is not None and not isinstance(mail[field], list):
                        raise ValueError(f"{field} must be an array")
        result = build(events, mails, options, process_context)
        result["cursor"] = next_cursor
        result["stats"]["truncated"] |= bool(body.get("truncated")) or children_truncated
        return JsonResponse(result)
    except (ValueError, TypeError) as exc:
        return JsonResponse({"error": str(exc)[:300]}, status=400)
