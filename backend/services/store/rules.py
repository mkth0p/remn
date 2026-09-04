"""
Server-side rule engine over a case store. Same YAML DSL and finding shape as
frontend/src/rules/engine.ts, executed with SQL (aggregates) plus a streaming
burst detector for windowed rules.
"""
from __future__ import annotations

import re
import time
from typing import Any, Callable

from services.store.casestore import CaseStore, q
from services.store.sqlfilter import Ctx, FilterError, compile_cond, resolve

SEVERITIES = ["info", "low", "medium", "high", "critical"]
_DUR = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?\s*$", re.I)
_THR = re.compile(r"^\s*(>=|<=|==|=|>|<|!=)?\s*(\d+)\s*$")
MAX_FINDINGS = 2000
MAX_REFS = 500
COLLAPSE_AFTER = 200
# Entity fields that make sense as a collapse key (avoid grouping by free text such as subject/commandLine).
_GROUPABLE = {
    "events": ["computer", "targetUser", "subjectUser", "ipAddress", "processName", "serviceName", "memberName", "groupName", "shareName", "image", "destinationIp", "query"],
    "mails": ["fromAddr", "fromDomain", "fromRegistrable", "fromNameNorm", "originIp", "replyToDomain", "folder"],
}


def sev_rank(s: Any) -> int:
    return SEVERITIES.index(s) if s in SEVERITIES else 0


def parse_duration(v: Any) -> int | None:
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return int(v * 1000)
    m = _DUR.match(str(v))
    if not m:
        return None
    n = float(m.group(1))
    unit = (m.group(2) or "s").lower()
    return int(n * {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000, "w": 604_800_000}[unit])


def parse_threshold(v: Any) -> tuple[str, int] | None:
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return (">=", int(v))
    m = _THR.match(str(v))
    if not m:
        return None
    return (m.group(1) or ">=", int(m.group(2)))


def _cmp(op: str, n: int, v: int) -> bool:
    return {">=": n >= v, ">": n > v, "<=": n <= v, "<": n < v, "==": n == v, "=": n == v, "!=": n != v}[op]


def _default_entities(rule: dict[str, Any]) -> list[str]:
    if rule.get("entities"):
        return list(rule["entities"])
    if rule.get("group_by"):
        return list(rule["group_by"])
    return ["fromAddr", "fromDomain", "subject", "originIp"] if rule["source"] == "mails" else ["computer", "targetUser", "subjectUser", "ipAddress", "processName", "serviceName"]


def _time_sql(rule: dict[str, Any], settings: dict[str, Any], ctx: Ctx, ts_field: str) -> str | None:
    t = rule.get("time")
    if not t or not (t.get("outside_business_hours") or t.get("weekend") or t.get("hours")):
        return None
    bh = settings.get("businessHours") or {"start": 8, "end": 19, "tz": "UTC"}
    start, end = (t.get("hours") or [bh.get("start", 8), bh.get("end", 19)])[:2]
    weekend = settings.get("weekendDays") or [0, 6]
    field = t.get("field") or ts_field
    tz = str(bh.get("tz") or "UTC")

    def local() -> str:  # one placeholder per use
        return f"timezone({ctx.p(tz)}, to_timestamp({q(field)} / 1000.0))"

    start, end = int(start), int(end)
    parts = []
    if t.get("outside_business_hours") or (not t.get("weekend") and t.get("hours")):
        if start < end:
            parts.append(f"NOT (hour({local()}) BETWEEN {start} AND {end - 1})")
        elif start == end:
            parts.append("FALSE")
        else:
            parts.append(f"(hour({local()}) BETWEEN {end} AND {start - 1})")
    if t.get("weekend"):
        parts.append(f"dayofweek({local()}) IN ({', '.join(str(int(d)) for d in weekend)})" if weekend else "FALSE")
    return f"({q(field)} IS NOT NULL AND (" + " OR ".join(parts) + "))"


def _entity_exprs(fields: list[str], ctx: Ctx) -> list[tuple[str, str]]:
    out = []
    for f in fields:
        try:
            out.append((f, f"CAST({resolve(f, ctx).sql} AS VARCHAR)"))
        except FilterError:
            continue
    return out


def _clean_entities(pairs: list[tuple[str, Any]]) -> dict[str, str]:
    return {k: str(v)[:200] for k, v in pairs if v not in (None, "", "[]")}


def _where_sql(rule: dict[str, Any], settings: dict[str, Any], ctx: Ctx, ts_field: str) -> str:
    where = compile_cond(rule.get("where"), ctx)
    if rule.get("exclude"):
        where += f" AND NOT ({compile_cond(rule['exclude'], ctx)})"
    tsql = _time_sql(rule, settings, ctx, ts_field)
    if tsql:
        where += f" AND {tsql}"
    return where


def run_rule(store: CaseStore, rule: dict[str, Any], settings: dict[str, Any]) -> list[dict[str, Any]]:
    source = rule["source"]
    ts_field = "date" if source == "mails" else "ts"
    ctx = Ctx(source=source, settings=settings)
    req = rule.get("require_setting")
    if req:
        camel = re.sub(r"_([a-z])", lambda m: m.group(1).upper(), req)
        if not (settings.get(req) or settings.get(camel)):
            return []
    where = _where_sql(rule, settings, ctx, ts_field)
    base = {"ruleId": rule["id"], "title": rule.get("title") or rule["id"], "description": rule.get("description"), "severity": rule.get("severity", "medium"),
            "source": source, "attack": list(rule.get("attack") or []), "tags": list(rule.get("tags") or [])}
    entity_fields = _default_entities(rule)
    group_by = list(rule.get("group_by") or [])
    threshold = parse_threshold(rule.get("threshold"))
    window = parse_duration(rule.get("window"))
    then_flags = [(k, v) for o in (rule.get("then_flags") or []) for k, v in dict(o).items()]
    cur = store.cursor()
    findings: list[dict[str, Any]] = []

    if not group_by and not threshold:
        # Per-row rules that match thousands of rows are collapsed into one finding per entity combination
        # (e.g. "logon outside business hours: user X on host Y, 154 times") instead of 2000 identical alerts.
        collapse_after = int(rule.get("collapse_after") or COLLAPSE_AFTER)
        total = int(cur.execute(f"SELECT count(*) FROM {source} WHERE {where}", ctx.params).fetchone()[0])
        if total > collapse_after:
            grouped = dict(rule)
            grouped["group_by"] = [f for f in entity_fields if f in _GROUPABLE.get(source, entity_fields)] or entity_fields[:2]
            grouped["threshold"] = ">= 1"
            grouped.pop("then_flags", None)
            grouped["_collapsed"] = True
            out = run_rule(store, grouped, settings)
            for f in out:
                f["escalation"] = (f.get("escalation") or "") or f"collapsed: {total:,} matching rows"
            return out
        ents = _entity_exprs(entity_fields, ctx)
        cols = ", ".join([f"id", q(ts_field)] + [f"{e} AS e{i}" for i, (_, e) in enumerate(ents)] + (["flags"] if source == "mails" else []))
        cur.execute(f"SELECT {cols} FROM {source} WHERE {where} ORDER BY {q(ts_field)} NULLS LAST LIMIT {MAX_FINDINGS}", ctx.params)
        for rec in cur.fetchall():
            rid, ts = rec[0], rec[1]
            ev = _clean_entities([(ents[i][0], rec[2 + i]) for i in range(len(ents))])
            sev = base["severity"]
            esc = None
            if then_flags and source == "mails":
                flags = rec[2 + len(ents)] or []
                for flag, s in then_flags:
                    if flag in flags and sev_rank(s) > sev_rank(sev):
                        sev, esc = s, flag
            findings.append({**base, "severity": sev, "key": f"{rule['id']}|{rid}", "ts": ts, "entities": ev, "count": 1, "refs": [rid], "escalation": esc})
        return findings

    # DuckDB binds "?" placeholders in textual order. The any_in_group condition sits in the SELECT
    # list (before WHERE) and again in HAVING, so the grouped query is compiled into a fresh context
    # in exactly that order; compiling it once and reusing the text left placeholders unbound
    # (the internal-name-on-external-domain rule failed on every store).
    ctx = Ctx(source=source, settings=settings)
    gexprs = _entity_exprs(group_by, ctx) if group_by else []
    gkeys = [f"lower(coalesce({e}, ''))" for _, e in gexprs]
    dexpr = f"lower(CAST({resolve(rule['distinct'], ctx).sql} AS VARCHAR))" if rule.get("distinct") else None
    any_sql = compile_cond(rule["any_in_group"], ctx) if rule.get("any_in_group") else None
    extra_ents = [f for f in entity_fields if f not in group_by]
    eexprs = _entity_exprs(extra_ents, ctx)
    where = _where_sql(rule, settings, ctx, ts_field)

    if not window:
        select = gkeys + [f"any_value({e})" for _, e in gexprs] + ["count(*)", f"count(DISTINCT {dexpr})" if dexpr else "count(*)", f"min({q(ts_field)})", f"max({q(ts_field)})",
                          f"list(id ORDER BY {q(ts_field)})[1:{MAX_REFS}]", f"list_distinct(list({dexpr}))[1:8]" if dexpr else "[]",
                          f"bool_or({any_sql})" if any_sql else "TRUE"] + [f"any_value({e})" for _, e in eexprs]
        having = []
        if threshold:
            having.append(f"{'count(DISTINCT ' + dexpr + ')' if dexpr else 'count(*)'} {threshold[0].replace('==', '=')} {threshold[1]}")
        if any_sql:
            having.append(f"bool_or({compile_cond(rule['any_in_group'], ctx)})")  # bound after WHERE, in SQL order
        if gkeys:
            having.append("NOT (" + " AND ".join(f"{k} = ''" for k in gkeys) + ")")
        gb = f"GROUP BY {', '.join(gkeys)}" if gkeys else ""
        hv = f"HAVING {' AND '.join(having)}" if having else ""
        cur.execute(f"SELECT {', '.join(select)} FROM {source} WHERE {where} {gb} {hv} ORDER BY count(*) DESC LIMIT {MAX_FINDINGS}", ctx.params)
        ng = len(gexprs)
        for rec in cur.fetchall():
            keyvals = rec[:ng]
            disp = rec[ng:2 * ng]
            n, d, first, last, ids, dvals, _anyok = rec[2 * ng:2 * ng + 7]
            ents = _clean_entities([(gexprs[i][0], disp[i]) for i in range(ng)])
            ents.update(_clean_entities([(eexprs[i][0], rec[2 * ng + 7 + i]) for i in range(len(eexprs))]))
            if dexpr:  # the distinct values are the point of the finding: never let any_value() overwrite them
                ents[rule["distinct"]] = ", ".join(str(x) for x in (dvals or []) if x)
            findings.append({**base, "key": f"{rule['id']}|{''.join(str(k) for k in keyvals)}", "ts": first, "tsEnd": last, "entities": ents,
                             "count": int(d if dexpr else n), "refs": list(ids or [])})
    else:
        # streaming burst detection per group
        select = ["id", q(ts_field)] + gkeys + [e for _, e in gexprs] + ([dexpr] if dexpr else []) + ([any_sql] if any_sql else []) + [e for _, e in eexprs]
        order = ", ".join(gkeys + [q(ts_field)]) if gkeys else q(ts_field)
        cur.execute(f"SELECT {', '.join(select)} FROM {source} WHERE {where} AND {q(ts_field)} IS NOT NULL ORDER BY {order}", ctx.params)
        ng = len(gexprs)
        thr = threshold or (">=", 1)
        cur_key: tuple | None = None
        win: list[tuple[int, int, Any]] = []
        open_burst: dict[str, Any] | None = None
        group_any = False
        buffered: list[dict[str, Any]] = []
        first_disp: tuple = ()
        first_extra: tuple = ()

        def distinct_count(items: list[tuple[int, int, Any]]) -> int:
            return len({x[2] for x in items if x[2] not in (None, "")}) if dexpr else len(items)

        def close_burst() -> None:
            nonlocal open_burst
            if open_burst is None:
                return
            b = open_burst
            open_burst = None
            ents = _clean_entities([(gexprs[i][0], first_disp[i]) for i in range(ng)])
            if dexpr:
                seen: list[str] = []
                for _, _, dv in b["rows"]:
                    if dv not in (None, "") and dv not in seen:
                        seen.append(dv)
                ents[rule["distinct"]] = ", ".join(seen[:8])
            ents.update(_clean_entities([(eexprs[i][0], first_extra[i]) for i in range(len(eexprs))]))
            buffered.append({**base, "key": f"{rule['id']}|{''.join(str(k) for k in (cur_key or ()))}|{b['start'] // 60000}", "ts": b["start"], "tsEnd": b["last"],
                             "entities": ents, "count": len(b["rows"]), "refs": [r[0] for r in b["rows"][:MAX_REFS]]})

        def flush_group() -> None:
            nonlocal win, open_burst, group_any
            close_burst()
            if group_any or not any_sql:
                findings.extend(buffered)
            buffered.clear()
            win = []
            group_any = False

        while True:
            batch = cur.fetchmany(20000)
            if not batch:
                break
            for rec in batch:
                rid, ts = rec[0], int(rec[1])
                key = tuple(rec[2:2 + ng])
                pos = 2 + ng
                disp = tuple(rec[pos:pos + ng])
                pos += ng
                dv = rec[pos] if dexpr else None
                pos += 1 if dexpr else 0
                anyv = rec[pos] if any_sql else True
                pos += 1 if any_sql else 0
                extra = tuple(rec[pos:pos + len(eexprs)])
                if key != cur_key:
                    if cur_key is not None:
                        flush_group()
                    cur_key = key
                    first_disp, first_extra = disp, extra
                    if ng and all(k == "" for k in key):
                        continue
                if ng and all(k == "" for k in key):
                    continue
                if anyv:
                    group_any = True
                win.append((rid, ts, dv))
                while win and ts - win[0][1] > window:
                    win.pop(0)
                if open_burst is not None:
                    if ts - open_burst["last"] <= window:
                        open_burst["rows"].append((rid, ts, dv))
                        open_burst["last"] = ts
                        continue
                    close_burst()
                if _cmp(thr[0], distinct_count(win), thr[1]):
                    open_burst = {"rows": list(win), "start": win[0][1], "last": ts}
                    first_disp, first_extra = disp, extra
                if len(findings) + len(buffered) >= MAX_FINDINGS:
                    break
            if len(findings) + len(buffered) >= MAX_FINDINGS:
                break
        if cur_key is not None:
            flush_group()
        findings = findings[:MAX_FINDINGS]

    # follow-up ("then")
    then = rule.get("then") or {}
    if then.get("where") and findings:
        within = parse_duration(then.get("within")) or 0
        join = list(then.get("join") or group_by)
        checked = 0
        for f in findings:
            if checked >= 500:
                break
            checked += 1
            tctx = Ctx(source=source, settings=settings)
            cond = compile_cond(then["where"], tctx)
            end = f.get("tsEnd") or f.get("ts") or 0
            parts = [cond, f"{q(ts_field)} >= {tctx.p(f.get('ts') or 0)}", f"{q(ts_field)} <= {tctx.p(end + within)}"]
            ok = True
            for j in join:
                a, b = (j.split("=", 1) if "=" in j else (j, j))
                want = f["entities"].get(a)
                if not want:
                    ok = False
                    break
                try:
                    parts.append(f"lower(CAST({resolve(b, tctx).sql} AS VARCHAR)) = {tctx.p(want.lower())}")
                except FilterError:
                    ok = False
                    break
            if not ok:
                continue
            cur.execute(f"SELECT id, {q(ts_field)} FROM {source} WHERE {' AND '.join(parts)} ORDER BY {q(ts_field)} LIMIT 1", tctx.params)
            hit = cur.fetchone()
            if hit:
                if sev_rank(then.get("severity")) > sev_rank(f["severity"]):
                    f["severity"] = then["severity"]
                f["escalation"] = then.get("title") or "follow-up matched"
                if then.get("title"):
                    f["title"] = f"{base['title']} → {then['title']}"
                f["refs"] = list(f["refs"]) + [hit[0]]
                f["tsEnd"] = max(end, int(hit[1] or 0))
    return findings


def _rule_event_ids(cond: dict[str, Any] | None) -> list[int] | None:
    """Event ids a rule's where clause pins down (None when it does not)."""
    if not cond:
        return None
    direct: list[int] = []
    for k, v in cond.items():
        if k in ("eventId", "eventId|eq", "eventId|in"):
            for x in v if isinstance(v, list) else [v]:
                try:
                    direct.append(int(x))
                except (TypeError, ValueError):
                    pass
    if direct:
        return sorted(set(direct))
    for k, v in cond.items():
        if re.match(r"^any_of(_\d+)?$", k) and isinstance(v, list):
            all_ids: list[int] = []
            for alt in v:
                ids = _rule_event_ids(alt if isinstance(alt, dict) else None)
                if not ids:
                    return None
                all_ids += ids
            if all_ids:
                return sorted(set(all_ids))
    return None


def _setting_empty(settings: dict[str, Any], name: str) -> bool:
    camel = re.sub(r"_([a-z])", lambda m: m.group(1).upper(), name)
    return not (settings.get(name) or settings.get(camel))


def _empty_positive_settings(cond: dict[str, Any] | None, settings: dict[str, Any], acc: list[str] | None = None) -> list[str]:
    """Setting names used by AND-position `in_setting` conditions whose lists are empty."""
    acc = [] if acc is None else acc
    if not cond:
        return acc
    for k, v in cond.items():
        if re.match(r"^any_of(_\d+)?$", k) or k == "not":
            continue
        if re.match(r"^all_of(_\d+)?$", k):
            for alt in v if isinstance(v, list) else [v]:
                if isinstance(alt, dict):
                    _empty_positive_settings(alt, settings, acc)
            continue
        _, _, op = k.partition("|")
        if op == "in_setting" and _setting_empty(settings, str(v)) and str(v) not in acc:
            acc.append(str(v))
    return acc


def diagnose_zero(store: CaseStore, rule: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    """Explain why a rule produced zero findings (funnel: settings -> where -> exclude -> time -> threshold)."""
    source = rule["source"]
    ts_field = "date" if source == "mails" else "ts"
    base = {"ruleId": rule["id"], "matched": 0, "afterExclude": 0, "afterTime": 0}
    req = rule.get("require_setting")
    if req and _setting_empty(settings, req):
        return {**base, "reason": "missing_setting", "detail": f'setting "{req}" is empty'}
    missing = _empty_positive_settings(rule.get("where"), settings)
    cur = store.cursor()
    ctx = Ctx(source=source, settings=settings)
    where = compile_cond(rule.get("where"), ctx)
    n_where = int(cur.execute(f"SELECT count(*) FROM {source} WHERE {where}", ctx.params).fetchone()[0])
    if n_where == 0:
        if missing:
            return {**base, "reason": "missing_setting", "detail": f"empty setting(s): {', '.join(missing)}"}
        detail = None
        ids = _rule_event_ids(rule.get("where"))
        if ids and source == "events":
            present = int(cur.execute(f'SELECT count(*) FROM events WHERE "eventId" IN ({", ".join(str(i) for i in ids)})').fetchone()[0])
            if present == 0:
                detail = f"event id(s) {', '.join(map(str, ids))} absent from this case (channel not collected?)"
        return {**base, "reason": "no_selector_match", "detail": detail}
    ctx2 = Ctx(source=source, settings=settings)
    w2 = compile_cond(rule.get("where"), ctx2)
    if rule.get("exclude"):
        w2 += f" AND NOT ({compile_cond(rule['exclude'], ctx2)})"
    n_ex = int(cur.execute(f"SELECT count(*) FROM {source} WHERE {w2}", ctx2.params).fetchone()[0])
    if n_ex == 0:
        return {**base, "matched": n_where, "reason": "all_excluded", "detail": "every matching row is on a whitelist (exclude clause)"}
    tsql = _time_sql(rule, settings, ctx2, ts_field)
    n_t = n_ex
    if tsql:
        n_t = int(cur.execute(f"SELECT count(*) FROM {source} WHERE {w2} AND {tsql}", ctx2.params).fetchone()[0])
        if n_t == 0:
            return {**base, "matched": n_where, "afterExclude": n_ex, "reason": "outside_time_window", "detail": "matching rows exist but none inside the rule's time condition"}
    detail = f"{n_t} row(s) matched but no group met {rule.get('threshold') or 'the threshold'}"
    if rule.get("window"):
        detail += f" within {rule['window']}"
    return {**base, "matched": n_where, "afterExclude": n_ex, "afterTime": n_t, "reason": "below_threshold", "detail": detail}


def run_rules(store: CaseStore, rules: list[dict[str, Any]], settings: dict[str, Any],
              progress: Callable[[dict[str, Any]], None] | None = None, cancelled: Callable[[], bool] | None = None) -> dict[str, Any]:
    all_findings: list[dict[str, Any]] = []
    by_rule: dict[str, int] = {}
    errors: list[dict[str, str]] = []
    diagnostics: list[dict[str, Any]] = []
    for i, rule in enumerate(rules):
        if cancelled and cancelled():
            break
        if rule.get("enabled") is False:
            continue
        t0 = time.time()
        failed = False
        try:
            found = run_rule(store, rule, settings)
        except Exception as exc:  # noqa: BLE001
            errors.append({"ruleId": rule.get("id", "?"), "error": str(exc)[:300]})
            found = []
            failed = True
        by_rule[rule.get("id", "?")] = len(found)
        all_findings.extend(found)
        if not found and not failed:
            try:
                diagnostics.append(diagnose_zero(store, rule, settings))
            except Exception as exc:  # noqa: BLE001
                diagnostics.append({"ruleId": rule.get("id", "?"), "reason": "no_selector_match", "detail": f"diagnostic failed: {exc}"[:200], "matched": 0, "afterExclude": 0, "afterTime": 0})
        if progress:
            progress({"index": i + 1, "total": len(rules), "ruleId": rule.get("id"), "findings": len(found), "ms": int((time.time() - t0) * 1000)})
    return {"findings": all_findings, "byRule": by_rule, "errors": errors, "diagnostics": diagnostics, "total": len(all_findings)}
