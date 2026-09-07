"""
Filter DSL -> DuckDB SQL. Same semantics as frontend/src/rules/filter.ts:
case-insensitive string comparison, arrays flatten (attachments.flags matches
any attachment), settings-backed operators, regex, time and hour ranges.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from services.parsers.mail.common import normalize_name
from services.reference import lists as reference_lists
from services.store.casestore import EVENT_COLUMNS, EVENT_INT, MAIL_COLUMNS, MAIL_INT, MAIL_LIST, q

OPS = {
    "eq",
    "ne",
    "in",
    "nin",
    "contains",
    "not_contains",
    "contains_any",
    "contains_all",
    "startswith",
    "not_startswith",
    "endswith",
    "not_endswith",
    "re",
    "not_re",
    "gt",
    "gte",
    "lt",
    "lte",
    "exists",
    "empty",
    "in_setting",
    "nin_setting",
    "levenshtein",
    "length",
    "contains_cs",
    "startswith_cs",
    "endswith_cs",
}

EVENT_COLS = {n for n, _ in EVENT_COLUMNS}
MAIL_COLS = {n for n, _ in MAIL_COLUMNS}
MAIL_BOOL = {n for n, t in MAIL_COLUMNS if t[0] == "BOOLEAN"}
ATT_COLS = {"name", "ext", "realExt", "realMime", "size", "sha256", "md5", "risk", "flags", "category", "inline", "details", "date", "fromAddr", "mailSubject"}
URL_COLS = {"url", "normalized", "defanged", "host", "domain", "scheme", "flags", "text", "source", "date"}
ATT_INT = {"size", "risk", "date"}
BODY_COLS = {"bodyText", "bodyHtml", "headersText", "visibleText"}
MAIL_ALIASES = {
    "auth.spf": "spf",
    "auth.dkim": "dkim",
    "auth.dmarc": "dmarc",
    "auth.compauth": "compauth",
    "reputation.worst": "reputationWorst",
    "reputation.originIp.verdict": "reputationOriginIp",
    "replyTo.addr": "replyToList",
    "replyTo.domain": "replyToDomain",
    "to.addr": "toList",
    "cc.addr": "ccList",
    "bcc.addr": "bccList",
    "sender.addr": "senderAddr",
}
TEXT_FIELDS_EVENTS = [
    "summary",
    "targetUser",
    "subjectUser",
    "ipAddress",
    "computer",
    "commandLine",
    "processName",
    "serviceName",
    "serviceFile",
    "scriptBlockText",
    "message",
    "workstation",
    "provider",
    "channel",
    "taskName",
    "objectName",
    "image",
    "query",
    "destinationIp",
    "targetFilename",
    "targetObject",
    "raw",
]
TEXT_FIELDS_MAILS = ["subject", "fromName", "fromAddr", "fromDomain", "originIp", "textPreview", "messageId", "folder", "returnPath"]


class FilterError(ValueError):
    pass


def _json_path(key: str) -> str:
    """A JSON path literal for one (possibly dotted) key: $."Role.DisplayName". Inlined rather
    than bound, because operators such as exists/empty repeat the column expression in SQL."""
    k = key.replace("\\", "\\\\").replace('"', '\\"').replace("'", "''")
    return "'$.\"" + k + "\"'"


@dataclass
class Expr:
    sql: str
    kind: str  # 'text' | 'num' | 'list' | 'bool'


@dataclass
class Ctx:
    source: str  # events | mails
    settings: dict[str, Any] = field(default_factory=dict)
    params: list[Any] = field(default_factory=list)
    table: str = ""
    alias: str = ""

    def p(self, value: Any) -> str:
        self.params.append(value)
        return "?"


_RE2_META = set("\\.^$|()[]{}*+?")


def _re_literal(s: str) -> str:
    """Escape a literal for RE2 (only the metacharacters, so non-ASCII and spaces stay readable)."""
    return "".join("\\" + ch if ch in _RE2_META else ch for ch in s)


def _alternation(values: list[str], prefix: str = "", suffix: str = "") -> str:
    """One regex matching any of the (already lowercased) literals: evaluated once per row, unlike a
    chain of lower(col) LIKE ?, which recomputes lower() for every alternative (a 179-item
    contains_any on script-block rows went from 5.6 s to 0.04 s)."""
    return prefix + "(?:" + "|".join(_re_literal(v) for v in values) + ")" + suffix


_CS_FN = {"contains_cs": "contains", "startswith_cs": "starts_with", "endswith_cs": "ends_with"}


def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _norm(v: Any) -> str:
    return "" if v is None else str(v).lower()


def _setting(settings: dict[str, Any], name: str) -> list[str]:
    """A case-settings list by snake or camel name, else a built-in reference list of that name (tranco_10k)."""
    camel = re.sub(r"_([a-z])", lambda m: m.group(1).upper(), name)
    v = settings.get(name, settings.get(camel))
    if isinstance(v, list) and v:
        return [str(x) for x in v]
    builtin = reference_lists.builtin_list(name)
    return list(builtin) if builtin else []


_THRESHOLD_RE = re.compile(r"^\s*(>=|<=|==|=|!=|>|<)?\s*(\d+)\s*$")


def _threshold(v: Any) -> tuple[str, int]:
    """'< 500' / '>= 3' / 3 -> (sql comparator, n) for the length operator."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return "=", int(v)
    m = _THRESHOLD_RE.match(str(v))
    if not m:
        raise FilterError(f"length expects a threshold such as '< 500', got {v!r}")
    sym = {"==": "=", "!=": "<>"}.get(m.group(1) or "=", m.group(1) or "=")
    return sym, int(m.group(2))


def _ipv4_int_sql(expr: str) -> str:
    parts = f"string_split({expr}, '.')"
    return (
        f"(CASE WHEN regexp_matches({expr}, '^\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}$') THEN "
        f"try_cast({parts}[1] AS BIGINT) * 16777216 + try_cast({parts}[2] AS BIGINT) * 65536 + try_cast({parts}[3] AS BIGINT) * 256 + try_cast({parts}[4] AS BIGINT) END)"
    )


def resolve(field_name: str, ctx: Ctx) -> Expr:
    """Map a DSL field to a SQL expression in the current table context."""
    f = field_name.strip()
    tbl = ctx.table or ctx.source
    a = (ctx.alias + ".") if ctx.alias else ""
    if tbl == "events":
        if f in EVENT_COLS:
            return Expr(f"{a}{q(f)}", "num" if f in EVENT_INT else "text")
        if f.startswith("data."):
            return Expr(f'json_extract_string({a}"data", {_json_path(f[5:])})', "text")
        return Expr(f'json_extract_string({a}"data", {_json_path(f)})', "text")
    if tbl == "mails":
        if f in MAIL_ALIASES:
            f = MAIL_ALIASES[f]
        # sub-fields of the address lists (JSON columns): to.domain, cc.name, replyTo.domain ...
        m_sub = re.match(r"^(to|cc|bcc|replyTo)\.(domain|name|addr)$", f)
        if m_sub:
            col, sub = m_sub.groups()
            return Expr(f"CAST(json_extract({a}\"{col}\", '$[*].{sub}') AS VARCHAR[])", "list")
        if f in MAIL_COLS:
            kind = "list" if f in MAIL_LIST else ("num" if f in MAIL_INT else ("bool" if f in MAIL_BOOL else "text"))
            return Expr(f"{a}{q(f)}", kind)
        if f in BODY_COLS:
            return Expr(f'(SELECT b.{q(f)} FROM mail_bodies b WHERE b."mailId" = {a or "mails."}id)', "text")
        if f.startswith("auth."):
            return Expr(f'json_extract_string({a}"auth", {_json_path(f[5:])})', "text")
        if f.startswith("lookalike."):
            return Expr(f'json_extract_string({a}"lookalike", {_json_path(f[10:])})', "text")
        if f.startswith("htmlInfo."):
            return Expr(f'json_extract_string({a}"htmlInfo", {_json_path(f[9:])})', "text")
        if f.startswith("keywordHits."):
            return Expr(f'json_extract_string({a}"keywordHits", {_json_path(f[12:])})', "text")
        raise FilterError(f"unknown mail field {field_name!r}")
    if tbl == "attachments":
        if f in ATT_COLS:
            return Expr(f"{a}{q(f)}", "list" if f == "flags" else ("bool" if f == "inline" else ("num" if f in ATT_INT else "text")))
        return Expr(f'json_extract_string({a}"details", {_json_path(f)})', "text")
    if tbl == "urls":
        if f in URL_COLS:
            return Expr(f"{a}{q(f)}", "list" if f == "flags" else ("num" if f == "date" else "text"))
        if f == "subdomain":
            # host minus the registrable domain ("www.foo.co.uk" -> "www"); NULL when there is none
            h, d = f'{a}"host"', f'{a}"domain"'
            return Expr(
                f"(CASE WHEN {h} IS NULL OR {d} IS NULL OR {d} = '' OR {h} = {d} OR NOT ends_with({h}, '.' || {d}) "
                f"THEN NULL ELSE left({h}, length({h}) - length({d}) - 1) END)",
                "text",
            )
        if f == "fragment":
            u = f'{a}"url"'
            return Expr(f"(CASE WHEN strpos({u}, '#') > 0 THEN substr({u}, strpos({u}, '#') + 1) ELSE NULL END)", "text")
        raise FilterError(f"unknown url field {field_name!r}")
    raise FilterError(f"unknown table {tbl}")


def compile_condition(field_name: str, op: str, value: Any, ctx: Ctx) -> str:
    if op not in OPS:
        raise FilterError(f"unknown operator {op!r}")
    # child tables of mails: any attachment / url matching
    if ctx.source == "mails" and not ctx.table and (field_name.startswith("attachments.") or field_name.startswith("urls.")):
        child = "attachments" if field_name.startswith("attachments.") else "urls"
        sub = Ctx(source="mails", settings=ctx.settings, params=ctx.params, table=child, alias="c")
        negative = op in ("ne", "nin", "not_contains", "not_startswith", "not_endswith", "not_re", "nin_setting")
        if negative:
            # "no attachment matches" semantics for negative operators. Only the positive form is
            # compiled: params are bound positionally, so compiling the negated form too would leave
            # its "?" values unbound (urls.domain|nin failed with an argument-count mismatch).
            positive_op = {
                "ne": "eq",
                "nin": "in",
                "not_contains": "contains",
                "not_startswith": "startswith",
                "not_endswith": "endswith",
                "not_re": "re",
                "nin_setting": "in_setting",
            }[op]
            inner_pos = compile_condition(field_name.split(".", 1)[1], positive_op, value, sub)
            return f'NOT EXISTS (SELECT 1 FROM {child} c WHERE c."mailId" = mails.id AND ({inner_pos}))'
        inner = compile_condition(field_name.split(".", 1)[1], op, value, sub)
        return f'EXISTS (SELECT 1 FROM {child} c WHERE c."mailId" = mails.id AND ({inner}))'

    e = resolve(field_name, ctx)
    vals = value if isinstance(value, list) else ([] if value is None else [value])
    if isinstance(value, str) and "," in value and op in ("in", "nin", "contains_any", "contains_all"):
        vals = [s.strip() for s in value.split(",") if s.strip()]
    sql = e.sql
    if e.kind == "bool":
        sql = f"CAST({sql} AS VARCHAR)"  # 'true' / 'false', so eq/ne/in compare like any text value
    low = f"lower({sql})"

    if op == "exists":
        cond = f"({sql} IS NOT NULL AND CAST({sql} AS VARCHAR) <> ''" + (f" AND len({sql}) > 0" if e.kind == "list" else "") + ")"
        return f"NOT {cond}" if value is False else cond
    if op == "empty":
        return f"({sql} IS NULL OR CAST({sql} AS VARCHAR) = ''" + (f" OR len({sql}) = 0" if e.kind == "list" else "") + ")"

    if e.kind == "list":
        lowlist = f"list_transform({sql}, x -> lower(x))"
        if op in ("eq", "in", "contains", "contains_any"):
            if len(vals) == 1 and op in ("eq", "contains"):
                v = _norm(vals[0])
                if op == "contains":
                    return f"(list_contains({lowlist}, {ctx.p(v)}) OR list_bool_or(list_transform({lowlist}, x -> x LIKE {ctx.p('%' + _like_escape(v) + '%')} ESCAPE '\\')))"
                return f"list_contains({lowlist}, {ctx.p(v)})"
            return f"list_has_any({lowlist}, [{', '.join(ctx.p(_norm(v)) for v in vals)}])" if vals else "FALSE"
        if op == "contains_all":
            return f"list_has_all({lowlist}, [{', '.join(ctx.p(_norm(v)) for v in vals)}])" if vals else "TRUE"
        if op in ("ne", "nin", "not_contains"):
            return f"NOT list_has_any({lowlist}, [{', '.join(ctx.p(_norm(v)) for v in vals)}])" if vals else "TRUE"
        if op in ("startswith", "not_startswith", "endswith", "not_endswith"):
            neg = op.startswith("not_")
            pat = (
                " OR ".join(f"x LIKE {ctx.p((_like_escape(_norm(v)) + '%') if 'start' in op else ('%' + _like_escape(_norm(v))))} ESCAPE '\\'" for v in vals)
                or "FALSE"
            )
            cond = f"list_bool_or(list_transform({lowlist}, x -> ({pat})))"
            return f"NOT coalesce({cond}, FALSE)" if neg else f"coalesce({cond}, FALSE)"
        if op in ("re", "not_re"):
            pat = " OR ".join(f"regexp_matches(x, {ctx.p(_regex(v))}, 'i')" for v in vals) or "FALSE"
            cond = f"coalesce(list_bool_or(list_transform({sql}, x -> ({pat}))), FALSE)"
            return f"NOT {cond}" if op == "not_re" else cond
        if op in ("in_setting", "nin_setting"):
            items = [_norm(x) for x in _setting(ctx.settings, str(value))]
            cond = f"list_has_any({lowlist}, [{', '.join(ctx.p(v) for v in items)}])" if items else "FALSE"
            return f"NOT {cond}" if op == "nin_setting" else cond
        if op == "length":
            sym, n = _threshold(value)
            return f"coalesce(len({sql}) {sym} {ctx.p(n)}, FALSE)"
        if op in _CS_FN:
            strs = [str(v) for v in vals]
            if not strs:
                return "FALSE"
            pat = " OR ".join(f"{_CS_FN[op]}(x, {ctx.p(s)})" for s in strs)
            return f"coalesce(list_bool_or(list_transform({sql}, x -> ({pat}))), FALSE)"
        raise FilterError(f"operator {op} not supported on list field {field_name}")

    # scalar
    if op in ("eq", "ne"):
        if len(vals) > 1:
            cond = f"{low} IN ({', '.join(ctx.p(_norm(v)) for v in vals)})"
        elif not vals or vals[0] in (None, ""):
            cond = f"({sql} IS NULL OR CAST({sql} AS VARCHAR) = '')"
        elif e.kind == "num" or isinstance(vals[0], (int, float)) and not isinstance(vals[0], bool):
            cond = (
                f"try_cast({sql} AS DOUBLE) = {ctx.p(float(vals[0]) if isinstance(vals[0], (int, float)) else _num(vals[0]))}"
                if e.kind != "num" or not isinstance(vals[0], (int, float))
                else f"{sql} = {ctx.p(int(vals[0]))}"
            )
        else:
            cond = f"{low} = {ctx.p(_norm(vals[0]))}"
        return f"NOT coalesce({cond}, FALSE)" if op == "ne" else f"coalesce({cond}, FALSE)"
    if op in ("in", "nin"):
        if not vals:
            return "FALSE" if op == "in" else "TRUE"
        nums = [v for v in vals if isinstance(v, (int, float)) and not isinstance(v, bool)]
        strs = [v for v in vals if not (isinstance(v, (int, float)) and not isinstance(v, bool))]
        parts = []
        if nums:
            parts.append(f"try_cast({sql} AS DOUBLE) IN ({', '.join(ctx.p(float(n)) for n in nums)})")
        if strs:
            parts.append(f"{low} IN ({', '.join(ctx.p(_norm(s)) for s in strs)})")
        cond = "(" + " OR ".join(parts) + ")"
        return f"NOT coalesce({cond}, FALSE)" if op == "nin" else f"coalesce({cond}, FALSE)"
    if op in ("contains", "contains_any", "not_contains", "contains_all"):
        if not vals:
            return "TRUE" if op in ("not_contains", "contains_all") else "FALSE"
        strs = [_norm(v) for v in vals]
        if op == "contains_all":
            cond = "(" + " AND ".join(f"regexp_matches({low}, {ctx.p(_alternation([s]))})" for s in strs) + ")"
        elif len(strs) == 1:
            cond = f"({low} LIKE {ctx.p('%' + _like_escape(strs[0]) + '%')} ESCAPE '\\')"
        else:
            cond = f"regexp_matches({low}, {ctx.p(_alternation(strs))})"
        return f"NOT coalesce({cond}, FALSE)" if op == "not_contains" else f"coalesce({cond}, FALSE)"
    if op in ("startswith", "not_startswith"):
        strs = [_norm(v) for v in vals]
        if not strs:
            cond = "FALSE"
        elif len(strs) == 1:
            cond = f"({low} LIKE {ctx.p(_like_escape(strs[0]) + '%')} ESCAPE '\\')"
        else:
            cond = f"regexp_matches({low}, {ctx.p(_alternation(strs, prefix='^'))})"
        return f"NOT coalesce({cond}, FALSE)" if op == "not_startswith" else f"coalesce({cond}, FALSE)"
    if op in ("endswith", "not_endswith"):
        strs = [_norm(v) for v in vals]
        if not strs:
            cond = "FALSE"
        elif len(strs) == 1:
            cond = f"({low} LIKE {ctx.p('%' + _like_escape(strs[0]))} ESCAPE '\\')"
        else:
            cond = f"regexp_matches({low}, {ctx.p(_alternation(strs, suffix='$'))})"
        return f"NOT coalesce({cond}, FALSE)" if op == "not_endswith" else f"coalesce({cond}, FALSE)"
    if op in ("re", "not_re"):
        cond = "(" + " OR ".join(f"regexp_matches(CAST({sql} AS VARCHAR), {ctx.p(_regex(v))}, 'i')" for v in vals) + ")" if vals else "FALSE"
        return f"NOT coalesce({cond}, FALSE)" if op == "not_re" else f"coalesce({cond}, FALSE)"
    if op in ("gt", "gte", "lt", "lte"):
        if not vals:
            return "FALSE"
        n = _num(vals[0])
        if n is None:
            return "FALSE"
        sym = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[op]
        target = sql if e.kind == "num" else f"try_cast({sql} AS DOUBLE)"
        return f"coalesce({target} {sym} {ctx.p(n)}, FALSE)"
    if op in ("in_setting", "nin_setting"):
        cond = _setting_condition(sql, low, str(value), ctx)
        return f"NOT coalesce({cond}, FALSE)" if op == "nin_setting" else f"coalesce({cond}, FALSE)"
    if op == "levenshtein":
        # value = [needle, max_distance]: edit distance between the lower-cased field and the needle
        if not isinstance(value, list) or len(value) != 2:
            raise FilterError("levenshtein expects [needle, max_distance]")
        needle, dist = _norm(value[0]), _num(value[1])
        if dist is None:
            raise FilterError("levenshtein max_distance must be a number")
        return f"coalesce(levenshtein(lower(CAST({sql} AS VARCHAR)), {ctx.p(needle)}) <= {ctx.p(int(dist))}, FALSE)"
    if op == "length":
        # value = threshold string ("< 500", ">= 3") or a number (exact); character count of the text value
        sym, n = _threshold(value)
        return f"coalesce(length(CAST({sql} AS VARCHAR)) {sym} {ctx.p(n)}, FALSE)"
    if op in _CS_FN:
        # case-sensitive variants (MQL strings.contains / starts_with / ends_with): the literal's case matters
        strs = [str(v) for v in vals]
        if not strs:
            return "FALSE"
        text = f"CAST({sql} AS VARCHAR)"
        if len(strs) == 1:
            return f"coalesce({_CS_FN[op]}({text}, {ctx.p(strs[0])}), FALSE)"
        pre = "^" if op == "startswith_cs" else ""
        suf = "$" if op == "endswith_cs" else ""
        return f"coalesce(regexp_matches({text}, {ctx.p(_alternation(strs, prefix=pre, suffix=suf))}), FALSE)"
    raise FilterError(f"unsupported operator {op}")


def _num(v: Any) -> float | None:
    if isinstance(v, bool):
        return float(v)
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    try:
        if s.lower().startswith("0x"):
            return float(int(s, 16))
        return float(s)
    except ValueError:
        return None


def _regex(pattern: Any) -> str:
    p = str(pattern)
    # Python/JS inline flags -> DuckDB (RE2) supports (?i) natively; keep as is
    return p


def _setting_condition(sql: str, low: str, name: str, ctx: Ctx) -> str:
    items = _setting(ctx.settings, name)
    if not items:
        return "FALSE"
    if name in ("internal_ips", "internalIps"):
        ranges: list[tuple[int, int]] = []
        exact: list[str] = []
        for item in items:
            it = item.strip().lower()
            try:
                net = ipaddress.ip_network(it, strict=False)
            except ValueError:
                exact.append(it)
                continue
            if net.version == 4:
                ranges.append((int(net.network_address), int(net.broadcast_address)))
            else:
                exact.append(it)
        parts = []
        if ranges:
            ipint = _ipv4_int_sql(f"CAST({sql} AS VARCHAR)")
            parts.append("(" + " OR ".join(f"{ipint} BETWEEN {ctx.p(lo)} AND {ctx.p(hi)}" for lo, hi in ranges) + ")")
        if exact:
            parts.append(f"{low} IN ({', '.join(ctx.p(x) for x in exact)})")
        return "(" + " OR ".join(parts) + ")"
    if name in ("vip_names", "vipNames", "org_display_names", "orgDisplayNames"):
        norms = sorted({normalize_name(x) for x in items if x})
        return f"{low} IN ({', '.join(ctx.p(n) for n in norms)})" if norms else "FALSE"
    if name in ("internal_domains", "internalDomains", "trusted_senders", "trustedSenders"):
        doms = [d.lower().lstrip("@").strip() for d in items if d.strip()]
        return "(" + " OR ".join(f"({low} = {ctx.p(d)} OR {low} LIKE {ctx.p('%.' + _like_escape(d))} ESCAPE '\\')" for d in doms) + ")"
    return f"{low} IN ({', '.join(ctx.p(x.lower().strip()) for x in items)})"


# ---------------------------------------------------------------------------
# YAML rule "where" conditions (field|op keys, any_of/all_of/not)
# ---------------------------------------------------------------------------
def compile_cond(cond: dict[str, Any] | None, ctx: Ctx) -> str:
    if not cond:
        return "TRUE"
    parts: list[str] = []
    for key, value in cond.items():
        if re.match(r"^any_of(_\d+)?$", key):
            alts = value if isinstance(value, list) else [value]
            parts.append("(" + " OR ".join(compile_cond(a, ctx) for a in alts) + ")")
        elif re.match(r"^all_of(_\d+)?$", key):
            alts = value if isinstance(value, list) else [value]
            parts.append("(" + " AND ".join(compile_cond(a, ctx) for a in alts) + ")")
        elif key == "not":
            parts.append(f"NOT ({compile_cond(value, ctx)})")
        else:
            field_name, _, op = key.partition("|")
            if not op:
                op = "in" if isinstance(value, list) else "eq"
            if op == "contains" and isinstance(value, list):
                op = "contains_any"
            parts.append(compile_condition(field_name, op, value, ctx))
    return "(" + " AND ".join(parts) + ")" if parts else "TRUE"


# ---------------------------------------------------------------------------
# Search filter object (conditions/logic/timeRange/hourRange/regex/text)
# ---------------------------------------------------------------------------
def compile_filter(f: dict[str, Any] | None, ctx: Ctx) -> str:
    f = f or {}
    ts_field = "date" if ctx.source == "mails" else "ts"
    parts: list[str] = []
    conds = [c for c in (f.get("conditions") or []) if isinstance(c, dict) and c.get("field") and c.get("op")]
    if conds:
        sqls = [compile_condition(str(c["field"]), str(c["op"]), c.get("value"), ctx) for c in conds]
        parts.append("(" + (" OR " if f.get("logic") == "or" else " AND ").join(sqls) + ")")
    tr = f.get("timeRange") or {}
    lo, hi = _to_ms(tr.get("from")), _to_ms(tr.get("to"))
    if lo is not None:
        parts.append(f"{q(ts_field)} >= {ctx.p(lo)}")
    if hi is not None:
        parts.append(f"{q(ts_field)} <= {ctx.p(hi)}")
    hr = f.get("hourRange")
    if isinstance(hr, dict) and hr.get("from") is not None and hr.get("to") is not None:
        tz = str(hr.get("tz") or (ctx.settings.get("businessHours") or {}).get("tz") or "UTC")
        hour = f"hour(timezone({ctx.p(tz)}, to_timestamp({q(ts_field)} / 1000.0)))"
        a, b = int(hr["from"]), int(hr["to"])
        # single occurrence of the hour expression so the placeholder count stays right
        inside = f"({hour} BETWEEN {a} AND {b - 1})" if a < b else f"NOT ({hour} BETWEEN {b} AND {a - 1})"
        parts.append(f"({q(ts_field)} IS NOT NULL AND {'NOT ' if hr.get('outside') else ''}{inside})")
    rx = f.get("regex") or {}
    if rx.get("pattern"):
        fld = rx.get("field") or "*"
        if fld == "*":
            target = '"raw"' if ctx.source == "events" else f"concat_ws(' ', {', '.join(q(x) for x in TEXT_FIELDS_MAILS)})"
        else:
            target = resolve(str(fld), ctx).sql
        parts.append(f"coalesce(regexp_matches(CAST({target} AS VARCHAR), {ctx.p(str(rx['pattern']))}, 'i'), FALSE)")
    text = str(f.get("text") or "").strip().lower()
    if text:
        fields = TEXT_FIELDS_EVENTS if ctx.source == "events" else TEXT_FIELDS_MAILS
        pattern = "%" + _like_escape(text) + "%"
        ors = [f"lower({q(x)}) LIKE {ctx.p(pattern)} ESCAPE '\\'" for x in fields]
        if ctx.source == "events":
            ors.append(f"lower(\"data\") LIKE {ctx.p(pattern)} ESCAPE '\\'")
        parts.append("(" + " OR ".join(ors) + ")")
    return "(" + " AND ".join(parts) + ")" if parts else "TRUE"


def _to_ms(v: Any) -> int | None:
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return int(v)
    from services.common import parse_timestamp

    ms, _ = parse_timestamp(str(v))
    return ms


def order_by(sort: dict[str, Any] | None, ctx: Ctx) -> str:
    ts_field = "date" if ctx.source == "mails" else "ts"
    fld = str((sort or {}).get("field") or ts_field)
    direction = "ASC" if str((sort or {}).get("dir") or "desc").lower() == "asc" else "DESC"
    try:
        e = resolve(fld, ctx)
    except FilterError:
        e = resolve(ts_field, ctx)
    return f"ORDER BY {e.sql} {direction} NULLS LAST, id {direction}"
