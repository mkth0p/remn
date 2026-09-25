"""Tool definitions executed by the browser (against IndexedDB) and the structured-output schema for the query builder."""

from __future__ import annotations

from typing import Any

FILTER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "conditions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "field": {"type": "string"},
                    "op": {
                        "type": "string",
                        "enum": ["eq", "ne", "in", "nin", "contains", "startswith", "endswith", "re", "gt", "gte", "lt", "lte", "exists", "empty"],
                    },
                    "value": {},
                },
                "required": ["field", "op"],
            },
        },
        "logic": {"type": "string", "enum": ["and", "or"]},
        "timeRange": {"type": "object", "properties": {"from": {"type": "string"}, "to": {"type": "string"}}},
        "hourRange": {"type": "object", "properties": {"from": {"type": "integer"}, "to": {"type": "integer"}, "outside": {"type": "boolean"}}},
        "regex": {"type": "object", "properties": {"field": {"type": "string"}, "pattern": {"type": "string"}, "flags": {"type": "string"}}},
        "text": {"type": "string"},
        "sort": {"type": "object", "properties": {"field": {"type": "string"}, "dir": {"type": "string", "enum": ["asc", "desc"]}}},
        "limit": {"type": "integer"},
    },
}

QUERY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "source": {"type": "string", "enum": ["events", "mails"]},
        "filter": FILTER_SCHEMA,
        "groupBy": {"type": "string"},
        "explanation": {"type": "string"},
        "confidence": {"type": "number"},
    },
    "required": ["source", "filter", "explanation"],
}

# Kept deliberately small: the DSL is described once in the system prompt. Repeating the full
# JSON schema in every tool costs thousands of prompt tokens on CPU-bound models.
_FILTER_PARAM = {
    "type": "object",
    "description": "Filter DSL object: {conditions:[{field,op,value}], logic, timeRange:{from,to}, hourRange, regex:{field,pattern}, text}. Empty object = everything.",
}


def _fn(name: str, description: str, properties: dict[str, Any] | None = None, required: list[str] | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {"type": "object", "properties": properties or {}}
    if required:
        params["required"] = required
    return {"type": "function", "function": {"name": name, "description": description, "parameters": params}}


_INT = {"type": "integer"}
_STR = {"type": "string"}
_REF = {"type": "string", "description": 'a row reference as the tools return it, e.g. "ev:123" (or the bare number)'}
_CITES = {
    "type": "array",
    "items": {"type": "string"},
    "description": 'references of rows you retrieved that support this, e.g. ["ev:123", "mail:4", "finding:7"]',
}
_SOURCE = {"type": "string", "enum": ["events", "mails"]}

# The browser executes every tool against the case and drops the ones a case cannot use (mail tools
# without mail, sql outside a server store, lookup_ioc without network) before a turn is sent.
# Read tools return rows with a "ref" ("ev:12", "mail:3", "finding:7", "chain:<id>") that the answer
# cites; the propose_* tools only queue a proposal the analyst accepts or rejects.
TOOLS: list[dict[str, Any]] = [
    # ---- read: the case ----
    _fn(
        "get_case_summary",
        "Overview of the case: evidence files, row counts, time range, top event ids and senders, findings by severity, open proposals and hypotheses. Call it first.",
    ),
    _fn("list_evidence", "The evidence files of the case: name, kind, rows, time range, parser notes."),
    # ---- read: events ----
    _fn(
        "search_events",
        "Windows and cloud events matching a filter. Returns up to `limit` rows (default 30, max 100) and the exact total that match.",
        {"filter": _FILTER_PARAM, "limit": _INT, "fields": {"type": "array", "items": _STR, "description": "optional fields to return"}},
        ["filter"],
    ),
    _fn(
        "count_events",
        "Exact number of events matching a filter; with group_by, the exact count per value of that field (top `limit`).",
        {"filter": _FILTER_PARAM, "group_by": _STR, "limit": _INT},
    ),
    _fn(
        "aggregate_events",
        "Events grouped by one field (eventId, ipAddress, targetUser, computer, logonType, provider...): top groups with counts and first/last time.",
        {"filter": _FILTER_PARAM, "field": _STR, "limit": _INT},
        ["field"],
    ),
    _fn(
        "timeline_events",
        "Histogram of matching events over time (bucket minute|hour|day), to find bursts.",
        {"filter": _FILTER_PARAM, "bucket": {"type": "string", "enum": ["minute", "hour", "day"]}, "limit": _INT},
        ["bucket"],
    ),
    _fn("get_event", "One event in full (all EventData fields).", {"id": _REF}, ["id"]),
    _fn(
        "process_tree",
        "A process with its parents and children: give process_guid (Sysmon), or computer and pid (Security 4688). Returns the chain of parents, the children and what the process did.",
        {"process_guid": _STR, "computer": _STR, "pid": _STR},
    ),
    _fn(
        "logon_session",
        "Everything one logon session did on a host: the logon (4624), the events carrying its logon id, and the logoff. Give computer and logon_id (TargetLogonId of the 4624).",
        {"computer": _STR, "logon_id": _STR},
        ["logon_id"],
    ),
    # ---- read: mails ----
    _fn(
        "search_mails",
        "Mails matching a filter (subject, fromAddr, fromDomain, flags, risk, date, originIp...). Returns up to `limit` rows and the exact total.",
        {"filter": _FILTER_PARAM, "limit": _INT},
        ["filter"],
    ),
    _fn(
        "count_mails",
        "Exact number of mails matching a filter; with group_by, the exact count per value.",
        {"filter": _FILTER_PARAM, "group_by": _STR, "limit": _INT},
    ),
    _fn(
        "aggregate_mails",
        "Mails grouped by one field (fromDomain, fromAddr, originIp, folder, flags...).",
        {"filter": _FILTER_PARAM, "field": _STR, "limit": _INT},
        ["field"],
    ),
    _fn(
        "timeline_mails",
        "Histogram of matching mails over time (bucket minute|hour|day).",
        {"filter": _FILTER_PARAM, "bucket": {"type": "string", "enum": ["minute", "hour", "day"]}},
        ["bucket"],
    ),
    _fn(
        "get_mail",
        "One mail in full: headers, hops, authentication, urls, attachments (metadata), optionally the body text.",
        {"id": _REF, "includeBody": {"type": "boolean"}},
        ["id"],
    ),
    # ---- read: what the tool concluded ----
    _fn(
        "list_findings",
        "Findings of the detection rules, most severe first; filter by severity, source, status, rule id or words in the title.",
        {
            "severity": _STR,
            "source": _SOURCE,
            "status": {"type": "string", "enum": ["new", "reviewed", "escalated", "false_positive"]},
            "rule": _STR,
            "q": _STR,
            "limit": _INT,
        },
    ),
    _fn("get_finding", "One finding with the rows it matched (up to `rows`, default 10).", {"id": _REF, "rows": _INT}, ["id"]),
    _fn(
        "get_chain",
        "One attack chain: recipient, score, seed mail, steps tied to the mail and the findings linked to it. By chain id or by the recipient's user name.",
        {"chain_id": _STR, "user": _STR},
    ),
    _fn(
        "get_story",
        "One story: what happened to a person or a host, read along ATT&CK's phases, each step with why it is in the story and how surely, "
        "its hops, and what its evidence cannot show. By story id, or by a user or host name; without one, the list of stories.",
        {"story_id": _STR, "user": _STR},
    ),
    _fn(
        "list_iocs",
        "Indicators extracted from the case (ip, domain, url, hash, email), with counts and any reputation verdict.",
        {"kind": _STR, "only_bad": {"type": "boolean"}, "q": _STR, "limit": _INT},
    ),
    _fn("get_case_notes", "The analyst's notes, tasks and timeline entries.", {"kind": {"type": "string", "enum": ["note", "task", "timeline"]}}),
    _fn(
        "facet_values",
        "The most frequent values of one field (or those containing q): what users, hosts, senders exist.",
        {"source": _SOURCE, "field": _STR, "q": _STR, "limit": _INT},
        ["source", "field"],
    ),
    _fn(
        "pivot",
        "A value (IP, user, host, domain, hash, subject fragment) across the case: counts of events and mails that mention it, first and last seen.",
        {"value": _STR},
        ["value"],
    ),
    _fn(
        "regex_test",
        "Test a JavaScript regular expression on a sample string or on the first rows of a field.",
        {"pattern": _STR, "flags": _STR, "sample": _STR, "source": _SOURCE, "field": _STR, "limit": _INT},
        ["pattern"],
    ),
    _fn(
        "lookup_ioc",
        "Reputation of an indicator from the configured providers (external lookups enabled for this case).",
        {"kind": {"type": "string", "enum": ["ip", "domain", "url", "hash"]}, "value": _STR},
        ["kind", "value"],
    ),
    _fn(
        "sql",
        "One read-only DuckDB query (SELECT/WITH) over the case tables (events, mails, attachments, urls, mail_bodies, iocs), for joins and window functions. Quote camelCase columns.",
        {"sql": _STR, "limit": _INT},
        ["sql"],
    ),
    _fn(
        "search_rules",
        "Detection rules in the library by words or ATT&CK id: id, title, severity, whether enabled and how many findings each has here.",
        {"q": _STR, "limit": _INT},
    ),
    _fn("test_rule", "Run a draft YAML rule on this case without saving anything: how many findings it makes and the first ones.", {"yaml": _STR}, ["yaml"]),
    # ---- the investigation itself ----
    _fn(
        "update_plan",
        "Write or update your investigation plan, shown to the analyst: the steps with a status each. Call it at the start and when a step is done.",
        {
            "steps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"title": _STR, "status": {"type": "string", "enum": ["todo", "doing", "done", "skipped"]}},
                    "required": ["title"],
                },
            },
        },
        ["steps"],
    ),
    _fn(
        "record_hypothesis",
        "Add or update a hypothesis on the board: what you think happened, its status, and the rows for and against it. Pass id to update one.",
        {
            "id": _STR,
            "statement": _STR,
            "status": {"type": "string", "enum": ["open", "supported", "refuted", "inconclusive"]},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            "cites": _CITES,
            "against": _CITES,
            "next_check": _STR,
        },
        ["statement"],
    ),
    _fn(
        "finish",
        "End the investigation with your answer (markdown), citing rows inline like [ev:123]. Every claim about the evidence needs a citation.",
        {"answer": _STR, "confidence": {"type": "string", "enum": ["low", "medium", "high"]}, "open_questions": {"type": "array", "items": _STR}},
        ["answer"],
    ),
    # ---- proposals: queued for the analyst, never applied by the model ----
    _fn(
        "propose_decision",
        "Propose a review decision on one finding (finding_id) or one chain (chain_id): incident escalated|reviewed|false_positive, chain confirmed|benign|unsure, a severity, whether the report carries it, findings to unlink from a chain. The analyst accepts or rejects it.",
        {
            "finding_id": _REF,
            "chain_id": _STR,
            "decision": {"type": "string", "enum": ["escalated", "reviewed", "false_positive", "confirmed", "benign", "unsure"]},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
            "include": {"type": "boolean"},
            "unlink_finding_ids": {"type": "array", "items": _INT},
            "reason": _STR,
            "cites": _CITES,
        },
        ["reason", "cites"],
    ),
    _fn(
        "propose_note",
        "Propose a case note, a task, or a timeline entry (with its UTC time) for the analyst to accept.",
        {
            "kind": {"type": "string", "enum": ["note", "task", "timeline"]},
            "text": _STR,
            "at": {"type": "string", "description": "timeline: ISO time of the event"},
            "cites": _CITES,
        },
        ["kind", "text", "cites"],
    ),
    _fn(
        "propose_row_mark",
        "Propose marking rows as relevant, noise or a pivot, with tags, for the analyst to accept.",
        {"refs": _CITES, "verdict": {"type": "string", "enum": ["relevant", "noise", "pivot"]}, "tags": {"type": "array", "items": _STR}, "reason": _STR},
        ["refs", "verdict", "reason"],
    ),
    _fn(
        "propose_rule",
        "Propose a new detection rule (YAML in the rule language). It is tested on the case first; the analyst adds it or not.",
        {"yaml": _STR, "reason": _STR},
        ["yaml", "reason"],
    ),
    _fn("propose_summary", "Propose the report's executive summary (markdown), for the analyst to accept or edit.", {"text": _STR, "cites": _CITES}, ["text"]),
]

TOOL_NAMES = [t["function"]["name"] for t in TOOLS]
