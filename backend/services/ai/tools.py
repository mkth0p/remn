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
                    "op": {"type": "string", "enum": ["eq", "ne", "in", "nin", "contains", "startswith", "endswith", "re", "gt", "gte", "lt", "lte", "exists", "empty"]},
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
_FILTER_PARAM = {"type": "object", "description": "Filter DSL object: {conditions:[{field,op,value}], logic, timeRange:{from,to}, hourRange, regex:{field,pattern}, text}. Empty object = everything."}

TOOLS: list[dict[str, Any]] = [
    {"type": "function", "function": {
        "name": "get_case_summary",
        "description": "Overview of the loaded evidence: files, counts, time range, top event ids, top senders, number of findings. Call this first when you know nothing about the case.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "search_events",
        "description": "Search Windows events with the filter DSL. Returns up to `limit` rows (default 30, max 100) with the most useful columns.",
        "parameters": {"type": "object", "properties": {"filter": _FILTER_PARAM, "limit": {"type": "integer"}, "fields": {"type": "array", "items": {"type": "string"}, "description": "optional list of fields to return"}}, "required": ["filter"]},
    }},
    {"type": "function", "function": {
        "name": "aggregate_events",
        "description": "Count events grouped by one field (e.g. eventId, ipAddress, targetUser, computer, logonType, provider). Returns top N groups with counts and first/last timestamps.",
        "parameters": {"type": "object", "properties": {"filter": _FILTER_PARAM, "field": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["field"]},
    }},
    {"type": "function", "function": {
        "name": "timeline_events",
        "description": "Histogram of matching events over time. bucket: 'hour' | 'day' | 'minute'. Use it to spot bursts (brute force, spraying).",
        "parameters": {"type": "object", "properties": {"filter": _FILTER_PARAM, "bucket": {"type": "string", "enum": ["minute", "hour", "day"]}, "limit": {"type": "integer"}}, "required": ["bucket"]},
    }},
    {"type": "function", "function": {
        "name": "get_event",
        "description": "Full detail of one event by its id (all EventData fields).",
        "parameters": {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]},
    }},
    {"type": "function", "function": {
        "name": "search_mails",
        "description": "Search parsed mails with the filter DSL (fields: subject, fromAddr, fromDomain, fromName, flags, risk, date, originIp, attachments...). Returns up to `limit` rows.",
        "parameters": {"type": "object", "properties": {"filter": _FILTER_PARAM, "limit": {"type": "integer"}}, "required": ["filter"]},
    }},
    {"type": "function", "function": {
        "name": "aggregate_mails",
        "description": "Count mails grouped by one field (fromDomain, fromAddr, fromName, originIp, folder, flags...).",
        "parameters": {"type": "object", "properties": {"filter": _FILTER_PARAM, "field": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["field"]},
    }},
    {"type": "function", "function": {
        "name": "timeline_mails",
        "description": "Histogram of matching mails over time. bucket: 'minute' | 'hour' | 'day'. Use it to spot sending bursts (compromised account, campaign waves).",
        "parameters": {"type": "object", "properties": {"filter": _FILTER_PARAM, "bucket": {"type": "string", "enum": ["minute", "hour", "day"]}}, "required": ["bucket"]},
    }},
    {"type": "function", "function": {
        "name": "get_mail",
        "description": "Full detail of one mail by id: headers, hops, auth results, urls, attachments (metadata only) and text preview.",
        "parameters": {"type": "object", "properties": {"id": {"type": "integer"}, "includeBody": {"type": "boolean"}}, "required": ["id"]},
    }},
    {"type": "function", "function": {
        "name": "list_findings",
        "description": "Findings produced by the detection rules (optionally filtered by severity or source).",
        "parameters": {"type": "object", "properties": {"severity": {"type": "string"}, "source": {"type": "string", "enum": ["events", "mails"]}, "limit": {"type": "integer"}}},
    }},
    {"type": "function", "function": {
        "name": "regex_test",
        "description": "Test a JavaScript regular expression against a sample string or against the first N matching rows of a field. Returns matches.",
        "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}, "flags": {"type": "string"}, "sample": {"type": "string"}, "source": {"type": "string", "enum": ["events", "mails"]}, "field": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["pattern"]},
    }},
    {"type": "function", "function": {
        "name": "lookup_ioc",
        "description": "Reputation of an indicator (ip, domain, url, hash) from the configured providers. Only works if the analyst enabled external lookups; otherwise returns a notice.",
        "parameters": {"type": "object", "properties": {"kind": {"type": "string", "enum": ["ip", "domain", "url", "hash"]}, "value": {"type": "string"}}, "required": ["kind", "value"]},
    }},
    {"type": "function", "function": {
        "name": "sql",
        "description": "Server-stored cases only: run ONE read-only DuckDB SQL query (SELECT/WITH) over the case tables (events, mails, attachments, urls, mail_bodies, iocs). Use it for precise aggregations, window functions and joins. Quote camelCase columns with double quotes. Results are capped (limit).",
        "parameters": {"type": "object", "properties": {"sql": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["sql"]},
    }},
    {"type": "function", "function": {
        "name": "get_chain",
        "description": "One attack chain in full: recipient, score and its parts, seed mail, steps tied to the mail, and the findings linked to the chain (with their ids). Find it by chain id, or by the recipient's user name.",
        "parameters": {"type": "object", "properties": {"chain_id": {"type": "string"}, "user": {"type": "string"}}},
    }},
    {"type": "function", "function": {
        "name": "suggest_review",
        "description": "Record a review proposal for the analyst (shown on the Review page, applied by the analyst): a new severity, a decision (incident: reviewed|escalated|false_positive; chain: confirmed|benign|unsure), whether the report should carry it, findings to unlink from a chain, and the reason. Target one finding (finding_id) or one chain (chain_id).",
        "parameters": {"type": "object", "properties": {"finding_id": {"type": "integer"}, "chain_id": {"type": "string"}, "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]}, "decision": {"type": "string", "enum": ["reviewed", "escalated", "false_positive", "confirmed", "benign", "unsure"]}, "include": {"type": "boolean"}, "unlink_finding_ids": {"type": "array", "items": {"type": "integer"}}, "reason": {"type": "string"}}, "required": ["reason"]},
    }},
    {"type": "function", "function": {
        "name": "pivot",
        "description": "Cross-source pivot on a value (IP, user, domain, hash, subject fragment): counts of events and mails mentioning it, with first/last seen.",
        "parameters": {"type": "object", "properties": {"value": {"type": "string"}}, "required": ["value"]},
    }},
]

TOOL_NAMES = [t["function"]["name"] for t in TOOLS]
