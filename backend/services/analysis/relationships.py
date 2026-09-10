"""Evidence-backed entity relationships, independent of phishing seeds.

Edges assert an observation in a source record, not causation. Process GUIDs and
explicit start times identify instances; a PID on its own never merges processes.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import ntpath
import re
from typing import Any
from urllib.parse import urlsplit

from services.analysis.collection_context import prepare
from services.parsers.collection import timestamp

ROW_CAP = 20_000
NODE_CAP = 20_000
EDGE_CAP = 40_000
REF_CAP = 30
FIELDS = (
    "id",
    "evidenceId",
    "sourceFile",
    "sourceName",
    "sourceIndex",
    "sourceSha256",
    "packageId",
    "memberIndex",
    "recordKind",
    "artifactType",
    "observedAt",
    "ts",
    "date",
    "computer",
    "targetUser",
    "targetDomain",
    "targetSid",
    "subjectUser",
    "subjectDomain",
    "user",
    "upn",
    "image",
    "processName",
    "processGuid",
    "processId",
    "newProcessId",
    "processStart",
    "parentProcessGuid",
    "parentImage",
    "parentProcessName",
    "serviceName",
    "serviceFile",
    "taskName",
    "path",
    "targetFilename",
    "hashes",
    "destinationIp",
    "sourceIp",
    "ipAddress",
    "destinationHostname",
    "query",
    "fromAddr",
    "toList",
    "to",
    "urls",
    "attachments",
    "summary",
    "subject",
    "name",
    "groupName",
    "memberName",
    "serviceAccount",
    "company",
    "deceptionEpisodeId",
    "deceptionExhibitId",
    "deceptionParentExhibitId",
    "deceptionScope",
    "deceptionAction",
    "deceptionResult",
    "deceptionStage",
)


def clean(value: Any) -> str:
    return str(value).strip()[:2048] if value is not None and not isinstance(value, (dict, list)) else ""


def ident(kind: str, value: str, scope: str = "") -> str:
    return kind + ":" + hashlib.sha256(json.dumps([kind, scope, value], ensure_ascii=False).encode()).hexdigest()[:24]


def file_path(value: Any) -> str:
    value = clean(value)
    # An executable field may contain a command line. Only take an unambiguous
    # quoted path or a complete path with no arguments; retain all raw fields elsewhere.
    if value.startswith('"'):
        value = value.split('"', 2)[1]
    elif re.search(r"\.(exe|dll|com|bat|cmd|ps1)\s+", value, re.I):
        return ""
    if not re.match(r"^(?:[a-zA-Z]:[\\/]|\\\\)", value):
        return ""
    return ntpath.normpath(value).casefold()


def build(events: list[dict[str, Any]], mails: list[dict[str, Any]], options: dict | None = None, process_context: list | None = None) -> dict[str, Any]:
    events = prepare(events, options, process_context)
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    limited = False

    def node(kind: str, value: str, scope: str = "", label: str | None = None) -> str | None:
        nonlocal limited
        if not value:
            return None
        nid = ident(kind, value, scope)
        if nid not in nodes:
            if len(nodes) >= NODE_CAP:
                limited = True
                return None
            nodes[nid] = {"id": nid, "kind": kind, "value": value, "scope": scope, "label": label or value}
        return nid

    def link(a: str | None, b: str | None, relation: str, reason: str, confidence: str, ref: dict[str, Any]) -> None:
        nonlocal limited
        if not a or not b or a == b:
            return
        k = (a, b, relation)
        if k not in edges:
            if len(edges) >= EDGE_CAP:
                limited = True
                return
            edges[k] = {"source": a, "target": b, "relation": relation, "reason": reason, "confidence": confidence, "refs": [], "count": 0}
        edge = edges[k]
        edge["count"] += 1
        if len(edge["refs"]) < REF_CAP:
            edge["refs"].append(ref)

    def ip(value: Any) -> str | None:
        try:
            addr = ipaddress.ip_address(clean(value))
            return node("ip", str(addr)) if not addr.is_unspecified else None
        except ValueError:
            return None

    def domain(value: Any) -> str | None:
        v = clean(value).casefold().rstrip(".")
        try:
            ipaddress.ip_address(v)
            return ip(v)
        except ValueError:
            return node("domain", v) if "." in v and not re.search(r"[\s/\\]", v) else None

    def account(value: Any, realm: Any, host: str, ref_scope: str) -> str | None:
        v = clean(value).casefold()
        if not v or v in ("-", "n/a"):
            return None
        if "@" in v or "\\" in v:
            return node("account", v)
        if clean(realm):
            return node("account", clean(realm).casefold() + "\\" + v)
        return node("account", v, host or ref_scope, f"{v} ({host or 'unresolved scope'})")

    for source, rows in (("events", events[:ROW_CAP]), ("mails", mails[:ROW_CAP])):
        for row_index, row in enumerate(rows):
            ref = {k: row.get(k) for k in ("id", "evidenceId", "sourceFile", "sourceSha256", "sourceIndex", "packageId", "memberIndex", "observedAt")}
            ref.update(
                source=source,
                ts=row.get("ts") if source == "events" else row.get("date"),
                recordKind=row.get("recordKind") or "event",
                title=clean(row.get("summary") or row.get("subject")),
            )
            if not ref["sourceFile"]:
                ref["sourceFile"] = row.get("sourceName")
            # dict.get returns a stored None, so an explicit "id": null would give every row of a
            # page the same scope and collapse them onto one fabricated record node.
            row_id = row.get("id") if row.get("id") is not None else row_index
            scope = f"{source}:{row_id}:{row.get('evidenceId')}"
            record = node("record", scope, label=ref["title"] or f"{source} #{row_id}")
            if row.get("artifactType") == "deception":
                episode = clean(row.get("deceptionEpisodeId"))
                exhibit = clean(row.get("deceptionExhibitId"))
                parent = clean(row.get("deceptionParentExhibitId"))
                mode = clean(row.get("deceptionScope"))
                if re.fullmatch(r"[a-f0-9]{32}", episode) and mode in ("archive", "challenge"):
                    en = node("deception-episode", episode, mode, f"{mode} episode {episode[:12]}")
                    if re.fullmatch(r"[a-f0-9]{32}", exhibit):
                        xn = node("deception-exhibit", exhibit, episode, f"Exhibit {exhibit[:12]}")
                        link(record, xn, "records exhibit", "Measured request to a synthetic service; source provenance retained", "high", ref)
                        link(xn, en, "within episode", "Signed reference episode, not a visitor identity", "high", ref)
                        if re.fullmatch(r"[a-f0-9]{32}", parent):
                            pn = node("deception-exhibit", parent, episode, f"Exhibit {parent[:12]}")
                            link(
                                pn,
                                xn,
                                "supplied reference",
                                "Request used a signed reference issued by this parent exhibit; sharing and replay are possible",
                                "high",
                                ref,
                            )
                continue  # Synthetic labels and response hashes are never promoted to real host/IOC nodes.
            host = clean(row.get("computer")).casefold().rstrip(".")
            hn = node("host", host)
            link(record, hn, "observed on", "Host explicitly named by this record or collection manifest", "high", ref)
            for user, realm in (("targetUser", "targetDomain"), ("subjectUser", "subjectDomain"), ("user", "targetDomain"), ("upn", "targetDomain")):
                an = account(row.get(user), row.get(realm), host, scope)
                link(
                    record,
                    an,
                    "names account",
                    f"Account in {user}; bare names are scoped to the host or source record",
                    "high" if clean(row.get(realm)) or "@" in clean(row.get(user)) or "\\" in clean(row.get(user)) else "contextual",
                    ref,
                )
            sid = clean(row.get("targetSid"))
            if re.fullmatch(r"S-1-(?:\d+-)*\d+", sid, re.I):
                sn = node("sid", sid.upper())
                link(record, sn, "names SID", "Security identifier explicitly recorded", "high", ref)
                link(
                    account(row.get("targetUser"), row.get("targetDomain"), host, scope),
                    sn,
                    "reported SID",
                    "Account and security identifier reported together",
                    "high",
                    ref,
                )
            image_value = file_path(row.get("image") or row.get("processName"))
            file_scope = host or scope
            fn = node("file", image_value, file_scope)
            link(record, fn, "names executable", "Full Windows path in the executable field, scoped to its host", "high" if host else "contextual", ref)
            guid = clean(row.get("processGuid")).casefold()
            start = timestamp(row.get("processStart"))
            pid = clean(row.get("processId") or row.get("newProcessId"))
            process_key = guid if guid else f"{pid}@{start}" if pid and start is not None else ""
            pn = node("process", process_key, host, f"{image_value or 'process'} · {process_key}") if host and process_key else None
            if not pn and pid:
                pn = node("process-observation", pid, scope, f"PID {pid} · {host or 'unknown host'} · instance unresolved")
            link(
                record,
                pn,
                "observed process",
                row.get("_processResolution") or "Process GUID or PID plus explicit start time identifies an instance"
                if process_key
                else "PID alone identifies only this observation; it is not merged with other records",
                "high" if process_key and host and not row.get("_processResolution") else "contextual",
                ref,
            )
            if supporting := row.get("_processEvidence"):
                support_ref = {
                    k: supporting.get(k) for k in ("id", "evidenceId", "sourceFile", "sourceSha256", "sourceIndex", "packageId", "memberIndex", "observedAt")
                }
                support_ref.update(source="events", ts=supporting.get("ts"), recordKind="observation", title=clean(supporting.get("summary")))
                link(record, pn, "observed process", row["_processResolution"], "contextual", support_ref)
            link(
                pn,
                fn,
                "uses executable",
                row.get("_processResolution") or "Process and executable appear in the same source record",
                "contextual" if row.get("_processResolution") else "high",
                ref,
            )
            parent_guid = clean(row.get("parentProcessGuid")).casefold()
            if host and parent_guid:
                parent = node("process", parent_guid, host)
                link(parent, pn, "parent of", "Explicit parent process GUID", "high", ref)
            for field, kind in (("serviceName", "service"), ("taskName", "task")):
                entity = node(kind, clean(row.get(field)).casefold(), file_scope)
                link(record, entity, "observed configuration", f"{field} appears in this record; observation does not establish creation time", "high", ref)
                target = node("file", file_path(row.get("serviceFile")) if kind == "service" else image_value, file_scope)
                link(entity, target, "configured executable", "Explicit executable path in the configuration record", "high", ref)
                if kind == "service":
                    link(
                        entity,
                        account(row.get("serviceAccount"), None, host, scope),
                        "configured account",
                        "Service account named by this configuration",
                        "high",
                        ref,
                    )
            artifact = clean(row.get("artifactType"))
            if artifact in ("program", "autorun"):
                entity = node(artifact, clean(row.get("name")).casefold(), file_scope)
                link(record, entity, "observed configuration", f"{artifact} named in the collected export", "high", ref)
                link(entity, fn, "configured executable", "Executable reported in the same export row", "high", ref)
            group = node("group", clean(row.get("groupName")).casefold(), host or scope)
            link(record, group, "names group", "Group explicitly recorded; names scoped to the host", "high", ref)
            link(
                group,
                account(row.get("memberName") or row.get("targetUser"), row.get("targetDomain"), host, scope),
                "reported member",
                "Group and member appear in this record",
                "high",
                ref,
            )
            for field in ("path", "targetFilename"):
                other = node("file", file_path(row.get(field)), file_scope)
                link(record, other, "names file", f"Full path in {field}, scoped to its host", "high" if host else "contextual", ref)
                fn = fn or other
            for algorithm, value in re.findall(r"(SHA256|SHA1|MD5)=([a-fA-F0-9]+)", clean(row.get("hashes")), re.I):
                if len(value) != {"SHA256": 64, "SHA1": 40, "MD5": 32}[algorithm.upper()]:
                    continue
                hash_node = node("hash", algorithm.lower() + ":" + value.lower())
                link(record, hash_node, "reports hash", "Explicit digest in the source record", "high", ref)
                link(fn, hash_node, "reported digest", "Path and digest are reported together; historical versions remain separate observations", "high", ref)
            for field in ("destinationIp", "sourceIp", "ipAddress"):
                endpoint = ip(row.get(field))
                link(record, endpoint, "names address", f"Address in {field}", "high", ref)
                if field == "destinationIp":
                    link(
                        pn,
                        endpoint,
                        "observed endpoint",
                        row.get("_processResolution") or "Process and destination appear together in this record",
                        "high" if process_key and not row.get("_processResolution") else "contextual",
                        ref,
                    )
            for field in ("query", "destinationHostname"):
                link(record, domain(row.get(field)), "names domain", f"Domain in {field}", "high", ref)
            if source == "mails":
                link(
                    record,
                    account(row.get("fromAddr"), None, "", scope),
                    "sent by",
                    "Sender address in the message; authentication is assessed separately",
                    "contextual",
                    ref,
                )
                recipients = row.get("toList") or row.get("to") or []
                for recipient in recipients if isinstance(recipients, list) else []:
                    addr = recipient.get("addr") if isinstance(recipient, dict) else recipient
                    link(record, account(addr, None, "", scope), "addressed to", "Recipient address in the message", "high", ref)
                for url in row.get("urls") or []:
                    if not isinstance(url, dict):
                        continue
                    value = clean(url.get("normalized") or url.get("url"))
                    un = node("url", value)
                    link(record, un, "contains URL", "URL extracted from the message", "high", ref)
                    try:
                        link(un, domain(urlsplit(value).hostname), "has host", "Hostname parsed from this URL", "high", ref)
                    except ValueError:
                        pass
                for attachment in row.get("attachments") or []:
                    if not isinstance(attachment, dict):
                        continue
                    # Validate and use the same cleaned string: a JSON number that stringifies to
                    # 64 hex digits passes the check and then has no .lower().
                    digest = clean(attachment.get("sha256"))
                    if re.fullmatch(r"[a-fA-F0-9]{64}", digest):
                        link(record, node("hash", "sha256:" + digest.lower()), "attachment digest", "SHA-256 of the attached file", "high", ref)
    return {
        "cursor": None,
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "stats": {
            "events": min(len(events), ROW_CAP),
            "mails": min(len(mails), ROW_CAP),
            "truncated": limited or len(events) > ROW_CAP or len(mails) > ROW_CAP,
            "rowCap": ROW_CAP,
            "referenceCap": REF_CAP,
        },
    }
