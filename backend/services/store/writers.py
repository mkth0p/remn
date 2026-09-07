"""Convert parser rows into store rows (events, mails, attachments, urls, bodies, IOCs) and write them in batches."""

from __future__ import annotations

import json
import re
from typing import Any

from services.common import is_public_ip
from services.store.casestore import (
    ATTACHMENT_COLUMNS,
    EVENT_COLUMNS,
    MAIL_BOOL,
    MAIL_COLUMNS,
    MAIL_INT,
    MAIL_JSON,
    MAIL_LIST,
    URL_COLUMNS,
    CaseStore,
    as_bool,
)

EVENT_NAMES = [n for n, _ in EVENT_COLUMNS]
MAIL_NAMES = [n for n, _ in MAIL_COLUMNS]
ATT_NAMES = [n for n, _ in ATTACHMENT_COLUMNS]
URL_NAMES = [n for n, _ in URL_COLUMNS]
BATCH = 5000
_IPV4 = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def _int(v: Any) -> int | None:
    if v is None or v == "" or isinstance(v, bool):
        return None if v is None or v == "" else int(v)
    try:
        if isinstance(v, str) and v.lower().startswith("0x"):
            return int(v, 16)
        return int(float(v))
    except (TypeError, ValueError):
        return None


def _json(v: Any) -> str | None:
    if v is None:
        return None
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"), default=str)


class IocBatch:
    def __init__(self, evidence_id: int) -> None:
        self.evidence_id = evidence_id
        self.map: dict[tuple[str, str], dict[str, Any]] = {}

    def add(self, kind: str, value: Any, source: str, ts: int | None) -> None:
        if not value:
            return
        v = str(value).strip().lower()[:2048]
        if not v:
            return
        key = (kind, v)
        cur = self.map.get(key)
        if cur:
            cur["count"] += 1
            if source not in cur["sources"] and len(cur["sources"]) < 8:
                cur["sources"].append(source)
            if ts is not None:
                cur["firstSeen"] = ts if cur["firstSeen"] is None else min(cur["firstSeen"], ts)
                cur["lastSeen"] = ts if cur["lastSeen"] is None else max(cur["lastSeen"], ts)
        elif len(self.map) < 200000:
            self.map[key] = {"kind": kind, "value": v, "evidenceId": self.evidence_id, "count": 1, "firstSeen": ts, "lastSeen": ts, "sources": [source]}

    def drain(self) -> list[dict[str, Any]]:
        rows = list(self.map.values())
        self.map = {}
        return rows


def _hashes_from_sysmon(h: Any) -> list[str]:
    if not isinstance(h, str):
        return []
    out = []
    for part in h.split(","):
        k, _, v = part.partition("=")
        if k.strip().upper() in ("SHA256", "MD5", "SHA1") and v.strip():
            out.append(v.strip())
    return out


def event_iocs(row: dict[str, Any], batch: IocBatch) -> None:
    ts = row.get("ts") if isinstance(row.get("ts"), int) else None
    src = f"event:{row.get('eventId')}"
    for f in ("ipAddress", "destinationIp", "sourceIp"):
        v = row.get(f)
        if isinstance(v, str) and is_public_ip(v):
            batch.add("ip", v, src, ts)
    if isinstance(row.get("query"), str) and "." in row["query"]:
        batch.add("domain", row["query"], "sysmon-dns", ts)
    if isinstance(row.get("destinationHostname"), str) and "." in row["destinationHostname"]:
        batch.add("domain", row["destinationHostname"], "sysmon-net", ts)
    for h in _hashes_from_sysmon(row.get("hashes")):
        batch.add("hash", h, f"sysmon:{row.get('eventId')}", ts)
    u = row.get("url")
    if isinstance(u, str) and re.match(r"^https?://(?![+*]|localhost|127\.)[a-z0-9.-]+(?::\d+)?(?:/|$)", u, re.I):
        batch.add("url", u, str(row.get("provider") or "event"), ts)


def mail_iocs(row: dict[str, Any], batch: IocBatch) -> None:
    ts = row.get("date") if isinstance(row.get("date"), int) else None
    if row.get("originIp") and is_public_ip(row["originIp"]):
        batch.add("ip", row["originIp"], "mail-origin", ts)
    if row.get("fromAddr"):
        batch.add("email", row["fromAddr"], "mail-from", ts)
    if row.get("fromRegistrable"):
        batch.add("domain", row["fromRegistrable"], "mail-from", ts)
    for u in row.get("urls") or []:
        scheme = u.get("scheme")
        if scheme in ("http", "https", None, ""):
            batch.add("url", u.get("normalized") or u.get("url"), "mail-url", ts)
            dom = u.get("domain")
            if dom and not _IPV4.match(dom):
                batch.add("domain", dom, "mail-url", ts)
            elif dom and is_public_ip(dom):
                batch.add("ip", dom, "mail-url", ts)
    for a in row.get("attachments") or []:
        if a.get("sha256"):
            batch.add("hash", a["sha256"], "attachment", ts)


class EventWriter:
    def __init__(self, store: CaseStore, evidence_id: int, include_raw: bool = True, preserve_ids: bool = False) -> None:
        self.store = store
        self.evidence_id = evidence_id
        self.include_raw = include_raw
        self.preserve_ids = preserve_ids
        self.batch: list[dict[str, Any]] = []
        self.iocs = IocBatch(evidence_id)
        self.count = 0

    def add(self, row: dict[str, Any]) -> None:
        # Keep the row sparse: the Arrow batch builder only materialises columns that are present.
        # Type coercion happens per column in the batch builder (with a per-value fallback).
        out = dict(row)
        data = out.get("data")
        if data is not None and not isinstance(data, str):
            out["data"] = _json(data)
        if not self.include_raw:
            out.pop("raw", None)
        for k in ("caseId", "type") if self.preserve_ids else ("id", "caseId", "type"):
            out.pop(k, None)
        if self.preserve_ids:
            out["id"] = preserved_id(self.store, "events", row.get("id"))
        out["evidenceId"] = self.evidence_id
        self.batch.append(out)
        event_iocs(row, self.iocs)
        if len(self.batch) >= BATCH:
            self.flush()

    def flush(self) -> None:
        if self.batch:
            if not self.preserve_ids:
                start = self.store.reserve_ids("events", len(self.batch))
                for i, r in enumerate(self.batch):
                    r["id"] = start + i
            self.store.insert_rows("events", self.batch)
            self.count += len(self.batch)
            self.batch = []
        iocs = self.iocs.drain()
        if iocs:
            self.store.insert_rows("iocs", iocs)


def preserved_id(store: CaseStore, table: str, value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value < 2**53:
        raise ValueError("Restored rows require a positive safe integer id")
    with store.lock:
        store._next[table] = max(store._next[table], value + 1)
    return value


class MailWriter:
    def __init__(self, store: CaseStore, evidence_id: int, keep_bodies: bool = True, preserve_ids: bool = False) -> None:
        self.store = store
        self.evidence_id = evidence_id
        self.keep_bodies = keep_bodies
        self.preserve_ids = preserve_ids
        self.mails: list[dict[str, Any]] = []
        self.bodies: list[dict[str, Any]] = []
        self.attachments: list[dict[str, Any]] = []
        self.urls: list[dict[str, Any]] = []
        self.iocs = IocBatch(evidence_id)
        self.count = 0

    def add(self, row: dict[str, Any]) -> None:
        mail_id = preserved_id(self.store, "mails", row.get("id")) if self.preserve_ids else self.store.reserve_ids("mails", 1)
        out: dict[str, Any] = {"id": mail_id, "evidenceId": self.evidence_id}
        auth = row.get("auth") or {}
        reply_to = row.get("replyTo") or []
        for name in MAIL_NAMES:
            if name in ("id", "evidenceId"):
                continue
            if name == "replyToAddr":
                out[name] = reply_to[0].get("addr") if reply_to else None
            elif name == "replyToDomain":
                out[name] = reply_to[0].get("domain") if reply_to else None
            elif name == "replyToList":
                out[name] = [x.get("addr") for x in reply_to if x.get("addr")]
            elif name in ("toList", "ccList", "bccList"):
                out[name] = [x.get("addr") for x in (row.get(name[:-4]) or []) if x.get("addr")]
            elif name == "senderAddr":
                out[name] = (row.get("sender") or {}).get("addr") if isinstance(row.get("sender"), dict) else None
            elif name in ("spf", "dkim", "dmarc", "compauth"):
                out[name] = auth.get(name)
            elif name == "reputationWorst":
                out[name] = (row.get("reputation") or {}).get("worst")
            elif name == "reputationOriginIp":
                out[name] = ((row.get("reputation") or {}).get("originIp") or {}).get("verdict")
            elif name in MAIL_JSON:
                out[name] = _json(row.get(name))
            elif name in MAIL_LIST:
                v = row.get(name)
                out[name] = [str(x) for x in v] if isinstance(v, list) else []
            elif name in MAIL_INT:
                out[name] = _int(row.get(name))
            elif name in MAIL_BOOL:
                out[name] = as_bool(row.get(name))
            else:
                v = row.get(name)
                out[name] = v if (v is None or isinstance(v, str)) else str(v)
        self.mails.append(out)
        if self.keep_bodies:
            self.bodies.append(
                {
                    "mailId": mail_id,
                    "bodyText": row.get("bodyText"),
                    "bodyHtml": row.get("bodyHtml"),
                    "headersText": row.get("headersText"),
                    "visibleText": row.get("visibleText"),
                }
            )
        for a in row.get("attachments") or []:
            self.attachments.append(
                {
                    "id": 0,
                    "mailId": mail_id,
                    "evidenceId": self.evidence_id,
                    "name": a.get("name"),
                    "ext": a.get("ext"),
                    "realExt": a.get("realExt"),
                    "realMime": a.get("realMime"),
                    "size": _int(a.get("size")),
                    "sha256": a.get("sha256"),
                    "md5": a.get("md5"),
                    "risk": _int(a.get("risk")),
                    "flags": list(a.get("flags") or []),
                    "category": a.get("category"),
                    "inline": bool(a.get("inline")),
                    "details": _json(a.get("details")),
                    "date": _int(row.get("date")),
                    "fromAddr": row.get("fromAddr"),
                    "mailSubject": row.get("subject"),
                }
            )
        for u in row.get("urls") or []:
            self.urls.append(
                {
                    "id": 0,
                    "mailId": mail_id,
                    "evidenceId": self.evidence_id,
                    "url": u.get("url"),
                    "normalized": u.get("normalized"),
                    "defanged": u.get("defanged"),
                    "host": u.get("host"),
                    "domain": u.get("domain"),
                    "scheme": u.get("scheme"),
                    "flags": list(u.get("flags") or []),
                    "text": u.get("text"),
                    "source": u.get("source"),
                    "date": _int(row.get("date")),
                }
            )
        mail_iocs(row, self.iocs)
        if len(self.mails) >= 500:
            self.flush()

    def flush(self) -> None:
        if self.mails:
            self.store.insert_rows("mails", self.mails)
            self.count += len(self.mails)
            self.mails = []
        if self.bodies:
            self.store.insert_rows("mail_bodies", self.bodies)
            self.bodies = []
        if self.attachments:
            start = self.store.reserve_ids("attachments", len(self.attachments))
            for i, r in enumerate(self.attachments):
                r["id"] = start + i
            self.store.insert_rows("attachments", self.attachments)
            self.attachments = []
        if self.urls:
            start = self.store.reserve_ids("urls", len(self.urls))
            for i, r in enumerate(self.urls):
                r["id"] = start + i
            self.store.insert_rows("urls", self.urls)
            self.urls = []
        iocs = self.iocs.drain()
        if iocs:
            self.store.insert_rows("iocs", iocs)
