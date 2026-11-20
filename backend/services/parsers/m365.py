"""
Microsoft 365 Unified Audit Log (UAL) and Entra ID sign-in exports -> event rows.

Business-email-compromise investigations live on three sources: the mailbox itself, the
Unified Audit Log (inbox rules, forwarding, MailItemsAccessed, consent grants, role changes)
and the Entra sign-in log (who authenticated from where, with what client, at what risk).
REMN ingests the exports the acquisition tools produce - Purview / Invictus
Microsoft-Extractor-Suite / Office-365-Extractor CSV and JSON, Untitled Goose Tool JSON,
Entra portal CSV, Graph sign-in JSON - as rows of the *events* table, so the timeline, facets,
rules, AI tools and cross-source pivots work on them unchanged.

Formats (detected from the first bytes, in UTF-8, UTF-16 or UTF-32 with a byte order mark, also
inside zip/tar archives):
    m365-ual-csv        CSV with an AuditData column (CreationDate, UserIds, Operations, AuditData ...)
    m365-ual-json       JSON array / NDJSON of AuditData objects, or of {..., "AuditData": "<json>"} rows
    entra-signin-json   JSON array / NDJSON of Graph signIn objects (Get-EntraSignInLogs, Goose)
    entra-signin-csv    Entra portal CSV export or a Graph-property CSV

Row conventions (shared with the EVTX parser so rules can mix both):
    provider   "Microsoft 365 Unified Audit Log" | "Microsoft Entra ID Sign-in"
    channel    the UAL Workload (Exchange, AzureActiveDirectory, SharePoint, OneDrive ...) | "Entra SignIn"
    category   "M365 Exchange" | "M365 Entra" | "M365 SharePoint" | ... | "Entra sign-in"
    operation  the UAL Operation / "SignIn"
    subjectUser = user (actor UPN), targetUser = affected user when the operation has one
    ipAddress   client IP (port and brackets stripped), status / statusText, objectName
    data        every AuditData field flattened one level: Parameters, ExtendedProperties,
                ModifiedProperties (NewValue, plus "<name>.old"), OperationProperties, Target,
                Actor, AppAccessContext.*; Entra: appDisplayName, clientAppUsed, country, city,
                riskLevelDuringSignIn, riskState, conditionalAccessStatus, errorCode ...
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import itertools
import json
import logging
import os
import re
from array import array
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

log = logging.getLogger(__name__)

# The longest field a CSV export may hold. Python's csv stops at 131,072 characters, which one
# DLP or MailItemsAccessed record passes, and the export then ended at that record. The limit is
# the csv module's own, for the whole process, so it is only ever raised here.
MAX_FIELD_CHARS = 16 * 1024 * 1024
if csv.field_size_limit() < MAX_FIELD_CHARS:
    csv.field_size_limit(MAX_FIELD_CHARS)

UAL_PROVIDER = "Microsoft 365 Unified Audit Log"
ENTRA_PROVIDER = "Microsoft Entra ID Sign-in"
FORMATS = ("m365-ual-csv", "m365-ual-json", "entra-signin-json", "entra-signin-csv")

_WORKLOAD_CATEGORY = {
    "exchange": "M365 Exchange",
    "azureactivedirectory": "M365 Entra",
    "sharepoint": "M365 SharePoint",
    "onedrive": "M365 OneDrive",
    "microsoftteams": "M365 Teams",
    "securitycompliancecenter": "M365 Compliance",
    "compliance": "M365 Compliance",
    "threatintelligence": "M365 Defender",
    "microsoftdefenderforidentity": "M365 Defender",
    "powerbi": "M365 Power BI",
    "microsoftflow": "M365 Power Automate",
    "powerapps": "M365 Power Apps",
    "dynamics365": "M365 Dynamics",
}
_PRIVILEGED_ROLES = (
    "global administrator",
    "company administrator",
    "privileged role administrator",
    "exchange administrator",
    "security administrator",
    "conditional access administrator",
    "application administrator",
    "cloud application administrator",
    "authentication administrator",
    "privileged authentication administrator",
    "user administrator",
    "helpdesk administrator",
    "sharepoint administrator",
    "global reader",
)


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------
# PowerShell 5 (Export-Csv -Encoding Unicode, Out-File) and the admin centres write UTF-16 with a
# byte order mark, and Microsoft-Extractor-Suite takes -Encoding utf32. Read as UTF-8, such an
# export was not recognised and was reported as an event log that failed. The longer marks come
# first: UTF-32's little-endian mark starts with UTF-16's.
_BOMS = (
    (b"\xff\xfe\x00\x00", "utf-32"),
    (b"\x00\x00\xfe\xff", "utf-32"),
    (b"\xff\xfe", "utf-16"),
    (b"\xfe\xff", "utf-16"),
    (b"\xef\xbb\xbf", "utf-8-sig"),
)


def encoding_of(head: bytes) -> str:
    """The encoding an export's byte order mark names; UTF-8 when it has none."""
    for bom, encoding in _BOMS:
        if head.startswith(bom):
            return encoding
    return "utf-8-sig"


def head_text(head: bytes) -> str:
    """The first bytes of an export as text, in the encoding its byte order mark names. A head cut
    inside a character loses that character only."""
    encoding = encoding_of(head)
    width = 4 if encoding == "utf-32" else 2 if encoding == "utf-16" else 1
    return head[: len(head) - len(head) % width].decode(encoding, "replace")


def _header_line(text: str) -> str:
    """A table's header: its first line, or its second after the "#TYPE <type name>" line that
    Windows PowerShell's Export-Csv writes without -NoTypeInformation."""
    lines = text.split("\n", 2)
    line = lines[1] if lines[0].startswith("#TYPE") and len(lines) > 1 else lines[0]
    return line.rstrip("\r")


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
def detect_format(name: str, head: bytes) -> str | None:
    """Return one of FORMATS for a UAL / Entra export, else None."""
    if not looks_like_export(name, head):
        return None
    text = head_text(head).lstrip()
    low = text.lower()
    if text.startswith(("[", "{")):
        if '"auditdata"' in low or ('"operation"' in low and ('"workload"' in low or '"creationtime"' in low)):
            return "m365-ual-json"
        if is_signin(_KEY_RE.findall(text)):
            return "entra-signin-json"
        # Azure Monitor diagnostic records (Log Analytics, Event Hub, storage account): the
        # sign-in is under "properties", past the head
        if any(f'"category": "{c}"' in low or f'"category":"{c}"' in low for c in _SIGNIN_CATEGORIES):
            return "entra-signin-json"
        return None
    header = _header_line(text)
    if "auditdata" in header.lower():
        return "m365-ual-csv"
    if is_signin(next(csv.reader([header]), [])):
        return "entra-signin-csv"
    return None


UNRECOGNISED = "not a recognised Microsoft 365 or Entra export"


def looks_like_export(name: str, head: bytes) -> bool:
    """Whether a file is a table or a JSON document by its name or first character: what a cloud
    export is, and what an event log is not."""
    n = (name or "").lower()
    return n.endswith((".csv", ".json", ".jsonl", ".ndjson", ".txt", ".log")) or head_text(head[:8])[:1] in ("[", "{")


_KEY_RE = re.compile(r'"([^"\\]{1,64})"\s*:')
# A sign-in says, together, when it happened, the address it came from, and who signed in to
# which application. A directory audit, a risk detection, a risky-user list and a user list
# name a userPrincipalName too, and each of their records was read as a successful sign-in.
_SIGNIN_WHO = frozenset({"userprincipalname", "appdisplayname", "clientappused", "conditionalaccessstatus"})


def is_signin(keys: Iterable[Any]) -> bool:
    """Whether a record, or a table, with these field names (Graph, portal, any case) is a sign-in."""
    low = {str(k).strip().lower() for k in keys}
    low = {(_PORTAL_MAP.get(k) or k).lower() for k in low}
    return "createddatetime" in low and "ipaddress" in low and bool(low & _SIGNIN_WHO)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_BRACKETED_RE = re.compile(r"^\[([0-9a-fA-F:.]+)\](?::\d+)?$")


def clean_ip(v: Any) -> str | None:
    """The address in "1.2.3.4", "1.2.3.4:443", "2001:db8::1" or "[2001:db8::1]:443".

    A bare IPv6 address is taken whole: its last group can be all digits, and reading that as a
    port turned 2001:db8::1 into 2001:db8:. Anything that is not an address is kept as it came."""
    s = str(v or "").strip()
    if not s or s.lower() in ("null", "none", "<null>"):
        return None
    m = _BRACKETED_RE.match(s)
    candidate = m.group(1) if m else s.rsplit(":", 1)[0] if s.count(":") == 1 else s
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return s[:100]


_NUMERIC_DATE_RE = re.compile(r"^\s*(\d{1,2})[/.-](\d{1,2})[/.-](\d{4})\b")


def date_order(values: Iterable[Any]) -> bool | None:
    """Whether the numeric dates of one export are day-first (True), month-first (False), or
    cannot tell (None). An export is written in one culture, so one value with a day above 12
    settles the order for all of them; before this, 05/01 in a French export was read as 1 May
    while 15/01 in the same file was read as 15 January."""
    day_first = month_first = False
    for v in values:
        m = _NUMERIC_DATE_RE.match(str(v or ""))
        if not m:
            continue
        a, b = int(m.group(1)), int(m.group(2))
        day_first = day_first or a > 12
        month_first = month_first or b > 12
    if day_first == month_first:
        return None
    return day_first


def guessed_order(v: Any) -> bool:
    """Whether a numeric date reads differently day-first and month-first (05/01, not 05/05, and
    never a dotted date, which is always day-first)."""
    m = _NUMERIC_DATE_RE.match(str(v or ""))
    return bool(m) and "." not in m.group(0) and m.group(1) != m.group(2) and int(m.group(1)) <= 12 and int(m.group(2)) <= 12


# a date as a culture writes it, with its time to the minute or the second, a 12-hour clock or
# not, and the zone when the exporter wrote one: 9/1/2026 10:00 AM, 01.09.2026 10:00:00,
# 2026/09/01 10:00:00, 9/1/2026, 10:00:00 AM +02:00. The spaces after AM or PM belong to it: two runs
# of spaces side by side were split every way before a field that is not a date
_CULTURE_RE = re.compile(
    r"^(\d{1,4})([/.-])(\d{1,2})\2(\d{1,4}),?\s+(\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d{1,7}))?)?\s*(?:([AaPp][Mm])\s*)?(Z|[+-]\d{2}:?\d{2})?$"
)


def _culture_date(s: str, day_first: bool | None) -> datetime | None:
    m = _CULTURE_RE.match(s)
    if not m:
        return None
    a, sep, b, c, hour, minute, second, fraction, half, zone = m.groups()
    if len(a) == 4:
        year, month, day = int(a), int(b), int(c)
    elif len(c) != 4:
        return None
    elif sep == "." or day_first:
        day, month, year = int(a), int(b), int(c)
    else:
        month, day, year = int(a), int(b), int(c)
    h = int(hour)
    if half:
        if not 1 <= h <= 12:
            return None
        h = h % 12 + (12 if half.lower() == "pm" else 0)
    tz = UTC
    if zone and zone != "Z":
        sign = -1 if zone[0] == "-" else 1
        digits = zone[1:].replace(":", "")
        tz = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
    try:
        return datetime(year, month, day, h, int(minute), int(second or 0), int((fraction or "0")[:6].ljust(6, "0")), tzinfo=tz)
    except ValueError:
        return None


# a .NET date as Windows PowerShell's ConvertTo-Json writes one: "\/Date(1756720800000)\/", the
# milliseconds since 1970 in UTC, with the writer's offset after them when it had one
_DOTNET_DATE_RE = re.compile(r"^/Date\((-?\d{1,15})(?:[+-]\d{4})?\)/$")


def parse_ts(v: Any, day_first: bool | None = None) -> tuple[int | None, str | None]:
    """ISO-8601 (with or without zone / fractional seconds), portal 'M/D/YYYY, h:mm:ss AM', a
    culture's numeric date, or a .NET "/Date(ms)/" -> (ms, iso). day_first is the order date_order found for the file;
    None keeps the portal's own month-first order for slashes and dashes. Dotted dates are always
    day-first. A time written with a zone keeps it; one without is UTC, the zone the audit log,
    Graph and the portal's "Date (UTC)" write."""
    if v is None:
        return None, None
    if isinstance(v, (int, float)):
        ms = int(v if v > 10_000_000_000 else v * 1000)
        return ms, datetime.fromtimestamp(ms / 1000, tz=UTC).isoformat().replace("+00:00", "Z")
    s = str(v).strip()
    if not s:
        return None, None
    if m := _DOTNET_DATE_RE.match(s):
        ms = int(m.group(1))
        try:
            return ms, datetime.fromtimestamp(ms / 1000, tz=UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return None, None
    try:
        dt: datetime | None = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        dt = _culture_date(s, day_first)
    if dt is None:
        return None, None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    dt = dt.astimezone(UTC)
    return int(dt.timestamp() * 1000), dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class _Cut(str):
    """A value cut at its length limit. Its closing ellipsis says so wherever it is read, and the
    record that holds it is counted (stats.cut): a nested value cut into JSON that does not parse
    used to pass for the whole of it."""


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else _Cut(text[:limit] + "…")


def _scalar(v: Any) -> Any:
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, list):
        if all(x is None or isinstance(x, (str, int, float, bool)) for x in v):
            return ", ".join("" if x is None else str(x) for x in v)
        return _cut(json.dumps(v, ensure_ascii=False), 4000)
    if isinstance(v, dict):
        return _cut(json.dumps(v, ensure_ascii=False), 4000)
    return str(v)


def _named_list(items: Any, name_key: str = "Name", value_key: str = "Value") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not isinstance(items, list):
        return out
    for it in items:
        if isinstance(it, dict) and it.get(name_key) is not None:
            out[str(it[name_key])] = _scalar(it.get(value_key))
    return out


# an address starts where a run of address characters starts: retrying from every character of a
# long run with no "@" in it made the search quadratic in the length of the field
_EMAIL_RE = re.compile(r"(?<![\w.+'-])[\w.+'-]+@[\w-]+(?:\.[\w-]+)+")


def _json_value(v: Any) -> Any:
    if isinstance(v, str) and v.strip()[:1] in ("[", "{"):
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def _strings(v: Any) -> Iterator[str]:
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for x in v.values():
            yield from _strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x)


def _walk(v: Any) -> Iterator[tuple[str, Any]]:
    if isinstance(v, dict):
        for k, x in v.items():
            yield str(k), x
            yield from _walk(x)
    elif isinstance(v, list):
        for x in v:
            yield from _walk(x)


def outlook_rule_fields(data: dict[str, Any]) -> dict[str, Any]:
    """The fields of an inbox rule made in Outlook or over MAPI (UpdateInboxRules), under the names
    the New-/Set-InboxRule cmdlets use, so the same rules read both.

    UpdateInboxRules logs the rule as RuleActions and RuleCondition, each a JSON string, rather than
    as cmdlet parameters. An attacker in a stolen Outlook session makes exactly this kind of rule,
    and with only the cmdlet names looked at, a forward-and-delete rule raised a low finding."""
    out: dict[str, Any] = {}
    if data.get("RuleName") and not data.get("Name"):
        out["Name"] = data["RuleName"]
    actions = _json_value(data.get("RuleActions"))
    for action in actions if isinstance(actions, list) else [actions] if isinstance(actions, dict) else []:
        if not isinstance(action, dict):
            continue
        kind = str(action.get("ActionType") or action.get("Type") or "").lower()
        recipients = sorted({m.lower() for text in _strings(action) for m in _EMAIL_RE.findall(text)})
        if "redirect" in kind:
            key = "RedirectTo"
        elif "forward" in kind and "attach" in kind:
            key = "ForwardAsAttachmentTo"
        elif "forward" in kind:
            key = "ForwardTo"
        else:
            key = ""
        if key and recipients:
            out[key] = ";".join(recipients)
        if "delete" in kind:
            out["DeleteMessage" if "permanent" in kind or "soft" not in kind else "SoftDeleteMessage"] = "True"
        if "markasread" in kind.replace(" ", "") or "markread" in kind.replace(" ", ""):
            out["MarkAsRead"] = "True"
        if "move" in kind:
            folder = action.get("Folder") or action.get("FolderName") or action.get("TargetFolder") or action.get("FolderId")
            if folder:
                out["MoveToFolder"] = _cut(str(folder), 200)
    condition = _json_value(data.get("RuleCondition"))
    words: dict[str, list[str]] = {}
    for k, v in _walk(condition):
        if k.lower() not in ("words", "value", "values"):
            continue
        items = v if isinstance(v, list) else [v]
        texts = [str(x) for x in items if isinstance(x, (str, int, float))]
        if texts:
            words.setdefault("SubjectOrBodyContainsWords", []).extend(texts)
    for k, v in _walk(condition):
        if k.lower() in ("type", "conditiontype") and isinstance(v, str):
            low = v.lower()
            if "subject" in low and "body" not in low and "SubjectOrBodyContainsWords" in words:
                words["SubjectContainsWords"] = words.pop("SubjectOrBodyContainsWords")
            elif "from" in low and "SubjectOrBodyContainsWords" in words:
                words["FromAddressContainsWords"] = words.pop("SubjectOrBodyContainsWords")
    for k, v in words.items():
        out[k] = _cut(";".join(v), 500)
    return {k: v for k, v in out.items() if k not in data}


def flatten_audit(a: dict[str, Any]) -> dict[str, Any]:
    """AuditData -> flat data dict: scalars as-is, well-known list-of-{Name,Value} shapes by name."""
    data: dict[str, Any] = {}
    for k, v in a.items():
        if k == "Parameters":
            data.update(_named_list(v))
        elif k == "ExtendedProperties" or k == "OperationProperties":
            data.update(_named_list(v))
        elif k == "ModifiedProperties":
            if isinstance(v, list):
                for it in v:
                    if isinstance(it, dict) and it.get("Name"):
                        nm = str(it["Name"])
                        data[nm] = _clean_json_string(it.get("NewValue"))
                        old = _clean_json_string(it.get("OldValue"))
                        if old not in (None, "", "[]"):
                            data[nm + ".old"] = old
        elif k in ("Target", "Actor"):
            if isinstance(v, list):
                ids = [str(it.get("ID")) for it in v if isinstance(it, dict) and it.get("ID") is not None]
                data[k] = _cut("; ".join(ids), 2000)
                data[k + ".Type"] = _cut(", ".join(str(it.get("Type")) for it in v if isinstance(it, dict)), 200)
        elif k == "Folders" and isinstance(v, list):
            data["Folders"] = _cut("; ".join(str(f.get("Path")) for f in v if isinstance(f, dict) and f.get("Path")), 2000)
            data["FolderItemCount"] = sum(len(f.get("FolderItems") or []) for f in v if isinstance(f, dict))
            _message_ids(data, (it for f in v if isinstance(f, dict) for it in (f.get("FolderItems") or [])))
        elif k == "AffectedItems" and isinstance(v, list):
            data["AffectedItems"] = _scalar(v)
            _message_ids(data, v)
        elif isinstance(v, dict):
            for k2, v2 in v.items():
                data[f"{k}.{k2}"] = _scalar(v2)
        else:
            data[k] = _scalar(v)
    return data


MAX_MESSAGE_IDS = 1000


def _message_ids(data: dict[str, Any], items: Iterable[Any]) -> None:
    """The Internet message ids of the items a record read (MailItemsAccessed FolderItems) or
    deleted and moved (AffectedItems), as data.InternetMessageId, the way the mailbox stores
    messageId: it answers "which messages did the attacker read" against the mailbox itself.
    Beyond MAX_MESSAGE_IDS the list stops and data["InternetMessageId.total"] says how many
    there were."""
    ids = [str(it["InternetMessageId"]).strip() for it in items if isinstance(it, dict) and it.get("InternetMessageId")]
    ids = list(dict.fromkeys(i for i in ids if i))
    if not ids:
        return
    have = [i for i in str(data.get("InternetMessageId") or "").split(", ") if i]
    ids = list(dict.fromkeys(have + ids))
    data["InternetMessageId"] = ", ".join(ids[:MAX_MESSAGE_IDS])
    if len(ids) > MAX_MESSAGE_IDS:
        data["InternetMessageId.total"] = len(ids)


def _clean_json_string(v: Any) -> Any:
    """ModifiedProperties values are JSON-encoded strings ('[\"Global Administrator\"]')."""
    if isinstance(v, str):
        s = v.strip()
        if s.startswith(("[", "{", '"')):
            try:
                parsed = json.loads(s)
                return _scalar(parsed)
            except ValueError:
                return s
        return s
    return _scalar(v)


def _first(d: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return None


# ---------------------------------------------------------------------------
# Unified Audit Log rows
# ---------------------------------------------------------------------------
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")


def record_key(prefix: str, value: Any) -> str | None:
    """A record's own identity, the same whichever export or file it came in: the UAL
    AuditData.Id, the Graph sign-in id. Two rows with one key are one record exported twice
    (overlapping time slices, a re-run export), so only the first is kept. A value that is not
    a GUID is no identity and gives no key: a row without a key is never dropped."""
    v = str(value or "").strip().strip("{}")
    return f"{prefix}:{v.lower()}" if _GUID_RE.match(v) else None


def ual_row(a: dict[str, Any], record_type: Any = None) -> dict[str, Any]:
    op = str(a.get("Operation") or "")
    workload = str(a.get("Workload") or "")
    user = str(_first(a, "UserId", "UserKey") or "").strip()
    ts, iso = parse_ts(a.get("CreationTime") or a.get("CreationDate"))
    ip = clean_ip(_first(a, "ClientIP", "ClientIPAddress", "ActorIpAddress", "ClientIp"))
    data = flatten_audit(a)
    result = _first(a, "ResultStatus", "ResultStatusDetail")
    target = None
    if isinstance(a.get("Target"), list):
        for t in a["Target"]:
            if isinstance(t, dict) and "@" in str(t.get("ID", "")):
                target = str(t["ID"])
                break
    if not target and a.get("MailboxOwnerUPN"):
        target = str(a["MailboxOwnerUPN"])
    if op.lower() == "updateinboxrules":
        data.update(outlook_rule_fields(data))
    obj = str(a.get("ObjectId") or "")
    if op.lower() in ("new-inboxrule", "set-inboxrule", "remove-inboxrule", "enable-inboxrule", "disable-inboxrule", "updateinboxrules") and data.get("Name"):
        obj = str(data["Name"])
    row: dict[str, Any] = {
        "ts": ts,
        "tsIso": iso,
        "eventId": None,
        "recordId": _int(record_type if record_type is not None else a.get("RecordType")),
        "level": 3 if str(result or "").lower() in ("failed", "false", "failure") else 4,
        "levelName": "Warning" if str(result or "").lower() in ("failed", "false", "failure") else "Information",
        "provider": UAL_PROVIDER,
        "channel": workload or "Unknown",
        "computer": None,
        "category": _WORKLOAD_CATEGORY.get(workload.lower(), f"M365 {workload}" if workload else "M365"),
        "description": op,
        "operation": op,
        "objectName": obj[:500] or None,
        "user": user or None,
        "upn": user or None,
        "subjectUser": user or None,
        "targetUser": target,
        "ipAddress": ip,
        "status": str(result) if result not in (None, "") else None,
        "workstation": (str(_first(a, "ClientInfoString", "UserAgent") or "")[:200] or None),
        "recordKey": record_key("ual", a.get("Id")),
        "data": data,
    }
    row["summary"] = _ual_summary(op, user, ip, data, obj, target, result)
    if op.lower() in ("userloggedin", "userloginfailed"):
        row["category"] = "M365 Entra"
        err = data.get("LogonError") or data.get("ErrorNumber")
        row["statusText"] = str(err) if err else ("failed" if op.lower() == "userloginfailed" else None)
        row["failureReason"] = str(err) if err else None
    return row


def _ual_summary(op: str, user: str, ip: str | None, d: dict[str, Any], obj: str, target: str | None, result: Any) -> str:
    parts = [op or "operation", "by", user or "?"]
    if ip:
        parts += ["from", ip]
    lo = op.lower()
    if lo in ("new-inboxrule", "set-inboxrule", "updateinboxrules"):
        bits = []
        for k in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo"):
            if d.get(k):
                bits.append(f"{k}={d[k]}")
        if str(d.get("DeleteMessage", "")).lower() == "true":
            bits.append("DeleteMessage")
        if d.get("MoveToFolder"):
            bits.append(f"MoveToFolder={d['MoveToFolder']}")
        if d.get("SubjectContainsWords"):
            bits.append(f"SubjectContains={str(d['SubjectContainsWords'])[:60]}")
        parts.append(f"rule '{obj}'" + (": " + ", ".join(bits) if bits else ""))
    elif lo == "set-mailbox":
        for k in ("ForwardingSmtpAddress", "ForwardingAddress", "DeliverToMailboxAndForward", "AuditEnabled"):
            if d.get(k) is not None:
                parts.append(f"{k}={d[k]}")
        if target:
            parts.append(f"on {target}")
    elif lo == "mailitemsaccessed":
        parts.append(f"{d.get('MailAccessType') or 'access'}, {d.get('FolderItemCount') or 0} item(s)")
        if target:
            parts.append(f"mailbox {target}")
    elif lo in ("add member to role.", "remove member from role."):
        parts.append(f"role {d.get('Role.DisplayName') or ''} -> {target or d.get('Target') or ''}")
    elif lo in ("consent to application.", "add oauth2permissiongrant.", "add app role assignment grant to user.", "add service principal."):
        parts.append(f"app {obj or d.get('Target') or ''}")
        if d.get("ConsentAction.Permissions"):
            parts.append(str(d["ConsentAction.Permissions"])[:120])
    elif lo in ("userloggedin", "userloginfailed"):
        parts.append(f"sign-in {'failed' if lo == 'userloginfailed' else 'ok'}")
        if d.get("RequestType"):
            parts.append(str(d["RequestType"]))
    elif obj:
        parts.append(os.path.basename(obj.rstrip("/")) or obj[:80])
    if result and str(result).lower() not in ("succeeded", "true", "success"):
        parts.append(f"[{result}]")
    return " ".join(str(p) for p in parts)[:500]


def _int(v: Any) -> int | None:
    try:
        return int(str(v).strip()) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Entra sign-in rows
# ---------------------------------------------------------------------------
_PORTAL_MAP = {
    "date (utc)": "createdDateTime",
    "date": "createdDateTime",
    "username": "userPrincipalName",
    "user": "userDisplayName",
    "user id": "userId",
    "ip address": "ipAddress",
    "location": "location",
    "application": "appDisplayName",
    "application id": "appId",
    "resource": "resourceDisplayName",
    "client app": "clientAppUsed",
    "browser": "browser",
    "operating system": "operatingSystem",
    "status": "status",
    "failure reason": "failureReason",
    "sign-in error code": "errorCode",
    "conditional access": "conditionalAccessStatus",
    "risk state": "riskState",
    "risk level (aggregate)": "riskLevelAggregated",
    "risk level (sign-in)": "riskLevelDuringSignIn",
    "risk level - aggregate": "riskLevelAggregated",
    "risk level - sign-in": "riskLevelDuringSignIn",
    "risk detail": "riskDetail",
    "multifactor authentication result": "mfaResult",
    "authentication requirement": "authenticationRequirement",
    "user agent": "userAgent",
    "request id": "requestId",
    "correlation id": "correlationId",
    "interactive": "isInteractive",
    "compliant": "isCompliant",
    "managed": "isManaged",
    "device id": "deviceId",
    "device name": "deviceName",
    "join type": "trustType",
    "user type": "userType",
    "country or region": "country",
    "country": "country",
    "city": "city",
    "state": "state",
    "id": "id",
    "session id": "sessionId",
    "unique token identifier": "uniqueTokenIdentifier",
    "authentication protocol": "authenticationProtocol",
    "original transfer method": "originalTransferMethod",
    "incoming token type": "incomingTokenType",
    "token issuer type": "tokenIssuerType",
    "cross tenant access type": "crossTenantAccessType",
    "autonomous system number": "autonomousSystemNumber",
    "ip address (seen by resource)": "ipAddressFromResourceProvider",
    "resource id": "resourceId",
    "resource tenant id": "resourceTenantId",
    "home tenant id": "homeTenantId",
    "multifactor authentication auth method": "authenticationMethods",
}


def _auth_methods(g: dict[str, Any]) -> Any:
    """The methods that succeeded (Graph authenticationDetails), or the portal's MFA method."""
    details = g.get("authenticationDetails")
    if isinstance(details, list):
        done = [
            str(d.get("authenticationMethod")) for d in details if isinstance(d, dict) and d.get("authenticationMethod") and d.get("succeeded") is not False
        ]
        return ", ".join(dict.fromkeys(done)) or None
    return g.get("authenticationMethods")


def _ca_policies(v: Any) -> str | None:
    """Conditional access policies that applied, as "name=result" (notApplied and notEnabled left out)."""
    if not isinstance(v, list):
        return None
    out = [
        f"{p.get('displayName') or p.get('id')}={p.get('result')}"
        for p in v
        if isinstance(p, dict) and str(p.get("result") or "").lower() not in ("notapplied", "notenabled", "")
    ]
    return _cut("; ".join(out), 2000) or None


# Azure Monitor diagnostic categories whose records carry a sign-in in "properties"
_SIGNIN_CATEGORIES = ("signinlogs", "noninteractiveusersigninlogs", "serviceprincipalsigninlogs", "managedidentitysigninlogs")


def _signin_of(obj: Any) -> dict[str, Any] | None:
    """The sign-in an exported object holds: a Graph or portal sign-in as it is, or the
    "properties" of an Azure Monitor diagnostic record of a sign-in category. None for another
    diagnostic category, for a record of another kind, or for something that is not an object."""
    if not isinstance(obj, dict):
        return None
    category = str(obj.get("category") or "").lower()
    if category not in _SIGNIN_CATEGORIES or not isinstance(obj.get("properties"), dict):
        # a record without the envelope is a sign-in only by its own fields
        return obj if is_signin(obj) else None
    props = dict(obj["properties"])
    # the envelope's time, when the sign-in itself has none
    if not props.get("createdDateTime") and obj.get("time"):
        props["createdDateTime"] = obj["time"]
    return props


# The Graph names entra_row reads, by their lower case. The Graph PowerShell SDK writes them in
# PascalCase (CreatedDateTime, IPAddress, Status.ErrorCode), and read by the camelCase names only,
# each of its rows was a blank, undated sign-in.
_GRAPH_NAMES = {
    n.lower(): n
    for n in (
        *_PORTAL_MAP.values(),
        "status",
        "deviceDetail",
        "deviceDisplayName",
        "riskEventTypes",
        "riskEventTypes_v2",
        "signInEventTypes",
        "authenticationDetails",
        "appliedConditionalAccessPolicies",
        "createdDateTime",
        "userPrincipalName",
        "userDisplayName",
        "ipAddress",
        # inside status, location, deviceDetail, authenticationDetails and the policies
        "errorCode",
        "failureReason",
        "additionalDetails",
        "countryOrRegion",
        "displayName",
        "authenticationMethod",
        "succeeded",
        "result",
    )
}
_GRAPH_NAMES["riskeventtypesv2"] = "riskEventTypes_v2"
# Export-Csv writes an object it cannot flatten as its .NET type name: a status, a location or a
# device that the export does not hold, never a value.
_TYPE_NAME_RE = re.compile(r"^(?:Microsoft\.Graph\.(?:Beta\.)?PowerShell\.Models\.\w+|System\.[\w.`]+(?:\[[^\]]*\])+)$")


def _graph_keys(d: dict[str, Any]) -> dict[str, Any]:
    """d under the Graph names, from the portal's column names or any case of the Graph ones; a
    name already in Graph form wins over a column that maps to it."""
    g = {k: v for k, v in d.items() if not (isinstance(v, str) and _TYPE_NAME_RE.match(v.strip()))}
    for k in list(g):
        low = str(k).strip().lower()
        mapped = _PORTAL_MAP.get(low) or _GRAPH_NAMES.get(low)
        if mapped and mapped != k and mapped not in g:
            g[mapped] = g.pop(k)
    for k, v in g.items():
        if isinstance(v, dict):
            g[k] = _graph_keys(v)
        elif isinstance(v, list):
            g[k] = [_graph_keys(x) if isinstance(x, dict) else x for x in v]
    return g


def entra_row(o: dict[str, Any], day_first: bool | None = None) -> dict[str, Any]:
    g = _graph_keys(o)
    status = g.get("status")
    if isinstance(status, dict):
        err = status.get("errorCode")
        failure = status.get("failureReason") or status.get("additionalDetails")
    else:
        err = g.get("errorCode")
        failure = g.get("failureReason")
        if isinstance(status, str) and status.lower() in ("failure", "failed") and err in (None, ""):
            err = -1
        elif isinstance(status, str) and status.lower() == "success" and err in (None, ""):
            err = 0
    if isinstance(err, str) and err.strip().lstrip("-").isdigit():
        err = int(err)
    # neither an error code nor a status: the export does not say how the sign-in ended, and a
    # sign-in read as successful by default counts toward every rule on successes
    known = err not in (None, "")
    if isinstance(failure, str) and failure.lower() in ("other.", "", "none"):
        failure = None
    loc = g.get("location")
    country = city = state = None
    if isinstance(loc, dict):
        country, city, state = loc.get("countryOrRegion"), loc.get("city"), loc.get("state")
    elif isinstance(loc, str) and loc.strip():
        bits = [b.strip() for b in loc.split(",")]
        country = bits[-1] if bits else None
        city = bits[0] if len(bits) > 1 else None
        state = bits[1] if len(bits) > 2 else None
    country = country or g.get("country")
    dev = g.get("deviceDetail") if isinstance(g.get("deviceDetail"), dict) else {}
    user = str(g.get("userPrincipalName") or g.get("userDisplayName") or "").strip()
    ts, iso = parse_ts(g.get("createdDateTime"), day_first)
    ip = clean_ip(g.get("ipAddress"))
    success = known and err in (0, "0")
    risk_signin = g.get("riskLevelDuringSignIn")
    risk_agg = g.get("riskLevelAggregated")
    data: dict[str, Any] = {
        "appDisplayName": g.get("appDisplayName"),
        "appId": g.get("appId"),
        "resourceDisplayName": g.get("resourceDisplayName"),
        "clientAppUsed": g.get("clientAppUsed"),
        "conditionalAccessStatus": g.get("conditionalAccessStatus"),
        "riskLevelDuringSignIn": risk_signin,
        "riskLevelAggregated": risk_agg,
        "riskState": g.get("riskState"),
        "riskDetail": g.get("riskDetail"),
        "riskEventTypes": _scalar(g.get("riskEventTypes_v2") or g.get("riskEventTypes")),
        "country": country,
        "city": city,
        "state": state,
        "browser": dev.get("browser") or g.get("browser"),
        "operatingSystem": dev.get("operatingSystem") or g.get("operatingSystem"),
        "deviceId": dev.get("deviceId") or g.get("deviceId"),
        # the device's name in Entra and how it is joined: a joined device named like a host of the
        # case is that host (analysis/lineage.py)
        "deviceName": dev.get("displayName") or g.get("deviceDisplayName") or g.get("deviceName"),
        "trustType": dev.get("trustType") or g.get("trustType"),
        "isCompliant": dev.get("isCompliant", g.get("isCompliant")),
        "isManaged": dev.get("isManaged", g.get("isManaged")),
        "errorCode": err,
        "failureReason": failure,
        "authenticationRequirement": g.get("authenticationRequirement"),
        "isInteractive": g.get("isInteractive"),
        "userAgent": g.get("userAgent"),
        "correlationId": g.get("correlationId"),
        "userType": g.get("userType"),
        "userDisplayName": g.get("userDisplayName"),
        "mfaResult": g.get("mfaResult"),
        "tokenIssuerType": g.get("tokenIssuerType"),
        "signInEventTypes": _scalar(g.get("signInEventTypes")),
        # what ties a sign-in to the audit records its token made (AppAccessContext.AADSessionId,
        # AppAccessContext.UniqueTokenId) and shows device-code and token-replay use
        "id": g.get("id"),
        "requestId": g.get("requestId"),
        "userId": g.get("userId"),
        "sessionId": g.get("sessionId"),
        "uniqueTokenIdentifier": g.get("uniqueTokenIdentifier"),
        "authenticationProtocol": g.get("authenticationProtocol"),
        "originalTransferMethod": g.get("originalTransferMethod"),
        "incomingTokenType": g.get("incomingTokenType"),
        "crossTenantAccessType": g.get("crossTenantAccessType"),
        "autonomousSystemNumber": g.get("autonomousSystemNumber"),
        "ipAddressFromResourceProvider": g.get("ipAddressFromResourceProvider"),
        "resourceId": g.get("resourceId"),
        "resourceTenantId": g.get("resourceTenantId"),
        "homeTenantId": g.get("homeTenantId"),
        "authenticationMethods": _auth_methods(g),
        "appliedConditionalAccessPolicies": _ca_policies(g.get("appliedConditionalAccessPolicies")),
    }
    data = {k: _scalar(v) for k, v in data.items() if v not in (None, "")}
    device_code = str(g.get("authenticationProtocol") or "").lower() == "devicecode" or str(g.get("originalTransferMethod") or "").lower() == "devicecodeflow"
    risk_txt = " [device code]" if device_code else ""
    if (risk_signin and str(risk_signin).lower() not in ("none", "hidden")) or (g.get("riskState") and str(g.get("riskState")).lower() not in ("none",)):
        risk_txt += f" risk={risk_signin or risk_agg or ''}/{g.get('riskState') or ''}"
    outcome = "ok" if success else f"FAILED ({err})" if known else "(outcome not in the export)"
    summary = (
        f"Sign-in {outcome}: {user or '?'} from {ip or '?'}"
        f"{' (' + str(country) + ')' if country else ''} via {g.get('clientAppUsed') or '?'} to {g.get('appDisplayName') or '?'}{risk_txt}"
    )
    return {
        "ts": ts,
        "tsIso": iso,
        "eventId": None,
        "recordId": None,
        "level": 3 if known and not success else 4,
        "levelName": "Warning" if known and not success else "Information",
        "provider": ENTRA_PROVIDER,
        "channel": "Entra SignIn",
        "computer": None,
        "category": "Entra sign-in",
        "description": "Sign-in failure" if known and not success else "Sign-in",
        "operation": "SignIn",
        "user": user or None,
        "upn": user or None,
        "subjectUser": user or None,
        "targetUser": user or None,
        "ipAddress": ip,
        "status": str(err) if known else None,
        "statusText": failure,
        "failureReason": failure,
        "workstation": (str(g.get("userAgent") or "")[:200] or None),
        "objectName": g.get("appDisplayName"),
        "recordKey": record_key("entra", g.get("id")),
        "data": data,
        "summary": summary[:500],
    }


# ---------------------------------------------------------------------------
# Iteration
# ---------------------------------------------------------------------------
def _open_text(path: str | None, data: bytes | None) -> io.TextIOBase:
    """An export as text, in the encoding its byte order mark names, the mark itself not read."""
    if path:
        with open(path, "rb") as raw:
            encoding = encoding_of(raw.read(4))
        return open(path, encoding=encoding, errors="replace", newline="")
    return io.TextIOWrapper(io.BytesIO(data or b""), encoding=encoding_of((data or b"")[:4]), errors="replace", newline="")


# The longest record a JSON export may hold (a sign-in is a few kilobytes, an audit record rarely
# more than a few hundred). JSON arrays used to be loaded whole, about ten times their size in the
# web process, so one large Graph export could take the server down; they are read one record at
# a time, and only a record past this length stops the file.
MAX_RECORD_CHARS = MAX_FIELD_CHARS
_CHUNK = 1024 * 1024
_DECODER = json.JSONDecoder()
_SPACE = re.compile(r"[ \t\r\n]*")


class _JsonStream:
    """The records of a JSON text read a piece at a time: the objects of an array, of a Graph
    page's "value" array, a lone object, or several such documents one after the other."""

    def __init__(self, fh: io.TextIOBase, stats: Any = None) -> None:
        self.fh, self.stats, self.buf, self.pos, self.eof, self.count = fh, stats, "", 0, False, 0

    def _more(self) -> bool:
        if self.eof:
            return False
        self.buf, self.pos = self.buf[self.pos :], 0
        if len(self.buf) > MAX_RECORD_CHARS:
            raise ValueError(f"a JSON record after record {self.count:,} is longer than {MAX_RECORD_CHARS:,} characters; the file was read up to it")
        # the read doubles with what one value already holds, so a long record is decoded a few
        # times rather than once per megabyte
        chunk = self.fh.read(max(_CHUNK, len(self.buf)))
        self.eof = not chunk
        self.buf += chunk
        return bool(chunk)

    def _peek(self) -> str:
        """The next character that is not white space, "" at the end."""
        while True:
            self.pos = _SPACE.match(self.buf, self.pos).end()  # type: ignore[union-attr]
            if self.pos < len(self.buf):
                return self.buf[self.pos]
            if not self._more():
                return ""

    def _fail(self, what: str) -> ValueError:
        return ValueError(f"invalid JSON after record {self.count:,}: {what}")

    def _take(self, char: str) -> None:
        if self._peek() != char:
            raise self._fail(f"expected {char!r}")
        self.pos += 1

    def _value(self) -> Any:
        self._peek()
        while True:
            try:
                value, end = _DECODER.raw_decode(self.buf, self.pos)
            except json.JSONDecodeError as exc:
                if self._more():
                    continue  # the value goes on in the next piece
                raise self._fail(exc.msg) from None
            if end == len(self.buf) and isinstance(value, (int, float)) and self._more():
                continue  # a number at the end of a piece may go on in the next one
            self.pos = end
            return value

    def _items(self) -> Iterator[Any]:
        """The objects of the array whose "[" was just passed."""
        if self._peek() == "]":
            self.pos += 1
            return
        while True:
            value = self._value()
            self.count += 1
            if isinstance(value, dict):
                yield value
            elif self.stats is not None:
                self.stats.errors += 1  # an element that is not a record
            if self._peek() == ",":
                self.pos += 1
                continue
            self._take("]")
            return

    def records(self) -> Iterator[Any]:
        while (c := self._peek()) != "":
            if c == "[":
                self.pos += 1
                yield from self._items()
            elif c == "{":
                # a Graph page {"value": [...]} gives its records as the array is read; any other
                # object is a record of its own
                self.pos += 1
                obj: dict[str, Any] = {}
                paged = False
                while self._peek() != "}":
                    key = self._value()
                    if not isinstance(key, str):
                        raise self._fail("expected a name")
                    self._take(":")
                    if key == "value" and self._peek() == "[":
                        self.pos += 1
                        paged = True
                        yield from self._items()
                    else:
                        obj[key] = self._value()
                    if self._peek() != ",":
                        break
                    self.pos += 1
                self._take("}")
                if not paged:
                    self.count += 1
                    yield obj
            else:
                raise self._fail("expected an array or an object")


def _iter_json_objects(fh: io.TextIOBase, stats: Any = None) -> Iterator[Any]:
    """A JSON array, a single object (a Graph page {"value": [...]} included, however it is
    indented), several of them one after the other, or NDJSON, read one record at a time. A line
    of NDJSON that does not parse is counted as an error, never dropped without a trace: a
    pretty-printed Graph page read line by line used to give 0 rows and 0 errors, which reads as
    "no sign-ins"."""
    first = ""
    while not first:
        line = fh.readline(MAX_RECORD_CHARS)
        if not line:
            break
        first = line.strip().rstrip(",")
    fh.seek(0)
    try:
        lines = first.startswith("{") and isinstance(json.loads(first), dict)
    except ValueError:
        lines = False  # the first line is not an object on its own: an indented document
    if not lines:
        yield from _JsonStream(fh, stats).records()
        return
    while line := fh.readline(MAX_RECORD_CHARS + 1):
        if len(line) > MAX_RECORD_CHARS:
            # longer than any record: counted, and passed over to the end of its line
            while line and not line.endswith("\n"):
                line = fh.readline(_CHUNK)
            if stats is not None:
                stats.errors += 1
            continue
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            if stats is not None:
                stats.errors += 1
            continue
        items = obj["value"] if isinstance(obj, dict) and isinstance(obj.get("value"), list) else [obj]  # a Graph page {"value": [...]}
        for x in items:
            if isinstance(x, dict):
                yield x
            elif stats is not None:
                stats.errors += 1  # a line or an element that is not a record


# Graph audit log query records (auditLogRecord, Microsoft-Extractor-Suite Get-UALGraph) carry
# these in their envelope; an AuditData that omits one takes it from there
_GRAPH_ENVELOPE = (
    ("CreationTime", "createdDateTime"),
    ("Operation", "operation"),
    ("UserId", "userPrincipalName"),
    ("ClientIP", "clientIp"),
    ("Workload", "service"),
)


def _audit_from_row(obj: dict[str, Any]) -> tuple[dict[str, Any] | None, Any]:
    """Accept a bare AuditData object, an export row carrying AuditData as a JSON string/object,
    or a Graph auditLogRecord, whose record is under auditData."""
    ad = obj.get("AuditData")
    if ad is None:
        ad = obj.get("auditdata") or obj.get("Auditdata") or obj.get("auditData")
    if isinstance(ad, str):
        try:
            ad = json.loads(ad)
        except ValueError:
            return None, None
    if isinstance(ad, dict):
        if "CreationTime" not in ad and (obj.get("CreationDate") or obj.get("CreationTime")):
            ad = {**ad, "CreationTime": obj.get("CreationDate") or obj.get("CreationTime")}
        missing = {k: obj[top] for k, top in _GRAPH_ENVELOPE if not ad.get(k) and obj.get(top)}
        if missing:
            ad = {**ad, **missing}
        return ad, obj.get("RecordType") or ad.get("RecordType")
    if "Operation" in obj or "Workload" in obj:
        return obj, obj.get("RecordType")
    return None, None


def _csv_rows(fh: io.TextIOBase, stats: Any) -> Iterator[dict[str, Any]]:
    """The rows of a CSV export. A row the csv module cannot read (a field past MAX_FIELD_CHARS, a
    stray quote) is counted as an error and the rows after it are still read. The "#TYPE" line
    Windows PowerShell's Export-Csv writes above the header without -NoTypeInformation is passed
    over."""
    lines: Iterator[str] = iter(fh)
    first = next(lines, "")
    if not first.startswith("#TYPE"):
        lines = itertools.chain([first], lines)
    reader = csv.DictReader(lines)
    # the header is read outside the loop: a header that cannot be read fails the file
    if reader.fieldnames is None:
        return
    while True:
        try:
            rec = next(reader)
        except StopIteration:
            return
        except csv.Error:
            if stats is not None:
                stats.errors += 1
            continue
        yield {k: v for k, v in rec.items() if k is not None}


def _key_hash(key: str) -> int:
    return int.from_bytes(hashlib.blake2b(key.encode(), digest_size=8).digest(), "big")


# How many record ids are held to find repeats. They were Python ints in a set, about 70 bytes
# each, without a bound: a package of sixteen million audit records held a gigabyte in the web
# process. Held as 8-byte slots of a table at most three quarters full, this many fill 64 MiB.
MAX_REMEMBERED = 6 * 1024 * 1024


class RecordKeys:
    """The ids (_key_hash) of the cloud records read so far, in an open-addressing table. Once it
    holds its limit, further ids are still looked up but no longer added."""

    def __init__(self, limit: int = MAX_REMEMBERED) -> None:
        self.limit = limit
        self._slots = array("Q", bytes(8 * 1024))
        self._size = 0

    def __len__(self) -> int:
        return self._size

    def _slot(self, h: int) -> int:
        slots, mask = self._slots, len(self._slots) - 1
        i = h & mask
        while slots[i] not in (0, h):
            i = (i + 1) & mask
        return i

    def __contains__(self, h: object) -> bool:
        return isinstance(h, int) and self._slots[self._slot(h or 1)] == (h or 1)

    def add(self, h: int) -> bool:
        """Hold h (0 marks an empty slot, so it is held as 1); False when the table is full."""
        h = h or 1
        i = self._slot(h)
        if self._slots[i] == h:
            return True
        if self._size >= self.limit:
            return False
        self._slots[i] = h
        self._size += 1
        if self._size * 4 > len(self._slots) * 3:
            old, self._slots = self._slots, array("Q", bytes(16 * len(self._slots)))
            for x in old:
                if x:
                    self._slots[self._slot(x)] = x
        return True


def iter_records(
    path: str | None, data: bytes | None, fmt: str, stats: Any = None, include_raw: bool = True, seen: RecordKeys | None = None
) -> Iterator[dict[str, Any]]:
    """Yield event rows from a UAL / Entra export in the given format (see FORMATS). A record
    whose key (record_key) is already in ``seen`` is the same record exported again: it is
    counted in ``stats.duplicates`` and not yielded: Search-UnifiedAuditLog's ReturnLargeSet
    pages repeat records within one file, and overlapping time slices repeat them across files.
    Pass one RecordKeys for every file of an upload so an archive of slices gives each record
    once. A record read once it is full is counted in ``stats.repeats_unchecked``."""
    seen = RecordKeys() if seen is None else seen
    for row in _iter_rows(path, data, fmt, stats, include_raw):
        marks = row.pop("_marks", ())
        key = row.get("recordKey")
        if key:
            h = _key_hash(key)
            if h in seen:
                if stats is not None:
                    stats.duplicates = getattr(stats, "duplicates", 0) + 1
                continue
            if not seen.add(h):
                marks = (*marks, "repeats_unchecked")
        if stats is not None:
            _count(row, stats)
            for mark in marks:
                setattr(stats, mark, getattr(stats, mark, 0) + 1)
        yield row


# what each count on a cloud export's stats says on its member of an archive or a package
_NOTES = (
    ("cut", "{:,} record(s) hold a value cut at its length limit, marked by a closing …"),
    ("undated", "{:,} record(s) have no time: their date is missing or could not be read"),
    ("date_order_guessed", "{:,} record(s) were dated month-first: no date in the file has a day above 12 to show its order"),
    ("repeats_unchecked", "{:,} record(s) were read once the ids held to find repeats were full, and were not compared with one another"),
)


def counts(stats: Any) -> dict[str, int]:
    """The counts of what reading cloud exports compromised on, so far."""
    return {name: int(getattr(stats, name, 0) or 0) for name, _ in _NOTES}


def note(counts: dict[str, int]) -> str:
    """Those counts in words, for one file: "" when there is nothing to say."""
    return "; ".join(text.format(counts[name]) for name, text in _NOTES if counts.get(name))


def _count(row: dict[str, Any], stats: Any) -> None:
    try:
        stats.add(row)
    except Exception:  # noqa: BLE001
        stats.count += 1


def _iter_rows(path: str | None, data: bytes | None, fmt: str, stats: Any, include_raw: bool) -> Iterator[dict[str, Any]]:
    # rows are counted by the caller once it knows they are kept; errors are counted here
    fh = _open_text(path, data)
    try:
        if fmt == "m365-ual-csv":
            for rec in _csv_rows(fh, stats):
                ad, rtype = _audit_from_row(rec)
                if ad is None:
                    if stats is not None:
                        stats.errors += 1
                    continue
                yield _finish(ual_row(ad, rtype), ad, stats, include_raw)
        elif fmt == "m365-ual-json":
            for obj in _iter_json_objects(fh, stats):
                ad, rtype = _audit_from_row(obj)
                if ad is None:
                    if stats is not None:
                        stats.errors += 1
                    continue
                yield _finish(ual_row(ad, rtype), ad, stats, include_raw)
        elif fmt == "entra-signin-json":
            for obj in _iter_json_objects(fh, stats):
                signin = _signin_of(obj)
                if signin is None:
                    # another diagnostic category (AuditLogs, RiskyUsers, ...): not a sign-in, not read
                    if stats is not None:
                        stats.errors += 1
                    continue
                yield _finish(entra_row(signin), obj, stats, include_raw)
        elif fmt == "entra-signin-csv":
            day_first = _csv_date_order(path, data)
            for obj in _csv_rows(fh, stats):
                row = _finish(entra_row(obj, day_first), obj, stats, include_raw)
                if day_first is None and any(guessed_order(v) for k, v in obj.items() if _date_column(k)):
                    row["_marks"] = (*row.get("_marks", ()), "date_order_guessed")
                yield row
        else:
            raise ValueError(f"unknown M365 format {fmt}")
    finally:
        fh.close()


def _date_column(name: str) -> bool:
    low = str(name).strip().lower()
    return (_PORTAL_MAP.get(low) or _GRAPH_NAMES.get(low)) == "createdDateTime"


def _csv_date_order(path: str | None, data: bytes | None) -> bool | None:
    """The date order of a sign-in CSV, from a first pass over its date column that stops at the
    first date settling it (or at the first date not written as numbers, whose order does not
    matter). Deciding from the first 5,000 rows read a day-first export whose first days were all
    12 or below month-first, every date of it wrong."""
    fh = _open_text(path, data)
    try:
        for rec in _csv_rows(fh, None):
            for k, v in rec.items():
                if v and _date_column(k):
                    if not _NUMERIC_DATE_RE.match(str(v)):
                        return None
                    order = date_order([v])
                    if order is not None:
                        return order
    finally:
        fh.close()
    return None


def _finish(row: dict[str, Any], source: dict[str, Any], stats: Any, include_raw: bool) -> dict[str, Any]:
    if include_raw:
        row["raw"] = _cut(json.dumps(source, ensure_ascii=False, separators=(",", ":")), 200_000)
    # what the row is counted for, by iter_records once it knows the row is kept
    marks: tuple[str, ...] = ()
    if isinstance(row.get("raw"), _Cut) or any(isinstance(v, _Cut) for v in row["data"].values()):
        marks += ("cut",)
    if row.get("ts") is None:
        marks += ("undated",)
    if marks:
        row["_marks"] = marks
    return row


def is_privileged_role(name: str | None) -> bool:
    return bool(name) and str(name).strip().lower() in _PRIVILEGED_ROLES
