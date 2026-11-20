"""
Microsoft 365 Unified Audit Log (UAL), Entra ID sign-in, Entra ID directory audit, Entra ID
Protection and Exchange Online message trace exports -> event rows.

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
    entra-audit-json    Graph directoryAudit objects (auditLogs/directoryAudits, the portal's JSON download)
    entra-audit-csv     the portal's audit log CSV download, or directoryAudit properties as columns
    entra-riskdetection-json  Graph riskDetection objects (identityProtection/riskDetections)
    entra-riskdetection-csv   riskDetection properties as columns (Get-MgRiskDetection | Export-Csv,
                              Microsoft-Extractor-Suite Get-RiskyDetections)
    entra-riskyuser-json      Graph riskyUser objects (identityProtection/riskyUsers)
    entra-riskyuser-csv       riskyUser properties as columns (Get-MgRiskyUser | Export-Csv, Get-RiskyUsers)
    exo-messagetrace-csv         Get-MessageTrace / Get-MessageTraceV2 | Export-Csv
    exo-messagetrace-report-csv  the Exchange admin centre's enhanced summary or extended report

Row conventions (shared with the EVTX parser so rules can mix both):
    provider   "Microsoft 365 Unified Audit Log" | "Microsoft Entra ID Sign-in" | "Microsoft Entra ID Audit"
               | "Microsoft Entra ID Protection" | "Exchange Online Message Trace"
    channel    the UAL Workload (Exchange, AzureActiveDirectory, SharePoint, OneDrive ...) | "Entra SignIn"
               | "Entra Audit" | "Entra RiskDetection" | "Entra RiskyUser" | "Exchange MessageTrace"
    category   "M365 Exchange" | "M365 Entra" | "M365 SharePoint" | ... | "Entra sign-in" | "Entra audit"
               | "Entra risk" | "Exchange message trace"
    operation  the UAL Operation / "SignIn" / a directory activity as the UAL names it ("Consent to
               application.") / "RiskDetection" / "RiskyUser" / "MessageTrace"
    subjectUser = user (actor UPN, sender), targetUser = affected user (recipient) when the record has one
    ipAddress   client IP (port and brackets stripped), status / statusText, objectName
    data        every AuditData field flattened one level: Parameters, ExtendedProperties,
                ModifiedProperties (NewValue, plus "<name>.old"), OperationProperties, Target,
                Actor, AppAccessContext.*; Entra: appDisplayName, clientAppUsed, country, city,
                riskLevelDuringSignIn, riskState, conditionalAccessStatus, errorCode ...; directory
                audits: their modified properties under the names the UAL gives them, initiatedBy.*,
                Target.*, additionalDetails by key; risk: riskEventType, riskLevel, riskState,
                riskDetail, country, city, additionalInfo.<key> ...; message trace: every column,
                and SenderDomain, RecipientDomain, InternetMessageId
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
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

log = logging.getLogger(__name__)

# The longest field a CSV export may hold. Python's csv stops at 131,072 characters, which one
# DLP or MailItemsAccessed record passes, and the export then ended at that record. The limit is
# the csv module's own, for the whole process, so it is only ever raised here.
MAX_FIELD_CHARS = 16 * 1024 * 1024
if csv.field_size_limit() < MAX_FIELD_CHARS:
    csv.field_size_limit(MAX_FIELD_CHARS)

UAL_PROVIDER = "Microsoft 365 Unified Audit Log"
ENTRA_PROVIDER = "Microsoft Entra ID Sign-in"
AUDIT_PROVIDER = "Microsoft Entra ID Audit"
RISK_PROVIDER = "Microsoft Entra ID Protection"
TRACE_PROVIDER = "Exchange Online Message Trace"
FORMATS = (
    "m365-ual-csv",
    "m365-ual-json",
    "entra-signin-json",
    "entra-signin-csv",
    "entra-audit-json",
    "entra-audit-csv",
    "entra-riskdetection-json",
    "entra-riskdetection-csv",
    "entra-riskyuser-json",
    "entra-riskyuser-csv",
    "exo-messagetrace-csv",
    "exo-messagetrace-report-csv",
)

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
        keys = _KEY_RE.findall(text)
        kind = entra_kind(keys)
        # a file is of the kind of its first record: a sign-in file with a directory audit in it is
        # a sign-in file, whose audit record is not read
        if is_signin(keys) and not (kind and low.find(f'"{_KIND_KEY[kind]}"') < low.find('"createddatetime"')):
            return "entra-signin-json"
        # Azure Monitor diagnostic records (Log Analytics, Event Hub, storage account): the
        # sign-in is under "properties", past the head
        if any(f'"category": "{c}"' in low or f'"category":"{c}"' in low for c in _SIGNIN_CATEGORIES):
            return "entra-signin-json"
        # Azure Monitor records of the other categories hold an audit or risk record under
        # "properties" in a schema Microsoft says may differ from Graph's: they are not read
        if _MONITOR_CATEGORY_RE.search(low):
            return None
        return f"entra-{kind}-json" if kind else None
    header = _header_line(text)
    if "auditdata" in header.lower():
        return "m365-ual-csv"
    columns = next(csv.reader([header]), [])
    if is_signin(columns):
        return "entra-signin-csv"
    kind = entra_kind(columns)
    return f"entra-{kind}-csv" if kind else trace_kind(columns)


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


_MONITOR_CATEGORY_RE = re.compile(r'"category"\s*:\s*"(?:auditlogs|riskyusers|userriskevents|serviceprincipalriskevents|riskyserviceprincipals)"')


def trace_kind(columns: Iterable[Any]) -> str | None:
    """Which message trace a table with these columns is: Get-MessageTrace or Get-MessageTraceV2
    written with Export-Csv ("exo-messagetrace-csv"), or a report downloaded from the Exchange
    admin centre ("exo-messagetrace-report-csv"); None for anything else."""
    low = {_report_name(c) for c in columns}
    if {"received", "senderaddress", "recipientaddress"} <= low:
        return "exo-messagetrace-csv"
    if {"sender_address", "message_id", "network_message_id"} <= low and low & {"origin_timestamp", "date_time"}:
        return "exo-messagetrace-report-csv"
    return None


def _report_name(column: Any) -> str:
    """A column of a message trace report by the name the Exchange admin centre documents: in lower
    case, and without the "_utc" a download may end a time column with."""
    name = str(column).strip().lower()
    return name[:-4] if name.endswith("_utc") else name


# The columns the Entra admin centre writes in its audit log download whatever the language of the
# portal; the date, service, category, activity and result columns are translated.
_PORTAL_AUDIT_COLUMNS = frozenset({"correlationid", "resultreason", "actortype", "target1type"})


# the field only a record of each kind has, by its lower case
_KIND_KEY = {"audit": "activitydisplayname", "riskdetection": "riskeventtype", "riskyuser": "risklastupdateddatetime"}


def entra_kind(keys: Iterable[Any]) -> str | None:
    """Which Entra record a record or a table with these field names (any case) holds, by the
    fields Microsoft documents for it: "audit" (a directoryAudit, or a row of the portal's audit
    log download), "riskdetection" (a riskDetection) or "riskyuser" (a riskyUser); None for
    anything else."""
    low = {str(k).strip().lower() for k in keys}
    if "riskeventtype" in low and low & {"activitydatetime", "detecteddatetime"}:
        return "riskdetection"
    if "risklastupdateddatetime" in low and low & {"risklevel", "riskstate"}:
        return "riskyuser"
    if "activitydisplayname" in low and "activitydatetime" in low:
        return "audit"
    if _PORTAL_AUDIT_COLUMNS <= low:
        return "audit"
    return None


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


def _culture_date(s: str, day_first: bool | None, zone: tzinfo | None = None) -> datetime | None:
    m = _CULTURE_RE.match(s)
    if not m:
        return None
    a, sep, b, c, hour, minute, second, fraction, half, written = m.groups()
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
    # a zone written with the time is the time's own; the evidence's zone is for a time without one
    tz = zone or UTC
    if written and written != "Z":
        sign = -1 if written[0] == "-" else 1
        digits = written[1:].replace(":", "")
        tz = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
    elif written == "Z":
        tz = UTC
    try:
        return datetime(year, month, day, h, int(minute), int(second or 0), int((fraction or "0")[:6].ljust(6, "0")), tzinfo=tz)
    except ValueError:
        return None


# a .NET date as Windows PowerShell's ConvertTo-Json writes one: "\/Date(1756720800000)\/", the
# milliseconds since 1970 in UTC, with the writer's offset after them when it had one
_DOTNET_DATE_RE = re.compile(r"^/Date\((-?\d{1,15})(?:[+-]\d{4})?\)/$")


def parse_ts(v: Any, day_first: bool | None = None, zone: tzinfo | None = None) -> tuple[int | None, str | None]:
    """ISO-8601 (with or without zone / fractional seconds), portal 'M/D/YYYY, h:mm:ss AM', a
    culture's numeric date, or a .NET "/Date(ms)/" -> (ms, iso). day_first is the order date_order
    found for the file, or the order set for the evidence; None keeps the portal's own month-first
    order for slashes and dashes. Dotted dates are always day-first. A time written with a zone
    keeps it; one without is in ``zone``, else UTC, the zone the audit log, Graph and the portal's
    "Date (UTC)" write. _Dates says which times the evidence's zone is for."""
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
        dt = _culture_date(s, day_first, zone)
    if dt is None:
        return None, None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=zone or UTC)
    dt = dt.astimezone(UTC)
    return int(dt.timestamp() * 1000), dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def culture_written(v: Any) -> bool:
    """Whether a time is written as a culture or a spreadsheet writes one (9/1/2026 10:00 AM,
    01.09.2026 10:00) and says nothing of its zone: the form Export-Csv gives a DateTime, whose
    zone is whatever the value held. An ISO 8601 time is written by Graph or the audit log
    service, in UTC."""
    m = _CULTURE_RE.match(str(v or "").strip())
    return bool(m) and not m.group(10)


def _naive_iso(v: Any) -> bool:
    """Whether a time is ISO 8601 without a zone ("2026-09-01T10:00:00")."""
    s = str(v or "").strip()
    try:
        return datetime.fromisoformat(s).tzinfo is None if "T" in s and not s.endswith("Z") else False
    except ValueError:
        return False


def utc_column(name: Any) -> bool:
    """Whether a column's name says its times are UTC ("Date (UTC)", "origin_timestamp_utc"), in
    which case no setting of the evidence moves them."""
    return "utc" in re.split(r"[^a-z]+", str(name or "").lower())


# ---------------------------------------------------------------------------
# The date order and time zone an evidence file is read in
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DateSetting:
    """What the analyst says of one evidence file's dates where the file cannot say: the order of a
    numeric date's day and month, and the zone of a culture-written time without one. It is chosen
    for the evidence, recorded with it, and each file read with it says which of its records it
    applied to."""

    day_first: bool | None = None
    zone: tzinfo | None = None
    zone_name: str = ""

    @property
    def order(self) -> str:
        return "" if self.day_first is None else "day-first" if self.day_first else "month-first"

    def to_dict(self) -> dict[str, str]:
        return {k: v for k, v in (("order", self.order), ("zone", self.zone_name)) if v}


_ZONE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_+\-/]{0,63}$")
_OFFSET_RE = re.compile(r"^(?:UTC|GMT)?\s*([+-])(\d{1,2})(?::?(\d{2}))?$", re.IGNORECASE)


def date_setting(value: Any) -> DateSetting | None:
    """The date setting a request gives for one evidence file, {"order": "day-first" |
    "month-first", "zone": "UTC" | "+02:00" | "Europe/Paris"}, as JSON text or an object; None when
    it sets neither. A value that cannot be used raises ValueError, its message written for the
    analyst."""
    if value in (None, "", {}):
        return None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            raise ValueError("the date setting is not JSON") from None
    if not isinstance(value, dict):
        raise ValueError("the date setting is an object with an order and a zone")
    order = str(value.get("order") or "").strip().lower()
    if order not in ("", "day-first", "month-first"):
        raise ValueError(f"the date order {order[:40]!r} is neither day-first nor month-first")
    name = str(value.get("zone") or "").strip()
    zone = time_zone(name) if name else None
    if not order and zone is None:
        return None
    return DateSetting(day_first=None if not order else order == "day-first", zone=zone, zone_name=name if zone is not None else "")


def time_zone(name: str) -> tzinfo:
    """A zone by its name: UTC, an offset (+02:00, -0530, UTC+2) or an IANA name (Europe/Paris), whose
    offset follows daylight saving time. Raises ValueError for anything else."""
    if name.upper() in ("UTC", "Z", "GMT"):
        return UTC
    if m := _OFFSET_RE.match(name):
        hours, minutes = int(m.group(2)), int(m.group(3) or 0)
        if hours > 14 or minutes > 59:
            raise ValueError(f"the offset {name[:20]!r} is not one a clock uses")
        return timezone((-1 if m.group(1) == "-" else 1) * timedelta(hours=hours, minutes=minutes))
    if _ZONE_NAME_RE.match(name):
        try:
            return ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError):
            pass
    raise ValueError(f"the time zone {name[:64]!r} is not known: give UTC, an offset such as +02:00, or a name such as Europe/Paris")


class _Dates:
    """How the times of one file are read: in the date order its own dates show, unless the evidence
    sets one, and a culture-written time without a zone in the evidence's zone, or UTC. local: the
    export writes its times in a zone of the reader's choosing, so an ISO 8601 time without a zone
    is local too (the message trace reports, in the zone of the admin who asked for them)."""

    def __init__(self, setting: DateSetting | None = None, file_order: bool | None = None, local: bool = False) -> None:
        self.set_order = setting is not None and setting.day_first is not None
        self.day_first = setting.day_first if setting is not None and setting.day_first is not None else file_order
        self.zone = setting.zone if setting is not None else None
        self.local = local

    def read(self, value: Any, utc: bool = False) -> tuple[int | None, str | None, tuple[str, ...]]:
        """(ms, iso, marks) of one time; utc when the export's column says its times are UTC. The
        marks name what the record is counted for: dated in an order the file did not show, in the
        order or the zone the evidence sets, or read as UTC with nothing to say so."""
        moved = not utc and (culture_written(value) or (self.local and _naive_iso(value)))
        ms, iso = parse_ts(value, self.day_first, self.zone if moved else None)
        marks: tuple[str, ...] = ()
        if guessed_order(value):
            if self.set_order:
                marks += ("date_order_set",)
            elif self.day_first is None:
                marks += ("date_order_guessed",)
        if ms is None and self.set_order and parse_ts(value, not self.day_first)[0] is not None:
            marks += ("date_order_contradicted",)
        if moved and ms is not None:
            marks += ("zone_set",) if self.zone is not None else ("zone_assumed",)
        return ms, iso, marks


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
_TYPE_NAME_RE = re.compile(r"^(?:Microsoft\.Graph\.(?:Beta\.)?PowerShell\.Models\.\w+(?:\[\])?|System\.[\w.`]+(?:\[[^\]]*\])+)$")


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
# Entra directory audit rows
# ---------------------------------------------------------------------------
def _canon(d: dict[str, Any], names: dict[str, str]) -> dict[str, Any]:
    """d with its keys under the names Microsoft documents (names: lower case -> documented), in
    whatever case the export wrote them (the Graph PowerShell SDK writes PascalCase), nested
    objects included. A value Export-Csv wrote as a .NET type name is left out: the export does
    not hold it. A name already in documented form wins over another case of it."""
    out: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, str) and _TYPE_NAME_RE.match(v.strip()):
            continue
        name = names.get(str(k).strip().lower(), str(k))
        if isinstance(v, dict):
            v = _canon(v, names)
        elif isinstance(v, list):
            v = [_canon(x, names) if isinstance(x, dict) else x for x in v]
        if name not in out or k == name:
            out[name] = v
    return out


# directoryAudit and the types it holds (auditActivityInitiator, userIdentity, appIdentity,
# targetResource, modifiedProperty, keyValue), learn.microsoft.com/graph/api/resources/directoryaudit
_AUDIT_NAMES = {
    n.lower(): n
    for n in (
        "activityDateTime",
        "activityDisplayName",
        "additionalDetails",
        "category",
        "correlationId",
        "id",
        "initiatedBy",
        "loggedByService",
        "operationType",
        "result",
        "resultReason",
        "targetResources",
        "user",
        "app",
        "displayName",
        "userPrincipalName",
        "ipAddress",
        "appId",
        "servicePrincipalId",
        "servicePrincipalName",
        "type",
        "groupType",
        "modifiedProperties",
        "oldValue",
        "newValue",
        "key",
        "value",
    )
}
# the audit log writes a directory activity with a closing period ("Consent to application.");
# rules, stories and chains know the activities by those names. Privileged Identity Management
# names its own without one, and the audit log spells this one with a dash and a space instead.
_ACTIVITY_AS_WRITTEN = frozenset({"update application - certificates and secrets management"})


def ual_operation(activity: str, service: Any = None) -> str:
    """A directory activity ("Consent to application") under the name the Unified Audit Log gives
    it ("Consent to application.")."""
    low = activity.lower()
    if not activity or activity.endswith(".") or low in _ACTIVITY_AS_WRITTEN or "privileged identity management" in str(service or "").lower():
        return activity
    return activity + "."


_GUID_IN_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def resource_key(prefix: str, value: Any) -> str | None:
    """record_key for an id that holds a GUID among other text, as a directory audit's does
    ("Directory_<guid>_<suffix>"): the whole id is the record's identity. An id without a GUID in
    it gives no key, as in record_key."""
    v = str(value or "").strip()
    return f"{prefix}:{v.lower()}" if len(v) <= 200 and _GUID_IN_RE.search(v) else None


def audit_row(o: dict[str, Any], when: _Dates | None = None, utc: bool = False) -> dict[str, Any] | None:
    """A Graph directoryAudit (any case of its names) -> event row, its time read by ``when``
    (utc: the column it came from says UTC); None for a record that is not one."""
    a = _canon(o, _AUDIT_NAMES)
    activity = str(a.get("activityDisplayName") or "").strip()
    if not activity:
        return None
    ts, iso, marks = (when or _Dates()).read(a.get("activityDateTime"), utc)
    initiator = a.get("initiatedBy") if isinstance(a.get("initiatedBy"), dict) else {}
    by_user = initiator.get("user") if isinstance(initiator.get("user"), dict) else {}
    by_app = initiator.get("app") if isinstance(initiator.get("app"), dict) else {}
    actor = str(_first(by_user, "userPrincipalName", "displayName", "id") or _first(by_app, "displayName", "servicePrincipalName", "appId") or "").strip()
    ip = clean_ip(by_user.get("ipAddress") or a.get("ipAddress"))
    targets = [t for t in a.get("targetResources") or [] if isinstance(t, dict)]
    target_user = next((str(t["userPrincipalName"]) for t in targets if t.get("userPrincipalName")), None)
    named = [t for t in targets if t.get("displayName")]
    obj = next((str(t["displayName"]) for t in named if str(t.get("type") or "").lower() != "user"), None) or (str(named[0]["displayName"]) if named else None)
    result = str(a.get("result") or "").strip()
    data: dict[str, Any] = {
        k: a.get(k) for k in ("id", "correlationId", "activityDisplayName", "category", "loggedByService", "operationType", "result", "resultReason")
    }
    for who, ident in (("user", by_user), ("app", by_app)):
        for k, v in ident.items():
            data[f"initiatedBy.{who}.{k}"] = _scalar(v)
    if targets:
        data["Target"] = _cut("; ".join(str(t.get("id")) for t in targets if t.get("id")), 2000)
        data["Target.Type"] = _cut(", ".join(str(t.get("type") or "") for t in targets), 200)
        data["Target.DisplayName"] = _cut("; ".join(str(t["displayName"]) for t in named), 2000)
        data["Target.UserPrincipalName"] = "; ".join(str(t["userPrincipalName"]) for t in targets if t.get("userPrincipalName"))
    # what changed, under the names the audit log gives it (Role.DisplayName, ConsentAction.Permissions,
    # StrongAuthenticationMethod); the first target's value when two name the same property
    for t in targets:
        for prop in t.get("modifiedProperties") or []:
            if isinstance(prop, dict) and prop.get("displayName"):
                name = str(prop["displayName"])
                data.setdefault(name, _clean_json_string(prop.get("newValue")))
                old = _clean_json_string(prop.get("oldValue"))
                if old not in (None, "", "[]"):
                    data.setdefault(name + ".old", old)
    for detail in a.get("additionalDetails") or []:
        if isinstance(detail, dict) and detail.get("key"):
            data.setdefault(str(detail["key"]), _scalar(detail.get("value")))
    # what the export holds beyond the documented properties is kept as it is
    for k, v in a.items():
        if k not in _AUDIT_KEPT and not str(k).startswith("@"):
            data.setdefault(str(k), _scalar(v))
    data = {k: v for k, v in data.items() if v not in (None, "")}
    failed = result.lower() in ("failure", "timeout")
    summary = f"{activity} by {actor or '?'}"
    if ip:
        summary += f" from {ip}"
    if data.get("Role.DisplayName"):
        summary += f": role {data['Role.DisplayName']}"
    if target_user or obj:
        summary += f" on {target_user or obj}"
    if data.get("ConsentAction.Permissions"):
        summary += f" {str(data['ConsentAction.Permissions'])[:120]}"
    if result and result.lower() != "success":
        summary += f" [{result}{': ' + str(a['resultReason']) if a.get('resultReason') else ''}]"
    row: dict[str, Any] = {
        "ts": ts,
        "tsIso": iso,
        "eventId": None,
        "recordId": None,
        "level": 3 if failed else 4,
        "levelName": "Warning" if failed else "Information",
        "provider": AUDIT_PROVIDER,
        "channel": "Entra Audit",
        "computer": None,
        "category": "Entra audit",
        "description": activity,
        "operation": ual_operation(activity, a.get("loggedByService")),
        "objectName": obj[:500] if obj else None,
        "objectType": next((str(t["type"]) for t in targets if t.get("type")), None),
        "user": actor or None,
        "upn": actor or None,
        "subjectUser": actor or None,
        "targetUser": target_user,
        "ipAddress": ip,
        "status": result or None,
        "statusText": str(a.get("resultReason") or "") or None,
        "failureReason": (str(a.get("resultReason") or "") or None) if failed else None,
        "workstation": str(data.get("User-Agent") or "")[:200] or None,
        "recordKey": resource_key("entra-audit", a.get("id")),
        "data": data,
        "summary": summary[:500],
    }
    if marks:
        row["_marks"] = marks
    return row


# the properties audit_row reads into a row; any other is kept under its own name
_AUDIT_KEPT = frozenset(
    {"activityDateTime", "activityDisplayName", "additionalDetails", "category", "correlationId", "id", "initiatedBy"}
    | {"loggedByService", "operationType", "result", "resultReason", "targetResources", "ipAddress"}
)


def _portal_audit(columns: list[str]) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """What reads a row of the Entra admin centre's audit log download (columns: its header) as a
    directoryAudit. The portal writes the date, service, category, activity and result columns in
    the language it is shown in, so they are read by their place, first and third to sixth;
    CorrelationId and ResultReason, second and seventh, are written in English whatever the
    language. Its actor is a user (ActorUserPrincipalName) or an application (ActorServicePrincipal*),
    its targets up to three with up to five modified properties each, and its additional details
    up to six."""
    named = {c.strip().lower(): c for c in columns}
    placed = len(columns) >= 7 and columns[1].strip().lower() == "correlationid" and columns[6].strip().lower() == "resultreason"
    date, service, category, activity, result = (columns[i] for i in (0, 2, 3, 4, 5)) if placed else ("",) * 5

    def col(rec: dict[str, Any], name: str) -> Any:
        v = rec.get(named.get(name.lower(), name))
        return v if v not in (None, "") else None

    def convert(rec: dict[str, Any]) -> dict[str, Any]:
        used = {date, service, category, activity, result}
        app = {
            "displayName": col(rec, "ActorDisplayName") if not col(rec, "ActorUserPrincipalName") else None,
            "servicePrincipalId": col(rec, "ActorServicePrincipalId"),
            "servicePrincipalName": col(rec, "ActorServicePrincipalName"),
        }
        user = {
            "id": col(rec, "ActorObjectId"),
            "displayName": col(rec, "ActorDisplayName"),
            "userPrincipalName": col(rec, "ActorUserPrincipalName"),
            "ipAddress": col(rec, "IPAddress"),
        }
        is_app = not user["userPrincipalName"] and bool(app["servicePrincipalId"] or app["servicePrincipalName"])
        targets = []
        for n in range(1, 4):
            props = []
            for m in range(1, 6):
                head = f"Target{n}ModifiedProperty{m}"
                if col(rec, head + "Name"):
                    props.append({"displayName": col(rec, head + "Name"), "oldValue": col(rec, head + "OldValue"), "newValue": col(rec, head + "NewValue")})
            target = {
                "type": col(rec, f"Target{n}Type"),
                "displayName": col(rec, f"Target{n}DisplayName"),
                "id": col(rec, f"Target{n}ObjectId"),
                "userPrincipalName": col(rec, f"Target{n}UserPrincipalName"),
                "modifiedProperties": props,
            }
            if any(target[k] for k in ("type", "displayName", "id", "userPrincipalName")):
                targets.append(target)
        details = [
            {"key": col(rec, f"AdditionalDetail{n}Key"), "value": col(rec, f"AdditionalDetail{n}Value")}
            for n in range(1, 7)
            if col(rec, f"AdditionalDetail{n}Key")
        ]
        out: dict[str, Any] = {
            "activityDateTime": rec.get(date) if date else None,
            "activityDisplayName": rec.get(activity) if activity else None,
            "loggedByService": rec.get(service) if service else None,
            "category": rec.get(category) if category else None,
            "result": rec.get(result) if result else None,
            "correlationId": col(rec, "CorrelationId"),
            "resultReason": col(rec, "ResultReason"),
            "initiatedBy": {"app": {k: v for k, v in app.items() if v} or None} if is_app else {"user": {k: v for k, v in user.items() if v} or None},
            "targetResources": targets,
            "additionalDetails": details,
        }
        if not is_app and (app["servicePrincipalId"] or app["servicePrincipalName"]):
            out["initiatedBy"]["app"] = {k: v for k, v in app.items() if v and k != "displayName"}
        if col(rec, "ActorType"):
            out["ActorType"] = col(rec, "ActorType")
        # a column the download is not documented to hold is kept as it is
        for k, v in rec.items():
            if k not in used and not _PORTAL_AUDIT_RE.match(str(k).strip()) and v not in (None, ""):
                out.setdefault(str(k), v)
        return out

    return convert


_PORTAL_AUDIT_RE = re.compile(
    r"^(?:CorrelationId|ResultReason|ActorType|ActorDisplayName|ActorObjectId|ActorUserPrincipalName|IPAddress|ActorServicePrincipalId|ActorServicePrincipalName"
    r"|Target[1-3](?:Type|DisplayName|ObjectId|UserPrincipalName|ModifiedProperty[1-5](?:Name|OldValue|NewValue))|AdditionalDetail[1-6](?:Key|Value))$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Entra ID Protection rows
# ---------------------------------------------------------------------------
# riskDetection and riskyUser, learn.microsoft.com/graph/api/resources/riskdetection and
# .../riskyuser, with signInLocation's names, which Microsoft-Extractor-Suite writes as columns
_RISK_NAMES = {
    n.lower(): n
    for n in (
        "activity",
        "activityDateTime",
        "additionalInfo",
        "correlationId",
        "detectedDateTime",
        "detectionTimingType",
        "id",
        "ipAddress",
        "lastUpdatedDateTime",
        "location",
        "city",
        "state",
        "countryOrRegion",
        "requestId",
        "riskDetail",
        "riskEventType",
        "riskLevel",
        "riskState",
        "source",
        "tokenIssuerType",
        "userDisplayName",
        "userId",
        "userPrincipalName",
        "isDeleted",
        "isProcessing",
        "riskLastUpdatedDateTime",
    )
}
# a risk ID Protection rates medium or high, or a compromise someone confirmed
_RISKY_LEVELS = ("medium", "high")
_HEX_ID_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")


def _additional_info(v: Any) -> dict[str, Any]:
    """A risk detection's additionalInfo, JSON text of [{"Key": ..., "Value": ...}], by key."""
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            return {}
    out: dict[str, Any] = {}
    for item in v if isinstance(v, list) else []:
        if isinstance(item, dict):
            item = {str(k).lower(): x for k, x in item.items()}
            if item.get("key"):
                out[f"additionalInfo.{item['key']}"] = _scalar(item.get("value"))
    return out


def _risk_data(a: dict[str, Any], skip: tuple[str, ...] = ()) -> dict[str, Any]:
    """Every field of a risk record under its own name, the location under the names a sign-in
    gives it (country, city, state), and what additionalInfo holds by its key."""
    data: dict[str, Any] = {}
    loc = a.get("location") if isinstance(a.get("location"), dict) else {}
    for k, v in a.items():
        if k in skip or k == "location" or str(k).startswith("@"):
            continue
        if k == "countryOrRegion":
            data["country"] = v
        elif k in ("city", "state"):
            data[k] = v
        else:
            data[k] = _scalar(v)
    data.setdefault("country", loc.get("countryOrRegion"))
    data.setdefault("city", loc.get("city"))
    data.setdefault("state", loc.get("state"))
    data.update(_additional_info(a.get("additionalInfo")))
    return {k: v for k, v in data.items() if v not in (None, "")}


def risk_detection_row(o: dict[str, Any], when: _Dates | None = None, utc: bool = False) -> dict[str, Any] | None:
    """A Graph riskDetection (any case of its names) -> event row at the time of the risky
    activity, or when it was detected if the record has no activity time; None for a record that
    is not one."""
    a = _canon(o, _RISK_NAMES)
    kind = str(a.get("riskEventType") or "").strip()
    if not kind:
        return None
    ts, iso, marks = (when or _Dates()).read(a.get("activityDateTime") or a.get("detectedDateTime"), utc)
    user = str(_first(a, "userPrincipalName", "userDisplayName", "userId") or "").strip()
    ip = clean_ip(a.get("ipAddress"))
    level, state = str(a.get("riskLevel") or "").strip(), str(a.get("riskState") or "").strip()
    risky = level.lower() in _RISKY_LEVELS or state.lower() == "confirmedcompromised"
    data = _risk_data(a)
    summary = f"Risk detection {kind} ({level or '?'}, {state or '?'}) for {user or '?'}"
    if ip:
        summary += f" from {ip}{' (' + str(data['country']) + ')' if data.get('country') else ''}"
    if data.get("riskDetail") and str(data["riskDetail"]).lower() != "none":
        summary += f": {data['riskDetail']}"
    row: dict[str, Any] = {
        "ts": ts,
        "tsIso": iso,
        "eventId": None,
        "recordId": None,
        "level": 3 if risky else 4,
        "levelName": "Warning" if risky else "Information",
        "provider": RISK_PROVIDER,
        "channel": "Entra RiskDetection",
        "computer": None,
        "category": "Entra risk",
        "description": kind,
        "operation": "RiskDetection",
        "objectName": None,
        "user": user or None,
        "upn": user or None,
        "subjectUser": user or None,
        "targetUser": user or None,
        "ipAddress": ip,
        "status": state or None,
        "statusText": str(a.get("riskDetail") or "") or None,
        "workstation": str(data.get("additionalInfo.userAgent") or "")[:200] or None,
        "recordKey": _risk_key(a.get("id")),
        "data": data,
        "summary": summary[:500],
    }
    if marks:
        row["_marks"] = marks
    return row


def _risk_key(value: Any) -> str | None:
    """A risk detection's id is a long hexadecimal string, not a GUID: it is its identity all the same."""
    v = str(value or "").strip()
    return f"entra-risk:{v.lower()}" if _HEX_ID_RE.match(v) else resource_key("entra-risk", v)


def risky_user_row(o: dict[str, Any], when: _Dates | None = None, utc: bool = False) -> dict[str, Any] | None:
    """A Graph riskyUser (any case of its names) -> event row at the time its risk was last
    updated: the state of one user's risk when the list was taken. None for a record that is not one."""
    a = _canon(o, _RISK_NAMES)
    user = str(_first(a, "userPrincipalName", "userDisplayName", "id") or "").strip()
    if "riskLastUpdatedDateTime" not in a or not user:
        return None
    ts, iso, marks = (when or _Dates()).read(a.get("riskLastUpdatedDateTime"), utc)
    level, state = str(a.get("riskLevel") or "").strip(), str(a.get("riskState") or "").strip()
    risky = level.lower() in _RISKY_LEVELS or state.lower() == "confirmedcompromised"
    data = _risk_data(a)
    detail = str(a.get("riskDetail") or "")
    summary = f"Risky user {user}: risk {level or '?'}, {state or '?'}"
    if detail and detail.lower() != "none":
        summary += f" ({detail})"
    # a user's risk changes over time; the same user listed at another time is another record
    key = record_key("entra-riskyuser", a.get("id"))
    row: dict[str, Any] = {
        "ts": ts,
        "tsIso": iso,
        "eventId": None,
        "recordId": None,
        "level": 3 if risky else 4,
        "levelName": "Warning" if risky else "Information",
        "provider": RISK_PROVIDER,
        "channel": "Entra RiskyUser",
        "computer": None,
        "category": "Entra risk",
        "description": "Risky user",
        "operation": "RiskyUser",
        "objectName": None,
        "user": user,
        "upn": user,
        "subjectUser": user,
        "targetUser": user,
        "ipAddress": None,
        "status": state or None,
        "statusText": detail or None,
        "workstation": None,
        "recordKey": f"{key}|{iso}" if key and iso else None,
        "data": data,
        "summary": summary[:500],
    }
    if marks:
        row["_marks"] = marks
    return row


# ---------------------------------------------------------------------------
# Exchange Online message trace rows
# ---------------------------------------------------------------------------
# what the message trace says of a message it did not deliver, as a word of its status
_UNDELIVERED = frozenset({"failed", "fail", "filteredasspam", "quarantined", "quarantine"})


def _domain(address: Any) -> str | None:
    """The domain of an address, in lower case, as internal_domains lists them."""
    a = str(address or "").strip().lower()
    return a.rsplit("@", 1)[1] if "@" in a else None


def _trace_row(
    sender: str, recipient: str, status: str, when: tuple[int | None, str | None], data: dict[str, Any], subject: str, message_id: str, ip: str, to_ip: str
) -> dict[str, Any]:
    """One message to one recipient, as the message trace saw it."""
    # InternetMessageId is how an audit record and a mailbox message name the same message
    data = {**data, "SenderDomain": _domain(sender), "RecipientDomain": _domain(recipient), "InternetMessageId": message_id}
    data = {k: _scalar(v) for k, v in data.items() if v not in (None, "")}
    undelivered = bool(set(re.findall(r"[a-z]+", status.lower())) & _UNDELIVERED)
    summary = f"Message from {sender or '?'} to {recipient or '?'}: {status or '?'}"
    if subject:
        summary += f", '{str(subject)[:120]}'"
    if ip:
        summary += f" from {ip}"
    return {
        "ts": when[0],
        "tsIso": when[1],
        "eventId": None,
        "recordId": None,
        "level": 3 if undelivered else 4,
        "levelName": "Warning" if undelivered else "Information",
        "provider": TRACE_PROVIDER,
        "channel": "Exchange MessageTrace",
        "computer": None,
        "category": "Exchange message trace",
        "description": status or "Message",
        "operation": "MessageTrace",
        "objectName": str(subject)[:500] if subject else None,
        "user": sender or None,
        "upn": sender or None,
        "subjectUser": sender or None,
        "targetUser": recipient or None,
        "ipAddress": clean_ip(ip),
        "destinationIp": clean_ip(to_ip),
        "status": status or None,
        "recordKey": None,
        "data": data,
        "summary": summary[:500],
    }


def trace_rows(rec: dict[str, Any], when: _Dates, received: str) -> list[dict[str, Any]]:
    """A row of Get-MessageTrace or Get-MessageTraceV2 written with Export-Csv (the MessageTrace
    report's fields: Received, SenderAddress, RecipientAddress, Subject, Status, FromIP, ToIP,
    Size, MessageId, MessageTraceId ...) -> its event row; none when it names neither a sender
    nor a recipient. received: the column its time is in. The cmdlets write their times in UTC,
    Microsoft says, so no zone set for the evidence moves them."""
    canon = {str(k).strip().lower(): k for k in rec}

    def col(name: str) -> Any:
        v = rec.get(canon.get(name.lower(), name))
        return str(v).strip() if v not in (None, "") else ""

    sender, recipient = col("SenderAddress"), col("RecipientAddress")
    if not sender and not recipient:
        return []
    ts, iso, marks = when.read(rec.get(received), utc=True)
    status = col("Status")
    row = _trace_row(sender, recipient, status, (ts, iso), dict(rec), col("Subject"), col("MessageId"), col("FromIP"), col("ToIP"))
    trace_id = col("MessageTraceId").strip("{}")
    # one message to one recipient in one state: the same row in two exports of the same hours
    if _GUID_RE.match(trace_id) and recipient:
        row["recordKey"] = f"exo-trace:{trace_id.lower()}|{recipient.lower()}|{status.lower()}"
    if marks:
        row["_marks"] = marks
    return [row]


# "<address>##<status>": one recipient of a message and what happened to it there
_RECIPIENT_STATUS_RE = re.compile(r"^\s*([^#;\s]+)##(.*)$")


def report_rows(rec: dict[str, Any], when: _Dates, time_column: str) -> list[dict[str, Any]]:
    """A row of the Exchange admin centre's enhanced summary report (one message, its recipients
    in Recipient_status as "<address>##<status>") or extended report (one event of a message, its
    recipients in recipient_address, separated by ";") -> one event row per recipient; none when
    it names neither a sender nor a recipient. time_column: the column its time is in."""
    canon = {_report_name(k): k for k in rec}

    def col(name: str) -> str:
        v = rec.get(canon.get(name, name))
        return str(v).strip() if v not in (None, "") else ""

    sender = col("sender_address")
    statuses = col("recipient_status")
    # recipients of the enhanced summary are written one after the other; Microsoft does not say
    # how they are separated, so a ";" counts as a separator only before another "<address>##"
    parts = [p for p in re.split(r";(?=[^;#\s]+##)", statuses) if p.strip()] if "##" in statuses else []
    pairs = [(m.group(1), m.group(2).strip()) for p in parts if (m := _RECIPIENT_STATUS_RE.match(p))]
    if not pairs:
        status = col("event_id") or statuses
        pairs = [(r.strip(), status) for r in col("recipient_address").split(";") if r.strip()] or [("", status)]
    if not sender and not any(r for r, _ in pairs):
        return []
    ts, iso, marks = when.read(rec.get(time_column), utc_column(time_column))
    rows = []
    for recipient, status in pairs:
        ip = col("original_client_ip") or col("client_ip")
        row = _trace_row(sender, recipient, status, (ts, iso), dict(rec), col("message_subject"), col("message_id"), ip, col("server_ip"))
        row["direction"] = col("directionality") or None
        if marks:
            row["_marks"] = marks
        rows.append(row)
    return rows


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
    reader = csv.DictReader(_table_lines(fh))
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


def _table_lines(fh: io.TextIOBase) -> Iterator[str]:
    """The lines of a table without the "#TYPE <type name>" line Export-Csv may write above it."""
    lines: Iterator[str] = iter(fh)
    first = next(lines, "")
    return lines if first.startswith("#TYPE") else itertools.chain([first], lines)


def _csv_header(path: str | None, data: bytes | None) -> list[str]:
    """A table's column names."""
    fh = _open_text(path, data)
    try:
        return next(csv.reader(_table_lines(fh)), [])
    except csv.Error:
        return []
    finally:
        fh.close()


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
    path: str | None,
    data: bytes | None,
    fmt: str,
    stats: Any = None,
    include_raw: bool = True,
    seen: RecordKeys | None = None,
    dates: DateSetting | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield event rows from a UAL / Entra export in the given format (see FORMATS), its dates read
    in the order and the zone ``dates`` sets for the evidence where the file cannot say. A record
    whose key (record_key) is already in ``seen`` is the same record exported again: it is
    counted in ``stats.duplicates`` and not yielded: Search-UnifiedAuditLog's ReturnLargeSet
    pages repeat records within one file, and overlapping time slices repeat them across files.
    Pass one RecordKeys for every file of an upload so an archive of slices gives each record
    once. A record read once it is full is counted in ``stats.repeats_unchecked``."""
    seen = RecordKeys() if seen is None else seen
    if stats is not None and dates is not None:
        stats.dates = dates.to_dict()
    for row in _iter_rows(path, data, fmt, stats, include_raw, dates):
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


# what each count on a cloud export's stats says on its member of an archive or a package; {order}
# and {zone} are what the evidence sets
_NOTES = (
    ("not_read", "{:,} record(s) are not of the kind the file holds and were not read"),
    ("cut", "{:,} record(s) hold a value cut at its length limit, marked by a closing …"),
    ("undated", "{:,} record(s) have no time: their date is missing or could not be read"),
    ("date_order_guessed", "{:,} record(s) were dated month-first: no date in the file has a day above 12 to show its order"),
    ("date_order_set", "{:,} record(s) were dated {order}, the date order set for the evidence"),
    ("date_order_contradicted", "{:,} record(s) have a date that cannot be read {order}, the date order set for the evidence, but can be read the other way"),
    ("zone_set", "{:,} record(s) were read in {zone}, the time zone set for the evidence: their times say none"),
    ("zone_assumed", "{:,} record(s) were read as UTC: their times say no time zone, and none is set for the evidence"),
    ("repeats_unchecked", "{:,} record(s) were read once the ids held to find repeats were full, and were not compared with one another"),
)


# the counts that say how the dates of the cloud exports were read
DATE_COUNTS = ("date_order_guessed", "date_order_set", "date_order_contradicted", "zone_set", "zone_assumed")


def date_stats(counts: dict[str, int], dates: DateSetting | None) -> dict[str, Any]:
    """What an evidence's statistics say of its cloud exports' dates: the setting they were read
    with, and the counts of DATE_COUNTS that are not zero, as Stats.to_dict names them."""
    out: dict[str, Any] = {"dates": dates.to_dict()} if dates is not None else {}
    for name in DATE_COUNTS:
        if counts.get(name):
            head, *rest = name.split("_")
            out[head + "".join(w.title() for w in rest)] = counts[name]
    return out


def counts(stats: Any) -> dict[str, int]:
    """The counts of what reading cloud exports compromised on, so far."""
    return {name: int(getattr(stats, name, 0) or 0) for name, _ in _NOTES}


def note(counts: dict[str, int], dates: DateSetting | None = None) -> str:
    """Those counts in words, for one file read with the evidence's date setting: "" when there is
    nothing to say."""
    order = dates.order if dates is not None and dates.order else "in the order set"
    zone = dates.zone_name if dates is not None and dates.zone_name else "the zone set"
    return "; ".join(text.format(counts[name], order=order, zone=zone) for name, text in _NOTES if counts.get(name))


def _not_read(stats: Any) -> None:
    """A record of a recognised export that is not of the export's kind: an error of the file, and
    said as what it is."""
    if stats is not None:
        stats.errors += 1
        stats.not_read = getattr(stats, "not_read", 0) + 1


def _count(row: dict[str, Any], stats: Any) -> None:
    try:
        stats.add(row)
    except Exception:  # noqa: BLE001
        stats.count += 1


def _iter_rows(path: str | None, data: bytes | None, fmt: str, stats: Any, include_raw: bool, dates: DateSetting | None = None) -> Iterator[dict[str, Any]]:
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
                    _not_read(stats)
                    continue
                yield _finish(entra_row(signin), obj, stats, include_raw)
        elif fmt == "entra-signin-csv":
            when = _csv_dates(path, data, dates, _date_column)
            for obj in _csv_rows(fh, stats):
                row = entra_row(obj)
                row["ts"], row["tsIso"], marks = _csv_when(obj, _date_column, when)
                yield _finish(row, obj, stats, include_raw, marks)
        elif fmt == "entra-audit-json":
            when = _Dates(dates)
            for obj in _iter_json_objects(fh, stats):
                row = audit_row(obj, when)
                if row is None:
                    _not_read(stats)
                    continue
                yield _finish(row, obj, stats, include_raw, row.pop("_marks", ()))
        elif fmt in ("entra-riskdetection-json", "entra-riskyuser-json"):
            read = risk_detection_row if fmt == "entra-riskdetection-json" else risky_user_row
            when = _Dates(dates)
            for obj in _iter_json_objects(fh, stats):
                row = read(obj, when)
                if row is None:
                    _not_read(stats)
                    continue
                yield _finish(row, obj, stats, include_raw, row.pop("_marks", ()))
        elif fmt in ("entra-riskdetection-csv", "entra-riskyuser-csv"):
            read = risk_detection_row if fmt == "entra-riskdetection-csv" else risky_user_row
            names = ("activitydatetime", "detecteddatetime") if fmt == "entra-riskdetection-csv" else ("risklastupdateddatetime",)

            def is_date(k: str) -> bool:
                return k.strip().lower() in names

            when = _csv_dates(path, data, dates, is_date)
            for obj in _csv_rows(fh, stats):
                row = read(obj, when, any(utc_column(k) for k, v in obj.items() if v and is_date(k)))
                if row is None:
                    _not_read(stats)
                    continue
                yield _finish(row, obj, stats, include_raw, row.pop("_marks", ()))
        elif fmt in ("exo-messagetrace-csv", "exo-messagetrace-report-csv"):
            columns = _csv_header(path, data)
            if fmt == "exo-messagetrace-csv":
                date = next((c for c in columns if c.strip().lower() == "received"), "Received")
                when = _csv_dates(path, data, dates, lambda k: k == date)
            else:
                date = next((c for c in columns if _report_name(c) in ("origin_timestamp", "date_time")), "")
                when = _csv_dates(path, data, dates, lambda k: k == date, local=True)
            for obj in _csv_rows(fh, stats):
                rows = trace_rows(obj, when, date) if fmt == "exo-messagetrace-csv" else report_rows(obj, when, date)
                if not rows:
                    _not_read(stats)
                for row in rows:
                    yield _finish(row, obj, stats, include_raw, row.pop("_marks", ()))
        elif fmt == "entra-audit-csv":
            columns = _csv_header(path, data)
            graph = next((c for c in columns if c.strip().lower() == "activitydatetime"), None)
            portal = None if graph else _portal_audit(columns)
            date = graph or (columns[0] if columns else "")
            when = _csv_dates(path, data, dates, lambda k: k == date)
            for obj in _csv_rows(fh, stats):
                row = audit_row(portal(obj) if portal else obj, when, utc_column(date))
                if row is None:
                    _not_read(stats)
                    continue
                yield _finish(row, obj, stats, include_raw, row.pop("_marks", ()))
        else:
            raise ValueError(f"unknown M365 format {fmt}")
    finally:
        fh.close()


def _date_column(name: str) -> bool:
    low = str(name).strip().lower()
    return (_PORTAL_MAP.get(low) or _GRAPH_NAMES.get(low)) == "createdDateTime"


def _csv_dates(path: str | None, data: bytes | None, dates: DateSetting | None, is_date: Callable[[str], bool], local: bool = False) -> _Dates:
    """How a CSV's times are read: in the order the evidence sets, or else the order its own dates
    show (is_date names its date columns)."""
    if dates is not None and dates.day_first is not None:
        return _Dates(dates, local=local)
    return _Dates(dates, _csv_date_order(path, data, is_date), local)


def _csv_when(rec: dict[str, Any], is_date: Callable[[str], bool], when: _Dates) -> tuple[int | None, str | None, tuple[str, ...]]:
    """The time of a CSV row, from its first date column that holds one, and what it is counted for."""
    for k, v in rec.items():
        if v and is_date(k):
            return when.read(v, utc_column(k))
    return None, None, ()


def _csv_date_order(path: str | None, data: bytes | None, is_date: Callable[[str], bool]) -> bool | None:
    """The date order of a CSV, from a first pass over its date columns that stops at the first
    date settling it (or at the first date not written as numbers, whose order does not matter).
    Deciding from the first 5,000 rows read a day-first export whose first days were all 12 or
    below month-first, every date of it wrong."""
    fh = _open_text(path, data)
    try:
        for rec in _csv_rows(fh, None):
            for k, v in rec.items():
                if v and is_date(k):
                    if not _NUMERIC_DATE_RE.match(str(v)):
                        return None
                    order = date_order([v])
                    if order is not None:
                        return order
    finally:
        fh.close()
    return None


def _finish(row: dict[str, Any], source: dict[str, Any], stats: Any, include_raw: bool, marks: tuple[str, ...] = ()) -> dict[str, Any]:
    """The row with its raw record, and what it is counted for (marks, from reading its time, and
    whether a value was cut or it has no time), counted by iter_records once it knows the row is kept."""
    if include_raw:
        row["raw"] = _cut(json.dumps(source, ensure_ascii=False, separators=(",", ":")), 200_000)
    if isinstance(row.get("raw"), _Cut) or any(isinstance(v, _Cut) for v in row["data"].values()):
        marks += ("cut",)
    if row.get("ts") is None:
        marks += ("undated",)
    if marks:
        row["_marks"] = marks
    return row


def is_privileged_role(name: str | None) -> bool:
    return bool(name) and str(name).strip().lower() in _PRIVILEGED_ROLES
