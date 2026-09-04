"""
Microsoft 365 Unified Audit Log (UAL) and Entra ID sign-in exports -> event rows.

Business-email-compromise investigations live on three sources: the mailbox itself, the
Unified Audit Log (inbox rules, forwarding, MailItemsAccessed, consent grants, role changes)
and the Entra sign-in log (who authenticated from where, with what client, at what risk).
REMN ingests the exports the acquisition tools produce - Purview / Invictus
Microsoft-Extractor-Suite / Office-365-Extractor CSV and JSON, Untitled Goose Tool JSON,
Entra portal CSV, Graph sign-in JSON - as rows of the *events* table, so the timeline, facets,
rules, AI tools and cross-source pivots work on them unchanged.

Formats (detected from the first bytes, also inside zip/tar archives):
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
import io
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Iterator

log = logging.getLogger(__name__)

UAL_PROVIDER = "Microsoft 365 Unified Audit Log"
ENTRA_PROVIDER = "Microsoft Entra ID Sign-in"
FORMATS = ("m365-ual-csv", "m365-ual-json", "entra-signin-json", "entra-signin-csv")

_WORKLOAD_CATEGORY = {
    "exchange": "M365 Exchange", "azureactivedirectory": "M365 Entra", "sharepoint": "M365 SharePoint", "onedrive": "M365 OneDrive",
    "microsoftteams": "M365 Teams", "securitycompliancecenter": "M365 Compliance", "compliance": "M365 Compliance",
    "threatintelligence": "M365 Defender", "microsoftdefenderforidentity": "M365 Defender", "powerbi": "M365 Power BI",
    "microsoftflow": "M365 Power Automate", "powerapps": "M365 Power Apps", "dynamics365": "M365 Dynamics",
}
_PRIVILEGED_ROLES = ("global administrator", "company administrator", "privileged role administrator", "exchange administrator",
                     "security administrator", "conditional access administrator", "application administrator",
                     "cloud application administrator", "authentication administrator", "privileged authentication administrator",
                     "user administrator", "helpdesk administrator", "sharepoint administrator", "global reader")


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
def detect_format(name: str, head: bytes) -> str | None:
    """Return one of FORMATS for a UAL / Entra export, else None."""
    n = (name or "").lower()
    if not n.endswith((".csv", ".json", ".jsonl", ".ndjson", ".txt", ".log")) and not head[:1] in (b"[", b"{"):
        return None
    text = head.lstrip(b"\xef\xbb\xbf").decode("utf-8", "replace").lstrip()
    low = text.lower()
    if text.startswith(("[", "{")):
        if '"auditdata"' in low or ('"operation"' in low and ('"workload"' in low or '"creationtime"' in low)):
            return "m365-ual-json"
        if '"userprincipalname"' in low or '"appdisplayname"' in low or '"conditionalaccessstatus"' in low or '"clientappused"' in low:
            return "entra-signin-json"
        return None
    header = low.split("\n", 1)[0]
    if "auditdata" in header:
        return "m365-ual-csv"
    if ("userprincipalname" in header and ("createddatetime" in header or "ipaddress" in header)) or \
       ("sign-in identifier" in header) or ("username" in header and "ip address" in header and ("application" in header or "status" in header)):
        return "entra-signin-csv"
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_IP_RE = re.compile(r"^\[?([0-9a-fA-F:.]+?)\]?(?::\d+)?$")


def clean_ip(v: Any) -> str | None:
    s = str(v or "").strip()
    if not s or s.lower() in ("null", "none", "<null>"):
        return None
    m = _IP_RE.match(s)
    if m:
        ip = m.group(1)
        # IPv4 with port "1.2.3.4:443" is handled; bare IPv6 keeps its colons
        return ip
    return s[:100]


def parse_ts(v: Any) -> tuple[int | None, str | None]:
    """ISO-8601 (with or without zone / fractional seconds) or portal 'M/D/YYYY, h:mm:ss AM' -> (ms, iso)."""
    if v is None:
        return None, None
    if isinstance(v, (int, float)):
        ms = int(v if v > 10_000_000_000 else v * 1000)
        return ms, datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    s = str(v).strip()
    if not s:
        return None, None
    s2 = s.replace("Z", "+00:00")
    dt = None
    try:
        dt = datetime.fromisoformat(s2)
    except ValueError:
        for fmt in ("%m/%d/%Y, %I:%M:%S %p", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
    if dt is None:
        return None, None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return int(dt.timestamp() * 1000), dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _scalar(v: Any) -> Any:
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, list):
        if all(x is None or isinstance(x, (str, int, float, bool)) for x in v):
            return ", ".join("" if x is None else str(x) for x in v)
        return json.dumps(v, ensure_ascii=False)[:4000]
    if isinstance(v, dict):
        return json.dumps(v, ensure_ascii=False)[:4000]
    return str(v)


def _named_list(items: Any, name_key: str = "Name", value_key: str = "Value") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not isinstance(items, list):
        return out
    for it in items:
        if isinstance(it, dict) and it.get(name_key) is not None:
            out[str(it[name_key])] = _scalar(it.get(value_key))
    return out


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
                data[k] = "; ".join(ids)[:2000]
                data[k + ".Type"] = ", ".join(str(it.get("Type")) for it in v if isinstance(it, dict))[:200]
        elif k == "Folders" and isinstance(v, list):
            data["Folders"] = "; ".join(str(f.get("Path")) for f in v if isinstance(f, dict) and f.get("Path"))[:2000]
            data["FolderItemCount"] = sum(len(f.get("FolderItems") or []) for f in v if isinstance(f, dict))
        elif isinstance(v, dict):
            for k2, v2 in v.items():
                data[f"{k}.{k2}"] = _scalar(v2)
        else:
            data[k] = _scalar(v)
    return data


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
    obj = str(a.get("ObjectId") or "")
    if op.lower() in ("new-inboxrule", "set-inboxrule", "remove-inboxrule", "enable-inboxrule", "disable-inboxrule") and data.get("Name"):
        obj = str(data["Name"])
    row: dict[str, Any] = {
        "ts": ts, "tsIso": iso, "eventId": None, "recordId": _int(record_type if record_type is not None else a.get("RecordType")),
        "level": 3 if str(result or "").lower() in ("failed", "false", "failure") else 4,
        "levelName": "Warning" if str(result or "").lower() in ("failed", "false", "failure") else "Information",
        "provider": UAL_PROVIDER, "channel": workload or "Unknown", "computer": None,
        "category": _WORKLOAD_CATEGORY.get(workload.lower(), f"M365 {workload}" if workload else "M365"),
        "description": op, "operation": op, "objectName": obj[:500] or None,
        "user": user or None, "upn": user or None, "subjectUser": user or None, "targetUser": target,
        "ipAddress": ip, "status": str(result) if result not in (None, "") else None,
        "workstation": (str(_first(a, "ClientInfoString", "UserAgent") or "")[:200] or None),
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
    if lo in ("new-inboxrule", "set-inboxrule"):
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
    "date (utc)": "createdDateTime", "date": "createdDateTime", "username": "userPrincipalName", "user": "userDisplayName",
    "user id": "userId", "ip address": "ipAddress", "location": "location", "application": "appDisplayName",
    "application id": "appId", "resource": "resourceDisplayName", "client app": "clientAppUsed", "browser": "browser",
    "operating system": "operatingSystem", "status": "status", "failure reason": "failureReason", "sign-in error code": "errorCode",
    "conditional access": "conditionalAccessStatus", "risk state": "riskState", "risk level (aggregate)": "riskLevelAggregated",
    "risk level (sign-in)": "riskLevelDuringSignIn", "risk level - aggregate": "riskLevelAggregated", "risk level - sign-in": "riskLevelDuringSignIn",
    "risk detail": "riskDetail", "multifactor authentication result": "mfaResult", "authentication requirement": "authenticationRequirement",
    "user agent": "userAgent", "request id": "requestId", "correlation id": "correlationId", "interactive": "isInteractive",
    "compliant": "isCompliant", "managed": "isManaged", "device id": "deviceId", "user type": "userType",
    "country or region": "country", "country": "country", "city": "city", "state": "state",
}


def entra_row(o: dict[str, Any]) -> dict[str, Any]:
    g = dict(o)
    # portal CSV headers -> Graph names
    for k in list(g.keys()):
        mapped = _PORTAL_MAP.get(k.strip().lower())
        if mapped and mapped not in g:
            g[mapped] = g.pop(k)
    status = g.get("status")
    if isinstance(status, dict):
        err = status.get("errorCode")
        failure = status.get("failureReason") or status.get("additionalDetails")
    else:
        err = g.get("errorCode")
        failure = g.get("failureReason")
        if isinstance(status, str) and status.lower() in ("failure", "failed") and err in (None, ""):
            err = -1
    if isinstance(err, str) and err.strip().isdigit():
        err = int(err)
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
    ts, iso = parse_ts(g.get("createdDateTime"))
    ip = clean_ip(g.get("ipAddress"))
    success = err in (0, None, "0")
    risk_signin = g.get("riskLevelDuringSignIn")
    risk_agg = g.get("riskLevelAggregated")
    data: dict[str, Any] = {
        "appDisplayName": g.get("appDisplayName"), "appId": g.get("appId"), "resourceDisplayName": g.get("resourceDisplayName"),
        "clientAppUsed": g.get("clientAppUsed"), "conditionalAccessStatus": g.get("conditionalAccessStatus"),
        "riskLevelDuringSignIn": risk_signin, "riskLevelAggregated": risk_agg, "riskState": g.get("riskState"), "riskDetail": g.get("riskDetail"),
        "riskEventTypes": _scalar(g.get("riskEventTypes_v2") or g.get("riskEventTypes")),
        "country": country, "city": city, "state": state,
        "browser": dev.get("browser") or g.get("browser"), "operatingSystem": dev.get("operatingSystem") or g.get("operatingSystem"),
        "deviceId": dev.get("deviceId") or g.get("deviceId"), "isCompliant": dev.get("isCompliant", g.get("isCompliant")), "isManaged": dev.get("isManaged", g.get("isManaged")),
        "errorCode": err, "failureReason": failure, "authenticationRequirement": g.get("authenticationRequirement"),
        "isInteractive": g.get("isInteractive"), "userAgent": g.get("userAgent"), "correlationId": g.get("correlationId"),
        "userType": g.get("userType"), "userDisplayName": g.get("userDisplayName"), "mfaResult": g.get("mfaResult"),
        "tokenIssuerType": g.get("tokenIssuerType"), "signInEventTypes": _scalar(g.get("signInEventTypes")),
    }
    data = {k: _scalar(v) for k, v in data.items() if v not in (None, "")}
    risk_txt = ""
    if (risk_signin and str(risk_signin).lower() not in ("none", "hidden")) or (g.get("riskState") and str(g.get("riskState")).lower() not in ("none",)):
        risk_txt = f" risk={risk_signin or risk_agg or ''}/{g.get('riskState') or ''}"
    summary = (f"Sign-in {'ok' if success else 'FAILED (' + str(err) + ')'}: {user or '?'} from {ip or '?'}"
               f"{' (' + str(country) + ')' if country else ''} via {g.get('clientAppUsed') or '?'} to {g.get('appDisplayName') or '?'}{risk_txt}")
    return {
        "ts": ts, "tsIso": iso, "eventId": None, "recordId": None,
        "level": 4 if success else 3, "levelName": "Information" if success else "Warning",
        "provider": ENTRA_PROVIDER, "channel": "Entra SignIn", "computer": None, "category": "Entra sign-in",
        "description": "Sign-in" if success else "Sign-in failure", "operation": "SignIn",
        "user": user or None, "upn": user or None, "subjectUser": user or None, "targetUser": user or None,
        "ipAddress": ip, "status": str(err) if err is not None else "0", "statusText": failure, "failureReason": failure,
        "workstation": (str(g.get("userAgent") or "")[:200] or None), "objectName": g.get("appDisplayName"),
        "data": data, "summary": summary[:500],
    }


# ---------------------------------------------------------------------------
# Iteration
# ---------------------------------------------------------------------------
def _open_text(path: str | None, data: bytes | None) -> io.TextIOBase:
    if path:
        return open(path, "r", encoding="utf-8-sig", errors="replace", newline="")
    return io.TextIOWrapper(io.BytesIO(data or b""), encoding="utf-8-sig", errors="replace", newline="")


def _iter_json_objects(fh: io.TextIOBase) -> Iterator[Any]:
    """A JSON array, a single object, or NDJSON."""
    head = fh.read(1)
    fh.seek(0)
    if head == "[":
        try:
            arr = json.load(fh)
        except ValueError as exc:
            raise ValueError(f"invalid JSON array: {str(exc)[:120]}") from None
        yield from (x for x in arr if isinstance(x, dict))
        return
    for line in fh:
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            if "value" in obj and isinstance(obj["value"], list):  # Graph page {"value": [...]}
                yield from (x for x in obj["value"] if isinstance(x, dict))
            else:
                yield obj


def _audit_from_row(obj: dict[str, Any]) -> tuple[dict[str, Any] | None, Any]:
    """Accept a bare AuditData object or an export row carrying AuditData as a JSON string/object."""
    ad = obj.get("AuditData")
    if ad is None:
        ad = obj.get("auditdata") or obj.get("Auditdata")
    if isinstance(ad, str):
        try:
            ad = json.loads(ad)
        except ValueError:
            return None, None
    if isinstance(ad, dict):
        if "CreationTime" not in ad and (obj.get("CreationDate") or obj.get("CreationTime")):
            ad = {**ad, "CreationTime": obj.get("CreationDate") or obj.get("CreationTime")}
        return ad, obj.get("RecordType") or ad.get("RecordType")
    if "Operation" in obj or "Workload" in obj:
        return obj, obj.get("RecordType")
    return None, None


def iter_records(path: str | None, data: bytes | None, fmt: str, stats: Any = None, include_raw: bool = True) -> Iterator[dict[str, Any]]:
    """Yield event rows from a UAL / Entra export in the given format (see FORMATS)."""
    fh = _open_text(path, data)
    try:
        if fmt == "m365-ual-csv":
            reader = csv.DictReader(fh)
            for rec in reader:
                ad, rtype = _audit_from_row({k: v for k, v in rec.items() if k is not None})
                if ad is None:
                    if stats is not None:
                        stats.errors += 1
                    continue
                yield _finish(ual_row(ad, rtype), ad, stats, include_raw)
        elif fmt == "m365-ual-json":
            for obj in _iter_json_objects(fh):
                ad, rtype = _audit_from_row(obj)
                if ad is None:
                    if stats is not None:
                        stats.errors += 1
                    continue
                yield _finish(ual_row(ad, rtype), ad, stats, include_raw)
        elif fmt == "entra-signin-json":
            for obj in _iter_json_objects(fh):
                yield _finish(entra_row(obj), obj, stats, include_raw)
        elif fmt == "entra-signin-csv":
            reader = csv.DictReader(fh)
            for rec in reader:
                obj = {k: v for k, v in rec.items() if k is not None}
                yield _finish(entra_row(obj), obj, stats, include_raw)
        else:
            raise ValueError(f"unknown M365 format {fmt}")
    finally:
        fh.close()


def _finish(row: dict[str, Any], source: dict[str, Any], stats: Any, include_raw: bool) -> dict[str, Any]:
    if include_raw:
        row["raw"] = json.dumps(source, ensure_ascii=False, separators=(",", ":"))[:200_000]
    if stats is not None:
        try:
            stats.add(row)
        except Exception:  # noqa: BLE001
            stats.count += 1
    return row


def is_privileged_role(name: str | None) -> bool:
    return bool(name) and str(name).strip().lower() in _PRIVILEGED_ROLES
