"""
EVTX parsing with pyevtx-rs: yields flattened, typed rows ready for IndexedDB.

Row shape (all keys optional except recordId/eventId/ts):
  recordId, ts (epoch ms UTC), tsIso, eventId, version, level, levelName, task, opcode,
  keywords, provider, providerGuid, channel, computer, userSid, processId, threadId,
  activityId, + mapped EventData/UserData fields (targetUser, ipAddress, logonType...),
  data (flattened EventData dict), summary, category, raw (compact JSON, optional).
"""

from __future__ import annotations

import bisect
import json
import logging
import os
import re
import struct
import zlib
from collections import Counter, OrderedDict
from collections.abc import Iterator
from typing import Any

from services.common import normalize_ip, parse_timestamp
from services.reference import eventids

log = logging.getLogger(__name__)

LEVELS = {0: "LogAlways", 1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}

# EventData / UserData field name -> row key
FIELD_MAP: dict[str, str] = {
    "TargetUserName": "targetUser",
    "TargetDomainName": "targetDomain",
    "TargetUserSid": "targetSid",
    "TargetSid": "targetSid",
    "TargetLogonId": "targetLogonId",
    "TargetServerName": "targetServer",
    "TargetInfo": "targetInfo",
    "TargetLinkedLogonId": "targetLinkedLogonId",
    "TargetOutboundUserName": "targetOutboundUser",
    "TargetOutboundDomainName": "targetOutboundDomain",
    "SubjectUserName": "subjectUser",
    "SubjectDomainName": "subjectDomain",
    "SubjectUserSid": "subjectSid",
    "SubjectLogonId": "subjectLogonId",
    "LogonType": "logonType",
    "LogonProcessName": "logonProcess",
    "AuthenticationPackageName": "authPackage",
    "LmPackageName": "lmPackage",
    "ElevatedToken": "elevatedToken",
    "ImpersonationLevel": "impersonationLevel",
    "KeyLength": "keyLength",
    "RestrictedAdminMode": "restrictedAdminMode",
    "VirtualAccount": "virtualAccount",
    "IpAddress": "ipAddress",
    "IpPort": "ipPort",
    "WorkstationName": "workstation",
    "ClientAddress": "ipAddress",
    "ClientName": "workstation",
    "Workstation": "workstation",
    "Address": "ipAddress",
    "SourceNetworkAddress": "ipAddress",
    "SourceAddress": "sourceIp",
    "SourcePort": "sourcePort",
    "DestAddress": "destinationIp",
    "DestPort": "destinationPort",
    "Status": "status",
    "SubStatus": "subStatus",
    "FailureReason": "failureReason",
    "FailureCode": "status",
    "ProcessName": "processName",
    "NewProcessName": "processName",
    "NewProcessId": "newProcessId",
    "ProcessId": "callerProcessId",
    "CommandLine": "commandLine",
    "ParentProcessName": "parentProcessName",
    "ParentProcessId": "parentProcessId",
    "TokenElevationType": "tokenElevationType",
    "MandatoryLabel": "mandatoryLabel",
    "ServiceName": "serviceName",
    "ServiceFileName": "serviceFile",
    "ImagePath": "serviceFile",
    "ServiceType": "serviceType",
    "StartType": "serviceStartType",
    "AccountName": "serviceAccount",
    "ServiceAccount": "serviceAccount",
    "TaskName": "taskName",
    "TaskContent": "taskContent",
    "TaskContentNew": "taskContent",
    "MemberName": "memberName",
    "MemberSid": "memberSid",
    "PrivilegeList": "privilegeList",
    "ShareName": "shareName",
    "ShareLocalPath": "shareLocalPath",
    "RelativeTargetName": "relativeTargetName",
    "ObjectName": "objectName",
    "ObjectType": "objectType",
    "ObjectServer": "objectServer",
    "AccessMask": "accessMask",
    "AccessList": "accessList",
    "ObjectValueName": "objectValueName",
    "NewValue": "newValue",
    "OldValue": "oldValue",
    "ObjectDN": "objectDn",
    "ObjectClass": "objectClass",
    "AttributeLDAPDisplayName": "attributeName",
    "AttributeValue": "attributeValue",
    "OperationType": "operationType",
    "TicketEncryptionType": "ticketEncryption",
    "TicketOptions": "ticketOptions",
    "PreAuthType": "preAuthType",
    "TransmittedServices": "transmittedServices",
    "ServiceSid": "serviceSid",
    "ScriptBlockText": "scriptBlockText",
    "ScriptBlockId": "scriptBlockId",
    "MessageNumber": "messageNumber",
    "MessageTotal": "messageTotal",
    "Payload": "payload",
    "ContextInfo": "contextInfo",
    "DeviceDescription": "deviceDescription",
    "DeviceId": "deviceId",
    "ClassName": "className",
    "ClassId": "classId",
    "VendorIds": "vendorIds",
    "CompatibleIds": "compatibleIds",
    "LocationInformation": "locationInformation",
    "PreviousTime": "previousTime",
    "NewTime": "newTime",
    "SubcategoryGuid": "subcategoryGuid",
    "SubcategoryId": "subcategoryId",
    "AuditPolicyChanges": "auditPolicyChanges",
    "CategoryId": "categoryId",
    "Channel": "channelCleared",
    "BackupPath": "backupPath",
    "SamAccountName": "samAccountName",
    "DisplayName": "displayName",
    "UserPrincipalName": "upn",
    "HomeDirectory": "homeDirectory",
    "ScriptPath": "scriptPath",
    "UserAccountControl": "userAccountControl",
    "AllowedToDelegateTo": "allowedToDelegateTo",
    "SidHistory": "sidHistory",
    "PasswordLastSet": "passwordLastSet",
    "AccountExpires": "accountExpires",
    "PrimaryGroupId": "primaryGroupId",
    "OldTargetUserName": "oldTargetUser",
    "NewTargetUserName": "newTargetUser",
    "SessionID": "sessionId",
    "SessionName": "sessionName",
    "User": "user",
    "Reason": "reason",
    "Param1": "param1",
    "Param2": "param2",
    "Param3": "param3",
    "Param4": "param4",
    "param1": "param1",
    "param2": "param2",
    "param3": "param3",
    "param4": "param4",
    # Sysmon
    "Image": "image",
    "ParentImage": "parentImage",
    "ParentCommandLine": "parentCommandLine",
    "OriginalFileName": "originalFileName",
    "Hashes": "hashes",
    "CurrentDirectory": "currentDirectory",
    "IntegrityLevel": "integrityLevel",
    "LogonGuid": "logonGuid",
    "TerminalSessionId": "terminalSessionId",
    "ProcessGuid": "processGuid",
    "ParentProcessGuid": "parentProcessGuid",
    "DestinationIp": "destinationIp",
    "DestinationPort": "destinationPort",
    "DestinationHostname": "destinationHostname",
    "SourceIp": "sourceIp",
    "SourceHostname": "sourceHostname",
    "Protocol": "protocol",
    "Initiated": "initiated",
    "QueryName": "query",
    "QueryResults": "queryResults",
    "QueryStatus": "queryStatus",
    "TargetFilename": "targetFilename",
    "TargetObject": "targetObject",
    "Details": "details",
    "EventType": "eventType",
    "ImageLoaded": "imageLoaded",
    "Signed": "signed",
    "Signature": "signature",
    "SignatureStatus": "signatureStatus",
    "SourceImage": "sourceImage",
    "TargetImage": "targetImage",
    "GrantedAccess": "grantedAccess",
    "CallTrace": "callTrace",
    "SourceProcessId": "sourceProcessId",
    "TargetProcessId": "targetProcessId",
    "StartAddress": "startAddress",
    "StartModule": "startModule",
    "StartFunction": "startFunction",
    "PipeName": "pipeName",
    "Device": "device",
    "UtcTime": "utcTime",
    "CreationUtcTime": "creationUtcTime",
    "PreviousCreationUtcTime": "previousCreationUtcTime",
    "Company": "company",
    # "Description" (the PE file description in Sysmon 1/6/7, the error text in Sysmon 255) is
    # deliberately not a column: "description" holds REMN's name for the event type, which
    # overwrote it, so no rule on the real value could match. It stays whole in data.Description,
    # which is where the Sigma converter sends the field.
    "Product": "product",
    "FileVersion": "fileVersion",
    "Consumer": "wmiConsumer",
    "Filter": "wmiFilter",
    "Query": "wmiQuery",
    "Name": "name",
    # Sysmon 25 "Image is replaced" / "Image is locked for access". Not "type": the ingest stream
    # marks every row with type=event, which overwrote it, so no rule on it could ever match.
    "Type": "typeName",
    "Contents": "contents",
    "Archived": "archived",
    "IsExecutable": "isExecutable",
    # Defender
    "Threat Name": "threatName",
    "Threat ID": "threatId",
    "Severity Name": "severityName",
    "Category Name": "categoryName",
    "Process Name": "processName",
    "Detection User": "subjectUser",
    "Action Name": "actionName",
    "Origin Name": "originName",
    "Source Name": "sourceName",
    "Detection Source": "detectionSource",
    "Old Value": "oldValue",
    "New Value": "newValue",
    "Detection ID": "detectionId",
    "Path": "path",
    # RDP / WinRM / others
    "ClientIP": "ipAddress",
    "Client IP": "ipAddress",
    "ClientIPAddress": "ipAddress",
    "IPString": "ipAddress",
    "Username": "targetUser",
    "UserName": "targetUser",
    "Domain": "targetDomain",
    "DomainName": "targetDomain",
    "SourceName": "sourceName",
    "Destination": "destination",
    "url": "url",
    "Url": "url",
    "URL": "url",
    "ConnectionName": "connectionName",
    "ConnectionType": "connectionType",
    "TargetIPAddress": "destinationIp",
    "TargetPort": "destinationPort",
    "RuleId": "ruleId",
    "RuleName": "ruleName",
    "ApplicationPath": "applicationPath",
    "ModifyingApplication": "modifyingApplication",
    "ModifyingUser": "subjectUser",
    "Direction": "direction",
    "Action": "action",
    "Profiles": "profiles",
    "LocalPorts": "localPorts",
    "RemotePorts": "remotePorts",
    "RemoteAddresses": "remoteAddresses",
    "LocalAddresses": "localAddresses",
    "FilePath": "path",
    "FileHash": "hashes",
    "Fqbn": "fqbn",
    "PolicyName": "policyName",
    "TargetUser": "targetUser",
    "TargetProcessName": "processName",
    "ClientProcessId": "callerProcessId",
    "Operation": "operation",
    "ResultCode": "status",
    "Application": "application",
    "Layer": "layer",
    "FilterRTID": "filterId",
    "LayerRTID": "layerId",
    "RemoteMachineID": "remoteMachineId",
    "RemoteUserID": "remoteUserId",
    "Data": "dataList",
}
_GROUP_EVENTS = {4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4764}
_INT_FIELDS = {"logonType", "ipPort", "sourcePort", "destinationPort", "messageNumber", "messageTotal", "sessionId", "keyLength"}


def _scalar(value: Any) -> Any:
    """Collapse pyevtx-rs JSON structures ({'#text':..., '#attributes':...}) into scalars."""
    if isinstance(value, dict):
        if "#text" in value:
            return _scalar(value["#text"])
        attrs = value.get("#attributes")
        rest = {k: v for k, v in value.items() if k != "#attributes"}
        if not rest and attrs:
            return {k: _scalar(v) for k, v in attrs.items()}
        return {k: _scalar(v) for k, v in rest.items()}
    if isinstance(value, list):
        return [_scalar(v) for v in value]
    return value


# The text rules search whole: a command line (Windows allows 32,767 characters), a script
# block, a task definition, a WMI consumer. Cut at 4,000 characters, an indicator placed after
# the cut escaped every rule, and padding a command is trivial. Other columns keep the short cut;
# every value stays whole in data.
_LONG_FIELDS = frozenset(
    {"commandLine", "parentCommandLine", "scriptBlockText", "taskContent", "payload", "contextInfo", "details", "wmiConsumer", "destination"}
)
LONG_LIMIT = 65_536


def _str(value: Any, limit: int = 4000) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        s = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    else:
        s = str(value)
    s = s.strip()
    if not s or s == "-":
        return None
    return s if len(s) <= limit else s[:limit] + "…"


# The rights an object-access event lists (4656, 4663, 5145 ...) arrive as message codes.
# Windows renders them as names in the event viewer, and rules are written against the names
# ("AccessList contains WriteData"), so the names are appended to the codes: both spellings match.
_ACCESS_NAMES = {
    "1537": "DELETE",
    "1538": "READ_CONTROL",
    "1539": "WRITE_DAC",
    "1540": "WRITE_OWNER",
    "1541": "SYNCHRONIZE",
    "1542": "ACCESS_SYS_SEC",
    "4416": "ReadData (or ListDirectory)",
    "4417": "WriteData (or AddFile)",
    "4418": "AppendData (or AddSubdirectory or CreatePipeInstance)",
    "4419": "ReadEA",
    "4420": "WriteEA",
    "4421": "Execute/Traverse",
    "4422": "DeleteChild",
    "4423": "ReadAttributes",
    "4424": "WriteAttributes",
    "4432": "Query key value",
    "4433": "Set key value",
    "4434": "Create sub-key",
    "4435": "Enumerate sub-keys",
    "4436": "Notify about changes to keys",
    "4437": "Create Link",
}
_ACCESS_CODE_RE = re.compile(r"%%(\d+)")


def render_access_list(value: str | None) -> str | None:
    """'%%4416 %%4417' -> the codes, then a line with their names."""
    if not value or "%%" not in value:
        return value
    names = [_ACCESS_NAMES[c] for c in _ACCESS_CODE_RE.findall(value) if c in _ACCESS_NAMES]
    return f"{value}\n{' '.join(names)}" if names else value


def _int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        s = str(value).strip()
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s)
    except (TypeError, ValueError):
        return None


def flatten(event: dict[str, Any], record: dict[str, Any] | None = None, include_raw: bool = True) -> dict[str, Any]:
    ev = event.get("Event", event)
    system = ev.get("System", {}) or {}
    provider = _scalar(system.get("Provider")) or {}
    if isinstance(provider, dict):
        provider_name = provider.get("Name") or provider.get("EventSourceName")
        provider_guid = provider.get("Guid")
    else:
        provider_name, provider_guid = _str(provider), None
    event_id_raw = system.get("EventID")
    event_id = _int(_scalar(event_id_raw))
    qualifiers = None
    if isinstance(event_id_raw, dict):
        qualifiers = _int((event_id_raw.get("#attributes") or {}).get("Qualifiers"))
    time_created = _scalar(system.get("TimeCreated")) or {}
    system_time = time_created.get("SystemTime") if isinstance(time_created, dict) else time_created
    ts, ts_iso = parse_timestamp(system_time)
    if ts is None and record is not None:
        ts, ts_iso = parse_timestamp(header_time(record))
    execution = _scalar(system.get("Execution")) or {}
    security = _scalar(system.get("Security")) or {}
    correlation = _scalar(system.get("Correlation")) or {}
    level = _int(_scalar(system.get("Level")))

    row: dict[str, Any] = {
        "recordId": _int(_scalar(system.get("EventRecordID"))) or (record or {}).get("event_record_id"),
        "ts": ts,
        "tsIso": ts_iso,
        "eventId": event_id,
        "qualifiers": qualifiers,
        "version": _int(_scalar(system.get("Version"))),
        "level": level,
        "levelName": LEVELS.get(level, str(level) if level is not None else None),
        "task": _int(_scalar(system.get("Task"))),
        "opcode": _int(_scalar(system.get("Opcode"))),
        "keywords": _str(_scalar(system.get("Keywords"))),
        "provider": _str(provider_name, 200),
        "providerGuid": _str(provider_guid, 64),
        "channel": _str(_scalar(system.get("Channel")), 200),
        "computer": _str(_scalar(system.get("Computer")), 200),
        "userSid": _str(security.get("UserID") if isinstance(security, dict) else security, 100),
        "processId": _int(execution.get("ProcessID")) if isinstance(execution, dict) else None,
        "threadId": _int(execution.get("ThreadID")) if isinstance(execution, dict) else None,
        "activityId": _str(correlation.get("ActivityID") if isinstance(correlation, dict) else None, 64),
    }

    data: dict[str, Any] = {}
    for section in ("EventData", "UserData"):
        payload = ev.get(section)
        if payload is None:
            continue
        payload = _scalar(payload)
        if isinstance(payload, dict):
            # UserData wraps content in one named element (EventXML, LogFileCleared, ...)
            if section == "UserData" and len(payload) == 1 and isinstance(next(iter(payload.values())), dict):
                inner_name, inner = next(iter(payload.items()))
                data["_userDataType"] = inner_name
                payload = inner
            for k, v in payload.items():
                if k == "#attributes":
                    if isinstance(v, dict):
                        data.update({f"@{ak}": _scalar(av) for ak, av in v.items()})
                    continue
                data[k] = v
        elif isinstance(payload, list):
            data["Data"] = payload
        elif payload is not None:
            data["Data"] = payload

    for k, v in data.items():
        key = FIELD_MAP.get(k)
        if key is None:
            continue
        if key in ("ipAddress", "sourceIp", "destinationIp"):
            row[key] = normalize_ip(v) or (_str(v, 100) if v not in (None, "-", "::", "0.0.0.0") else None)
            continue
        if key in _INT_FIELDS:
            row[key] = _int(v)
            continue
        if key == "dataList":
            if isinstance(v, list):
                row["message"] = _str("\n".join(str(_scalar(x)) for x in v if x is not None), 4000)
            else:
                row["message"] = _str(v, 4000)
            continue
        if key in row and row[key] not in (None, ""):
            continue  # first mapping wins
        row[key] = _str(v, LONG_LIMIT if key in _LONG_FIELDS else 4000)

    # Event-specific fix-ups
    if row.get("accessList"):
        row["accessList"] = render_access_list(row["accessList"])
    if event_id in _GROUP_EVENTS and row.get("targetUser"):
        row["groupName"] = row["targetUser"]
        row["groupDomain"] = row.get("targetDomain")
    if event_id == 1149 and data.get("Param1"):
        row["targetUser"] = _str(data.get("Param1"))
        row["targetDomain"] = _str(data.get("Param2"))
        row["ipAddress"] = normalize_ip(data.get("Param3")) or _str(data.get("Param3"), 100)
    if event_id in (7036, 7040, 7035, 7000, 7031, 7034, 7023, 7024) and data.get("param1"):
        row["serviceName"] = _str(data.get("param1"))
        row["serviceState"] = _str(data.get("param2"))
    if event_id in (21, 22, 23, 24, 25, 39, 40) and data.get("User") and not row.get("targetUser"):
        row["targetUser"] = _str(data.get("User"))
    if row.get("user") and not row.get("subjectUser") and "sysmon" in (row.get("provider") or "").lower():
        u = row["user"]
        if "\\" in u:
            row["subjectDomain"], row["subjectUser"] = u.split("\\", 1)
        else:
            row["subjectUser"] = u
    if row.get("logonType") is None and data.get("LogonType") is not None:
        row["logonType"] = _int(data.get("LogonType"))

    desc = eventids.describe(row["provider"], event_id)
    row["category"] = desc[1] if desc else None
    row["description"] = desc[0] if desc else None
    if row.get("logonType") is not None:
        row["logonTypeName"] = eventids.logon_type_name(row["logonType"])
    if row.get("subStatus") or row.get("status"):
        reason = eventids.status_text(row.get("subStatus")) or eventids.status_text(row.get("status"))
        if reason:
            row["statusText"] = reason
        elif event_id in (4768, 4769, 4771, 4772, 4773):
            k = eventids.kerberos_failure_text(row.get("status"))
            if k:
                row["statusText"] = k
    row["summary"] = eventids.summarize(row)
    row["data"] = {k: _scalar(v) for k, v in data.items()}
    if include_raw:
        row["raw"] = json.dumps(ev, ensure_ascii=False, separators=(",", ":"))
    return row


def header_time(record: dict[str, Any] | None) -> str | None:
    """The record header's write time as pyevtx-rs gives it ('2019-04-27T15:57:27.0876132Z UTC'),
    without the trailing ' UTC' that parse_timestamp does not read. None for the zero FILETIME
    (1601-01-01), which filtered exports write in place of a time."""
    value = (record or {}).get("timestamp")
    if isinstance(value, str) and value.endswith(" UTC"):
        value = value[:-4]
    if isinstance(value, str) and value.startswith("1601-01-01T00:00:00"):
        return None
    return value


EVTX_CHUNK = 65536


def chunk_checksums(src: Any) -> dict[str, Any] | None:
    """
    The CRC32 checks the EVTX format defines: the file header over its first 120 bytes, each
    chunk header over bytes 0-120 and 128-512, and each chunk's records from byte 512 to its
    free-space offset. A chunk that fails was changed after Windows wrote it, or damaged; the
    parser reads its records all the same, so this is where that is said. None when src is not
    an EVTX file that can be read a second time. A stream is left where it was.
    """
    if isinstance(src, (str, os.PathLike)):
        fh, start = open(src, "rb"), None  # noqa: SIM115 - closed in finally
    elif hasattr(src, "seek") and hasattr(src, "read"):
        fh, start = src, src.tell()
        src.seek(0)
    else:
        return None
    try:
        head = fh.read(4096)
        if len(head) < 128 or head[:8] != b"ElfFile\x00":
            return None
        out: dict[str, Any] = {
            "chunks": 0,
            "fileHeader": zlib.crc32(head[:120]) == struct.unpack_from("<I", head, 124)[0],
            # written while Windows still had the log open (a live copy): not a fault
            "dirty": bool(struct.unpack_from("<I", head, 120)[0] & 1),
        }
        bad_header: list[int] = []
        bad_data: list[int] = []
        index = 0
        while True:
            chunk = fh.read(EVTX_CHUNK)
            if len(chunk) < EVTX_CHUNK:
                break
            if chunk[:8] == b"ElfChnk\x00":
                out["chunks"] += 1
                if zlib.crc32(chunk[:120] + chunk[128:512]) != struct.unpack_from("<I", chunk, 124)[0]:
                    bad_header.append(index)
                free = struct.unpack_from("<I", chunk, 48)[0]
                if not 512 <= free <= EVTX_CHUNK or zlib.crc32(chunk[512:free]) != struct.unpack_from("<I", chunk, 52)[0]:
                    bad_data.append(index)
            index += 1
        if bad_header:
            out["badHeader"] = bad_header[:50]
            out["badHeaderCount"] = len(bad_header)
        if bad_data:
            out["badData"] = bad_data[:50]
            out["badDataCount"] = len(bad_data)
        return out
    except OSError:
        return None
    finally:
        if start is None:
            fh.close()
        else:
            fh.seek(start)


class FileSequence:
    """
    One EVTX file's records in the order the file numbers them: the record header's id and write
    time, which the file assigns itself, rather than the EventRecordID and TimeCreated inside the
    event, which a forwarded log copies from the machine that wrote them. A hole in the ids is
    records that are no longer in the file (deleted, or in a chunk that could not be read). A write
    time earlier than the record before it is a clock set back, events buffered while Windows
    started and written once the log service ran, or a record put in later: each step keeps both
    times, for the case's clock changes and log service starts to tell them apart.
    """

    # covered id ranges followed before a file is too fragmented to follow
    MAX_SPANS = 100_000
    # holes and backward steps listed in the stats; the counts stay exact
    LISTED = 50
    # computer names listed (a machine renamed during setup logs under both)
    NAMES = 20
    # clock changes and event log service starts listed
    MARKS = 500
    # EvtxECmd's default: a step back of more than a second
    BACKWARD_MS = 1000

    def __init__(self, name: str) -> None:
        self.name = name
        self.count = 0
        # sorted, disjoint [first, last] ranges of the ids read
        self.spans: list[list[int]] = []
        self.overflow = False
        self.channels: Counter[str] = Counter()
        self.computers: Counter[str] = Counter()
        self.first_ts: int | None = None
        self.last_ts: int | None = None
        self.prev_id: int | None = None
        self.prev_written: int | None = None
        self.backwards = 0
        self.backwards_max = 0
        # [record id, write time of the record before, its own write time]
        self.steps: list[list[int]] = []
        # what explains a step: the clock set (Kernel-General 1, Security 4616) and the event log
        # service started (System 6005), when records buffered meanwhile are written
        self.clock_changes: list[dict[str, Any]] = []
        self.log_starts: list[dict[str, Any]] = []
        self.checksums: dict[str, Any] | None = None

    def add(self, record_id: Any, written: int | None, row: dict[str, Any] | None = None) -> None:
        self.count += 1
        if row is not None:
            if row.get("channel"):
                self.channels[row["channel"]] += 1
            if row.get("computer"):
                self.computers[row["computer"]] += 1
            ts = row.get("ts")
            if ts is not None:
                self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
                self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
            if row.get("eventId") in (1, 4616, 6005):
                self._mark(row)
        if not isinstance(record_id, int) or isinstance(record_id, bool) or record_id < 1:
            return
        if self.prev_id is not None and record_id == self.prev_id + 1 and written is not None and self.prev_written is not None:
            step = self.prev_written - written
            if step > self.BACKWARD_MS:
                self.backwards += 1
                self.backwards_max = max(self.backwards_max, step)
                if len(self.steps) < self.LISTED:
                    self.steps.append([record_id, self.prev_written, written])
        self.prev_id, self.prev_written = record_id, written
        self._cover(record_id)

    def _mark(self, row: dict[str, Any]) -> None:
        eid, provider = row.get("eventId"), row.get("provider")
        if eid == 6005 and provider == "EventLog":
            if row.get("ts") is not None and len(self.log_starts) < self.MARKS:
                self.log_starts.append({"computer": row.get("computer"), "ts": row["ts"]})
            return
        if eid == 1 and provider == "Microsoft-Windows-Kernel-General":
            data = row.get("data") or {}
            old, new = data.get("OldTime"), data.get("NewTime")
        elif eid == 4616 and provider == "Microsoft-Windows-Security-Auditing":
            old, new = row.get("previousTime"), row.get("newTime")
        else:
            return
        old_ms, new_ms = parse_timestamp(old)[0], parse_timestamp(new)[0]
        # the time service corrects the clock by fractions of a second all day
        if old_ms is None or new_ms is None or abs(new_ms - old_ms) <= self.BACKWARD_MS:
            return
        if len(self.clock_changes) < self.MARKS:
            self.clock_changes.append({"computer": row.get("computer"), "old": old_ms, "new": new_ms})

    def _cover(self, rid: int) -> None:
        spans = self.spans
        if spans and spans[-1][1] + 1 == rid:
            spans[-1][1] = rid
            return
        if self.overflow:
            return
        # the first span that starts after rid
        i = bisect.bisect_right(spans, rid, key=lambda s: s[0])
        if i and spans[i - 1][1] >= rid:
            return
        joins_prev = i > 0 and spans[i - 1][1] + 1 == rid
        joins_next = i < len(spans) and spans[i][0] - 1 == rid
        if joins_prev and joins_next:
            spans[i - 1][1] = spans[i][1]
            del spans[i]
        elif joins_prev:
            spans[i - 1][1] = rid
        elif joins_next:
            spans[i][0] = rid
        else:
            spans.insert(i, [rid, rid])
            if len(spans) > self.MAX_SPANS:
                self.overflow = True

    def holes(self) -> list[tuple[int, int]]:
        return [(a[1] + 1, b[0] - 1) for a, b in zip(self.spans, self.spans[1:], strict=False)]

    def to_dict(self) -> dict[str, Any]:
        holes = self.holes()
        out: dict[str, Any] = {"file": self.name, "count": self.count}
        if self.channels:
            out["channel"] = self.channels.most_common(1)[0][0]
            out["channels"] = len(self.channels)
        if self.computers:
            out["computer"] = self.computers.most_common(1)[0][0]
            out["computers"] = len(self.computers)
            out["computerNames"] = [c for c, _ in self.computers.most_common(self.NAMES)]
        if self.spans:
            out.update(first=self.spans[0][0], last=self.spans[-1][1])
            out["missing"] = sum(b - a + 1 for a, b in holes)
            if holes:
                out["holes"] = [list(h) for h in holes[: self.LISTED]]
                out["holeCount"] = len(holes)
        out.update(firstTs=self.first_ts, lastTs=self.last_ts)
        if self.backwards:
            out.update(backwards=self.backwards, backwardsMaxMs=self.backwards_max, steps=self.steps)
        if self.clock_changes:
            out["clockChanges"] = self.clock_changes
        if self.log_starts:
            out["logStarts"] = self.log_starts
        if self.overflow:
            # too fragmented to follow every hole: the ones listed and counted are a floor
            out["overflow"] = True
        if self.checksums is not None:
            out["checksums"] = self.checksums
        return out


class Stats:
    def __init__(self) -> None:
        self.count = 0
        self.errors = 0
        # records dropped because the same record (one key) was already read: cloud exports only
        self.duplicates = 0
        # one per EVTX file read: its record numbering and chunk checksums, for the statement of
        # what the evidence cannot show
        self.sequences: list[FileSequence] = []
        self.first_ts: int | None = None
        self.last_ts: int | None = None
        self.event_ids: Counter[int] = Counter()
        self.channels: Counter[str] = Counter()
        self.providers: Counter[str] = Counter()
        self.computers: Counter[str] = Counter()
        self.levels: Counter[str] = Counter()

    def add(self, row: dict[str, Any]) -> None:
        self.count += 1
        ts = row.get("ts")
        if ts is not None:
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts
        if row.get("eventId") is not None:
            self.event_ids[row["eventId"]] += 1
        if row.get("channel"):
            self.channels[row["channel"]] += 1
        if row.get("provider"):
            self.providers[row["provider"]] += 1
        if row.get("computer"):
            self.computers[row["computer"]] += 1
        if row.get("levelName"):
            self.levels[row["levelName"]] += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "errors": self.errors,
            "firstTs": self.first_ts,
            "lastTs": self.last_ts,
            "eventIds": dict(self.event_ids.most_common(500)),
            "channels": dict(self.channels.most_common(100)),
            "providers": dict(self.providers.most_common(200)),
            "computers": dict(self.computers.most_common(200)),
            "levels": dict(self.levels),
            **({"duplicates": self.duplicates} if self.duplicates else {}),
            **self.coverage(),
        }

    def begin_file(self, name: str) -> FileSequence:
        seq = FileSequence(name)
        self.sequences.append(seq)
        return seq

    def coverage(self) -> dict[str, Any]:
        """The EVTX files' record numbering and checksums, when any EVTX file was read."""
        return {"sequences": [s.to_dict() for s in self.sequences[:500]]} if self.sequences else {}


class Lineage:
    """Fills in what an older log leaves out about a process's parent, from the parent's own event
    in the same log: the parent's account on a Sysmon 1 written before Sysmon had ParentUser, and
    the parent's image on a 4688 written before Windows logged ParentProcessName. Rules on "a
    SYSTEM child of a service account" or "a child of WmiPrvSE" then work on those logs. What was
    filled in is named in the row's `enriched` field; the record itself (raw) is unchanged."""

    MAX = 200_000

    def __init__(self) -> None:
        self.users: OrderedDict[str, str] = OrderedDict()
        self.images: OrderedDict[tuple[str, str], tuple[str, int]] = OrderedDict()

    def _keep(self, table: OrderedDict, key: Any, value: Any) -> None:
        table[key] = value
        table.move_to_end(key)
        if len(table) > self.MAX:
            table.popitem(last=False)

    def apply(self, row: dict[str, Any]) -> None:
        eid = row.get("eventId")
        data = row.get("data") if isinstance(row.get("data"), dict) else None
        if eid == 1 and data is not None and "sysmon" in str(row.get("provider") or "").lower():
            guid = str(row.get("processGuid") or "").lower()
            if guid and data.get("User"):
                self._keep(self.users, guid, str(data["User"]))
            parent = str(row.get("parentProcessGuid") or "").lower()
            if not data.get("ParentUser") and parent in self.users:
                data["ParentUser"] = self.users[parent]
                row["enriched"] = _enriched(row, "data.ParentUser from the parent's process creation event")
        elif eid == 4688 and str(row.get("channel") or "") == "Security":
            computer = str(row.get("computer") or "").lower()
            pid = str(row.get("newProcessId") or "").lower()
            if pid and row.get("processName"):
                self._keep(self.images, (computer, pid), (str(row["processName"]), int(row.get("ts") or 0)))
            creator = str(row.get("callerProcessId") or "").lower()
            if not row.get("parentProcessName") and creator:
                hit = self.images.get((computer, creator))
                # the latest creation of that process id before this one, within a week (ids are reused)
                if hit and 0 <= int(row.get("ts") or 0) - hit[1] <= 7 * 86_400_000:
                    row["parentProcessName"] = hit[0]
                    row["enriched"] = _enriched(row, "parentProcessName from the 4688 that created the parent process id")


def _enriched(row: dict[str, Any], note: str) -> str:
    return f"{row['enriched']}; {note}" if row.get("enriched") else note


def iter_events(
    path_or_file: Any, include_raw: bool = True, stats: Stats | None = None, number_of_threads: int = 0, source_file: str | None = None
) -> Iterator[dict[str, Any]]:
    """
    Yield flattened rows from an EVTX file path (str/Path) or file-like object.
    Invalid records are counted in ``stats.errors`` and skipped. With ``stats``, the file's record
    numbering and chunk checksums are kept in ``stats.sequences`` under ``source_file``.
    """
    from evtx import PyEvtxParser

    seq = stats.begin_file(source_file or "") if stats is not None else None
    if seq is not None:
        seq.checksums = chunk_checksums(path_or_file)
    try:
        parser = PyEvtxParser(path_or_file, number_of_threads=number_of_threads, indent=False)
    except TypeError:
        parser = PyEvtxParser(path_or_file, number_of_threads)
    iterator = parser.records_json()
    lineage = Lineage()
    while True:
        try:
            rec = next(iterator)
        except StopIteration:
            break
        except RuntimeError as exc:
            if stats is not None:
                stats.errors += 1
            log.debug("bad record: %s", exc)
            continue
        if rec is None:
            continue
        if isinstance(rec, RuntimeError):
            if stats is not None:
                stats.errors += 1
            continue
        try:
            payload = rec.get("data") if isinstance(rec, dict) else None
            event = json.loads(payload) if isinstance(payload, str) else (payload or {})
            row = flatten(event, rec, include_raw=include_raw)
        except Exception as exc:  # noqa: BLE001
            if stats is not None:
                stats.errors += 1
            # the record is in the file even though its content could not be read
            if seq is not None and isinstance(rec, dict):
                seq.add(rec.get("event_record_id"), parse_timestamp(header_time(rec))[0])
            log.debug("flatten failed: %s", exc)
            continue
        if seq is not None:
            seq.add(rec.get("event_record_id"), parse_timestamp(header_time(rec))[0], row)
        lineage.apply(row)
        if stats is not None:
            stats.add(row)
        yield row
