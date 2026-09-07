"""
EVTX parsing with pyevtx-rs: yields flattened, typed rows ready for IndexedDB.

Row shape (all keys optional except recordId/eventId/ts):
  recordId, ts (epoch ms UTC), tsIso, eventId, version, level, levelName, task, opcode,
  keywords, provider, providerGuid, channel, computer, userSid, processId, threadId,
  activityId, + mapped EventData/UserData fields (targetUser, ipAddress, logonType...),
  data (flattened EventData dict), summary, category, raw (compact JSON, optional).
"""

from __future__ import annotations

import json
import logging
from collections import Counter
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
    "Description": "description",
    "Product": "product",
    "FileVersion": "fileVersion",
    "Consumer": "wmiConsumer",
    "Filter": "wmiFilter",
    "Query": "wmiQuery",
    "Name": "name",
    "Type": "type",
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
        ts, ts_iso = parse_timestamp(record.get("timestamp"))
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
        row[key] = _str(v)

    # Event-specific fix-ups
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


class Stats:
    def __init__(self) -> None:
        self.count = 0
        self.errors = 0
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
        }


def iter_events(path_or_file: Any, include_raw: bool = True, stats: Stats | None = None, number_of_threads: int = 0) -> Iterator[dict[str, Any]]:
    """
    Yield flattened rows from an EVTX file path (str/Path) or file-like object.
    Invalid records are counted in ``stats.errors`` and skipped.
    """
    from evtx import PyEvtxParser

    try:
        parser = PyEvtxParser(path_or_file, number_of_threads=number_of_threads, indent=False)
    except TypeError:
        parser = PyEvtxParser(path_or_file, number_of_threads)
    iterator = parser.records_json()
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
            log.debug("flatten failed: %s", exc)
            continue
        if stats is not None:
            stats.add(row)
        yield row
