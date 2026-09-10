"""Collection export adapters. Snapshots are observations, never synthetic Windows events."""

from __future__ import annotations

import csv
import io
import json
import os
import re
from collections.abc import Iterator
from datetime import datetime
from typing import Any

VERSION = "collection/1"
CATEGORIES = {
    "autoruns": "autorun",
    "installedprograms": "program",
    "networkconnections": "connection",
    "prefetchfiles": "prefetch",
    "processes": "process",
    "scheduledtasks": "task",
    "services": "service",
    "smbsession": "smb-session",
    "systeminformation": "system",
    "tempdirectories": "file",
    "usersandgroups": "account",
    "wdsupportlogs": "defender",
    "registry": "registry",
    "deception": "deception",
}


def key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def category(name: str) -> str | None:
    for part in name.replace("\\", "/").split("/"):
        k = key(part.rsplit(".", 1)[0])
        if k in CATEGORIES:
            return CATEGORIES[k]
    if "forensicscollectionsummary" in key(name):
        return "collection-summary"
    return None


def supported(name: str) -> bool:
    return category(name) is not None and name.lower().endswith((".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".txt", ".log", ".xml"))


def timestamp(value: Any) -> int | None:
    """Only explicit, timezone-bearing timestamps; never guess local collection time."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000) if dt.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def _xml_records(path: str, name: str) -> Iterator[dict[str, Any]]:
    """Scheduled-task and CLIXML members, streamed.

    Every other branch of records() streams; building the whole document here instead cost about
    sixteen times the file size in the web process, which is the one parser with no subprocess
    memory ceiling in front of it. Only the container elements are cleared, and only once they
    have been read, so their subtrees are released while the element being parsed stays intact.
    """
    from defusedxml.ElementTree import iterparse

    def local(tag: str) -> str:
        return tag.split("}")[-1]

    root = None
    schema = None
    depth = 0
    task_fields: dict[str, Any] = {}
    commands: list[dict[str, Any]] = []
    for event, element in iterparse(path, events=("start", "end")):
        if event == "start":
            if root is None:
                root = element
                schema = local(element.tag)
                if schema not in ("Task", "Objs"):
                    raise ValueError("unsupported XML schema (expected scheduled task or PowerShell CLIXML)")
            depth += 1
            continue
        depth -= 1
        tag = local(element.tag)
        if schema == "Task":
            if element is not root and element.text and element.text.strip():
                task_fields.setdefault(tag, element.text)
            if tag == "Exec":
                commands.append({local(child.tag): child.text for child in element})
                element.clear()
        elif schema == "Objs" and tag == "Obj" and depth == 1:
            # depth 1 is a direct child of <Objs>; clearing a nested Obj would empty its parent
            values = {el.attrib["N"]: el.text for el in element.iter() if "N" in el.attrib and len(el) == 0}
            if values:
                yield values
            element.clear()
    if schema == "Task":
        if not commands:
            raise ValueError("scheduled task has no supported Exec action")
        for command in commands:
            yield {
                "TaskName": task_fields.get("URI", name),
                "Execute": command.get("Command"),
                "CommandLine": " ".join(x for x in (command.get("Command"), command.get("Arguments")) if x),
                "UserName": task_fields.get("UserId"),
                "RunLevel": task_fields.get("RunLevel"),
                "Enabled": task_fields.get("Enabled"),
            }


# Bytes a single structured export may be parsed from. Enforced while reading, not on the file
# size, so the records parsed before the ceiling survive and the member is reported as partial.
MAX_PARSE_BYTES = 64 * 1024**2


class _ByteBudget(io.RawIOBase):
    """Passes bytes through and stops the parse once the budget is spent.

    Rejecting an oversized export up front made a 200 MB file listing contribute nothing but a
    hash, while every other limit here raises during iteration and keeps what it read. This makes
    the byte ceiling behave the same way.
    """

    def __init__(self, raw: Any, limit: int) -> None:
        self._raw = raw
        self._limit = limit
        self._read = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return self._raw.seekable()

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        # Sniffing a CSV dialect rewinds; the budget counts bytes actually read, so a rewind of a
        # few kilobytes is simply counted twice and does not distort a 64 MiB ceiling.
        return self._raw.seek(offset, whence)

    def tell(self) -> int:
        return self._raw.tell()

    def readinto(self, buffer: Any) -> int:
        n = self._raw.readinto(buffer) or 0
        self._read += n
        if self._read > self._limit:
            raise ValueError(f"structured export exceeded the {self._limit // 1024**2} MiB parse limit; records beyond it were not read")
        return n


def records(path: str, name: str) -> Iterator[dict[str, Any]]:
    if name.lower().endswith(".xml"):
        yield from _xml_records(path, name)
        return
    with open(path, "rb") as raw:
        head = raw.read(4)
        raw.seek(0)
        encoding = "utf-16" if head.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        with io.TextIOWrapper(io.BufferedReader(_ByteBudget(raw, MAX_PARSE_BYTES)), encoding=encoding, errors="strict", newline="") as fh:
            if name.lower().endswith((".txt", ".log")):
                record = {}
                for index, line in enumerate(fh):
                    if index >= 100000:
                        raise ValueError("text export exceeds 100,000 lines")
                    line = line.strip()
                    if category(name) == "connection" and (net := re.match(r"^(TCP|UDP)\s+(\S+)\s+(\S+)(?:\s+(\S+))?\s+(\d+)$", line, re.I)):
                        proto, local_ep, remote_ep, state, pid = net.groups()

                        def endpoint(value):
                            address, _, port = value.rpartition(":")
                            return address.strip("[]"), port

                        local_ip, local_port = endpoint(local_ep)
                        remote_ip, remote_port = endpoint(remote_ep)
                        yield {
                            "Protocol": proto,
                            "LocalAddress": local_ip,
                            "LocalPort": local_port,
                            "RemoteAddress": remote_ip,
                            "RemotePort": remote_port,
                            "State": state,
                            "PID": pid,
                        }
                        continue
                    match = re.match(r"^([A-Za-z][A-Za-z0-9 _-]{0,60})\s+:\s*(.*)$", line)
                    if match and category(name) != "defender":
                        k, v = match.groups()
                        k = k.strip()
                        if k in record:
                            yield record
                            record = {}
                        record[k] = v
                    elif not line and record:
                        yield record
                        record = {}
                    elif line:
                        if record:
                            yield record
                            record = {}
                        yield {"Message": line, "LineNumber": index + 1}
                if record:
                    yield record
            elif name.lower().endswith((".jsonl", ".ndjson")):
                for line in fh:
                    if line.strip():
                        row = json.loads(line)
                        if not isinstance(row, dict):
                            raise ValueError("expected an object per line")
                        yield row
            elif name.lower().endswith(".json"):
                value = json.load(fh)
                rows = value if isinstance(value, list) else value.get("records", [value]) if isinstance(value, dict) else None
                if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
                    raise ValueError("expected an object, array of objects, or records array")
                yield from rows
            else:
                sample = fh.read(8192)
                fh.seek(0)
                # PowerShell exports may start with a #TYPE declaration.
                if sample.startswith("#TYPE "):
                    fh.readline()
                    sample = sample.split("\n", 1)[-1]
                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
                except csv.Error:
                    dialect = csv.excel_tab if name.lower().endswith(".tsv") else csv.excel
                reader = csv.DictReader(fh, dialect=dialect)
                if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):
                    raise ValueError("missing or duplicate column names")
                for row in reader:
                    if None in row:
                        raise ValueError("row has more values than its header")
                    yield dict(row)


def normalize(raw: dict[str, Any], name: str, index: int, context: dict[str, Any]) -> dict[str, Any]:
    if category(name) == "deception":
        from services.parsers.deception import normalize as normalize_deception

        return normalize_deception(raw, index, context)
    fields = {key(k): v for k, v in raw.items()}

    def get(*names: str) -> str | None:
        for n in names:
            v = fields.get(key(n))
            if v is not None and str(v).strip() and not isinstance(v, (dict, list)):
                return str(v).strip()
        return None

    kind = category(name) or "unknown"
    observed_text = get("CollectedAt", "CollectionTime", "CollectionTimestamp", "ObservedAt") or context.get("collectedAt")
    row: dict[str, Any] = {
        "recordKind": "observation",
        "artifactType": kind,
        "eventId": None,
        "ts": None,
        "observedAt": timestamp(observed_text),
        "sourceIndex": index,
        "parserVersion": VERSION,
        "provider": "REMN Collection",
        "category": f"collection:{kind}",
        "computer": get("ComputerName", "Computer", "HostName", "PSComputerName", "MachineName") or context.get("host"),
        "data": raw,
    }
    mappings = {
        "targetUser": ("UserName", "User", "AccountName", "Account", "RunAsUser", "ClientUserName"),
        "targetDomain": ("Domain", "DomainName"),
        "targetSid": ("SID", "UserSid"),
        "image": ("ExecutablePath", "ImagePath", "Image", "ProcessPath"),
        "commandLine": ("CommandLine", "Command"),
        "processGuid": ("ProcessGuid",),
        "parentProcessGuid": ("ParentProcessGuid",),
        "processId": ("ProcessId", "PID", "OwningProcess", "Id"),
        "parentProcessId": ("ParentProcessId", "PPID"),
        "destinationIp": ("RemoteAddress", "RemoteIP", "DestinationIp"),
        "destinationPort": ("RemotePort", "DestinationPort"),
        "sourceIp": ("LocalAddress", "LocalIP", "SourceIp"),
        "sourcePort": ("LocalPort", "SourcePort"),
        "protocol": ("Protocol",),
        "status": ("State", "Status"),
        "query": ("DomainName", "QueryName") if kind == "connection" else (),
        "serviceAccount": ("StartName", "ServiceAccount"),
        "groupName": ("GroupName", "Group"),
        "shareName": ("ShareName", "Share"),
        "destinationHostname": ("RemoteHost", "DestinationHostname", "ClientComputerName"),
        "processStart": ("CreationDate", "StartTime", "ProcessStartTime"),
    }
    for target, aliases in mappings.items():
        if (v := get(*aliases)) is not None:
            row[target] = v
    for n in ("processId", "sourcePort", "destinationPort"):
        try:
            v = row.get(n)
            row[n] = int(v, 16) if isinstance(v, str) and v.startswith("0x") else int(v) if v is not None else None
        except (ValueError, TypeError):
            row[n] = None
    if kind == "process":
        row["processName"] = get("ProcessName", "Name") or row.get("image")
    row["name"] = get("Name", "DisplayName", "Entry", "EntryName")
    row["message"] = get("Message")
    if kind == "account":
        row["targetUser"] = row.get("targetUser") or get("Name")
        row["memberName"] = get("MemberName", "Member")
    if kind == "program":
        row["company"] = get("Publisher", "Vendor", "Company")
    if kind == "service":
        row["serviceName"] = get("ServiceName", "Name", "DisplayName")
        row["serviceFile"] = get("PathName", "BinaryPathName", "ImagePath")
    if kind == "task":
        row["taskName"] = get("TaskName", "TaskPath", "Name")
        row["image"] = row.get("image") or get("Execute", "Executable")
    if kind in ("file", "prefetch", "autorun"):
        row["path"] = get("FullName", "Path", "ImagePath", "FilePath")
    if kind == "autorun":
        row["image"] = row.get("image") or get("LaunchString")
    hashes = []
    for algorithm, length in (("SHA256", 64), ("SHA1", 40), ("MD5", 32)):
        v = get(algorithm)
        if v and re.fullmatch(rf"[a-fA-F0-9]{{{length}}}", v):
            hashes.append(f"{algorithm}={v.lower()}")
    row["hashes"] = ",".join(hashes) or None
    # Collection timestamps and file timestamps remain raw unless explicitly identified.
    # Prefetch exports can provide an execution timestamp; it is not a collection time.
    if kind == "prefetch":
        row["ts"] = timestamp(get("LastRunTime", "LastExecutionTime"))
        if row["ts"] is not None:
            row["recordKind"] = "event"
    label = row.get("taskName") or row.get("serviceName") or row.get("image") or row.get("path") or get("Name", "DisplayName", "UserName") or kind
    row["summary"] = f"{kind}: {label}"[:2000]
    if row.get("message"):
        row["summary"] = f"{kind}: {row['message']}"[:2000]
    return row


def native_records(kind: str, path: str, name: str, context: dict, tmp_dir: str):
    from services.parsers import native

    for i, raw in enumerate(native.records(kind, path, tmp_dir)):
        row = normalize(raw, f"{'Prefetch Files' if kind == 'prefetch' else 'Registry'}/{name}", i, context)
        row["parserVersion"] = f"dissect-{kind}/1"
        if kind == "prefetch":
            row["processName"] = raw.get("Name")
        else:
            row["targetObject"] = raw["KeyPath"]
            row["data"]["keyLastWriteTime"] = raw.get("LastWriteTime")
            values = raw.get("Values") or {}
            if re.search(r"\\Services\\[^\\]+$", raw["KeyPath"], re.I) and "ImagePath" in values:
                row.update(
                    artifactType="service",
                    category="collection:service",
                    serviceName=raw["KeyPath"].rsplit("\\", 1)[-1],
                    serviceFile=values["ImagePath"],
                    serviceAccount=values.get("ObjectName"),
                )
            elif re.search(r"\\Run(?:Once)?$", raw["KeyPath"], re.I):
                for value_name, value in values.items():
                    yield {
                        **row,
                        "artifactType": "autorun",
                        "category": "collection:autorun",
                        "name": value_name,
                        "image": value if isinstance(value, str) else None,
                        "commandLine": value if isinstance(value, str) else None,
                        "summary": f"autorun: {value_name} → {value}"[:2000],
                    }
                continue
        yield row
