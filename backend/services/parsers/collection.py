"""Collection export adapters. Snapshots are observations, never synthetic Windows events."""

from __future__ import annotations

import csv
import io
import json
import os
import re
from collections import deque
from collections.abc import Iterator
from datetime import datetime
from itertools import chain, islice
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


# Collection exports are written by whatever produced them, and some write CSV badly. Two
# breakages show up in real service and process exports: a run of columns arrives joined into a
# single cell as 'a','b','c' because the writer quoted the group instead of its members, and a
# stray quote in a free-text description swallows a delimiter. Neither justifies discarding the
# file. A services list is evidence, and the rows that survive are worth more than an empty table
# with an error beside it.
MAX_TEXT_LINES = 100_000


def _text_encoding(raw) -> str:
    """Work out how a text export is encoded rather than trusting it to say so.

    Windows Defender writes several of its support logs as UTF-16 with no byte order mark. Read as
    UTF-8 some of those decode without raising at all, and every character comes back with a NUL
    after it: mojibake, handed to the analyst as evidence. The rest raise, and a strict decode
    discarded a nine-megabyte operational log over it. Neither outcome is acceptable, so the shape
    of the bytes decides, and an encoding that cannot be identified degrades instead of failing.
    """
    position = raw.tell()
    sample = raw.read(65536)
    raw.seek(position)
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    if len(sample) > 16:
        # In UTF-16 text that is mostly ASCII, half the bytes are NUL, and which half says which
        # byte order it is.
        if sum(1 for i in range(1, len(sample), 2) if sample[i] == 0) > len(sample) * 0.4:
            return "utf-16-le"
        if sum(1 for i in range(0, len(sample), 2) if sample[i] == 0) > len(sample) * 0.4:
            return "utf-16-be"
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError as exc:
        # A multi-byte character cut in half by the end of the sample is not a failed decode.
        if exc.start < len(sample) - 4:
            return "cp1252"
    return "utf-8-sig"


_GROUPED_CELL = re.compile(r"^'[^']*'(?:,'[^']*')+$")
SPILL_KEY = "_unmappedValues"
PARTIAL_KEY = "_partialRow"
REPAIRED_KEY = "_repairedRow"
# A row with more values than its header used to abort the member. Keeping it must not mean
# building one unbounded string out of however many delimiters the file happened to contain.
MAX_SPILL_VALUES = 64
MAX_SPILL_CHARS = 4096


def _ungroup(row: list[str]) -> list[str]:
    out: list[str] = []
    for cell in row:
        value = cell.strip()
        if _GROUPED_CELL.match(value):
            out.extend(value[1:-1].split("','"))
        else:
            out.append(cell)
    return out


# A Defender support cab carries a quarter of a million lines of engine logging. One row per line
# buries the few hundred that name a threat, a quarantine, an exclusion or a change of protection
# state under the scan bookkeeping around them, and duplicates the operational event log, which
# arrives in the same cab as a .evtx and is parsed properly there. Small files are state dumps
# where every line is content, so they are kept whole. Larger ones are reduced to their signal,
# and the member says how many lines were read to find it.
# A Defender support cab carries a quarter of a million lines of engine logging. One row per line
# buries the few hundred that name a threat under the scan bookkeeping around them, and duplicates
# the operational event log, which arrives in the same cab as a .evtx and is parsed properly there.
#
# A matching line alone is not enough, though. In a resource-scan block it is the NEIGHBOURING
# lines that carry the path of the file and the name of the process, so a match brings its
# surroundings with it. Files that are state dumps rather than engine logs are kept whole however
# long they are, because in those every line is a fact about how the machine was configured.
DEFENDER_WHOLE_FILE_LINES = 500
DEFENDER_CONTEXT = 4
DEFENDER_KEEP_WHOLE = re.compile(
    r"(mpdetection|mpstateinfo|mpregistry|wdatpinfo|networkprotectionstate|wsc(info|registry)|mpsupporteffectiveconfig|securityhealth)",
    re.I,
)
# Cheap substring gate in front of the precise test. The same bytes used to take a branch that ran
# at 45 MiB/s and this one runs at 1.6, which on a public instance is an amplifier by itself.
DEFENDER_TERMS = (
    "threat", "detect", "quarantin", "remediat", "cleaned", "removed", "blocked", "exclusion",
    "lowfi", "malware", "trojan", "backdoor", "ransom", "hacktool", "riskware", "pua:", "unwanted",
    "tamper", "time protection", "scan result", "scan finished", "scan started",
    # switching protection off is the move an attacker makes before the rest, so it is evidence
    "removedefinitions", "disableantispyware", "disablerealtime", "disablebehavior",
    "disableioav", "disablescriptscanning",
)


def _defender_signal(line: str) -> bool:
    low = line.lower()
    return any(term in low for term in DEFENDER_TERMS)


def _defender_filtered(pairs, notes: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Lines that say something, each with the lines around it that qualify it."""
    recent: deque[tuple[int, str]] = deque(maxlen=DEFENDER_CONTEXT)
    after = 0
    last = -1
    kept = 0
    for index, line in pairs:
        if _defender_signal(line):
            for held_index, held_line in recent:
                if held_index > last:
                    kept += 1
                    last = held_index
                    yield {"Message": held_line, "LineNumber": held_index + 1}
            recent.clear()
            after = DEFENDER_CONTEXT
        elif after:
            after -= 1
        else:
            recent.append((index, line))
            continue
        if index > last:
            kept += 1
            last = index
            yield {"Message": line, "LineNumber": index + 1}
    notes["defenderKept"] = kept


def _defender_records(fh, name: str, notes: dict[str, Any]) -> Iterator[dict[str, Any]]:
    def pairs():
        for index, raw_line in enumerate(fh):
            if index >= MAX_TEXT_LINES:
                notes["truncatedAtLine"] = MAX_TEXT_LINES
                return
            line = raw_line.strip()
            if line:
                yield index, line

    stream = pairs()
    head = list(islice(stream, DEFENDER_WHOLE_FILE_LINES + 1))
    if len(head) <= DEFENDER_WHOLE_FILE_LINES or DEFENDER_KEEP_WHOLE.search(name):
        for index, line in chain(head, stream):
            yield {"Message": line, "LineNumber": index + 1}
        return

    counted = {"scanned": 0}

    def counting():
        for pair in chain(head, stream):
            counted["scanned"] += 1
            yield pair

    yield from _defender_filtered(counting(), notes)
    notes["defenderScanned"] = counted["scanned"]


def _mark(out: dict[str, Any], header: list[str], key: str, value: str) -> None:
    """Record a parser marker without overwriting a column the export genuinely has."""
    while key in header:
        key += "_"
    out[key] = value


def _row_to_dict(row: list[str], header: list[str], notes: dict[str, Any]) -> dict[str, Any]:
    width = len(header)
    original = row
    if len(row) < width:
        repaired = _ungroup(row)
        # Trust the repair only when ONE cell was grouped and splitting that cell alone closes the
        # whole gap. Accepting any combination that happens to reach the header width lets a row
        # short for one reason and groupable for another be filed confidently under wrong columns.
        if len(repaired) == width and sum(1 for c in row if _GROUPED_CELL.match(c.strip())) == 1:
            row = repaired
            notes["repairedRows"] = notes.get("repairedRows", 0) + 1
    if len(row) == width:
        out = dict(zip(header, row))
        if row is not original:
            # Stamped on the row, not only counted on the member, so a row seen anywhere else
            # still says it was reassembled rather than read.
            _mark(out, header, REPAIRED_KEY, f"{len(original)} cells split to {width}")
        return out
    out = dict(zip(header, row))
    notes["malformedRows"] = notes.get("malformedRows", 0) + 1
    if len(row) < width:
        for column in header[len(row) :]:
            out[column] = ""
        _mark(out, header, PARTIAL_KEY, f"{len(row)} of {width} values")
    else:
        # Surplus values keep their content instead of being dropped: an unquoted delimiter inside
        # a command line is exactly what an analyst needs to see. Bounded, because a row of nothing
        # but delimiters used to abort the member and now becomes one enormous value instead.
        surplus = row[width:]
        spill = " | ".join(surplus[:MAX_SPILL_VALUES])[:MAX_SPILL_CHARS]
        if len(surplus) > MAX_SPILL_VALUES:
            spill += f" ... and {len(surplus) - MAX_SPILL_VALUES} more"
        _mark(out, header, SPILL_KEY, spill)
    return out


def records(path: str, name: str, notes: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
    if notes is None:
        notes = {}
    if name.lower().endswith(".xml"):
        yield from _xml_records(path, name)
        return
    with open(path, "rb") as raw:
        encoding = _text_encoding(raw)
        if encoding != "utf-8-sig":
            notes["encoding"] = encoding
        # Lenient because the encoding above is chosen, not guessed at random: what "replace"
        # covers here is a corrupt byte in one line, and losing the file over that helps nobody.
        with io.TextIOWrapper(io.BufferedReader(_ByteBudget(raw, MAX_PARSE_BYTES)), encoding=encoding, errors="replace", newline="") as fh:
            if category(name) == "defender" and name.lower().endswith((".txt", ".log")):
                yield from _defender_records(fh, name, notes)
            elif name.lower().endswith((".txt", ".log")):
                record = {}
                for index, line in enumerate(fh):
                    if index >= MAX_TEXT_LINES:
                        # Stop, rather than throw away the lines already read. A ten-megabyte
                        # engine log is exactly where the first hundred thousand lines are worth
                        # keeping and the file being absent is worth nothing.
                        notes["truncatedAtLine"] = MAX_TEXT_LINES
                        break
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
                reader = csv.reader(fh, dialect=dialect)
                header = next(reader, None)
                if not header or len(set(header)) != len(header):
                    raise ValueError("missing or duplicate column names")
                for row in reader:
                    if row:
                        yield _row_to_dict(row, header, notes)


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

    yield from native_rows(kind, native.records(kind, path, tmp_dir), name, context)


def native_rows(kind: str, raw_records, name: str, context: dict):
    """Normalize records a decoder produced. How they were decoded is the caller's business, so
    one artifact at a time and a whole group in one worker share this."""
    for i, raw in enumerate(raw_records):
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
