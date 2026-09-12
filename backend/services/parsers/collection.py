"""Collection export adapters. Snapshots are observations, never synthetic Windows events."""

from __future__ import annotations

import csv
import io
import json
import os
import re
from collections import deque
from collections.abc import Iterator
from datetime import UTC, datetime
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


# --- exports written by other tools ---------------------------------------------------------
# Velociraptor names a result file after the artifact that produced it; KAPE's module output
# lands in directories named by category; DFIR-ORC names each CSV after the tool that wrote it.
VELOCIRAPTOR: tuple[tuple[str, str], ...] = (
    ("windowseventlogs", "event-export"),
    ("windowssystemservices", "service"),
    ("windowssysprograms", "program"),
    ("windowsforensicsprefetch", "prefetch"),
    ("windowsnetworknetstat", "connection"),
    ("windowsnetworkarpcache", "connection"),
    ("windowssystemdns", "connection"),
    ("windowssystemtaskscheduler", "task"),
    ("windowssysinternalsautoruns", "autorun"),
    ("windowssystempslist", "process"),
    ("windowssysusers", "account"),
    ("windowsforensicsamcache", "amcache"),
    ("windowsregistryuserassist", "userassist"),
    ("windowsregistryappcompatcache", "shimcache"),
    ("windowsforensicsbam", "bam"),
    ("windowsforensicsshellbags", "shellbag"),
    ("windowsforensicssrum", "sru"),
    ("windowsforensicslnk", "file"),
    ("windowsforensicsrecentdocs", "file"),
    ("windowsforensicsusn", "file"),
    ("windowsntfsmft", "file"),
    ("windowsforensicstimeline", "file"),
    ("windowsapplicationschromehistory", "browser-history"),
    ("windowsapplicationsedgehistory", "browser-history"),
    ("windowsapplicationsfirefoxhistory", "browser-history"),
    ("windowssystempowershell", "powershell-history"),
)
KAPE_MODULES: dict[str, str] = {
    "eventlogs": "event-export",
    "programexecution": "amcache",
    "filefolderaccess": "file",
    "filesystem": "file",
    "srum": "sru",
    "lnk": "file",
    "jumplists": "file",
    "recyclebin": "file",
    "amcache": "amcache",
    "windowstimeline": "activity",
    "antivirus": "defender",
}
ORC_TOOLS: tuple[tuple[str, str], ...] = (
    ("ntfsinfo", "file"),
    ("usninfo", "file"),
    ("getthis", "file"),
    ("fatinfo", "file"),
    ("getsamples", "file"),
    ("reginfo", "registry"),
    ("jobstatistics", "system"),
    ("processstatistics", "system"),
)
# Eric Zimmerman's parsers write CSV with stable, distinctive headers, and KAPE's module output
# is made of them. The header decides the artifact whatever directory the file sits in.
EZ_SIGNATURES: tuple[tuple[frozenset[str], str], ...] = (
    (frozenset({"eventrecordid", "mapdescription", "timecreated"}), "event-export"),
    (frozenset({"executablename", "runcount", "lastrun"}), "prefetch"),
    (frozenset({"programid", "fullpath", "sha1"}), "amcache"),
    (frozenset({"programid", "installdate", "publisher"}), "program"),
    (frozenset({"cacheentryposition", "lastmodifiedtimeutc"}), "shimcache"),
    (frozenset({"entrynumber", "parentpath", "created0x10"}), "file"),
    (frozenset({"hivepath", "keypath", "valuename", "valuedata"}), "registry"),
    (frozenset({"absolutepath", "shelltype", "lastwritetime"}), "shellbag"),
    (frozenset({"targetidabsolutepath"}), "file"),
    (frozenset({"appid", "appiddescription"}), "file"),
    (frozenset({"exeinfo", "bytessent", "bytesreceived"}), "sru"),
)


def _ez_kind(fields: dict[str, Any]) -> str | None:
    present = set(fields)
    for needed, kind in EZ_SIGNATURES:
        if needed <= present:
            return kind
    return None


def category(name: str) -> str | None:
    parts = name.replace("\\", "/").split("/")
    for part in parts:
        k = key(part.rsplit(".", 1)[0])
        if k in CATEGORIES:
            return CATEGORIES[k]
        if k in KAPE_MODULES:
            return KAPE_MODULES[k]
    if "forensicscollectionsummary" in key(name):
        return "collection-summary"
    stem = key(parts[-1].rsplit(".", 1)[0]) if parts else ""
    for prefix, kind in VELOCIRAPTOR:
        if stem.startswith(prefix):
            return kind
    for prefix, kind in ORC_TOOLS:
        if stem.startswith(prefix):
            return kind
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


_FRACTION = re.compile(r"(\.\d{6})\d+")


def timestamp_utc(value: Any) -> int | None:
    """Timestamps from tools whose documentation fixes the zone as UTC without writing it: the
    Zimmerman parsers, DFIR-ORC and Velociraptor. Anything a zone is written on goes through
    timestamp(); this only fills in for the formats those tools are known to write."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    parsed = timestamp(text)
    if parsed is not None:
        return parsed
    text = _FRACTION.sub(r"\1", text)  # seven fractional digits is more than strptime takes
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %H:%M:%S.%f", "%m/%d/%Y %H:%M:%S"):
        try:
            return int(datetime.strptime(text, fmt).replace(tzinfo=UTC).timestamp() * 1000)
        except ValueError:
            continue
    return None


def _flatten(raw: dict[str, Any]) -> dict[str, Any]:
    """One level of nesting folded into dotted keys, so Laddr.IP is a column like any other."""
    out: dict[str, Any] = {}
    for k, v in raw.items():
        if isinstance(v, dict) and v and all(isinstance(sub, str) for sub in v):
            for sub, value in v.items():
                if not isinstance(value, (dict, list)):
                    out[f"{k}.{sub}"] = value
        out[k] = v
    return out


def _event_export(raw: dict[str, Any], fields: dict[str, Any], kind: str | None, name: str, index: int, context: dict[str, Any]) -> dict[str, Any] | None:
    """Event log records another tool exported become event rows, not observations.

    EvtxECmd writes one flat CSV row per record; Velociraptor writes the record's System and
    EventData objects as JSON. Both carry the same identity: channel, record id, event id, time.
    """
    system = raw.get("System") if isinstance(raw.get("System"), dict) else None
    if system is None and kind != "event-export":
        return None

    def get(*names: str) -> str | None:
        for n in names:
            v = fields.get(key(n))
            if v is not None and str(v).strip() and not isinstance(v, (dict, list)):
                return str(v).strip()
        return None

    if system is not None:
        event_id = system.get("EventID")
        if isinstance(event_id, dict):
            event_id = event_id.get("Value")
        provider = system.get("Provider")
        if isinstance(provider, dict):
            provider = provider.get("Name")
        created = system.get("TimeCreated")
        when = created.get("SystemTime") if isinstance(created, dict) else created
        channel, computer, record_id = system.get("Channel"), system.get("Computer"), system.get("EventRecordID")
        message = raw.get("Message")
        user = None
        payload = raw.get("EventData") if isinstance(raw.get("EventData"), dict) else {}
        if isinstance(payload, dict):
            user = payload.get("TargetUserName") or payload.get("SubjectUserName")
    else:
        event_id, provider, when = get("EventId", "EventID"), get("Provider"), get("TimeCreated")
        channel, computer, record_id = get("Channel"), get("Computer"), get("EventRecordId", "RecordNumber")
        message = get("MapDescription", "Message")
        user = get("UserName", "TargetUserName")
        payload = " ".join(v for v in (get(f"PayloadData{i}") for i in range(1, 7)) if v)
        if payload:
            message = f"{message}: {payload}" if message else payload
    row: dict[str, Any] = {
        "recordKind": "event",
        "artifactType": "event-export",
        "eventId": int(event_id) if str(event_id or "").strip().isdigit() else None,
        "ts": timestamp(when) or timestamp_utc(when) if isinstance(when, str) else None,
        "observedAt": timestamp(context.get("collectedAt")) if context.get("collectedAt") else None,
        "sourceIndex": index,
        "parserVersion": VERSION,
        "provider": str(provider) if provider else None,
        "channel": str(channel) if channel else None,
        "computer": (str(computer) if computer else None) or context.get("host"),
        "recordId": int(record_id) if str(record_id or "").strip().isdigit() else None,
        "category": "collection:event-export",
        "targetUser": str(user) if user else None,
        "message": str(message)[:4000] if message else None,
        "data": raw,
    }
    label = f"{row['provider'] or row['channel'] or 'event'} {row['eventId'] or ''}".strip()
    row["summary"] = f"{label}: {row['message'] or ''}".strip(": ")[:2000]
    return row


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


# Where a Defender log names what it found. Threat names have a fixed shape, Category:Platform/Name,
# so they can be lifted out of a free-text line without knowing which log it came from.
THREAT_NAME = re.compile(r"(?<![\w/])(?!(?i:lowfi|file|https?|ftp|urn):)([A-Za-z]{3,}:[A-Za-z0-9]+/[A-Za-z0-9._!#-]+)")

# `reg query /s` output: a key on its own line, its values indented beneath it in three columns
# separated by runs of spaces. Collectors dump the autostart keys this way and call it Autoruns.
REG_KEY = re.compile(r"^HKEY_[A-Z_]+\\")
REG_VALUE = re.compile(r"^\s{2,}(?P<name>.+?)\s{2,}(?P<type>REG_[A-Z_]+)(?:\s{2,}(?P<data>.*))?$")
LAUNCHABLE = re.compile(r"\.(exe|dll|cmd|bat|ps1|vbs|vbe|js|jse|wsf|hta|scr|com|msi|lnk|cpl)\b", re.I)


def _looks_like_reg_query(lines: list[str]) -> bool:
    return any(REG_KEY.match(line) for line in lines) and any(REG_VALUE.match(line.rstrip()) for line in lines)


def _reg_query_records(lines, notes: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """One record per registry value, under the key it was listed beneath."""
    key = None
    for index, raw_line in enumerate(lines):
        if index >= MAX_TEXT_LINES:
            notes["truncatedAtLine"] = MAX_TEXT_LINES
            break
        line = raw_line.rstrip()
        if not line.strip():
            continue
        if REG_KEY.match(line):
            key = line.strip()
            continue
        match = REG_VALUE.match(line) if key else None
        if match:
            yield {
                "Key": key,
                "ValueName": match.group("name").strip(),
                "Type": match.group("type"),
                "Data": (match.group("data") or "").strip(),
                "LineNumber": index + 1,
            }
        else:
            # what reg query says when a key is absent, in whatever language the host speaks
            yield {"Message": line.strip(), "LineNumber": index + 1}


def _launch_image(value: str | None) -> str | None:
    """A registry value that launches something, as opposed to a flag or a resource reference."""
    if not value or len(value) > 4096 or value.startswith("@"):
        return None
    if "\\" in value or LAUNCHABLE.search(value):
        return value
    return None


def _first_token(command: str | None) -> str | None:
    """The executable of a command line: the quoted first token, or up to the first space."""
    if not command:
        return None
    command = command.strip()
    if command.startswith('"'):
        end = command.find('"', 1)
        return command[1:end] if end > 0 else command[1:]
    return command.split(" ", 1)[0] or None


def _prefetch_image(name: str | None, referenced) -> str | None:
    """The executable's own path among the files a prefetch entry references."""
    if not name:
        return None
    want = str(name).upper()
    for entry in referenced or ():
        if isinstance(entry, str) and entry.upper().rsplit("\\", 1)[-1] == want:
            return entry
    return None


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
                head = list(islice(fh, 200))
                if _looks_like_reg_query(head):
                    yield from _reg_query_records(chain(head, fh), notes)
                    return
                record = {}
                for index, line in enumerate(chain(head, fh)):
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
    raw = _flatten(raw)
    fields = {key(k): v for k, v in raw.items()}
    exported = _event_export(raw, fields, _ez_kind(fields) or category(name), name, index, context)
    if exported is not None:
        return exported

    def get(*names: str) -> str | None:
        for n in names:
            v = fields.get(key(n))
            if v is not None and str(v).strip() and not isinstance(v, (dict, list)):
                return str(v).strip()
        return None

    kind = _ez_kind(fields) or category(name) or "unknown"
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
        "targetUser": ("UserName", "User", "AccountName", "Account", "RunAsUser", "ClientUserName", "Exécuter en tant qu'utilisateur"),
        "targetDomain": ("Domain", "DomainName"),
        "targetSid": ("SID", "UserSid"),
        "image": ("ExecutablePath", "ImagePath", "Image", "ProcessPath"),
        "commandLine": ("CommandLine", "Command", "Task To Run", "Tâche à exécuter"),
        "processGuid": ("ProcessGuid",),
        "parentProcessGuid": ("ParentProcessGuid",),
        "processId": ("ProcessId", "PID", "OwningProcess", "Id"),
        "parentProcessId": ("ParentProcessId", "PPID"),
        "destinationIp": ("RemoteAddress", "RemoteIP", "DestinationIp", "Raddr.IP"),
        "destinationPort": ("RemotePort", "DestinationPort", "Raddr.Port"),
        "sourceIp": ("LocalAddress", "LocalIP", "SourceIp", "Laddr.IP"),
        "sourcePort": ("LocalPort", "SourcePort", "Laddr.Port"),
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
    row["name"] = get("Name", "DisplayName", "Entry", "EntryName", "ValueName", "Nom de la tâche")
    row["message"] = get("Message")
    if kind == "defender" and row["message"]:
        found = THREAT_NAME.search(row["message"])
        if found:
            row["threatName"] = found.group(1)
    if kind == "account":
        row["targetUser"] = row.get("targetUser") or get("Name")
        row["memberName"] = get("MemberName", "Member")
    if kind == "program":
        row["company"] = get("Publisher", "Vendor", "Company")
        row["path"] = get("InstallLocation", "InstallSource")
    if kind == "service":
        row["serviceName"] = get("ServiceName", "Name", "DisplayName")
        row["serviceFile"] = get("PathName", "BinaryPathName", "ImagePath")
    if kind == "task":
        row["taskName"] = get("TaskName", "TaskPath", "Name", "Nom de la tâche")
        row["image"] = row.get("image") or get("Execute", "Executable") or _first_token(row.get("commandLine"))
    if kind in ("file", "prefetch", "autorun"):
        row["path"] = get("FullName", "Path", "ImagePath", "FilePath")
    if kind == "autorun":
        row["image"] = row.get("image") or get("LaunchString") or _launch_image(get("Data"))
        row["targetObject"] = get("Key", "KeyPath", "RegistryKey", "Entry Location")
    if kind == "program":
        row["path"] = row.get("path") or get("RootDirPath")
    if kind in ("amcache", "shimcache", "userassist", "bam", "shellbag", "sru", "activity", "browser-history", "browser-download", "powershell-history", "registry", "file"):
        candidate = get("FullPath", "Path", "AbsolutePath", "LocalPath", "TargetIDAbsolutePath", "FullName", "ExeInfo", "ImagePath", "FilePath")
        if kind == "file" and not candidate and get("ParentPath") and get("FileName"):
            candidate = get("ParentPath").rstrip("\\") + "\\" + get("FileName")
        row["path"] = row.get("path") or candidate
        if kind in ("amcache", "shimcache", "userassist", "bam", "sru"):
            row["image"] = row.get("image") or candidate
        if kind == "registry":
            row["targetObject"] = get("KeyPath", "Key")
            row["name"] = row.get("name") or get("ValueName")
            row["image"] = row.get("image") or _launch_image(get("ValueData", "Data"))
        if kind == "file":
            row["commandLine"] = row.get("commandLine") or get("Arguments")
            row["url"] = get("URL", "Url")
        if kind in ("browser-history", "browser-download"):
            row["url"] = get("URL", "Url", "VisitURL")
        when = get(
            "LastRun", "Timestamp", "TimeStamp", "LastModifiedTimeUTC", "FileKeyLastWriteTimestamp", "LastWriteTimestamp", "LastWriteTime",
            "TargetModified", "SourceModified", "Created0x10", "LastModificationDate", "LinkDate", "LastVisitedTime", "VisitTime",
        )
        # A registry last-write time stays metadata, as it does for hives decoded natively; the
        # other exports carry a moment something happened.
        if kind != "registry":
            row["ts"] = row.get("ts") or timestamp_utc(when)
        if row["ts"] is not None:
            row["recordKind"] = "event"
    hashes = []
    for algorithm, length in (("SHA256", 64), ("SHA1", 40), ("MD5", 32)):
        v = get(algorithm)
        if v and re.fullmatch(rf"[a-fA-F0-9]{{{length}}}", v):
            hashes.append(f"{algorithm}={v.lower()}")
    row["hashes"] = ",".join(hashes) or None
    # Collection timestamps and file timestamps remain raw unless explicitly identified.
    # Prefetch exports can provide an execution timestamp; it is not a collection time.
    if kind == "prefetch":
        row["processName"] = row.get("processName") or get("ExecutableName", "Executable", "Name")
        loaded = get("FilesLoaded")
        if loaded and not row.get("image"):
            row["image"] = row["path"] = _prefetch_image(row.get("processName"), [p.strip() for p in loaded.split(",")])
        row["ts"] = timestamp(get("LastRunTime", "LastExecutionTime")) or timestamp_utc(get("LastRun"))
        if row["ts"] is not None:
            row["recordKind"] = "event"
    label = row.get("taskName") or row.get("serviceName") or row.get("image") or row.get("path") or get("Name", "DisplayName", "UserName") or kind
    row["summary"] = f"{kind}: {label}"[:2000]
    if kind == "autorun" and row.get("targetObject"):
        launches = f" -> {row['image']}" if row.get("image") else ""
        row["summary"] = f"autorun: {row['targetObject']}\\{row.get('name') or ''}{launches}"[:2000]
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
            executable = _prefetch_image(raw.get("Name"), raw.get("ReferencedFiles"))
            if executable:
                row["image"] = executable
                row["path"] = executable
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
