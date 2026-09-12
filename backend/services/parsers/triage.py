"""A collection laid out like a drive is a dissect target.

KAPE, Velociraptor's offline collector, acquire and a plain copy of a system drive all deliver the
same thing: the original files under their original paths. dissect.target already knows how to read
every one of those artifacts, and re-implementing that here would be worse and slower. What this
module does is choose which of its functions to run, bound them, and turn their records into rows
the rules read.

The pass runs in the same disposable worker as the other native decoders. Records cross back as
JSON lines framed by function, so a function that fails or is cut short costs only its own tail.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Any

from services.parsers.collection import THREAT_NAME, timestamp

VERSION = "dissect-target/1"

# (function, artifact type, record cap). The order is the order an analyst needs them in, so a
# collection that exhausts its allowance loses the tail, not the head. evtx and prefetch are left
# out on purpose: the member loop parses those with provenance per file.
FUNCTIONS: tuple[tuple[str, str, int], ...] = (
    ("services", "service", 20_000),
    ("runkeys", "autorun", 20_000),
    ("tasks", "task", 20_000),
    ("defender.mplog", "defender", 100_000),
    ("defender.quarantine", "defender", 10_000),
    ("defender.exclusions", "defender", 10_000),
    ("defender.mpcmdrun", "defender", 10_000),
    ("amcache.applications", "program", 50_000),
    ("amcache.programs", "program", 50_000),
    ("amcache.application_files", "amcache", 200_000),
    ("amcache.files", "amcache", 200_000),
    ("amcache.applaunches", "amcache", 50_000),
    ("shimcache", "shimcache", 50_000),
    ("userassist", "userassist", 20_000),
    ("bam", "bam", 20_000),
    ("shellbags", "shellbag", 100_000),
    ("powershell_history", "powershell-history", 50_000),
    ("browser.history", "browser-history", 200_000),
    ("browser.downloads", "browser-download", 50_000),
    ("activitiescache", "activity", 50_000),
    ("sru.network_data", "sru", 100_000),
    ("sru.application", "sru", 100_000),
)
# Millions of rows on a real disk. Opt-in, and capped hard even then.
FILESYSTEM_FUNCTIONS: tuple[tuple[str, str, int], ...] = (
    ("mft.records", "file", 500_000),
    ("usnjrnl", "file", 500_000),
)

# A Windows system directory under a drive root, however the collector spelled the root:
# C/, C:/, C%3A/ (Velociraptor), sysvol/ (acquire, tar), $rootfs$/.
TRIAGE_MARKER = re.compile(r"(?:^|/)(?:[A-Za-z](?::|%3A)?|sysvol|\$rootfs\$)/(?:windows|winnt)/system32(?:/|$)", re.I)


def is_triage_layout(names) -> bool:
    """True when member names show a Windows system directory under a drive root."""
    for name in names:
        if TRIAGE_MARKER.search(str(name).replace("\\", "/")):
            return True
    return False


def _first(rec: dict[str, Any], *names: str) -> Any:
    for n in names:
        v = rec.get(n)
        if v not in (None, "", [], {}):
            return v
    return None


def _text(value: Any) -> str | None:
    if value in (None, "", [], {}):
        return None
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if v not in (None, ""))
    return str(value)


def _threat(*values: Any) -> str | None:
    """A Defender threat name from whichever field carries it: the shape is what identifies it."""
    for value in values:
        text = _text(value)
        if not text:
            continue
        found = THREAT_NAME.search(text)
        if found:
            return found.group(1)
    return None


def _hashes(digest: Any) -> str | None:
    if not isinstance(digest, dict):
        return None
    parts = [f"{algo.upper()}={str(value).lower()}" for algo, value in (("sha256", digest.get("sha256")), ("sha1", digest.get("sha1")), ("md5", digest.get("md5"))) if value]
    return ",".join(parts) or None


def to_row(function: str, artifact: str, rec: dict[str, Any], index: int, context: dict[str, Any]) -> dict[str, Any] | None:
    """One dissect record as a REMN row, or None for a record that carries no evidence of its own."""
    kind = str(rec.get("_type") or "")
    row: dict[str, Any] = {
        "recordKind": "observation",
        "artifactType": artifact,
        "eventId": None,
        "ts": None,
        "observedAt": timestamp(context.get("collectedAt")) if context.get("collectedAt") else None,
        "sourceIndex": index,
        "parserVersion": VERSION,
        "provider": "REMN Triage",
        "category": f"collection:{artifact}",
        "computer": _first(rec, "hostname") or context.get("host"),
        "targetUser": _text(_first(rec, "username", "user", "run_as")),
        "data": rec,
    }
    ts = None
    if kind == "windows/service":
        image = _text(rec.get("imagepath"))
        args = _text(rec.get("imagepath_args"))
        row.update(
            serviceName=_text(rec.get("name")),
            name=_text(_first(rec, "displayname", "name")),
            image=image,
            serviceFile=f"{image} {args}".strip() if image and args else image,
            serviceAccount=_text(rec.get("objectname")),
            serviceStartType=_text(rec.get("start")),
            serviceType=_text(rec.get("type")),
        )
        ts = rec.get("ts")
    elif kind == "windows/registry/run":
        command = _text(rec.get("command"))
        row.update(name=_text(rec.get("name")), image=command, commandLine=command, targetObject=_text(rec.get("key")))
        ts = rec.get("ts")
    elif kind == "filesystem/windows/task":
        app = _text(rec.get("app_name"))
        args = _text(rec.get("args"))
        row.update(
            taskName=_text(_first(rec, "task_path", "uri", "task_name")),
            name=_text(_first(rec, "task_name", "display_name")),
            image=app,
            commandLine=f"{app} {args}".strip() if app and args else app,
            targetUser=_text(_first(rec, "run_as", "user_id", "principal_id")),
        )
        ts = _first(rec, "date", "last_run_date")
    elif kind == "filesystem/windows/task/action" and str(rec.get("action_type") or "").lower() == "exec":
        command = _text(rec.get("command"))
        args = _text(rec.get("arguments"))
        row.update(taskName=_text(rec.get("uri")), image=command, commandLine=f"{command} {args}".strip() if command and args else command)
    elif kind.startswith("filesystem/windows/task/"):
        return None  # triggers and the other action types describe the task above, not a separate fact
    elif kind in ("windows/appcompat/InventoryApplicationFile", "windows/appcompat/file"):
        path = _text(rec.get("path"))
        row.update(image=path, path=path, name=_text(rec.get("name")), company=_text(_first(rec, "publisher", "company_name")), hashes=_hashes(rec.get("digest")))
        ts = _first(rec, "link_date", "mtime_regf")
    elif kind in ("windows/appcompat/InventoryApplication", "windows/appcompat/programs"):
        row.update(name=_text(rec.get("name")), company=_text(rec.get("publisher")), path=_text(_first(rec, "root_dir_path", "path", "uninstall_key")))
        ts = _first(rec, "install_date", "mtime_regf")
    elif kind.startswith("windows/appcompat/pca/"):
        path = _text(rec.get("path"))
        row.update(image=path, path=path, name=_text(rec.get("name")))
        ts = rec.get("ts")
    elif kind == "windows/shimcache":
        path = _text(rec.get("path"))
        row.update(image=path, path=path, name=_text(rec.get("name")))
        ts = rec.get("last_modified")
    elif kind in ("windows/registry/userassist", "windows/registry/bam"):
        path = _text(rec.get("path"))
        row.update(image=path, path=path)
        ts = rec.get("ts")
    elif kind == "windows/shellbag":
        row.update(path=_text(rec.get("path")))
        ts = _first(rec, "ts_mtime", "ts_btime")
    elif "defender" in kind:
        threat = _threat(rec.get("detection"), rec.get("threat"), rec.get("threat_type"), rec.get("threats"), rec.get("detection_name"), rec.get("command"))
        path = _text(_first(rec, "resource_path", "detection_path", "full_path", "blocked_file", "path", "full_path_with_drive_letter", "resources", "value"))
        leaf = kind.rsplit("/", 1)[-1]
        if leaf == "mpcmdrunlog":
            row["commandLine"] = _text(rec.get("command"))
            message = f"MpCmdRun {row['commandLine'] or ''}".strip()
        elif leaf == "exclusion" and rec.get("type"):
            message = f"exclusion {rec.get('type')}: {rec.get('value')}"
        elif leaf == "rtp_log":
            message = f"RTP log: path exclusions {_text(rec.get('path_exclusions')) or 'none'}; process exclusions {_text(rec.get('process_exclusions')) or 'none'}"
        elif leaf == "resourcescan":
            message = f"resource scan of {path or '?'}: {_text(rec.get('threats')) or 'no threat'}"
        elif leaf == "threataction":
            message = f"threat action {_text(rec.get('actions')) or '?'} on {_text(rec.get('resources')) or '?'}: {_text(rec.get('threats')) or ''}".strip()
        elif leaf in ("quarantine", "file"):
            message = f"quarantine {_text(rec.get('detection_name')) or ''} {path or ''}".strip()
        else:
            message = f"{leaf} {_text(_first(rec, 'detection', 'threat', 'threat_type', 'lowfi', 'original_file_name', 'process_image_name', 'blocked_file')) or ''}".strip()
        row.update(message=message[:2000], threatName=threat, path=path)
        ts = _first(rec, "ts", "ts_start")
    elif kind == "browser/history":
        row.update(url=_text(rec.get("url")), name=_text(rec.get("title")))
        ts = rec.get("ts")
    elif kind == "browser/download":
        row.update(url=_text(rec.get("url")), path=_text(rec.get("path")))
        ts = _first(rec, "ts_start", "ts_end")
    elif kind == "powershell/history":
        row.update(commandLine=_text(rec.get("command")))
        ts = rec.get("mtime")
    elif kind == "windows/activitiescache":
        row.update(image=_text(rec.get("app_id")))
        ts = _first(rec, "start_time", "last_modified_time")
    elif kind.startswith("filesystem/windows/sru/"):
        row.update(image=_text(rec.get("app")))
        ts = rec.get("ts")
    elif kind.startswith("filesystem/ntfs/mft") or kind.startswith("filesystem/ntfs/usnjrnl") or "usnjrnl" in kind:
        row.update(path=_text(_first(rec, "path", "filename")))
        ts = _first(rec, "ts", "creation_time", "last_modification_time")
    else:
        row.update(path=_text(rec.get("path")), image=_text(rec.get("image")), commandLine=_text(rec.get("command")))
        ts = rec.get("ts")

    if isinstance(ts, str):
        row["ts"] = timestamp(ts)
    if row["ts"] is not None:
        row["recordKind"] = "event"
    label = row.get("threatName") or row.get("taskName") or row.get("serviceName") or row.get("image") or row.get("path") or row.get("url") or row.get("commandLine") or row.get("name") or kind
    row["summary"] = f"{artifact}: {label}"[:2000]
    if row.get("message") and artifact == "defender":
        row["summary"] = f"defender: {row['message']}"[:2000]
    return row


class TriagePass:
    """Run the chosen dissect functions over a target and hand back rows, keeping per-function
    outcomes so the coverage table can say what ran, what was absent and what was cut short."""

    def __init__(self, target_path: str, tmp_dir: str, context: dict[str, Any], *, filesystem: bool = False, deadline_s: float | None = None) -> None:
        self.target_path = target_path
        self.tmp_dir = tmp_dir
        self.context = dict(context)
        self.functions = FUNCTIONS + (FILESYSTEM_FUNCTIONS if filesystem else ())
        self.deadline_s = deadline_s
        self.summary: dict[str, dict[str, Any]] = {}
        self.target: dict[str, Any] = {}

    def __iter__(self) -> Iterator[tuple[str, dict[str, Any]]]:
        from services.parsers import native

        artifact_of = {name: artifact for name, artifact, _cap in self.functions}
        counts: dict[str, int] = {}
        for line in native.triage_records(self.target_path, self.tmp_dir, [(name, cap) for name, _artifact, cap in self.functions], deadline_s=self.deadline_s):
            if "_target" in line:
                self.target = dict(line["_target"])
                if self.target.get("hostname") and not self.context.get("host"):
                    self.context["host"] = self.target["hostname"]
                continue
            fn = line.get("_fn")
            if not isinstance(fn, str):
                continue
            if "r" in line:
                rec = line["r"]
                if not isinstance(rec, dict):
                    continue
                index = counts.get(fn, 0)
                counts[fn] = index + 1
                row = to_row(fn, artifact_of.get(fn, "unknown"), rec, index, self.context)
                if row is not None:
                    yield fn, row
            elif "skipped" in line:
                self.summary[fn] = {"status": "unsupported", "count": 0, "reason": str(line["skipped"])[:300]}
            elif "failed" in line:
                self.summary[fn] = {"status": "error", "count": int(line.get("done") or 0), "reason": str(line["failed"])[:300]}
            elif "done" in line:
                note = f"stopped at {line['done']:,} records, the cap for this artifact" if line.get("truncated") else None
                self.summary[fn] = {"status": "parsed", "count": int(line["done"]), "note": note}
        for name, _artifact, _cap in self.functions:
            self.summary.setdefault(name, {"status": "error", "count": counts.get(name, 0), "reason": "the triage worker ended before this function reported"})


def frame(fn: str, rec: dict[str, Any]) -> str:
    """The line format the worker writes: kept here so both ends agree on it."""
    return json.dumps({"_fn": fn, "r": rec}, ensure_ascii=False)
