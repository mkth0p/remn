#!/usr/bin/env python
"""
OTRF's Security-Datasets (formerly Mordor) as recorded attacks: its atomic Windows datasets, each the
host logs of one lab run of one technique, labelled by its metadata with the ATT&CK techniques and
tactics it records.

    git clone --filter=blob:none --no-checkout https://github.com/OTRF/Security-Datasets
    git -C Security-Datasets checkout d9d40ef123d2c87d5d3df28c96bcab4f0faccc87 -- datasets/atomic/_metadata datasets/atomic/windows
    .venv/bin/python tools/security_datasets.py --root Security-Datasets       # list the recordings and read them

No REMN rule was written against these datasets: they were first run through REMN on 2026-09-28
(docs/reviews/2026-09-28-measures-across-libraries.md). A rule written after studying them goes in
WRITTEN_AGAINST in tools/measure_rules.py under "securityDatasets".

The host logs were shipped three ways, all as JSON, one record a line:
- NXLog through Logstash, 2019 to 2020 (EventTime, SeverityValue, the event's data beside them), the
  shape tools/apt29_stories.py reads for the APT29 evaluation, which comes from the same labs;
- NXLog without Logstash's fields, 2020 to 2023 (TimeCreated, Level as a string, Keywords in hex);
- Winlogbeat 6, 2019 (event_id, log_name, event_data).
EventTime and TimeCreated are the lab's local time, whatever their suffix says. A file's offset from
UTC is read from its Sysmon records, which carry their own UtcTime: the median gap, to the quarter
hour. A file without Sysmon records keeps its times as they are; its events stay in order, which
is all a rule's time window reads. Winlogbeat's @timestamp is UTC.

A dataset that lists several host files is one recording of them all. A zip's macOS resource forks
(__MACOSX/) are skipped.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import io
import json
import os
import statistics
import sys
import tarfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "tools"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "forensic.settings")

import yaml  # noqa: E402
from apt29_stories import SYSMON, nxlog_event  # noqa: E402

from services.parsers.evtx_parser import Lineage, flatten  # noqa: E402

PIN = {"repo": "OTRF/Security-Datasets", "sha": "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"}
METADATA = "datasets/atomic/_metadata"
# NXLog's fields of the later shape, beside the event's data
LATER_FIELDS = frozenset({"TimeCreated", "Level", "EventTypeOrignal", "@metadata"})
_LEVEL = {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "information": 4, "informational": 4, "warning": 3, "error": 2, "critical": 1, "verbose": 5}
TACTICS = {
    "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion", "TA0006": "Credential Access", "TA0007": "Discovery", "TA0008": "Lateral Movement",
    "TA0009": "Collection", "TA0010": "Exfiltration", "TA0011": "Command and Control", "TA0040": "Impact",
    "TA0042": "Resource Development", "TA0043": "Reconnaissance",
}  # fmt: skip


@dataclass
class Dataset:
    """One atomic Windows dataset: its metadata id, title, host files and labels."""

    id: str
    title: str
    files: list[Path]
    techniques: frozenset[str]
    tactics: tuple[str, ...]
    # host files the metadata lists that the checkout does not have
    missing: list[str] = field(default_factory=list)


def datasets(root: Path) -> list[Dataset]:
    """The atomic Windows datasets with host logs, by metadata id."""
    out = []
    for meta in sorted((root / METADATA).glob("SDWIN-*.yaml")):
        doc = yaml.safe_load(meta.read_text(encoding="utf-8")) or {}
        tech, tactics = set(), []
        for m in doc.get("attack_mappings") or []:
            if not isinstance(m, dict) or not m.get("technique"):
                continue
            sub = str(m.get("sub-technique") or "").strip()
            tech.add(str(m["technique"]).strip() + (f".{sub.zfill(3)}" if sub else ""))
            tactics += [TACTICS.get(str(t), str(t)) for t in m.get("tactics") or [] if str(t) not in tactics]
        files, missing = [], []
        for f in doc.get("files") or []:
            if not isinstance(f, dict) or str(f.get("type", "")).lower() != "host":
                continue
            rel = str(f.get("link", "")).split("/master/", 1)[-1]
            (files if (root / rel).is_file() else missing).append(root / rel if (root / rel).is_file() else rel)
        if files or missing:
            out.append(
                Dataset(str(doc.get("id") or meta.stem), str(doc.get("title") or meta.stem), files, frozenset(tech), tuple(dict.fromkeys(tactics)), missing)
            )
    return out


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------
def _members(path: Path) -> Iterator[tuple[str, bytes]]:
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as zf:
            for n in zf.namelist():
                if not n.endswith("/") and not n.startswith("__MACOSX/"):
                    yield n, zf.read(n)
    elif path.name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(path) as tf:
            for m in tf.getmembers():
                if m.isfile() and not Path(m.name).name.startswith("._"):
                    yield m.name, tf.extractfile(m).read()  # type: ignore[union-attr]
    else:
        yield path.name, path.read_bytes()


def _text(b: bytes) -> str:
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16")
    return b.decode("utf-8-sig", errors="replace")


def records(path: Path) -> Iterator[tuple[str, list[dict[str, Any]], int]]:
    """Each member of a host file: its name, its records, and the lines that were not JSON."""
    for name, raw in _members(path):
        out, bad = [], 0
        for line in io.StringIO(_text(raw)):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                bad += 1
                continue
            if isinstance(rec, dict):
                out.append(rec)
        yield name, out, bad


def _local(rec: dict[str, Any]) -> dt.datetime | None:
    raw = rec.get("EventTime") or rec.get("TimeCreated")
    if not raw:
        return None
    try:
        return dt.datetime.fromisoformat(str(raw).replace("Z", "").replace("T", " ")).replace(tzinfo=None)
    except ValueError:
        return None


def _sysmon_utc(rec: dict[str, Any]) -> dt.datetime | None:
    if rec.get("SourceName") != SYSMON or not rec.get("UtcTime"):
        return None
    try:
        return dt.datetime.fromisoformat(str(rec["UtcTime"]))
    except ValueError:
        return None


def offset(recs: list[dict[str, Any]]) -> dt.timedelta:
    """Local time minus UTC, from the Sysmon records' own UtcTime, to the quarter hour; zero without them."""
    gaps = []
    for r in recs:
        u, t = _sysmon_utc(r), _local(r)
        if u and t:
            gaps.append((t - u).total_seconds())
    if not gaps:
        return dt.timedelta(0)
    return dt.timedelta(minutes=round(statistics.median(gaps) / 900) * 15)


def _winlogbeat_event(rec: dict[str, Any]) -> dict[str, Any]:
    """A Winlogbeat 6 record as the event an .evtx gives for it."""
    when = str(rec.get("@timestamp") or "")
    system: dict[str, Any] = {
        "Provider": {"#attributes": {"Name": rec.get("source_name"), "Guid": rec.get("provider_guid")}},
        "EventID": int(rec.get("event_id") or 0),
        "Version": rec.get("version"),
        "Level": _LEVEL.get(str(rec.get("level") or "").lower()),
        "TimeCreated": {"#attributes": {"SystemTime": when}},
        "EventRecordID": rec.get("record_number"),
        "Execution": {"#attributes": {"ProcessID": rec.get("process_id"), "ThreadID": rec.get("thread_id")}},
        "Channel": rec.get("log_name"),
        "Computer": rec.get("computer_name"),
    }
    user = rec.get("user")
    if isinstance(user, dict) and user.get("identifier"):
        system["Security"] = {"#attributes": {"UserID": user["identifier"]}}
    event: dict[str, Any] = {"System": system, "EventData": {k: v if isinstance(v, str) else json.dumps(v) for k, v in (rec.get("event_data") or {}).items()}}
    if isinstance(rec.get("user_data"), dict):
        event["UserData"] = rec["user_data"]
    return {"Event": event}


def _nxlog_event(rec: dict[str, Any], shift: dt.timedelta) -> dict[str, Any]:
    local = _local(rec)
    when = _sysmon_utc(rec) or (local - shift if local else None)
    rec = dict(rec)
    if "TimeCreated" in rec:
        # the later shape: Keywords in hex, Level as a string, no SeverityValue
        kw = rec.get("Keywords")
        if isinstance(kw, str):
            try:
                rec["Keywords"] = int(kw, 0)
            except ValueError:
                rec.pop("Keywords")
        level = _LEVEL.get(str(rec.get("Level") or "").lower())
        rec = {k: v for k, v in rec.items() if k not in LATER_FIELDS}
        event = nxlog_event(rec, when.replace(tzinfo=dt.UTC) if when else None)
        event["Event"]["System"]["Level"] = level
        return event
    rec.pop("EventTypeOrignal", None)
    return nxlog_event(rec, when.replace(tzinfo=dt.UTC) if when else None)


@dataclass
class Read:
    records: int = 0
    unread: int = 0
    shapes: collections.Counter = field(default_factory=collections.Counter)
    offsets: dict[str, float] = field(default_factory=dict)


def rows(files: list[Path], include_raw: bool = True, read: Read | None = None) -> Iterator[dict[str, Any]]:
    """The rows of a dataset's host files, as an upload of the same records' .evtx files gives them."""
    read = read if read is not None else Read()
    for path in files:
        for name, recs, bad in records(path):
            read.unread += bad
            shift = offset(recs)
            read.offsets[name] = shift.total_seconds() / 3600
            lineage = Lineage()
            for rec in recs:
                if "event_id" in rec and "log_name" in rec:
                    read.shapes["winlogbeat"] += 1
                    event = _winlogbeat_event(rec)
                else:
                    read.shapes["nxlog-later" if "TimeCreated" in rec else "nxlog"] += 1
                    event = _nxlog_event(rec, shift)
                row = flatten(event, include_raw=include_raw)
                row["sourceFile"] = Path(name).name
                lineage.apply(row)
                read.records += 1
                yield row


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, required=True, help="the Security-Datasets checkout")
    ap.add_argument("--read", action="store_true", help="read every dataset's records and count them")
    args = ap.parse_args(argv)
    ds = datasets(args.root)
    missing = [m for d in ds for m in d.missing]
    print(f"{len(ds)} atomic Windows datasets with host logs, {sum(len(d.files) for d in ds)} host files ({len(missing)} listed but not in the checkout)")
    tactic = collections.Counter(t for d in ds for t in d.tactics[:1])
    print("first tactic:", ", ".join(f"{t} {n}" for t, n in tactic.most_common()))
    if args.read:
        total = Read()
        for d in ds:
            r = Read()
            n = sum(1 for _ in rows(d.files, include_raw=False, read=r))
            total.records += n
            total.unread += r.unread
            total.shapes.update(r.shapes)
            print(f"{d.id} {n:>8} {dict(r.shapes)} offsets {sorted(set(r.offsets.values()))} {d.title}")
        print(f"{total.records:,} records, {total.unread} lines not JSON, shapes {dict(total.shapes)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
