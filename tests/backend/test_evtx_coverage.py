"""What an EVTX file says about its own completeness: holes in its record numbering, write times
that run backwards, and chunks that fail their checksum."""

from __future__ import annotations

import hashlib
import io
import random
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from services.ingest.package import PackageSource
from services.ingest.pipeline import EvtxSource
from services.parsers import evtx_parser
from services.parsers.mail.common import ParseContext

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "samples" / "synthetic"))
from evtx_writer import EvtxWriter, event_node  # noqa: E402

T0 = 1_788_000_000_000


def iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def write(path: Path, stamps: list[int], skip: dict[int, int] | None = None, host: str = "WS01") -> Path:
    """One Security record per write time. skip maps a record's position to the number of ids left
    out before it, the way a record deleted from the log leaves its id unused."""
    with EvtxWriter(path) as w:
        for i, ts in enumerate(stamps):
            w.count += (skip or {}).get(i, 0)
            node = event_node(w.count + 1, iso(ts), "Microsoft-Windows-Security-Auditing", "Security", host, 4624, {"TargetUserName": "alice"})
            w.add(node, ts)
    return path


def read(path: Path, name: str = "Security.evtx") -> tuple[list[dict], dict]:
    stats = evtx_parser.Stats()
    rows = list(evtx_parser.iter_events(str(path), include_raw=False, stats=stats, source_file=name))
    return rows, stats.to_dict()


def test_the_record_header_time_is_read_with_its_utc_suffix():
    event = {"Event": {"System": {"EventID": 1, "Channel": "Security", "Computer": "WS01"}}}
    row = evtx_parser.flatten(event, {"event_record_id": 7, "timestamp": "2019-04-27T15:57:27.0876132Z UTC"})
    # the fallback when the event has no TimeCreated; it used to give no time at all
    assert row["ts"] == 1_556_380_647_087
    assert row["recordId"] == 7


def test_a_zero_write_time_is_no_time_and_no_step_back():
    # filtered exports (EVTX-ATTACK-SAMPLES has dozens) write the zero FILETIME on their last record
    assert evtx_parser.header_time({"timestamp": "1601-01-01T00:00:00Z UTC"}) is None
    event = {"Event": {"System": {"EventID": 1}}}
    assert evtx_parser.flatten(event, {"event_record_id": 2, "timestamp": "1601-01-01T00:00:00Z UTC"})["ts"] is None
    stats = evtx_parser.Stats()
    seq = stats.begin_file("x.evtx")
    seq.add(1, T0)
    seq.add(2, None)
    assert "backwards" not in stats.to_dict()["sequences"][0]


def test_a_file_sequence_follows_its_ids_in_any_order():
    rng = random.Random(5)
    ids = [i for i in range(1, 2001) if not 300 <= i <= 310 and i not in (999, 1500, 1501)]
    shuffled = ids + rng.sample(ids, 50)  # repeats change nothing
    rng.shuffle(shuffled)
    seq = evtx_parser.FileSequence("x.evtx")
    for rid in shuffled:
        seq.add(rid, None)
    out = seq.to_dict()
    assert (out["first"], out["last"]) == (1, 2000)
    assert out["holes"] == [[300, 310], [999, 999], [1500, 1501]]
    assert out["missing"] == 14 and out["holeCount"] == 3


def test_holes_and_backward_steps_are_found_in_a_written_file(tmp_path):
    stamps = [T0 + i * 60_000 for i in range(12)]
    stamps[9] = stamps[8] - 3 * 3_600_000  # the tenth record was written three hours before the ninth
    rows, stats = read(write(tmp_path / "Security.evtx", stamps, skip={5: 3}))
    assert len(rows) == 12 and stats["errors"] == 0
    (seq,) = stats["sequences"]
    assert seq["file"] == "Security.evtx" and seq["channel"] == "Security" and seq["computer"] == "WS01"
    assert (seq["first"], seq["last"]) == (1, 15)
    assert seq["holes"] == [[6, 8]] and seq["missing"] == 3
    assert seq["backwards"] == 1 and seq["backwardsMaxMs"] == 3 * 3_600_000
    # the step keeps both write times, for the clock changes and restarts of the case to explain
    assert seq["steps"] == [[13, stamps[8], stamps[9]]]
    assert seq["computerNames"] == ["WS01"]
    assert seq["checksums"] == {"chunks": 1, "fileHeader": True, "dirty": False}


def test_clock_changes_and_log_service_starts_are_listed(tmp_path):
    path = tmp_path / "System.evtx"
    with EvtxWriter(path) as w:
        events = [
            ("EventLog", 6005, {}),
            # set back an hour: listed
            ("Microsoft-Windows-Kernel-General", 1, {"NewTime": iso(T0 - 3_600_000), "OldTime": iso(T0 + 1000), "Reason": "2"}),
            # the time service's fraction of a second: not
            ("Microsoft-Windows-Kernel-General", 1, {"NewTime": iso(T0 + 2400), "OldTime": iso(T0 + 2000), "Reason": "3"}),
            # another provider's event 1: not a clock change
            ("Microsoft-Windows-Power-Troubleshooter", 1, {"NewTime": iso(T0), "OldTime": iso(T0 + 9_000_000)}),
        ]
        for i, (provider, eid, data) in enumerate(events):
            w.add(event_node(w.count + 1, iso(T0 + i * 1000), provider, "System", "WS01", eid, data), T0 + i * 1000)
    _rows, stats = read(path, "System.evtx")
    (seq,) = stats["sequences"]
    assert seq["logStarts"] == [{"computer": "WS01", "ts": T0}]
    assert seq["clockChanges"] == [{"computer": "WS01", "old": T0 + 1000, "new": T0 - 3_600_000}]


def test_a_complete_file_reports_no_gap(tmp_path):
    _rows, stats = read(write(tmp_path / "Security.evtx", [T0 + i * 1000 for i in range(50)]))
    (seq,) = stats["sequences"]
    assert seq["missing"] == 0 and "holes" not in seq and "backwards" not in seq


def test_a_record_changed_after_it_was_written_fails_its_chunk_checksum(tmp_path):
    path = write(tmp_path / "Security.evtx", [T0 + i * 1000 for i in range(20)])
    data = bytearray(path.read_bytes())
    at = data.index("alice".encode("utf-16le"), 4096 + 512)
    data[at] = ord("b")  # still a valid record, now naming another account
    path.write_bytes(bytes(data))
    rows, stats = read(path)
    # the parser reads the altered record without complaint: only the checksum tells
    assert stats["errors"] == 0 and any(r.get("targetUser") == "blice" for r in rows)
    assert stats["sequences"][0]["checksums"] == {"chunks": 1, "fileHeader": True, "dirty": False, "badData": [0], "badDataCount": 1}


def test_a_changed_chunk_header_and_file_header_are_named(tmp_path):
    path = write(tmp_path / "Security.evtx", [T0 + i * 1000 for i in range(5)])
    data = bytearray(path.read_bytes())
    data[4096 + 60] ^= 0xFF  # inside the chunk header's checked bytes
    data[30] ^= 0xFF  # inside the file header's checked bytes
    path.write_bytes(bytes(data))
    out = evtx_parser.chunk_checksums(str(path))
    assert out["fileHeader"] is False and out["badHeader"] == [0] and "badData" not in out


def test_a_stream_is_left_where_it_was_and_other_files_are_not_checked(tmp_path):
    blob = write(tmp_path / "Security.evtx", [T0]).read_bytes()
    stream = io.BytesIO(blob)
    stream.seek(17)
    assert evtx_parser.chunk_checksums(stream)["chunks"] == 1
    assert stream.tell() == 17
    assert evtx_parser.chunk_checksums(io.BytesIO(b"not an event log" * 300)) is None


def test_each_file_of_an_archive_keeps_its_own_sequence(tmp_path):
    first = write(tmp_path / "a.evtx", [T0 + i * 1000 for i in range(4)]).read_bytes()
    second = write(tmp_path / "b.evtx", [T0 + i * 1000 for i in range(6)], skip={2: 1}, host="DC01").read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("logs/Security.evtx", first)
        zf.writestr("logs/Archive-Security.evtx", second)
    source = EvtxSource("logs.zip", None, buf.getvalue(), str(tmp_path))
    assert len(list(source)) == 10
    seqs = {s["file"]: s for s in source.stats.to_dict()["sequences"]}
    assert seqs["logs/Security.evtx"]["missing"] == 0
    assert seqs["logs/Archive-Security.evtx"]["holes"] == [[3, 3]] and seqs["logs/Archive-Security.evtx"]["computer"] == "DC01"


def test_a_package_member_carries_its_sequence(tmp_path):
    log = write(tmp_path / "Security.evtx", [T0 + i * 1000 for i in range(8)], skip={4: 2}).read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("EventLogs/Security.evtx", log)
    blob = buf.getvalue()
    source = PackageSource("collection.zip", None, blob, str(tmp_path), ParseContext(analyze_attachments=False), package_id=hashlib.sha256(blob).hexdigest())
    assert len(list(source)) == 8
    member = next(f for f in source.stats()["files"] if f["name"] == "EventLogs/Security.evtx")
    assert member["status"] == "parsed"
    (seq,) = member["sequences"]
    assert seq["holes"] == [[5, 6]] and seq["checksums"]["chunks"] == 1
