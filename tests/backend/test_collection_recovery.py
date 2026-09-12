"""What a real collection export does wrong, and what the parser owes the analyst anyway.

Every case here was found in a genuine investigation package and reduced to a synthetic file with
the same defect. The theme is the same throughout: a limit or a strictness that discarded evidence
rather than degrading, so a member the parser understands perfectly well was reported as one it
did not.
"""

from __future__ import annotations

import io
import tempfile
import zipfile

from services.ingest.package import PackageSource
from services.parsers.collection import records
from services.parsers.mail.common import ParseContext

HEADER = "Name,Started,StartMode,DisplayName,PathName,ProcessId"


def parse(tmp_path, body: bytes, name="Services/Services.csv"):
    """Run one export through the parser and hand back its rows and its parse notes."""
    path = tmp_path / "member"
    path.write_bytes(body)
    notes: dict = {}
    return list(records(str(path), name, notes)), notes


def test_a_service_export_with_merged_columns_is_recovered_not_discarded(tmp_path):
    """The exporter quotes a run of columns as one cell, 'True','Auto', so the row is a field or
    five short. This cost a real collection every one of its 292 service rows."""
    body = (
        f"{HEADER}\n"
        'svc-clean,True,Auto,A clean row,C:\\Windows\\a.exe,101\n'
        "svc-merged,\"'True','Auto'\",Two columns in one cell,C:\\Windows\\b.exe,102\n"
        "svc-merged-3,\"'True','Auto','Three in one'\",C:\\Windows\\c.exe,103\n"
    ).encode()
    rows, notes = parse(tmp_path, body)

    assert len(rows) == 3, "no row is lost to the ragged ones"
    assert notes["repairedRows"] == 2
    assert "malformedRows" not in notes, "a repaired row is not also a damaged one"
    # the repair puts the values back under the right headers, which is the whole point
    assert [r["Name"] for r in rows] == ["svc-clean", "svc-merged", "svc-merged-3"]
    assert [r["Started"] for r in rows] == ["True", "True", "True"]
    assert [r["StartMode"] for r in rows] == ["Auto", "Auto", "Auto"]
    assert rows[0]["ProcessId"] == "101" and rows[1]["ProcessId"] == "102"


def test_a_row_that_cannot_be_repaired_is_kept_and_marked(tmp_path):
    """A stray quote in a description swallows a delimiter and no rule puts it back. The row is
    still evidence, so it is kept, and the mismatch is stated rather than implied."""
    body = (
        f"{HEADER}\n"
        "svc-long,True,Auto,Name,C:\\a.exe,101,surplus,more\n"
        "svc-short,True\n"
    ).encode()
    rows, notes = parse(tmp_path, body)

    assert len(rows) == 2
    assert notes["malformedRows"] == 2
    assert rows[0]["_unmappedValues"] == "surplus | more", "surplus values are kept, not dropped"
    assert rows[1]["_partialRow"] == "2 of 6 values"
    assert rows[1]["StartMode"] == "", "a missing trailing column reads as absent, not as None"


def test_a_well_formed_export_is_not_touched_by_the_repair(tmp_path):
    """The repair only runs on a short row and only survives if it reproduces the header exactly,
    so a cell that genuinely holds a quoted list stays one cell."""
    body = (f"{HEADER}\n" "svc,True,Auto,\"'a','b'\",C:\\a.exe,101\n").encode()
    rows, notes = parse(tmp_path, body)

    assert notes == {}
    assert rows[0]["DisplayName"] == "'a','b'"


def test_a_utf16_log_with_no_byte_order_mark_is_read_as_text(tmp_path):
    """Defender writes several support logs as UTF-16 with nothing declaring it. Read as UTF-8
    some of them decode without raising at all, and every character comes back with a NUL after
    it, which then reaches the analyst as evidence."""
    body = "threat detected: Trojan:Win32/Synthetic\nline two\n".encode("utf-16-le")
    assert body[:2] not in (b"\xff\xfe", b"\xfe\xff"), "the fixture must not declare its encoding"

    rows, notes = parse(tmp_path, body, "WdSupportLogs/MPLog.txt")

    assert notes["encoding"] == "utf-16-le"
    assert rows[0]["Message"] == "threat detected: Trojan:Win32/Synthetic"
    assert "\x00" not in rows[0]["Message"]


def test_an_eight_bit_log_is_read_rather_than_thrown_away(tmp_path):
    """A strict UTF-8 decode discarded a nine-megabyte operational log over one byte."""
    body = "Ereignis: caf\u00e9 r\u00e9solu\nthreat detected\n".encode("cp1252")

    rows, notes = parse(tmp_path, body, "WdSupportLogs/setupact.log")

    assert notes["encoding"] == "cp1252"
    assert any("caf\u00e9" in r["Message"] for r in rows)


def test_a_defender_engine_log_is_reduced_to_the_lines_that_say_something(tmp_path):
    """A support cab carries a quarter of a million lines of scan bookkeeping. One row per line
    buries the few hundred that name a threat."""
    noise = "\n".join(f"Scanning resource number {i} of the volume" for i in range(2000))
    body = (noise + "\nThreat Name: Trojan:Win32/Synthetic\nQuarantine action taken\n").encode()

    rows, notes = parse(tmp_path, body, "WdSupportLogs/MPLog-20260101.log")

    assert notes["defenderScanned"] == 2002
    kept = {r["Message"] for r in rows}
    assert "Threat Name: Trojan:Win32/Synthetic" in kept and "Quarantine action taken" in kept
    assert len(rows) <= 2 + 2 * collection_context(), "context is bounded, not the whole file"
    assert not any(r["Message"].endswith("number 500 of the volume") for r in rows), "the bulk is still dropped"
    # line numbers still point into the original file, which is inventoried and hashed whole
    assert max(r["LineNumber"] for r in rows) == 2002


def collection_context():
    from services.parsers import collection

    return collection.DEFENDER_CONTEXT


def test_a_detection_keeps_the_lines_that_say_what_was_detected(tmp_path):
    """In a resource-scan block it is the neighbouring lines that carry the path of the file and
    the process that touched it. A filter that keeps the threat name and drops those reports that
    something was found while discarding what it was."""
    block = [
        "Begin Resource Scan",
        "Scan ID:{00000000-0000-0000-0000-000000000000}",
        "Resource Path:C:\\Users\\Public\\dropped.exe",
        "Threat Name:Trojan:Win32/Synthetic",
        "Original Name:invoice.pdf.exe",
        "Process Name:C:\\Windows\\explorer.exe",
        "End Scan",
    ]
    noise = [f"Scanning resource number {i}" for i in range(1000)]
    body = ("\n".join(noise + block) + "\n").encode()

    rows, _ = parse(tmp_path, body, "WdSupportLogs/MPLog-20260101.log")
    kept = {r["Message"] for r in rows}

    assert "Threat Name:Trojan:Win32/Synthetic" in kept
    assert "Resource Path:C:\\Users\\Public\\dropped.exe" in kept, "the file that was detected"
    assert "Original Name:invoice.pdf.exe" in kept, "what it was pretending to be"
    assert "Process Name:C:\\Windows\\explorer.exe" in kept, "the process it came through"


def test_a_defender_state_dump_is_kept_whole_however_long_it_is(tmp_path):
    """MPRegistry and MPStateInfo run to thousands of lines and every one is a fact about how the
    machine was configured. Filtering those by threat vocabulary keeps almost none of them."""
    body = "\n".join(f"HKLM\\SOFTWARE\\Policies\\Setting{i} [REG_DWORD] : 0x1" for i in range(1200)).encode()

    rows, notes = parse(tmp_path, body, "WdSupportLogs/MPRegistry.txt")

    assert len(rows) == 1200
    assert "defenderKept" not in notes


def test_a_small_defender_export_keeps_every_line(tmp_path):
    """MPDetection is fifty lines and every one of them is content. Filtering it would throw away
    the most useful file in the cab."""
    body = "\n".join(f"Setting {i}: value" for i in range(60)).encode()

    rows, notes = parse(tmp_path, body, "WdSupportLogs/MPStateInfo.txt")

    assert len(rows) == 60
    assert "defenderKept" not in notes


def test_a_long_text_export_keeps_what_it_read_instead_of_failing(tmp_path):
    """The line ceiling used to raise, which discarded every line already read."""
    from services.parsers import collection

    body = "\n".join(f"Item {i} : value" for i in range(collection.MAX_TEXT_LINES + 50)).encode()

    rows, notes = parse(tmp_path, body, "System/systeminfo.txt")

    assert notes["truncatedAtLine"] == collection.MAX_TEXT_LINES
    assert len(rows) > 0, "the lines read before the ceiling are evidence"


def test_a_collection_reports_the_compromises_it_made_on_the_member(tmp_path):
    """A member that parsed is not necessarily a member that parsed cleanly, and the coverage
    table is where an analyst finds that out."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr(
            "Services/Services.csv",
            f"{HEADER}\nsvc,\"'True','Auto'\",Merged,C:\\a.exe,7\n",
        )
        z.writestr("WdSupportLogs/MPLog.txt", "threat detected\nline\n".encode("utf-16-le"))

    with tempfile.TemporaryDirectory() as tmp_dir:
        source = PackageSource("pkg.zip", None, out.getvalue(), tmp_dir, ParseContext(analyze_attachments=False))
        list(source)

    by_name = {f["name"]: f for f in source.files}
    assert by_name["Services/Services.csv"]["status"] == "parsed"
    assert "merged by the exporter" in by_name["Services/Services.csv"]["note"]
    assert "UTF-16LE" in by_name["WdSupportLogs/MPLog.txt"]["note"]


def prefetch_package(count, damaged=0):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "samples" / "synthetic"))
    from native_artifacts import prefetch_bytes

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for i in range(count):
            z.writestr(f"Prefetch Files/GOOD-{i:04d}.pf", prefetch_bytes())
        for i in range(damaged):
            z.writestr(f"Prefetch Files/BAD-{i:04d}.pf", b"NOTA" + bytes(512))
    return out.getvalue()


def run_package(blob):
    with tempfile.TemporaryDirectory() as tmp_dir:
        source = PackageSource("pkg.zip", None, blob, tmp_dir, ParseContext(analyze_attachments=False))
        rows = list(source)
    return source, rows


def test_a_group_of_prefetch_artifacts_shares_one_worker(monkeypatch):
    """A real collection carries several hundred prefetch files. One interpreter start each spent
    the whole decoding allowance on process startup and left two thirds of them undecoded, which
    was then reported as unsupported: artifacts the parser understands, described as ones it does
    not."""
    from services.parsers import native

    started = []
    real_popen = native.subprocess.Popen

    def spy(command, *args, **kwargs):
        started.append(command)
        return real_popen(command, *args, **kwargs)

    monkeypatch.setattr(native.subprocess, "Popen", spy)

    source, rows = run_package(prefetch_package(12))

    assert [f["status"] for f in source.files] == ["parsed"] * 12
    assert len(rows) == 24, "each synthetic artifact records two runs, and every one contributes"
    assert len(started) == 1, f"twelve artifacts should cost one worker, not twelve: {len(started)}"
    assert source.budget["decodes"] == 12, "the group is still charged per artifact against the budget"


def test_one_damaged_artifact_does_not_cost_its_neighbours():
    """Damaged artifacts are the normal case in forensics. A group must report the failure against
    the artifact that caused it and keep the rest."""
    source, rows = run_package(prefetch_package(6, damaged=3))

    by_name = {f["name"]: f for f in source.files}
    assert all(by_name[f"Prefetch Files/GOOD-{i:04d}.pf"]["status"] == "parsed" for i in range(6))
    for i in range(3):
        bad = by_name[f"Prefetch Files/BAD-{i:04d}.pf"]
        assert bad["status"] == "error"
        assert "signature" in bad["reason"], bad["reason"]
        assert bad["sha256"], "a member that failed to decode is still hashed"
    assert len(rows) == 12, "the six intact artifacts still contribute two rows each"


def test_the_decoding_allowance_still_bounds_a_hostile_package(monkeypatch):
    """Grouping makes the allowance affordable for a real collection; it does not remove it."""
    from services.ingest import package as P

    monkeypatch.setattr(P, "MAX_NATIVE_DECODES", 4)
    source, rows = run_package(prefetch_package(10))

    spent = [f for f in source.files if f["status"] == "unsupported"]
    assert len(spent) == 6, [f["status"] for f in source.files]
    assert all("budget for this package is spent" in f["reason"] for f in spent)
    assert all(f["sha256"] for f in spent), "artifacts past the allowance are still inventoried and hashed"


def test_a_repaired_row_says_so_on_the_row(tmp_path):
    """Counting repairs on the member is not enough: a row seen in a table, a finding or an export
    carries no member with it, so it has to say for itself that it was reassembled."""
    from services.parsers import collection

    body = (f"{HEADER}\n" "svc,\"'True','Auto'\",Merged,C:\a.exe,7\n").encode()
    rows, notes = parse(tmp_path, body)

    assert notes["repairedRows"] == 1
    assert rows[0][collection.REPAIRED_KEY] == "5 cells split to 6"


def test_a_row_short_for_two_different_reasons_is_not_confidently_repaired(tmp_path):
    """Reaching the header width by combining several splits is a coincidence, not a repair, and a
    confident wrong answer is worse than an admitted damaged row."""
    body = (f"{HEADER}\n" "svc,\"'True','Auto'\",\"'x','y'\",7\n").encode()
    rows, notes = parse(tmp_path, body)

    assert notes.get("repairedRows") is None
    assert notes["malformedRows"] == 1
    assert rows[0]["_partialRow"] == "4 of 6 values"


def test_a_row_of_nothing_but_delimiters_cannot_build_an_unbounded_value(tmp_path):
    """Surplus values are kept rather than dropped, but a member that used to abort must not
    instead stream one enormous value back."""
    from services.parsers import collection

    body = (f"{HEADER}\n" + "a" + "," * 200_000 + "\n").encode()
    rows, notes = parse(tmp_path, body)

    assert notes["malformedRows"] == 1
    spill = rows[0][collection.SPILL_KEY]
    assert len(spill) <= collection.MAX_SPILL_CHARS + 64
    assert "more" in spill, "the values that did not fit are counted, not silently dropped"


def test_a_parser_marker_never_overwrites_a_column_the_export_really_has(tmp_path):
    """The markers are ordinary keys in the row dict, so an export carrying a column of the same
    name would have its value replaced by ours, and a clean export could forge one."""
    from services.parsers import collection

    header = f"Name,{collection.SPILL_KEY}"
    body = (f"{header}\n" "svc,mine,surplus\n").encode()
    rows, _ = parse(tmp_path, body)

    assert rows[0][collection.SPILL_KEY] == "mine", "the export's own column survives"
    assert rows[0][collection.SPILL_KEY + "_"] == "surplus"
