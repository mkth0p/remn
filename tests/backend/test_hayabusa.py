"""Hayabusa as a detection engine: its output becomes findings linked to the rows REMN parsed.

The engine itself is not part of the test suite. A stand-in script plays it: it accepts the same
arguments, writes the JSONL the real one writes, and can be told to hang so the bound is tested.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings

from services.analysis import hayabusa

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "samples" / "synthetic"))
from evtx_writer import EvtxWriter, event_node  # noqa: E402

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
STAMP = "2026-08-19T01:34:26+00:00"

DETECTION = {
    "Timestamp": "2026-08-19 01:34:26.000 +00:00",
    "Computer": "WS01",
    "Channel": "Security",
    "EventID": 4688,
    "Level": "high",
    "RecordID": 1,
    "RuleTitle": "Suspicious Process Creation In Downloads",
    "Details": {"Cmdline": "C:\\Users\\jdoe\\Downloads\\upd.exe /silent", "User": "jdoe"},
    "ExtraFieldInfo": {},
    "RuleFile": "proc_creation_win_susp_downloads_exec.yml",
    "RuleID": "0d3c4a5b-0000-4000-8000-000000000001",
    "EvtxFile": "Security.evtx",
    "MitreTactics": ["Execution"],
    "MitreTags": ["T1204.002"],
    "OtherTags": ["attack.t1204.002", "sysmon"],
    "Provider": "Microsoft-Windows-Security-Auditing",
}

FAKE_ENGINE = r"""
import os, shutil, sys, time
args = sys.argv[1:]
output = args[args.index("-o") + 1]
target = args[args.index("-f") + 1] if "-f" in args else args[args.index("-d") + 1]
assert os.path.exists(target), target
if "-d" in args:
    assert any(n.lower().endswith(".evtx") for n in os.listdir(target)), os.listdir(target)
if os.environ.get("FAKE_HAYABUSA_SEEN"):
    # what the engine was handed: each file's name and whether it is an event log at all
    files = [os.path.join(target, n) for n in sorted(os.listdir(target))] if os.path.isdir(target) else [target]
    with open(os.environ["FAKE_HAYABUSA_SEEN"], "a", encoding="utf-8") as seen:
        for path in files:
            with open(path, "rb") as fh:
                seen.write(os.path.basename(path) + " " + str(fh.read(8) == b"ElfFile\x00") + "\n")
shutil.copyfile(os.environ["FAKE_HAYABUSA_OUTPUT"], output)
time.sleep(float(os.environ.get("FAKE_HAYABUSA_SLEEP", "0")))
"""


@pytest.fixture
def engine(tmp_path, monkeypatch):
    """Point the module at the stand-in and make it report itself available."""
    script = tmp_path / "fake_hayabusa.py"
    script.write_text(FAKE_ENGINE, encoding="utf-8")
    fixture = tmp_path / "detections.jsonl"
    fixture.write_text(json.dumps(DETECTION) + "\n" + "not json\n", encoding="utf-8")
    monkeypatch.setenv("FAKE_HAYABUSA_OUTPUT", str(fixture))
    monkeypatch.setattr(hayabusa, "binary", lambda: sys.executable)
    monkeypatch.setattr(hayabusa, "rules_dir", lambda: str(tmp_path))
    monkeypatch.setattr(
        hayabusa, "command", lambda target, output: [sys.executable, str(script), "-o", output, "-f" if os.path.isfile(target) else "-d", target]
    )
    return fixture


def evtx_bytes() -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "Security.evtx"
        with EvtxWriter(path) as writer:
            writer.add(
                event_node(
                    1,
                    STAMP,
                    "Microsoft-Windows-Security-Auditing",
                    "Security",
                    "WS01",
                    4688,
                    {"NewProcessName": "C:\\Users\\jdoe\\Downloads\\upd.exe", "SubjectUserName": "jdoe"},
                ),
                int(datetime.fromisoformat(STAMP).timestamp() * 1000),
            )
        return path.read_bytes()


def test_a_detection_becomes_a_finding_that_names_its_row():
    finding = hayabusa.to_finding(DETECTION)

    assert finding["ruleId"] == "engine:hayabusa:proc-creation-win-susp-downloads-exec"
    assert finding["title"] == "Suspicious Process Creation In Downloads" and finding["severity"] == "high"
    assert finding["ts"] == int(datetime.fromisoformat(STAMP).timestamp() * 1000)
    assert finding["entities"] == {"computer": "WS01", "channel": "Security", "eventId": "4688", "provider": "Microsoft-Windows-Security-Auditing"}
    assert finding["attack"] == ["T1204.002"]
    assert "engine:hayabusa" in finding["tags"] and "tactic:Execution" in finding["tags"]
    assert finding["refKeys"] == ["WS01|Security|1"] and finding["refs"] == []
    assert "upd.exe" in finding["description"]
    assert hayabusa.to_finding({"Level": "high"}) is None, "no title, no finding"
    assert hayabusa.to_finding({**DETECTION, "Level": "crit"})["severity"] == "critical"
    assert hayabusa.to_finding({**DETECTION, "Level": "informational"})["severity"] == "info"


def test_without_the_binary_nothing_runs(monkeypatch):
    monkeypatch.setattr(hayabusa, "binary", lambda: None)
    assert hayabusa.available() is False and hayabusa.engines() == []


def test_the_engine_runs_bounded_and_keeps_what_it_wrote(engine, tmp_path, monkeypatch):
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(evtx_bytes())

    findings, summary = hayabusa.run(str(evtx), str(tmp_path))
    assert summary["status"] == "parsed" and summary["findings"] == 1 and len(findings) == 1

    monkeypatch.setenv("FAKE_HAYABUSA_SLEEP", "5")
    with override_settings(HAYABUSA_MAX_S=1):
        findings, summary = hayabusa.run(str(evtx), str(tmp_path))
    assert summary["status"] == "error" and "time limit" in summary["reason"]
    assert len(findings) == 1, "detections written before the limit are kept"
    assert not [p for p in tmp_path.iterdir() if p.suffix == ".jsonl" and p.name != "detections.jsonl"], "the output file is removed"


def test_an_evtx_ingest_stream_carries_the_engine_findings(engine, tmp_path):
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path):
        response = Client().post("/api/ingest/evtx", {"file": SimpleUploadedFile("Security.evtx", evtx_bytes())}, **HDR)
        assert response.status_code == 200
        lines = [json.loads(line) for line in b"".join(response.streaming_content).splitlines() if line.strip()]

    meta = lines[0]
    assert meta["type"] == "meta" and meta["engines"] == ["hayabusa"], "the client is told to build the link index"
    events = [line for line in lines if line["type"] == "event"]
    findings = [line for line in lines if line["type"] == "finding"]
    summaries = [line for line in lines if line["type"] == "engine"]
    assert events and findings and summaries
    assert findings[0]["refKeys"] == [f"{events[0]['computer']}|{events[0]['channel']}|{events[0]['recordId']}"], (
        "the key the browser will resolve is the identity the row carries"
    )
    assert summaries[0]["engine"] == "hayabusa" and summaries[0]["status"] == "parsed"
    assert lines[-1]["type"] == "done"


def test_a_package_hands_its_event_logs_to_the_engine_once(engine, tmp_path):
    from services.ingest.package import PackageSource
    from services.parsers.mail.common import ParseContext

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("Security Event Log/Security.evtx", evtx_bytes())
        z.writestr("Security Event Log/System.evtx", evtx_bytes())
    staging = tmp_path / "staging"
    staging.mkdir()
    package = PackageSource("pkg.zip", None, out.getvalue(), str(staging), ParseContext(analyze_attachments=False))
    package.engines = ["hayabusa"]
    rows = list(package)

    assert sum(1 for r in rows if r["type"] == "event") == 2, "the rows are still parsed by REMN"
    assert not [r for r in rows if r.get("type") == "finding"], "findings are collected, never mixed into the rows"
    assert len(package.findings) == 1 and package.findings[0]["ruleId"].startswith("engine:hayabusa:")
    assert package.engine_summaries[0]["members"] == 2, "both logs went to one engine run"
    assert package.budget["deferredBytes"] == 0 and not package.evtx_held, "the held logs are released"
    assert not list(staging.iterdir()), "nothing staged is left behind"


def test_an_event_log_past_the_hold_allowance_is_said_to_be_unscanned(engine, tmp_path, monkeypatch):
    """The engine reads the logs held back for it, and the hold has a ceiling. A log past it was
    parsed but never scanned, and neither the member nor the engine's summary said so."""
    from services.ingest import package as P
    from services.ingest.package import PackageSource
    from services.parsers.mail.common import ParseContext

    log = evtx_bytes()
    monkeypatch.setattr(P, "MAX_DEFERRED_BYTES", len(log) + 1024)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("Logs/Security.evtx", log)
        z.writestr("Logs/System.evtx", log)
    staging = tmp_path / "staging"
    staging.mkdir()
    package = PackageSource("pkg.zip", None, out.getvalue(), str(staging), ParseContext(analyze_attachments=False))
    package.engines = ["hayabusa"]
    rows = list(package)

    assert sum(1 for r in rows if r["type"] == "event") == 2, "both logs are still in the case"
    summary = package.engine_summaries[0]
    assert summary["members"] == 1 and summary["notScanned"] == 1
    assert summary["status"] != "parsed" and "1 event log(s)" in summary["reason"] and "not scanned" in summary["reason"]
    files = {f["name"]: f for f in package.files}
    assert files["Logs/Security.evtx"]["status"] == "parsed" and "note" not in files["Logs/Security.evtx"]
    assert files["Logs/System.evtx"]["status"] == "parsed" and "not scanned by hayabusa" in files["Logs/System.evtx"]["note"]
    assert not list(staging.iterdir()), "nothing staged is left behind"


def test_when_no_event_log_fits_the_hold_the_engine_summary_still_says_so(engine, tmp_path, monkeypatch):
    from services.ingest import package as P
    from services.ingest.package import PackageSource
    from services.parsers.mail.common import ParseContext

    monkeypatch.setattr(P, "MAX_DEFERRED_BYTES", 1024)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("Logs/Security.evtx", evtx_bytes())
    package = PackageSource("pkg.zip", None, out.getvalue(), str(tmp_path), ParseContext(analyze_attachments=False))
    package.engines = ["hayabusa"]
    list(package)

    assert not package.findings
    [summary] = package.engine_summaries
    assert summary["engine"] == "hayabusa" and summary["status"] == "unsupported" and summary["notScanned"] == 1
    assert "not scanned" in summary["reason"]


def _seen(path: Path) -> list[tuple[str, bool]]:
    if not path.exists():
        return []
    return [(name, flag == "True") for name, flag in (line.rsplit(" ", 1) for line in path.read_text(encoding="utf-8").splitlines())]


def _logs_zip() -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("host1/Security.evtx", evtx_bytes())
        z.writestr("host1/System.evtx", evtx_bytes())
        z.writestr("host1/notes.txt", "collected by the lab script\n")
    return out.getvalue()


def test_an_archive_of_event_logs_hands_the_engine_its_logs_not_the_archive(engine, tmp_path, monkeypatch):
    """Event logs ingested as a zip went to the engine as the zip itself, renamed .evtx, so it read
    nothing and the summary looked like a clean run."""
    seen = tmp_path / "seen.txt"
    monkeypatch.setenv("FAKE_HAYABUSA_SEEN", str(seen))
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path):
        response = Client().post("/api/ingest/evtx", {"file": SimpleUploadedFile("logs.zip", _logs_zip())}, **HDR)
        assert response.status_code == 200
        lines = [json.loads(line) for line in b"".join(response.streaming_content).splitlines() if line.strip()]

    assert sum(1 for line in lines if line["type"] == "event") == 2
    assert [flag for _name, flag in _seen(seen)] == [True, True], _seen(seen)
    assert sorted(name.split("-", 1)[1] for name, _flag in _seen(seen)) == ["Security.evtx", "System.evtx"]
    [summary] = [line for line in lines if line["type"] == "engine"]
    assert summary["status"] == "parsed" and summary["members"] == 2
    assert [line for line in lines if line["type"] == "finding"]


def test_event_records_exported_as_xml_are_not_handed_to_the_engine(engine, tmp_path, monkeypatch):
    seen = tmp_path / "seen.txt"
    monkeypatch.setenv("FAKE_HAYABUSA_SEEN", str(seen))
    xml = (
        '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID>'
        '<TimeCreated SystemTime="2026-08-19T01:34:26.000Z"/><EventRecordID>1</EventRecordID>'
        "<Channel>Security</Channel><Computer>WS01</Computer></System></Event></Events>"
    )
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path):
        response = Client().post("/api/ingest/evtx", {"file": SimpleUploadedFile("Security.xml", xml.encode())}, **HDR)
        lines = [json.loads(line) for line in b"".join(response.streaming_content).splitlines() if line.strip()]

    assert lines[0]["format"] == "event-xml" and sum(1 for line in lines if line["type"] == "event") == 1
    assert _seen(seen) == [], "the engine was not started on a file it cannot read"
    [summary] = [line for line in lines if line["type"] == "engine"]
    assert summary["status"] == "unsupported" and "not scanned" in summary["reason"] and "event-xml" in summary["reason"]


def test_staging_an_archive_counts_the_logs_past_its_ceiling(tmp_path, monkeypatch):
    archive = tmp_path / "logs.zip"
    archive.write_bytes(_logs_zip())
    log_size = len(evtx_bytes())
    monkeypatch.setattr(hayabusa, "_stage_ceiling", lambda: log_size + 1024)
    staged, said = hayabusa.stage_upload("logs.zip", str(archive), None, "zip", str(tmp_path))
    try:
        assert len(os.listdir(staged)) == 1
        assert said["members"] == 1 and said["notScanned"] == 1 and "1 event log(s)" in said["reason"]
    finally:
        shutil.rmtree(staged, ignore_errors=True)


def test_staging_an_archive_counts_the_logs_its_walk_passed_over(tmp_path, monkeypatch):
    """An event log the archive walk does not hand over (here past the archive's expansion
    allowance, lowered so the invented fixture stays small) is a log the engine did not scan."""
    from services.ingest import pipeline

    monkeypatch.setattr(pipeline, "RATIO_FLOOR", 1024**2)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(3):
            z.writestr(f"Logs/padded{i}.evtx", bytes(600 * 1024))
    staged, said = hayabusa.stage_upload("logs.zip", None, out.getvalue(), "zip", str(tmp_path))
    try:
        assert len(os.listdir(staged)) == 1
        assert said["members"] == 1 and said["notScanned"] == 2, said
        assert "2 event log(s)" in said["reason"] and "times its own size" in said["reason"], said
    finally:
        shutil.rmtree(staged, ignore_errors=True)


def test_a_server_store_ingest_of_an_archive_hands_the_engine_its_logs(engine, settings, tmp_path, monkeypatch):
    import time
    import uuid

    from services.store.casestore import registry

    seen = tmp_path / "seen.txt"
    monkeypatch.setenv("FAKE_HAYABUSA_SEEN", str(seen))
    settings.CASES_DIR = tmp_path / "cases"
    settings.FILE_UPLOAD_TEMP_DIR = tmp_path
    registry.configure(settings.CASES_DIR)
    data = _logs_zip()
    c = Client()
    r = c.post("/api/upload/init", data=json.dumps({"name": "logs.zip", "size": len(data)}), content_type="application/json", **HDR)
    upload_id = r.json()["uploadId"]
    c.generic("PUT", f"/api/upload/{upload_id}/chunk?offset=0", data, content_type="application/octet-stream", **HDR)
    sha = c.post(f"/api/upload/{upload_id}/complete", **HDR).json()["sha256"]
    key = str(uuid.uuid4())
    r = c.post(
        f"/api/store/{key}/ingest",
        data=json.dumps({"uploadId": upload_id, "kind": "evtx", "evidence": {"id": 7, "name": "logs.zip", "sha256Client": sha}}),
        content_type="application/json",
        **HDR,
    )
    job_id = r.json()["jobId"]
    for _ in range(600):
        j = c.get(f"/api/jobs/{job_id}?case={key}", **HDR).json()
        if j["status"] in ("done", "error", "cancelled"):
            break
        time.sleep(0.1)
    assert j["status"] == "done", j
    assert [flag for _name, flag in _seen(seen)] == [True, True], _seen(seen)


def test_refs_resolve_against_a_server_store(tmp_path):
    import uuid

    from services.store.casestore import StoreRegistry
    from services.store.writers import EventWriter

    registry = StoreRegistry()
    registry.configure(tmp_path / "cases")
    try:
        store = registry.get(str(uuid.uuid4()))
        writer = EventWriter(store, 7)
        writer.add({"computer": "WS01", "channel": "Security", "recordId": 1, "eventId": 4688, "ts": None})
        writer.add({"computer": "WS01", "channel": "Security", "recordId": 2, "eventId": 4624, "ts": None})
        writer.flush()
        finding = hayabusa.to_finding(DETECTION)
        resolved = hayabusa.resolve_refs(store, 7, [finding])
    finally:
        registry.close_all()

    assert len(resolved[0]["refs"]) == 1 and "refKeys" not in resolved[0]


def test_only_one_engine_run_at_a_time_and_the_other_ingest_carries_on(engine, tmp_path, monkeypatch):
    """Two uploads at once must not add up to the container's memory limit. The second finds the
    slot taken, waits briefly, and finishes its ingest without the engine rather than queueing."""
    import threading

    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(evtx_bytes())
    monkeypatch.setenv("FAKE_HAYABUSA_SLEEP", "3")
    results: list[tuple[list, dict]] = []

    def one():
        with override_settings(HAYABUSA_WAIT_S=1, HAYABUSA_CONCURRENCY=1):
            results.append(hayabusa.run(str(evtx), str(tmp_path)))

    workers = [threading.Thread(target=one) for _ in range(2)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()

    statuses = sorted(summary["status"] for _findings, summary in results)
    assert statuses == ["parsed", "unsupported"], results
    busy = next(summary for _f, summary in results if summary["status"] == "unsupported")
    assert "busy" in busy["reason"]
    assert not [p for p in tmp_path.iterdir() if p.suffix == ".jsonl" and p.name != "detections.jsonl"], "the declined run leaves no output file"
