"""Hayabusa as a detection engine: its output becomes findings linked to the rows REMN parsed.

The engine itself is not part of the test suite. A stand-in script plays it: it accepts the same
arguments, writes the JSONL the real one writes, and can be told to hang so the bound is tested.
"""

from __future__ import annotations

import io
import json
import os
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

FAKE_ENGINE = r'''
import os, shutil, sys, time
args = sys.argv[1:]
output = args[args.index("-o") + 1]
target = args[args.index("-f") + 1] if "-f" in args else args[args.index("-d") + 1]
assert os.path.exists(target), target
if "-d" in args:
    assert any(n.lower().endswith(".evtx") for n in os.listdir(target)), os.listdir(target)
shutil.copyfile(os.environ["FAKE_HAYABUSA_OUTPUT"], output)
time.sleep(float(os.environ.get("FAKE_HAYABUSA_SLEEP", "0")))
'''


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
    monkeypatch.setattr(hayabusa, "command", lambda target, output: [sys.executable, str(script), "-o", output, "-f" if os.path.isfile(target) else "-d", target])
    return fixture


def evtx_bytes() -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "Security.evtx"
        with EvtxWriter(path) as writer:
            writer.add(
                event_node(1, STAMP, "Microsoft-Windows-Security-Auditing", "Security", "WS01", 4688, {"NewProcessName": "C:\\Users\\jdoe\\Downloads\\upd.exe", "SubjectUserName": "jdoe"}),
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
    assert findings[0]["refKeys"] == [f"{events[0]['computer']}|{events[0]['channel']}|{events[0]['recordId']}"], "the key the browser will resolve is the identity the row carries"
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
