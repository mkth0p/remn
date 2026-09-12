"""A collection laid out like a drive is read by dissect, not by hand-written adapters.

The fixture is a synthetic drive: registry hives written from scratch with the structures dissect
reads, a prefetch file, a scheduled task, a Defender log and a PowerShell history. Nothing in it
was collected from a real machine, and everything in it goes through the real parsers.
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

import pytest

from services.ingest.package import PackageSource
from services.parsers import triage
from services.parsers.mail.common import ParseContext

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "samples" / "synthetic"))
from triage_fixture import write_triage  # noqa: E402


@pytest.fixture(scope="module")
def collection(tmp_path_factory):
    return write_triage(tmp_path_factory.mktemp("triage"))


def zipped(root: Path) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                z.write(path, path.relative_to(root).as_posix())
    return out.getvalue()


def test_the_layout_is_recognised_however_the_collector_spelled_the_drive():
    assert triage.is_triage_layout(["C/Windows/System32/config/SYSTEM"])
    assert triage.is_triage_layout(["uploads/auto/C%3A/Windows/System32/config/SYSTEM"])
    assert triage.is_triage_layout(["sysvol/windows/system32/config/SYSTEM"])
    assert triage.is_triage_layout(["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"])
    assert not triage.is_triage_layout(["Prefetch Files/A.pf", "Services/Services.csv"]), "an export collection is not a drive"
    assert not triage.is_triage_layout(["C_/ProgramData/Microsoft/Windows Defender/Support/MPLog.log"]), "a Defender cab has no system directory"


def test_the_worker_reads_the_collection_as_one_target(collection, tmp_path):
    """The real dissect plugins, in the real worker subprocess, over the synthetic drive."""
    from services.parsers import native

    functions = [(name, cap) for name, _artifact, cap in triage.FUNCTIONS]
    lines = list(native.triage_records(str(collection), str(tmp_path), functions))

    target = next(line["_target"] for line in lines if "_target" in line)
    assert target["os"] == "windows"
    by_fn: dict[str, list] = {}
    outcome: dict[str, dict] = {}
    for line in lines:
        if "r" in line:
            by_fn.setdefault(line["_fn"], []).append(line["r"])
        elif "_fn" in line:
            outcome[line["_fn"]] = line
    assert {r["name"] for r in by_fn["services"]} == {"Spooler", "SyncHelper"}
    assert outcome["services"]["done"] == 2
    assert any("svc.exe" in str(r.get("command")) for r in by_fn["runkeys"]), "the command field type must survive serialisation"
    assert "skipped" in outcome["amcache.files"], "an artifact the collection does not carry is skipped, not failed"
    assert not [fn for fn, o in outcome.items() if "failed" in o], [(fn, o["failed"]) for fn, o in outcome.items() if "failed" in o]


def test_records_become_rows_the_rules_can_read():
    service = triage.to_row("services", "service", {"_type": "windows/service", "ts": "2026-09-09T10:00:00+00:00", "name": "SyncHelper", "displayname": "Sync Helper", "imagepath": "C:\\Users\\Public\\svc.exe", "imagepath_args": "-k", "objectname": "LocalSystem", "start": "Auto Start (2)"}, 0, {"host": "WS01"})
    assert service["artifactType"] == "service" and service["serviceName"] == "SyncHelper"
    assert service["serviceFile"] == "C:\\Users\\Public\\svc.exe -k" and service["image"] == "C:\\Users\\Public\\svc.exe"
    assert service["recordKind"] == "event" and service["ts"] == 1788948000000

    run = triage.to_row("runkeys", "autorun", {"_type": "windows/registry/run", "name": "Dropper", "command": '"C:\\Users\\Public\\svc.exe" -k', "key": "HKLM\\...\\Run", "username": "jdoe"}, 0, {})
    assert run["image"] == '"C:\\Users\\Public\\svc.exe" -k' and run["targetObject"] == "HKLM\\...\\Run" and run["targetUser"] == "jdoe"

    action = triage.to_row("tasks", "task", {"_type": "filesystem/windows/task/action", "action_type": "Exec", "uri": "\\Updater", "command": "C:\\Users\\jdoe\\AppData\\Roaming\\upd.exe", "arguments": "/silent"}, 0, {})
    assert action["taskName"] == "\\Updater" and action["commandLine"] == "C:\\Users\\jdoe\\AppData\\Roaming\\upd.exe /silent"
    assert triage.to_row("tasks", "task", {"_type": "filesystem/windows/task/trigger", "uri": "\\Updater"}, 0, {}) is None

    detection = triage.to_row("defender.mplog", "defender", {"_type": "windows/defender/mplog/detectionadd", "ts": "2026-08-19T01:34:27.500000+00:00", "detection": "Trojan:Win32/Synthetic.A!ml file:C:\\Users\\jdoe\\Downloads\\invoice.pdf.exe"}, 0, {})
    assert detection["threatName"] == "Trojan:Win32/Synthetic.A!ml"
    assert detection["message"].startswith("detectionadd Trojan:Win32/Synthetic.A!ml")

    scan = triage.to_row("defender.mplog", "defender", {"_type": "windows/defender/mplog/resourcescan", "ts": "2026-08-19T01:34:26.112000+00:00", "resource_path": "C:\\Users\\jdoe\\Downloads\\invoice.pdf.exe", "threats": ["Trojan:Win32/Synthetic.A!ml"]}, 1, {})
    assert scan["threatName"] == "Trojan:Win32/Synthetic.A!ml" and scan["path"] == "C:\\Users\\jdoe\\Downloads\\invoice.pdf.exe"

    amcache = triage.to_row("amcache.application_files", "amcache", {"_type": "windows/appcompat/InventoryApplicationFile", "path": "C:\\Users\\jdoe\\Downloads\\upd.exe", "digest": {"md5": None, "sha1": "a" * 40, "sha256": None}, "publisher": "Contoso", "mtime_regf": "2026-09-01T10:00:00+00:00"}, 0, {})
    assert amcache["image"] == "C:\\Users\\jdoe\\Downloads\\upd.exe" and amcache["hashes"] == "SHA1=" + "a" * 40 and amcache["company"] == "Contoso"

    history = triage.to_row("browser.history", "browser-history", {"_type": "browser/history", "ts": "2026-09-02T08:00:00+00:00", "url": "http://198.51.100.7/stage.bin", "title": "stage", "browser": "edge", "username": "jdoe"}, 0, {})
    assert history["url"] == "http://198.51.100.7/stage.bin" and history["recordKind"] == "event"


def test_a_zipped_collection_yields_triage_rows_with_coverage(collection, tmp_path):
    """The whole path: a KAPE-style zip through PackageSource. Hives are no longer walked raw, the
    triage rows carry the fields the persistence rules read, and every function is accounted for."""
    source = PackageSource("triage.zip", None, zipped(collection), str(tmp_path), ParseContext(analyze_attachments=False))
    rows = list(source)

    assert source.triage is True
    by_type: dict[str, list] = {}
    for row in rows:
        by_type.setdefault(row.get("artifactType") or row["type"], []).append(row)
    assert {r["serviceName"] for r in by_type["service"]} == {"Spooler", "SyncHelper"}
    assert any(r.get("image") == "C:\\Users\\Public\\svc.exe" for r in by_type["service"])
    assert any(r.get("targetObject", "").endswith("\\Run") and "svc.exe" in str(r.get("image")) for r in by_type["autorun"])
    assert any(r.get("commandLine") == "C:\\Users\\jdoe\\AppData\\Roaming\\upd.exe /silent" for r in by_type["task"])
    assert any(r.get("threatName") == "Trojan:Win32/Synthetic.A!ml" for r in by_type["defender"])
    assert any("stage.bin" in str(r.get("commandLine")) for r in by_type["powershell-history"])
    assert by_type["prefetch"], "prefetch still comes from the member loop, with provenance per file"

    entries = {f["name"]: f for f in source.files}
    hives = [f for f in source.files if f.get("format") == "regf"]
    assert hives and all(f["status"] == "metadata" and "triage pass" in f["reason"] for f in hives)
    assert entries["triage!/services"]["status"] == "parsed" and entries["triage!/services"]["count"] == 2
    assert entries["triage!/amcache.files"]["status"] == "unsupported"
    assert all(f["status"] != "error" for f in source.files), [(f["name"], f.get("reason")) for f in source.files if f["status"] == "error"]
    assert source.triage_summary["target"]["os"] == "windows"
    assert all(r.get("sourceFile", "").startswith("triage!/") for r in by_type["service"])


def test_the_persistence_rules_fire_on_triage_rows(collection, tmp_path):
    import uuid

    import yaml

    from services.store.casestore import StoreRegistry
    from services.store.rules import run_rules
    from services.store.writers import EventWriter

    rules = {d["id"]: d for d in yaml.safe_load_all((Path(__file__).resolve().parents[2] / "rules" / "collection" / "host-artifacts.yaml").read_text(encoding="utf-8")) if isinstance(d, dict)}
    registry = StoreRegistry()
    registry.configure(tmp_path / "cases")
    try:
        store = registry.get(str(uuid.uuid4()))
        writer = EventWriter(store, 1)
        for row in PackageSource("triage.zip", None, zipped(collection), str(tmp_path), ParseContext(analyze_attachments=False)):
            if row["type"] == "event":
                writer.add(row)
        writer.flush()
        out = run_rules(store, [rules["collection-persistence-user-path"], rules["collection-defender-detection"]], {})
    finally:
        registry.close_all()

    assert not out["errors"]
    persistence = [f for f in out["findings"] if f["ruleId"] == "collection-persistence-user-path"]
    assert len(persistence) >= 3, "the service, the run key and the task all launch from user-writable paths"
    assert [f["entities"]["threatName"] for f in out["findings"] if f["ruleId"] == "collection-defender-detection"] == ["Trojan:Win32/Synthetic.A!ml"]


def test_a_collection_without_a_system_directory_is_not_treated_as_a_drive(tmp_path):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("Services/Services.csv", "Name,PathName\nSpooler,C:\\Windows\\System32\\spoolsv.exe\n")
    source = PackageSource("exports.zip", None, out.getvalue(), str(tmp_path), ParseContext(analyze_attachments=False))
    list(source)
    assert source.triage is False
    assert not [f for f in source.files if f["name"].startswith("triage!/")]
