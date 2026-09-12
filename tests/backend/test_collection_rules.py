"""The collection rules fire on what the collection parsers now produce, and not on the rest.

The rows here are shaped exactly like collection.normalize() output for the artifact in question,
so a rule that passes here has a field to stand on in a real store.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
import yaml

from services.store.casestore import StoreRegistry
from services.store.rules import run_rules
from services.store.writers import EventWriter

RULES = {
    doc["id"]: doc
    for doc in yaml.safe_load_all((Path(__file__).resolve().parents[2] / "rules" / "collection" / "host-artifacts.yaml").read_text(encoding="utf-8"))
    if isinstance(doc, dict)
}


@pytest.fixture
def store(tmp_path):
    registry = StoreRegistry()
    registry.configure(tmp_path / "cases")
    yield registry.get(str(uuid.uuid4()))
    registry.close_all()


def observation(artifact, **fields):
    row = {"recordKind": "observation", "artifactType": artifact, "computer": "WS01", "ts": None, "eventId": None, "sourceFile": f"{artifact}/export.csv"}
    row.update(fields)
    return row


def fire(store, rule_id, rows):
    writer = EventWriter(store, 1)
    for row in rows:
        writer.add(row)
    writer.flush()
    out = run_rules(store, [RULES[rule_id]], {})
    assert not out["errors"], out["errors"]
    return out["findings"]


def test_defender_detections_group_by_threat_name(store):
    rows = [
        observation("defender", message="Threat Name:Trojan:Win32/Synthetic.A!ml", threatName="Trojan:Win32/Synthetic.A!ml", sourceFile="WdSupportLogs/MPLog.log"),
        observation("defender", message="Threat Name:Trojan:Win32/Synthetic.A!ml", threatName="Trojan:Win32/Synthetic.A!ml", sourceFile="WdSupportLogs/MPLog.log"),
        observation("defender", message="Threat Name:PUA:Win32/Presenoker", threatName="PUA:Win32/Presenoker", sourceFile="WdSupportLogs/MPLog.log"),
        observation("defender", message="Engine version: 1.1.24050.5", sourceFile="WdSupportLogs/MPLog.log"),
    ]
    found = fire(store, "collection-defender-detection", rows)

    assert len(found) == 1, "two lines naming the same threat are one finding"
    assert found[0]["entities"]["threatName"] == "Trojan:Win32/Synthetic.A!ml"
    assert found[0]["count"] == 2
    assert found[0]["severity"] == "high"


def test_pua_detections_are_their_own_finding(store):
    rows = [
        observation("defender", message="Threat Name:PUA:Win32/Presenoker", threatName="PUA:Win32/Presenoker", sourceFile="WdSupportLogs/MPLog.log"),
        observation("defender", message="Threat Name:Trojan:Win32/Synthetic.A!ml", threatName="Trojan:Win32/Synthetic.A!ml", sourceFile="WdSupportLogs/MPLog.log"),
    ]
    found = fire(store, "collection-defender-pua", rows)

    assert [f["entities"]["threatName"] for f in found] == ["PUA:Win32/Presenoker"]


def test_exclusions_are_one_finding_per_log(store):
    rows = [
        observation("defender", message="Path Exclusions:", sourceFile="WdSupportLogs/MPLog-1.log"),
        observation("defender", message="Process Exclusions:", sourceFile="WdSupportLogs/MPLog-1.log"),
        observation("defender", message="Ext Exclusions:", sourceFile="WdSupportLogs/MPLog-2.log"),
        observation("defender", message="No exclusions configured for this scan", sourceFile="WdSupportLogs/MPLog-2.log"),
    ]
    found = fire(store, "collection-defender-exclusions", rows)

    assert sorted(f["entities"]["sourceFile"] for f in found) == ["WdSupportLogs/MPLog-1.log", "WdSupportLogs/MPLog-2.log"]
    assert {f["count"] for f in found} == {2, 1}


def test_alert_text_does_not_double_report_a_named_threat(store):
    rows = [
        observation("defender", message="Threat detected: Trojan:Win32/Synthetic.A!ml", threatName="Trojan:Win32/Synthetic.A!ml"),
        observation("defender", message="Real-time protection disabled by policy"),
        observation("defender", message="Set-MpPreference -DisableRealtimeMonitoring $true"),
    ]
    found = fire(store, "collection-defender-alert-text", rows)

    assert len(found) == 2, "the named threat belongs to the detection rule, the other two to this one"


def test_unquoted_service_paths_with_spaces(store):
    rows = [
        observation("service", serviceName="Good", serviceFile='"C:\\Program Files\\Vendor\\svc.exe" -run'),
        observation("service", serviceName="Bad", serviceFile="C:\\Program Files\\Vendor\\svc.exe -run"),
        observation("service", serviceName="Builtin", serviceFile="C:\\Windows\\system32\\svchost.exe -k netsvcs"),
        observation("service", serviceName="Upper", serviceFile="C:\\PROGRAM FILES\\VENDOR\\SVC.EXE"),
    ]
    found = fire(store, "collection-service-unquoted-path", rows)

    assert sorted(f["entities"]["serviceName"] for f in found) == ["Bad", "Upper"]


def test_execution_from_user_writable_locations(store):
    rows = [
        observation("prefetch", processName="UPD.EXE", image="\\VOLUME{01d9}\\USERS\\JDOE\\DOWNLOADS\\UPD.EXE"),
        observation("prefetch", processName="NOTEPAD.EXE", image="\\VOLUME{01d9}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE"),
        observation("process", processName="helper.exe", image="C:\\Users\\jdoe\\AppData\\Local\\Temp\\helper.exe"),
        observation("process", processName="explorer.exe", image="C:\\Windows\\explorer.exe"),
        observation("service", serviceName="NotThisRule", serviceFile="C:\\Users\\Public\\svc.exe"),
    ]
    found = fire(store, "collection-execution-user-path", rows)

    assert sorted(f["entities"]["processName"] for f in found) == ["UPD.EXE", "helper.exe"]


def test_programs_installed_in_user_locations(store):
    rows = [
        observation("program", name="Helper", path="C:\\Users\\jdoe\\AppData\\Local\\Helper\\"),
        observation("program", name="Office", path="C:\\Program Files\\Microsoft Office\\"),
        observation("program", name="NoPath"),
    ]
    found = fire(store, "collection-program-user-location", rows)

    assert len(found) == 1


def test_persistence_through_a_script_host(store):
    rows = [
        observation("autorun", name="Loader", image='powershell.exe -w hidden -enc AAAA', targetObject="HKCU\\...\\Run"),
        observation("task", taskName="\\Sync", commandLine="C:\\Windows\\system32\\wscript.exe //B C:\\Users\\Public\\s.vbs"),
        observation("task", taskName="\\Backup", commandLine="C:\\Windows\\system32\\wbadmin.exe start backup"),
        observation("autorun", name="Desc", image=None, targetObject="HKLM\\...\\Run"),
    ]
    found = fire(store, "collection-persistence-script-host", rows)

    assert len(found) == 2


def test_the_existing_persistence_rule_now_reaches_tasks_and_reg_autoruns(store):
    """These two shapes produced rows before, but with image and commandLine empty."""
    rows = [
        observation("task", taskName="\\Updater", commandLine='"C:\\Users\\jdoe\\AppData\\Roaming\\upd.exe" /silent', image="C:\\Users\\jdoe\\AppData\\Roaming\\upd.exe"),
        observation("autorun", name="Dropper", image='"C:\\Users\\Public\\svc.exe" -k', targetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        observation("autorun", name="SecurityHealth", image="%windir%\\system32\\SecurityHealthSystray.exe", targetObject="HKLM\\...\\Run"),
    ]
    found = fire(store, "collection-persistence-user-path", rows)

    assert len(found) == 2
