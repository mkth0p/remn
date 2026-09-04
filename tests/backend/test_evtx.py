from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.parsers import evtx_parser
from services.reference import eventids

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def _sample_event(event_id: int, provider: str, data: dict, user_data: dict | None = None) -> dict:
    ev = {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": provider, "Guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}"}},
                "EventID": event_id, "Version": 2, "Level": 0, "Task": 12544, "Opcode": 0, "Keywords": "0x8010000000000000",
                "TimeCreated": {"#attributes": {"SystemTime": "2026-09-01T22:13:40.123456Z"}},
                "EventRecordID": 4242, "Correlation": {"#attributes": {"ActivityID": "{ABC}"}},
                "Execution": {"#attributes": {"ProcessID": 720, "ThreadID": 1234}},
                "Channel": "Security", "Computer": "WS01.corp.local", "Security": {"#attributes": {"UserID": "S-1-5-18"}},
            },
            "EventData": data,
        }
    }
    if user_data is not None:
        ev["Event"]["UserData"] = user_data
    return ev


def test_flatten_4625_maps_fields_and_summary():
    ev = _sample_event(4625, "Microsoft-Windows-Security-Auditing", {
        "SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "TargetUserName": "administrator", "TargetDomainName": "CORP",
        "Status": "0xc000006d", "SubStatus": "0xc000006a", "LogonType": 3, "IpAddress": "10.1.2.3", "IpPort": 51234,
        "WorkstationName": "KALI", "AuthenticationPackageName": "NTLM", "FailureReason": "%%2313",
    })
    row = evtx_parser.flatten(ev, {"event_record_id": 4242, "timestamp": "2026-09-01 22:13:40.123456 UTC"})
    assert row["eventId"] == 4625
    assert row["ts"] == 1788300820123
    assert row["tsIso"] == "2026-09-01T22:13:40.123Z"
    assert row["targetUser"] == "administrator" and row["targetDomain"] == "CORP"
    assert row["ipAddress"] == "10.1.2.3" and row["ipPort"] == 51234
    assert row["logonType"] == 3 and row["logonTypeName"] == "Network"
    assert row["statusText"] == "Wrong password"
    assert row["category"] == "logon"
    assert "Failed logon Network as CORP\\administrator from 10.1.2.3 - Wrong password" == row["summary"]
    assert json.loads(row["raw"])["System"]["EventID"] == 4625
    assert row["subjectUser"] is None  # "-" is normalised away


def test_flatten_classic_event_id_with_qualifiers_and_param_fields():
    ev = _sample_event({"#attributes": {"Qualifiers": 16384}, "#text": 7036}, "Service Control Manager", {"param1": "PSEXESVC", "param2": "running"})
    row = evtx_parser.flatten(ev, None, include_raw=False)
    assert row["eventId"] == 7036 and row["qualifiers"] == 16384
    assert row["serviceName"] == "PSEXESVC" and row["serviceState"] == "running"
    assert "raw" not in row
    assert row["description"] == "Service entered running/stopped state"


def test_flatten_userdata_rdp_and_log_cleared():
    ev = _sample_event(21, "Microsoft-Windows-TerminalServices-LocalSessionManager", {}, user_data={"EventXML": {"User": "CORP\\bob", "SessionID": 3, "Address": "203.0.113.9"}})
    row = evtx_parser.flatten(ev, None, include_raw=False)
    assert row["targetUser"] == "CORP\\bob" and row["ipAddress"] == "203.0.113.9" and row["sessionId"] == 3
    assert row["category"] == "rdp"
    ev2 = _sample_event(1102, "Microsoft-Windows-Security-Auditing", {}, user_data={"LogFileCleared": {"SubjectUserName": "eve", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1"}})
    row2 = evtx_parser.flatten(ev2, None, include_raw=False)
    assert row2["subjectUser"] == "eve" and row2["category"] == "log-tampering"
    assert row2["summary"].startswith("The audit log was cleared by CORP\\eve")


def test_flatten_group_event_sets_group_name():
    ev = _sample_event(4732, "Microsoft-Windows-Security-Auditing", {"MemberName": "CN=eve,DC=corp", "MemberSid": "S-1-5-21-1", "TargetUserName": "Administrators", "TargetDomainName": "Builtin", "SubjectUserName": "admin"})
    row = evtx_parser.flatten(ev, None, include_raw=False)
    assert row["groupName"] == "Administrators" and row["memberName"] == "CN=eve,DC=corp"


def test_flatten_classic_data_list_becomes_message():
    ev = _sample_event(400, "PowerShell", {"Data": ["Available", "None", "NewEngineState=Available\n\tPreviousEngineState=None"]})
    row = evtx_parser.flatten(ev, None, include_raw=False)
    assert "NewEngineState=Available" in row["message"]


def test_summarize_never_crashes_on_unknown_event_with_task():
    row = {"eventId": 9999, "provider": "Foo", "task": 5}
    assert eventids.summarize(row) == "Event 9999"


@pytest.mark.skipif(not (SAMPLES / "System-last7d.evtx").exists(), reason="local sample not exported")
def test_parse_real_sample_without_errors():
    stats = evtx_parser.Stats()
    rows = list(evtx_parser.iter_events(str(SAMPLES / "System-last7d.evtx"), include_raw=False, stats=stats))
    assert stats.count == len(rows) > 100
    assert stats.errors == 0
    assert stats.first_ts is not None and stats.last_ts >= stats.first_ts
    assert all(r["summary"] for r in rows)
    d = stats.to_dict()
    assert d["channels"].get("System")


@pytest.mark.skipif(not (SAMPLES / "System-last7d.evtx").exists(), reason="local sample not exported")
def test_parse_from_file_object():
    with open(SAMPLES / "System-last7d.evtx", "rb") as fh:
        rows = list(evtx_parser.iter_events(fh, include_raw=False))
    assert len(rows) > 100
