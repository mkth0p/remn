"""REMN's own rules do what their descriptions say. Each case builds the event a rule is about
through the EVTX parser's flatten() and runs the shipped rule on the SQL engine (the parity
fixture holds the browser engine to the same findings). Every event here is invented: hosts,
accounts, addresses and paths are made up for the test."""

from __future__ import annotations

import datetime
import uuid
from pathlib import Path

import pytest
import yaml

from services.parsers import evtx_parser
from services.store import rules as R
from services.store.casestore import StoreRegistry
from services.store.writers import EventWriter

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
RULES = {
    d["id"]: d
    for p in sorted(RULES_DIR.rglob("*.yaml"))
    if "community" not in p.parts
    for d in yaml.safe_load_all(p.read_text(encoding="utf-8"))
    if isinstance(d, dict)
}
SECURITY = ("Microsoft-Windows-Security-Auditing", "Security")
T0 = datetime.datetime(2026, 9, 1, 22, 13, 40, tzinfo=datetime.UTC)


@pytest.fixture
def store(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    yield reg.get(str(uuid.uuid4()))
    reg.close_all()


def event(event_id: int, data: dict, source: tuple[str, str] = SECURITY, second: int = 0, computer: str = "DC01.corp.example") -> dict:
    return evtx_parser.flatten(
        {
            "Event": {
                "System": {
                    "Provider": {"#attributes": {"Name": source[0]}},
                    "EventID": event_id,
                    "TimeCreated": {"#attributes": {"SystemTime": (T0 + datetime.timedelta(seconds=second)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}},
                    "EventRecordID": 1,
                    "Channel": source[1],
                    "Computer": computer,
                },
                "EventData": data,
            }
        }
    )


def fired(store, rule_id: str, rows: list[dict], settings: dict | None = None) -> list[dict]:
    writer = EventWriter(store, 1)
    for i, row in enumerate(rows, 1):
        writer.add({**row, "id": i})
    writer.flush()
    return R.run_rule(store, RULES[rule_id], settings or {})


def preauth_failure(status: str, second: int) -> dict:
    return event(4771, {"TargetUserName": "j.doe", "ServiceName": "krbtgt/CORP.EXAMPLE", "IpAddress": "::ffff:10.0.0.23", "Status": status}, second=second * 10)


def test_a_kerberos_preauth_burst_counts_wrong_passwords_and_not_expired_or_disabled_accounts(store):
    # an expired password (0x17) and a disabled or locked account (0x12) fail pre-authentication
    # too, again and again from every device that still holds the old credentials
    rows = [preauth_failure("0x17" if i % 2 else "0x12", i) for i in range(12)]
    assert fired(store, "win-kerberos-preauth-bruteforce", rows) == []


def test_a_kerberos_preauth_burst_of_wrong_passwords_is_reported(store):
    rows = [preauth_failure("0x18", i) for i in range(12)]
    found = fired(store, "win-kerberos-preauth-bruteforce", rows)
    assert len(found) == 1 and found[0]["count"] == 12


def unknown_principal(status: str, second: int) -> dict:
    return event(4768, {"TargetUserName": f"guess{second}", "ServiceName": "krbtgt", "IpAddress": "::ffff:10.0.0.23", "Status": status}, second=second * 10)


def test_kerberos_user_enumeration_reads_the_unknown_principal_code_and_no_code_that_starts_like_it(store):
    # 0x60 stands for any status whose text merely begins with "0x6"
    assert fired(store, "win-kerberos-user-enumeration", [unknown_principal("0x60", i) for i in range(6)]) == []


def test_kerberos_user_enumeration_reports_tgt_requests_for_unknown_accounts(store):
    found = fired(store, "win-kerberos-user-enumeration", [unknown_principal("0x6", i) for i in range(6)])
    assert len(found) == 1 and found[0]["count"] == 6


SYSMON = ("Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational")


def test_an_rdp_connection_and_a_run_dialog_command_are_paired_in_either_order_so_the_pair_is_rated_low(store):
    run_dialog = event(
        13,
        {"Image": r"C:\Windows\explorer.exe", "TargetObject": r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\a"},
        SYSMON,
        0,
        "WS01",
    )
    rdp_in = event(3, {"Image": r"C:\Windows\System32\svchost.exe", "Initiated": "false", "DestinationPort": 3389, "SourceIp": "10.0.0.66"}, SYSMON, 4, "WS01")
    # the command comes first here: the rule cannot tell, so it cannot claim the connection led to it
    found = fired(store, "win-rdp-connect-then-run-dialog", [run_dialog, rdp_in])
    assert len(found) == 1 and found[0]["severity"] == "low"
    assert " after " not in found[0]["title"] and "either order" in found[0]["description"]


def test_an_event_log_crash_and_a_client_on_its_pipe_are_paired_in_either_order_so_the_pair_is_rated_medium(store):
    crash = event(
        1,
        {
            "Image": r"C:\Windows\System32\WerFault.exe",
            "ParentImage": r"C:\Windows\System32\svchost.exe",
            "ParentCommandLine": r"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p",
        },
        SYSMON,
        0,
        "WS01",
    )
    pipe = event(18, {"Image": "System", "PipeName": "\\eventlog", "EventType": "ConnectPipe"}, SYSMON, 20, "WS01")
    # the crash comes first here: the rule cannot tell, so it cannot claim the client caused it
    found = fired(store, "win-eventlog-crash-after-remote-pipe", [crash, pipe])
    assert len(found) == 1 and found[0]["severity"] == "medium"
    assert "right after" not in found[0]["title"] and "either order" in found[0]["description"]


def test_an_ntlm_network_logon_without_a_session_key_is_reported_as_a_low_hint(store):
    # a client that negotiates no NTLM session key looks like this too, and the log cannot say
    # whether the source is a workstation, so the finding is a hint and says what it matched
    logon = event(
        4624,
        {
            "SubjectUserSid": "S-1-0-0",
            "TargetUserName": "j.doe",
            "LogonType": "3",
            "LogonProcessName": "NtLmSsp ",
            "AuthenticationPackageName": "NTLM",
            "KeyLength": "0",
            "IpAddress": "10.0.0.23",
        },
        computer="FS01.corp.example",
    )
    found = fired(store, "win-pass-the-hash-hint", [logon])
    assert len(found) == 1 and found[0]["severity"] == "low"
    assert "from a workstation" not in found[0]["description"] and "session key" in found[0]["description"]


def test_a_program_on_admin_share_is_reported_on_its_own_so_the_rule_promises_no_sequence(store):
    # the rule pairs nothing: a program opened on ADMIN$ is a finding without any service after it
    share = event(
        5145,
        {"SubjectUserName": "j.doe", "IpAddress": "10.0.0.23", "ShareName": "\\\\*\\ADMIN$", "RelativeTargetName": "upd.exe", "AccessMask": "0x2"},
        computer="FS01.corp.example",
    )
    found = fired(store, "win-psexec-pattern", [share])
    assert len(found) == 1 and found[0]["severity"] == "medium"
    assert "followed by" not in found[0]["description"]


def task_xml(command: str, arguments: str, description: str = "Keeps the agent up to date") -> str:
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\r\n<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\r\n'
        f"  <RegistrationInfo>\r\n    <Description>{description}</Description>\r\n  </RegistrationInfo>\r\n"
        "  <Settings>\r\n    <Hidden>true</Hidden>\r\n  </Settings>\r\n"
        f'  <Actions Context="Author">\r\n    <Exec>\r\n      <Command>{command}</Command>\r\n      <Arguments>{arguments}</Arguments>\r\n    </Exec>\r\n  </Actions>\r\n</Task>'
    )


def task_created(name: str, xml: str) -> dict:
    return event(4698, {"SubjectUserName": "j.doe", "TaskName": name, "TaskContent": xml}, computer="WS01.corp.example")


def test_a_task_is_not_suspicious_for_the_schema_address_every_task_carries_or_for_its_description(store):
    benign = task_xml(r"C:\Program Files\Example Vendor\agent.exe", "--check", "Runs the agent; never uses PowerShell or cmd.exe")
    assert fired(store, "win-scheduled-task-suspicious-content", [task_created(r"\Example Vendor Agent", benign)]) == []


def test_a_task_whose_action_runs_a_hidden_encoded_powershell_or_a_script_is_reported(store):
    bad = task_xml("powershell.exe", "-w hidden -enc SQBFAFgA")
    script = task_xml(r"C:\tools\shell.cmd", "")
    found = fired(store, "win-scheduled-task-suspicious-content", [task_created(r"\Updater", bad), task_created(r"\Helper", script)])
    assert sorted(f["entities"]["taskName"] for f in found) == [r"\Helper", r"\Updater"]


def test_a_task_action_reading_a_json_file_or_starting_internet_explorer_is_not_a_script(store):
    rows = [
        task_created(r"\Example Sync", task_xml(r"C:\Program Files\Example Vendor\sync.exe", r"--config C:\Program Files\Example Vendor\sync.json")),
        task_created(r"\Example Kiosk", task_xml(r"C:\Program Files\Internet Explorer\iexplore.exe", "-k")),
    ]
    assert fired(store, "win-scheduled-task-suspicious-content", rows) == []


def test_a_task_is_left_out_for_a_vendor_name_only_where_its_name_starts_with_it(store):
    plain = task_xml(r"C:\Program Files\Example Vendor\agent.exe", "")
    rows = [
        task_created(r"\Microsoft\Windows\Defrag\ScheduledDefrag", plain),
        task_created(r"\GoogleUpdateTaskMachineCore{00000000-0000-0000-0000-000000000000}", plain),
        task_created(r"\Intel\Telemetry 3", plain),
        # the creator chooses the name: a vendor's name inside it is not the vendor's task
        task_created(r"\Windows Defender Intel Check", plain),
        task_created(r"\SyncHPrinter", plain),
        task_created(r"\Users\Public\Adobe", plain),
    ]
    found = fired(store, "win-scheduled-task-created", rows)
    assert sorted(f["entities"]["taskName"] for f in found) == [r"\SyncHPrinter", r"\Users\Public\Adobe", r"\Windows Defender Intel Check"]
