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


def build() ->