"""Generate large, coherent mail/EVTX/M365 evidence entirely offline.

python samples/synthetic/make_linked_lab.py --out samples/generated/linked-lab
The output directory must not exist. No real logs, accounts or malware are used.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import heapq
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path

from evtx_writer import EvtxWriter, event_node

ROOT = Path(__file__).resolve().parents[2]
ORG = "northstar.example"
TENANT = "11111111-2222-4333-8444-555555555555"
NAMES = ["alice.martin", "benoit.durand", "carla.morel", "daniel.roy", "elise.bernard", "farah.benali"] + [f"employee{i:03d}" for i in range(7, 181)]
WORKDAYS = [datetime(2026, 8, 17, 8, tzinfo=UTC) + timedelta(days=i) for i in range(19) if (datetime(2026, 8, 17) + timedelta(days=i)).weekday() < 5]
PROVIDERS = {
    "Security": ("Microsoft-Windows-Security-Auditing", "Security"),
    "Sysmon": ("Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational"),
    "PowerShell": ("Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell/Operational"),
    "System": ("Service Control Manager", "System"),
    "Defender": ("Microsoft-Windows-Windows Defender", "Microsoft-Windows-Windows Defender/Operational"),
}
SETTINGS = {
    "internalDomains": [ORG],
    "expectedCountries": ["FR"],
    "vipNames": ["marie lefevre"],
    "adminAccounts": ["lab.admin"],
    "serviceAccounts": ["svc.backup", "svc.monitor"],
    "internalIps": ["10.0.0.0/8", "127.0.0.0/8", "::1"],
    "trustedSenders": [],
    "brands": [],
    "businessHours": {"start": 8, "end": 19, "tz": "Europe/Paris"},
    "weekendDays": [0, 6],
    "deepAttachments": True,
    "keepBodies": True,
    "includeRaw": True,
    "networkAllowed": False,
}


def epoch(value):
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())


def iso(t):
    return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def bg_time(i, n):
    day, fraction = divmod(i * len(WORKDAYS) / max(n, 1), 1)
    return int(WORKDAYS[min(int(day), len(WORKDAYS) - 1)].timestamp() + fraction * 9 * 3600)


def uid(key):
    h = hashlib.sha256(key.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"


def pdf_report(js=False):
    content = (
        b"BT /F1 12 Tf 50 780 Td (Northstar synthetic supplier report) Tj 0 -24 Td (Total approved: 42 units. Reference REMN-LAB. No action required.) Tj ET"
    )
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R" + (b" /OpenAction 6 0 R" if js else b"") + b" >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    if js:
        objs.append(b"<< /S /JavaScript /JS (var total = 42;) >>")
    out = bytearray(b"%PDF-1.7\n")
    offsets = [0]
    for i, obj in enumerate(objs, 1):
        offsets.append(len(out))
        out.extend(f"{i} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(out)
    out.extend(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        out.extend(f"{offset:010d} 00000 n \n".encode())
    out.extend(f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(out)


def zip_report():
    buf = io.BytesIO()
    info = zipfile.ZipInfo("report.html", (2026, 8, 17, 8, 0, 0))
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(info, "<!doctype html><html><body><h1>Weekly report</h1><p>All 42 deliverables accepted. No action required.</p></body></html>")
    return buf.getvalue()


CSV_HTML = b"""<!doctype html><html><body><h1>Monthly report</h1><button onclick="exportCsv()">Export CSV</button><script>function exportCsv(){const b=new Blob(['month,total\\nSeptember,42'],{type:'text/csv'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='report.csv';a.click();URL.revokeObjectURL(a.href);}</script></body></html>"""
PDF = pdf_report()


def message_bytes(m):
    t, key, frm, to = m["t"], m["key"], m["from"], m["to"]
    dom = frm.split("@")[-1]
    date = format_datetime(datetime.fromtimestamp(t, UTC))
    auth = "fail" if m.get("auth_fail") else "pass"
    headers = [
        f'From: "{m.get("display", frm.split("@")[0].replace(".", " ").title())}" <{frm}>',
        f"To: {to}",
        f"Subject: {m['subject']}",
        f"Date: {date}",
        f"Message-ID: <{key}@remn-lab.example>",
        f"Return-Path: <{frm}>",
        f"Received: from smtp.{dom} ([{m.get('ip', '198.51.100.10')}]) by mx.{ORG} with ESMTPS id {key}; {date}",
        f"Authentication-Results: mx.{ORG}; spf={auth} smtp.mailfrom={dom}; dkim={auth} header.d={dom}; dmarc={auth} header.from={dom}",
        "X-REMN-Synthetic: linked-investigation-v1",
        "MIME-Version: 1.0",
    ]
    if frm.endswith("@" + ORG) and not m.get("auth_fail"):
        headers.append("X-MS-Exchange-Organization-AuthAs: Internal")
    if m.get("reply_to"):
        headers.append(f"Reply-To: {m['reply_to']}")
    if m.get("reply"):
        headers += [f"In-Reply-To: <{m['reply']}@remn-lab.example>", f"References: <{m['reply']}@remn-lab.example>"]
    if m.get("bulk"):
        headers += ["List-Id: <reports.vendor.example>", "List-Unsubscribe: <https://vendor.example/unsubscribe>"]
    boundary = "REMN_" + key
    parts = [
        f'Content-Type: multipart/mixed; boundary="{boundary}"',
        "",
        f"--{boundary}",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Transfer-Encoding: 8bit",
        "",
        m["body"],
    ]
    if m.get("html"):
        parts += [f"--{boundary}", "Content-Type: text/html; charset=utf-8", "Content-Transfer-Encoding: 8bit", "", m["html"]]
    for name, data, mime in m.get("attachments", []):
        encoded = base64.b64encode(data).decode()
        parts += [
            f"--{boundary}",
            f"Content-Type: {mime}",
            f'Content-Disposition: attachment; filename="{name}"',
            "Content-Transfer-Encoding: base64",
            "",
            "\n".join(encoded[j : j + 76] for j in range(0, len(encoded), 76)),
        ]
    parts += [f"--{boundary}--", ""]
    return "\n".join(headers + parts).encode("utf-8")


def normal_mails(n):
    subjects = [
        "Project status",
        "Meeting notes",
        "Supplier invoice",
        "Weekly report",
        "Delivery schedule",
        "Approved purchase order",
        "IT service update",
        "Training invitation",
    ]
    for i in range(n):
        user = NAMES[i % len(NAMES)]
        frm = f"{NAMES[(i + 13) % len(NAMES)]}@{ORG}" if i % 3 else "reports@vendor.example"
        key = f"BG-M-{i:07d}"
        body = f"Hello {user},\n\nHere is the agreed project update, reference {key}.\n"
        body += "\n".join(
            f"Workstream {j}: task {(i * 17 + j) % 997} is complete; owner team-{i % 12}; accepted quantity {j * 3}; next review follows the usual approval process. Document /projects/{i % 80}/week-{i % 4}."
            for j in range(1, 18)
        )
        body += f"\n\nView the report at https://{frm.split('@')[1]}/reports/{i}.\nKind regards,\nProject coordination\nSynthetic training correspondence."
        row = {"t": bg_time(i, n), "key": key, "from": frm, "to": f"{user}@{ORG}", "subject": f"{subjects[i % len(subjects)]} NS-{i:07d}", "body": body}
        if i % 20 == 0:
            row["attachments"] = [(f"report-{i % 100}.pdf", PDF, "application/pdf")]
        if i % 13 == 0:
            row["reply_to"] = "accounts@billing.vendor.example"
        if i % 7 == 0 and not frm.endswith("@" + ORG):
            row["bulk"] = True
        yield row


def normal_windows(channel, n):
    for i in range(n):
        user = NAMES[i % len(NAMES)]
        host = f"WS-{i % len(NAMES) + 1:03d}.{ORG}"
        ip = f"10.20.{i % 8}.{i % 240 + 10}"
        if channel == "Security":
            eid = 4625 if i % 101 == 0 else 4634 if i % 4 == 0 else 4624
            data = {
                "TargetUserName": user,
                "TargetDomainName": "NORTHSTAR",
                "LogonType": 3,
                "IpAddress": ip,
                "AuthenticationPackageName": "Kerberos",
                "WorkstationName": host,
                "TargetLogonId": hex(i + 4096),
            }
            if eid == 4625:
                data.update(Status="0xc000006d", SubStatus="0xc000006a")
        elif channel == "Sysmon":
            eid = [1, 3, 22, 11][i % 4]
            data = {
                "User": "NORTHSTAR\\" + user,
                "ProcessGuid": "{" + uid(f"BG-P-{i}") + "}",
                "Image": r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            }
            if eid == 1:
                data.update(
                    CommandLine="msedge.exe https://portal.northstar.example/dashboard", ParentImage=r"C:\Windows\explorer.exe", ProcessId=3000 + i % 5000
                )
            elif eid == 3:
                data.update(DestinationIp="192.0.2.20", DestinationPort=443, DestinationHostname="portal.northstar.example", Protocol="tcp", Initiated="true")
            elif eid == 22:
                data.update(QueryName="portal.northstar.example", QueryResults="192.0.2.20", QueryStatus=0)
            else:
                data.update(TargetFilename=f"C:\\Users\\{user}\\Documents\\report-{i % 100}.pdf")
        elif channel == "PowerShell":
            eid = 4104
            data = {
                "User": "NORTHSTAR\\svc.monitor",
                "ScriptBlockText": f"Write-Output 'Routine inventory run {i}: WS-{i % 180 + 1:03d}'",
                "ScriptBlockId": uid(f"BG-PS-{i}"),
                "MessageNumber": 1,
                "MessageTotal": 1,
                "Path": r"C:\Program Files\Northstar\Inventory.ps1",
            }
        elif channel == "System":
            eid = 7036
            data = {"param1": ["Windows Update", "Print Spooler", "Background Intelligent Transfer Service"][i % 3], "param2": "running"}
        else:
            eid = 1001
            data = {"Scan ID": uid(f"BG-D-{i}"), "Scan Type": "Quick scan", "User": "NORTHSTAR\\svc.monitor"}
        data["SyntheticCase"] = "REMN-LAB"
        yield {"t": bg_time(i, n), "key": f"BG-W-{channel}-{i:07d}", "channel": channel, "event_id": eid, "host": host, "data": data}


def ual(key, t, user, op, workload="Exchange", ip="198.51.100.10", **extra):
    raw = {
        "CreationTime": iso(t),
        "Id": uid(key),
        "Operation": op,
        "Workload": workload,
        "UserId": user,
        "OrganizationId": TENANT,
        "RecordType": 1,
        "ResultStatus": "Succeeded",
        "UserType": 0,
        "UserKey": user,
        "ClientIP": ip,
        "Version": 1,
        "SyntheticCase": "REMN-LAB",
        "SyntheticRecord": key,
    }
    raw.update(extra)
    return {"t": t, "key": key, "raw": raw}


def signin(key, t, user, ip="198.51.100.10", country="FR", err=0, risk="none", client="Browser", **extra):
    raw = {
        "id": uid(key),
        "createdDateTime": iso(t),
        "userPrincipalName": user,
        "userDisplayName": user.split("@")[0],
        "appDisplayName": "Office 365 Exchange Online",
        "appId": "00000002-0000-0ff1-ce00-000000000000",
        "userId": uid(user),
        "ipAddress": ip,
        "clientAppUsed": client,
        "conditionalAccessStatus": "success" if not err else "failure",
        "isInteractive": client == "Browser",
        "riskLevelDuringSignIn": risk,
        "riskLevelAggregated": risk,
        "riskState": "atRisk" if risk != "none" else "none",
        "status": {"errorCode": err, "failureReason": "Invalid password" if err else "Success"},
        "location": {"countryOrRegion": country, "city": "Paris" if country == "FR" else "Synthetic remote location"},
        "deviceDetail": {
            "deviceId": uid(user + "device"),
            "displayName": "WS-" + user.split("@")[0],
            "operatingSystem": "Windows 11",
            "browser": "Edge",
            "isManaged": country == "FR",
            "isCompliant": country == "FR",
        },
        "SyntheticCase": "REMN-LAB",
        "SyntheticRecord": key,
    }
    raw.update(extra)
    return {"t": t, "key": key, "raw": raw}


def normal_ual(n):
    for i in range(n):
        user = f"{NAMES[i % len(NAMES)]}@{ORG}"
        op = ["FileAccessed", "FileModified", "FilePreviewed", "UserLoggedIn", "MailItemsAccessed"][i % 5]
        extra = {"ObjectId": f"https://documents.northstar.example/teams/team-{i % 12}/report-{i % 100}.pdf"}
        if op == "MailItemsAccessed":
            extra.update(MailboxOwnerUPN=user, RecordType=50, OperationProperties=[{"Name": "MailAccessType", "Value": "Bind"}])
        yield ual(
            f"BG-U-{i:07d}",
            bg_time(i, n),
            user,
            op,
            "AzureActiveDirectory" if op == "UserLoggedIn" else "Exchange" if op == "MailItemsAccessed" else "SharePoint",
            **extra,
        )


def normal_signins(n):
    for i in range(n):
        yield signin(f"BG-E-{i:07d}", bg_time(i, n), f"{NAMES[i % len(NAMES)]}@{ORG}", err=50126 if i % 997 == 0 else 0)


def scenarios():
    mails, windows, audits, signins, descriptions = [], [], [], [], []
    specs = [
        ("S01", "alice.martin", "2026-09-01T09:05:00Z", "Invoice diversion and mailbox takeover", "signin-review.example", "Invoice_NS-001.html"),
        (
            "S02",
            "benoit.durand",
            "2026-09-02T09:10:00Z",
            "Attachment execution, persistence and Defender alert",
            "delivery-review.example",
            "Shipping_NS-002.pdf.exe",
        ),
        ("S03", "carla.morel", "2026-09-03T10:15:00Z", "OAuth consent abuse and file access", "consent-review.example", "Consent_NS-003.html"),
        ("S04", "daniel.roy", "2026-09-04T08:20:00Z", "Password spray, RDP and lateral movement", "secure-documents.example", "Document_NS-004.html"),
        ("S06", "farah.benali", "2026-09-03T14:00:00Z", "Compromised previously authenticated supplier", "supplier-verify.example", "Supplier_NS-006.html"),
    ]
    for idx, (sid, user, date, title, domain, filename) in enumerate(specs):
        start = epoch(date)
        victim = f"{user}@{ORG}"
        host = f"WS-{NAMES.index(user) + 1:03d}.{ORG}"
        ip = f"203.0.113.{66 + idx}"
        frm = f"ceo@{ORG}" if sid == "S01" else "reports@vendor.example" if sid == "S06" else f"documents@{domain}"
        body = f"Hello {user}, I am the CEO and I need you to process the urgent invoice payment immediately. Keep this confidential. Verify your password to see the requested document: https://{domain}/session/login.\nReference {sid}.\nSYNTHETIC INVESTIGATION EXERCISE - NO REAL PAYMENT."
        html = f'<html><body><p>{body}</p><a href="https://{domain}/session/login">https://portal.{ORG}/documents</a></body></html>'
        # Disabled form and inert executable signatures: only static detection facts.
        payload = f'<html><body><h1>Synthetic sign-in simulation</h1><form action="https://{domain}/collect"><input type="password" disabled><button disabled>Simulation only</button></form></body></html>'.encode()
        if sid == "S02":
            payload = b"MZ" + b"\0" * 300 + b"REMN SYNTHETIC NON-EXECUTABLE TEST SIGNATURE"
        mail = {
            "t": start,
            "key": sid + "-MAIL-001",
            "scenario": sid,
            "label": "malicious_simulation",
            "from": frm,
            "to": victim,
            "display": "Marie Lefevre" if sid == "S01" else "Supplier Accounts",
            "subject": f"[{sid}] Urgent invoice NS-{sid[1:]}",
            "body": body,
            "html": html,
            "auth_fail": sid == "S01",
            "ip": ip,
            "attachments": [(filename, payload, "application/octet-stream" if sid == "S02" else "text/html")],
        }
        mails.append(mail)
        mails.append(
            {
                "t": start + 300,
                "key": sid + "-MAIL-002",
                "scenario": sid,
                "label": "victim_response",
                "from": victim,
                "to": frm,
                "subject": "RE: " + mail["subject"],
                "body": "I opened the requested document. Synthetic exercise reply only.",
                "reply": mail["key"],
            }
        )
        descriptions.append(
            {
                "id": sid,
                "title": title,
                "victim": victim,
                "host": host,
                "startUTC": iso(start),
                "ip": ip,
                "domain": domain,
                "mailMessageId": f"<{mail['key']}@remn-lab.example>",
                "attachment": filename,
                "attachmentSha256": hashlib.sha256(payload).hexdigest(),
                "expected": "Mail -> same-domain DNS -> downloaded attachment -> host activity -> risky cloud sign-in -> mailbox/consent activity",
            }
        )

        def win(suffix, minute, channel, eid, data, target_host=host):
            windows.append(
                {
                    "t": start + int(minute * 60),
                    "key": sid + "-WIN-" + suffix,
                    "scenario": sid,
                    "label": "malicious_simulation",
                    "channel": channel,
                    "event_id": eid,
                    "host": target_host,
                    "data": {"User": "NORTHSTAR\\" + user, "SyntheticCase": "REMN-LAB", "ScenarioId": sid, **data},
                }
            )

        win(
            "001",
            2,
            "Sysmon",
            22,
            {"Image": r"C:\Program Files\Microsoft\Edge\Application\msedge.exe", "QueryName": domain, "QueryResults": ip, "QueryStatus": 0},
        )
        win(
            "002",
            3,
            "Sysmon",
            11,
            {"Image": r"C:\Program Files\Microsoft\Edge\Application\msedge.exe", "TargetFilename": f"C:\\Users\\{user}\\Downloads\\{filename}"},
        )
        win(
            "003",
            4,
            "Sysmon",
            3,
            {
                "Image": r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                "DestinationIp": ip,
                "DestinationHostname": domain,
                "DestinationPort": 443,
                "Protocol": "tcp",
            },
        )
        win(
            "004",
            6,
            "Security",
            4624,
            {
                "TargetUserName": user,
                "TargetDomainName": "NORTHSTAR",
                "LogonType": 10,
                "IpAddress": ip,
                "TargetLogonId": "0x9a01",
                "AuthenticationPackageName": "NTLM",
            },
        )
        command = f"powershell.exe -NoProfile -Command Write-Output 'SYNTHETIC {sid} {filename} https://{domain}/stage'"
        if sid in ("S02", "S04"):
            win(
                "005",
                7,
                "Sysmon",
                1,
                {
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
                    "CommandLine": command,
                    "ProcessGuid": "{" + uid(sid + "proc") + "}",
                    "ProcessId": 7788,
                },
            )
            win(
                "006",
                8,
                "PowerShell",
                4104,
                {
                    "ScriptBlockText": f"Write-Output 'SYNTHETIC {sid}: {filename} https://{domain}/stage'",
                    "ScriptBlockId": uid(sid + "script"),
                    "MessageNumber": 1,
                    "MessageTotal": 1,
                },
            )
            win(
                "007",
                14,
                "Security",
                4698,
                {
                    "SubjectUserName": user,
                    "SubjectDomainName": "NORTHSTAR",
                    "TaskName": "\\Northstar\\Updater-" + sid,
                    "TaskContent": f"<Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-Command Write-Output SYNTHETIC-{sid}</Arguments></Exec></Actions></Task>",
                },
            )
            win(
                "008",
                17,
                "System",
                7045,
                {
                    "ServiceName": "NSLabUpdater-" + sid,
                    "ImagePath": f"C:\\Users\\Public\\{filename}",
                    "ServiceType": "user mode service",
                    "StartType": "auto start",
                    "AccountName": "LocalSystem",
                },
                "FS-001." + ORG,
            )
            win(
                "009",
                19,
                "Defender",
                1116,
                {
                    "Threat Name": "Trojan:Win32/REMN.Synthetic",
                    "Severity Name": "Severe",
                    "Category Name": "Trojan",
                    "Path": f"file:_C:\\Users\\{user}\\Downloads\\{filename}",
                    "Detection User": "NORTHSTAR\\" + user,
                },
            )
            win("010", 22, "Security", 1102, {"SubjectUserName": user, "SubjectDomainName": "NORTHSTAR", "SubjectLogonId": "0x9a01"})
        if sid == "S04":
            for j in range(30):
                win(
                    f"SPRAY-{j:02d}",
                    -4 + j / 10,
                    "Security",
                    4625,
                    {
                        "TargetUserName": user if j < 18 else NAMES[j],
                        "TargetDomainName": "NORTHSTAR",
                        "LogonType": 3,
                        "IpAddress": ip,
                        "Status": "0xc000006d",
                        "SubStatus": "0xc000006a",
                    },
                )
            win(
                "ADMIN",
                12,
                "Security",
                4732,
                {
                    "SubjectUserName": user,
                    "TargetUserName": "Administrators",
                    "TargetDomainName": "Builtin",
                    "MemberName": f"CN={user},DC=northstar,DC=example",
                    "MemberSid": "S-1-5-21-111-222-333-1042",
                },
            )
            win(
                "SHARE",
                16,
                "Security",
                5140,
                {"SubjectUserName": user, "SubjectDomainName": "NORTHSTAR", "IpAddress": ip, "ShareName": "\\\\*\\ADMIN$"},
                "FS-001." + ORG,
            )
        for j in range(12):
            row = signin(f"{sid}-ENTRA-FAIL-{j:02d}", start + 600 + j * 12, victim if j < 7 else NAMES[j] + "@" + ORG, ip, "NL", 50126, client="Other clients")
            row.update(scenario=sid, label="malicious_simulation")
            signins.append(row)
        for j, country in enumerate(("FR", "NL")):
            row = signin(
                f"{sid}-ENTRA-SUCCESS-{j}",
                start + 60 * (1 if j == 0 else 15),
                victim,
                "198.51.100.10" if j == 0 else ip,
                country,
                risk="none" if j == 0 else "high",
                client="Browser" if j == 0 else "Other clients",
            )
            row.update(scenario=sid, label="benign_context" if j == 0 else "malicious_simulation")
            signins.append(row)

        def audit(suffix, minute, operation, **extra):
            workload = extra.pop("workload", "Exchange")
            row = ual(f"{sid}-UAL-{suffix}", start + int(minute * 60), victim, operation, workload, ip, **extra)
            row.update(scenario=sid, label="malicious_simulation")
            audits.append(row)

        for j in range(35):
            audit(
                f"ACCESS-{j:02d}",
                17 + j * 0.15,
                "MailItemsAccessed",
                RecordType=50,
                MailboxOwnerUPN=victim,
                LogonType=2,
                OperationProperties=[{"Name": "MailAccessType", "Value": "Sync"}],
                Folders=[{"Path": "\\Inbox", "FolderItems": [{"InternetMessageId": f"<{mail['key']}@remn-lab.example>"}]}],
            )
        audit(
            "FORWARD",
            26,
            "New-InboxRule",
            ObjectId=victim + "\\Invoice routing",
            Parameters=[
                {"Name": "Name", "Value": "Invoice routing"},
                {"Name": "ForwardTo", "Value": f"finance@{domain}"},
                {"Name": "DeleteMessage", "Value": "True"},
                {"Name": "SubjectContainsWords", "Value": "invoice;payment;facture"},
            ],
        )
        audit(
            "MAILBOX",
            35,
            "Set-Mailbox",
            ObjectId=victim,
            Parameters=[{"Name": "ForwardingSmtpAddress", "Value": f"smtp:finance@{domain}"}, {"Name": "DeliverToMailboxAndForward", "Value": "True"}],
        )
        audit(
            "CONSENT",
            47,
            "Consent to application.",
            workload="AzureActiveDirectory",
            RecordType=8,
            ObjectId="Northstar Document Helper " + sid,
            ModifiedProperties=[{"Name": "ConsentAction.Permissions", "NewValue": "Scope: Mail.Read Mail.ReadWrite offline_access User.Read", "OldValue": ""}],
        )
        if sid == "S03":
            audit(
                "ROLE",
                55,
                "Add member to role.",
                workload="AzureActiveDirectory",
                RecordType=8,
                ObjectId=victim,
                ModifiedProperties=[{"Name": "Role.DisplayName", "NewValue": "Global Administrator", "OldValue": ""}],
                Target=[{"ID": victim, "Type": 5}],
            )
            for j in range(55):
                audit(
                    f"DOWNLOAD-{j}",
                    60 + j * 0.05,
                    "FileDownloaded",
                    workload="SharePoint",
                    RecordType=6,
                    ObjectId=f"https://documents.northstar.example/finance/invoice-{j}.xlsx",
                )

    # Independent benign controls, with realistic capabilities that should not be high.
    controls = [
        ("HTML-ZIP", "Static HTML report in ZIP", [("report.zip", zip_report(), "application/zip")]),
        ("PDF-JS", "Interactive supplier PDF", [("form.pdf", pdf_report(True), "application/pdf")]),
        ("CSV-EXPORT", "Monthly HTML CSV export", [("report.html", CSV_HTML, "text/html")]),
        ("BANK-NOTICE", "New bank details following merger", []),
        ("REPLYTO", "Invoice for completed work", []),
    ]
    for i, (key, subject, att) in enumerate(controls):
        mails.append(
            {
                "t": epoch("2026-09-02T11:00:00Z") + i * 60,
                "key": "S05-" + key,
                "scenario": "S05",
                "label": "benign_control",
                "from": "reports@vendor.example",
                "to": "elise.bernard@" + ORG,
                "subject": "[S05] " + subject,
                "body": "The agreed work is complete. Following our merger here are our new bank details. Verify with your usual contact number. No urgent action is needed.",
                "attachments": att,
                **({"reply_to": "remn.synthetic.accounts@gmail.com"} if key == "REPLYTO" else {}),
            }
        )
    descriptions.append(
        {
            "id": "S05",
            "title": "Five benign mail calibration controls",
            "victim": "elise.bernard@" + ORG,
            "startUTC": "2026-09-02T11:00:00Z",
            "expected": "All five controls should stay below high/critical mail risk and core finding priority.",
        }
    )
    # Deliberately tempting, incorrect joins: ground truth explicitly excludes these.
    windows.append(
        {
            "t": epoch("2026-09-01T09:25:00Z"),
            "key": "NEG-TENANT-001",
            "scenario": "NEG-TENANT",
            "label": "unrelated_negative_control",
            "channel": "Security",
            "event_id": 1102,
            "host": "OTHER-WS-001.other-tenant.example",
            "data": {
                "SubjectUserName": "alice.martin@other-tenant.example",
                "SubjectDomainName": "OTHER",
                "SyntheticCase": "REMN-LAB",
                "ScenarioId": "NEG-TENANT",
            },
        }
    )
    windows.append(
        {
            "t": epoch("2026-08-20T09:25:00Z"),
            "key": "NEG-TIME-001",
            "scenario": "NEG-TIME",
            "label": "unrelated_negative_control",
            "channel": "Sysmon",
            "event_id": 22,
            "host": "WS-001." + ORG,
            "data": {
                "User": "NORTHSTAR\\alice.martin",
                "QueryName": "signin-review.example",
                "Image": "msedge.exe",
                "SyntheticCase": "REMN-LAB",
                "ScenarioId": "NEG-TIME",
            },
        }
    )
    return mails, windows, audits, signins, sorted(descriptions, key=lambda d: d["id"])


def merge(background, planted):
    return heapq.merge(background, sorted(planted, key=lambda r: r["t"]), key=lambda r: r["t"])


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def build_pack(out, counts):
    out.mkdir(parents=True, exist_ok=False)
    mail_special, win_special, audit_special, entra_special, descriptions = scenarios()
    manifest = {
        "generatorVersion": "linked-investigation-v1",
        "synthetic": True,
        "seed": 20260905,
        "periodUTC": ["2026-08-17T08:00:00Z", "2026-09-04T17:00:00Z"],
        "files": [],
        "settings": SETTINGS,
        "scenarios": descriptions,
    }
    truth = []

    def finish(path, count, kind):
        entry = {"path": path.name, "records": count, "bytes": path.stat().st_size, "sha256": digest(path), "kind": kind}
        manifest["files"].append(entry)
        print(f"{out.name}/{path.name}: {count:,} records, {entry['bytes'] / 1e6:.1f} MB", flush=True)

    def record_truth(row, file, ordinal, locator):
        if row.get("scenario"):
            truth.append(
                {"scenario": row["scenario"], "label": row["label"], "key": row["key"], "file": file, "ordinal": ordinal, "timeUTC": iso(row["t"]), **locator}
            )

    path = out / "Mailboxes.mbox"
    n = counts["mails"] - len(mail_special)
    with path.open("xb") as fh:
        for i, row in enumerate(merge(normal_mails(n), mail_special), 1):
            raw = message_bytes(row)
            fh.write(b"From synthetic@remn-lab.example Mon Aug 17 08:00:00 2026\n" + raw.replace(b"\nFrom ", b"\n>From ").rstrip(b"\n") + b"\n\n")
            record_truth(
                row,
                path.name,
                i,
                {
                    "messageId": f"<{row['key']}@remn-lab.example>",
                    "attachments": [{"name": a[0], "sha256": hashlib.sha256(a[1]).hexdigest()} for a in row.get("attachments", [])],
                },
            )
    finish(path, i, "mail")
    ratios = {"Security": 0.6, "Sysmon": 0.3, "PowerShell": 0.08, "System": 0.019, "Defender": 0.001}
    remaining = counts["windows"]
    for channel, ratio in ratios.items():
        count = round(counts["windows"] * ratio) if channel != "Defender" else remaining
        remaining -= count
        special = [r for r in win_special if r["channel"] == channel]
        if count < len(special):
            raise ValueError(f"Too few {channel} rows for scenarios")
        path = out / (channel + ".evtx")
        provider, ch = PROVIDERS[channel]
        with EvtxWriter(path) as w:
            for i, row in enumerate(merge(normal_windows(channel, count - len(special)), special), 1):
                data = {**row["data"], "SyntheticRecord": row["key"]}
                w.add(
                    event_node(i, iso(row["t"]), provider, ch, row["host"], row["event_id"], data, level=3 if row["event_id"] in (4625, 1116) else 4),
                    row["t"] * 1000,
                )
                record_truth(row, path.name, i, {"eventRecordId": i, "eventId": row["event_id"], "host": row["host"]})
                if i % 100000 == 0:
                    print(f"  {channel}: {i:,} / {count:,}", flush=True)
        finish(path, i, "evtx")
    path = out / "M365-UnifiedAuditLog.csv"
    with path.open("x", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["CreationDate", "UserIds", "Operations", "AuditData"])
        for i, row in enumerate(merge(normal_ual(counts["ual"] - len(audit_special)), audit_special), 1):
            raw = row["raw"]
            writer.writerow([raw["CreationTime"], raw["UserId"], raw["Operation"], json.dumps(raw, separators=(",", ":"))])
            record_truth(row, path.name, i, {"auditId": raw["Id"], "operation": raw["Operation"]})
    finish(path, i, "m365-ual-csv")
    path = out / "M365-EntraSignIns.jsonl"
    with path.open("x", encoding="utf-8", newline="\n") as fh:
        for i, row in enumerate(merge(normal_signins(counts["entra"] - len(entra_special)), entra_special), 1):
            fh.write(json.dumps(row["raw"], separators=(",", ":")) + "\n")
            record_truth(row, path.name, i, {"signInId": row["raw"]["id"]})
    finish(path, i, "entra-signin-json")
    manifest["totalBytes"] = sum(f["bytes"] for f in manifest["files"])
    manifest["totalRecords"] = sum(f["records"] for f in manifest["files"])
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (out / "ground-truth.jsonl").write_text("".join(json.dumps(r) + "\n" for r in truth), encoding="utf-8")
    (out / "case-settings.json").write_text(json.dumps(SETTINGS, indent=2) + "\n", encoding="utf-8")
    return manifest


def write_guide(out):
    out = out.resolve()
    manifests = {p.name: json.loads((p / "manifest.json").read_text()) for p in out.iterdir() if p.is_dir() and (p / "manifest.json").exists()}
    text = [
        "# REMN linked investigation lab",
        "",
        "Start with **quick-start** in a new case. Use **large** in a separate server-store case for ingestion, search, rule and correlation load testing.",
        "",
        "Both packs contain the same planted stories, with different volumes of normal background activity. Do not import both packs into one case: the scenario records intentionally overlap.",
        "",
        "## Load the evidence",
        "",
        "1. Restart the updated REMN application. Create a new case named `Linked lab - quick` or `Linked lab - large`.",
        "2. For the large pack, choose **server store** before importing. Set internal domains to `northstar.example`, expected countries to `FR`, VIP names to `marie lefevre`, internal IPs to `10.0.0.0/8`, and business hours to 08:00-19:00 Europe/Paris. Keep deep attachment analysis and mail bodies enabled. `case-settings.json` is a reference to copy into Settings, not an importable case bundle.",
        "3. In Evidence, import `Mailboxes.mbox` as mail. Import the five `.evtx` files and the M365 `.csv`/`.jsonl` files as events. All eight evidence files must belong to the same case. Ignore the guides, manifest, ground truth and validation JSON files when importing.",
        "4. Wait until all eight evidence items finish. Verify the counts below and that no parsing errors are reported.",
        "5. Run **Mails -> rescore + refresh findings**. Then run all enabled rules from Findings, so Windows and M365 findings are refreshed too. For a comparison with the measured baseline, enable bundled core rules and disable community packs initially; then enable Sublime/Sigma to compare the extra findings.",
        "6. Open **Attack chains -> build chains**, using minimum mail risk 45 and a 72-hour window. Open each seed and follow the DNS, file, process, sign-in and mailbox links.",
        "7. Search Mails subjects for `[S01]` through `[S06]`. Search events in the raw/data fields for `S01` through `S06`; `ground-truth.jsonl` gives exact source record numbers and cloud record GUIDs.",
        "",
        "## Packs and files",
        "",
    ]
    for name, m in manifests.items():
        text += [
            f"### {name}: {m['totalRecords']:,} records / {m['totalBytes'] / 1e9:.3f} GB",
            "",
            "| Evidence file | Records | Size (MB) |",
            "|---|---:|---:|",
        ]
        for f in m["files"]:
            text.append(f"| [{f['path']}](<{out / name / f['path']}>) | {f['records']:,} | {f['bytes'] / 1e6:.1f} |")
        text += [
            "",
            f"Expected totals: **{sum(f['records'] for f in m['files'] if f['kind'] == 'mail'):,} mails**, **{sum(f['records'] for f in m['files'] if f['kind'] != 'mail'):,} events**. M365 and Windows share the Events table.",
            "",
        ]
        truth = [json.loads(line) for line in (out / name / "ground-truth.jsonl").read_text().splitlines()]
        with (out / name / "record-locators.csv").open("w", encoding="utf-8", newline="") as fh:
            fields = [
                "scenario",
                "label",
                "key",
                "file",
                "ordinal",
                "timeUTC",
                "messageId",
                "eventRecordId",
                "eventId",
                "host",
                "auditId",
                "signInId",
                "operation",
            ]
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(truth)
    text += ["## What should link", "", "| Scenario | Identity | Start (UTC) | Expected investigation |", "|---|---|---|---|"]
    for s in next(iter(manifests.values()))["scenarios"]:
        text.append(f"| {s['id']} | `{s['victim']}` | {s['startUTC']} | {s['title']} |")
    text += [
        "",
        "The five attack stories are S01, S02, S03, S04 and S06. They include a seed mail, an actual reply with matching In-Reply-To, a DNS lookup for the same domain, a download with the same attachment name, a risky sign-in, mailbox access and forwarding/consent records. S02 and S04 add Outlook-to-PowerShell process creation, a scheduled task, a service installation and a Defender alert. S03 adds role assignment and a file-download burst. S04 adds failed logons, RDP success, group membership and an admin-share event.",
        "",
        "S05 is the false-positive control: static HTML in ZIP, harmless PDF JavaScript, a CSV-export page, a bank-change notice and a normal invoice with a webmail Reply-To. Expected calibrated mail scores are **22, 31, 31, 13, 35**. These five should have no high/critical bundled mail findings.",
        "",
        "S06 comes from `reports@vendor.example`, the same authenticated supplier seen repeatedly in earlier benign mail. Its suspicious attachment should still receive a high/critical score despite sender history.",
        "",
        "## Deliberate negative controls",
        "",
        "- `NEG-TIME-001`: the same domain appears on Alice's host on 20 August, well outside S01's 72-hour window. It should not join S01.",
        "- `NEG-TENANT-001`: `alice.martin@other-tenant.example` on `OTHER-WS-001` is a different identity. It should not join Alice's Northstar chain. The current project normalizer drops domain scope and **does join this record in the tested version**. This is a planted test of the known correlation defect, not part of the attack story.",
        "",
        "## Ground truth and limits",
        "",
        "`manifest.json` contains exact file sizes, SHA-256 hashes, record counts, settings and scenario artifacts. `record-locators.csv` and `ground-truth.jsonl` label all planted records. Other records are generated background activity; a generic heuristic finding on background does not prove the generator planted an attack. Database row IDs can differ by import order: use Message-ID, source EVTX record ID or cloud GUID to locate the evidence.",
        "",
        "`validation-results.json` records the validation actually performed. Full file parsing/count/hash checks cover every record. Unless it says `all parsed rows`, the rule/chain evaluation uses all planted records plus the first 500 background rows from each source. Finding totals can vary with rule packs/settings/version; use the intended identities and artifact links as the acceptance criteria.",
        "",
        "Dates span 17 August-4 September 2026. Times here are UTC; the UI can display local time. Identities and logs are fabricated, service domains use `.example`, and IPs use private/documentation ranges. The Gmail address is only a synthetic header for the webmail Reply-To control. No messages are sent and no live services are contacted. Attachments contain static test signatures or disabled forms, not functioning malware. Authentication results are fabricated reports, not cryptographically signed mail.",
        "",
        "The EVTX files were generated offline, not by changing the computer's event logs. The format encoder was implemented using [Microsoft's BinXML specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/c73573ae-1c90-43a2-a65f-ad7501155956) and the [libevtx format documentation](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc).",
        "",
        "## Repeat or validate",
        "",
        "Run from the project root:",
        "",
        "```powershell",
        ".\\.venv\\Scripts\\python.exe samples/synthetic/make_linked_lab.py --out samples/generated/another-linked-lab",
        ".\\.venv\\Scripts\\python.exe samples/synthetic/validate_linked_lab.py samples/generated/another-linked-lab/quick-start --retain-all",
        ".\\.venv\\Scripts\\python.exe samples/synthetic/validate_linked_lab.py samples/generated/another-linked-lab/large",
        "```",
        "",
        "The generator refuses an existing output directory. Generated evidence is ignored by Git; the reproducible generators are source files.",
        "",
    ]
    (out / "START-HERE.md").write_text("\n".join(text), encoding="utf-8")
    with (out / "identities.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["upn", "windowsIdentity", "host", "expectedCountry"])
        for i, user in enumerate(NAMES, 1):
            writer.writerow([user + "@" + ORG, "NORTHSTAR\\" + user, f"WS-{i:03d}.{ORG}", "FR"])
    (out / "investigation-queries.sql").write_text(
        """-- Run SELECT queries in a server-store case after loading all eight evidence files.
-- Inspect planted mails and their risk.
SELECT id, "messageId", "dateIso", "fromAddr", subject, risk, flags
FROM mails WHERE subject LIKE '%[S0%' ORDER BY date;

-- Timeline for S01, including cloud and Windows observations.
SELECT id, "tsIso", "eventId", operation, computer, "targetUser", "subjectUser", "user", "ipAddress", summary
FROM events WHERE data LIKE '%S01%' ORDER BY ts;

-- Match an attachment across mail and endpoint observations.
SELECT id, "tsIso", "eventId", computer, "commandLine", "targetFilename", data
FROM events WHERE data LIKE '%Shipping_NS-002.pdf.exe%' ORDER BY ts;

-- Follow mailbox forwarding/consent across all victims.
SELECT id, "tsIso", operation, "subjectUser", "ipAddress", data
FROM events WHERE operation IN ('New-InboxRule','Set-Mailbox','Consent to application.','Add member to role.') ORDER BY ts;

-- Verify the unrelated same-name, different-tenant control.
SELECT id, "tsIso", computer, "subjectUser", data FROM events WHERE data LIKE '%NEG-TENANT%';
""",
        encoding="utf-8",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "samples/generated/linked-lab")
    parser.add_argument("--quick-only", action="store_true")
    args = parser.parse_args()
    if args.out.exists():
        parser.error("Output directory already exists; choose a new directory")
    args.out.mkdir(parents=True)
    build_pack(args.out / "quick-start", {"mails": 1000, "windows": 10000, "ual": 2000, "entra": 2000})
    if not args.quick_only:
        build_pack(args.out / "large", {"mails": 100000, "windows": 1000000, "ual": 250000, "entra": 250000})
    write_guide(args.out)
    print("Completed:", args.out.resolve(), flush=True)


if __name__ == "__main__":
    main()
