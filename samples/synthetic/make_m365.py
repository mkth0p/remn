"""
Synthetic Microsoft 365 exports for demos and tests: a small business-email-compromise
scenario as a Unified Audit Log CSV (Purview / Invictus layout), the same records as a JSON
array of AuditData objects, an Entra sign-in JSON (Graph objects) and an Entra portal CSV.

    .venv\\Scripts\\python.exe samples\\synthetic\\make_m365.py [out_dir]

Scenario (UTC, 1-2 September 2026), tenant contoso.com, victim alice@contoso.com:
  01 09:05  phishing mail arrives (not in these files - drop the mailbox export for that)
  01 09:20  sign-in from RU, "Other clients" (legacy IMAP), then a risky sign-in from NL
  01 09:25  MailItemsAccessed burst (Sync) from the RU IP
  01 09:31  New-InboxRule "." : forward to attacker@proton-mail.example + delete + subject "invoice"
  01 09:40  Set-Mailbox ForwardingSmtpAddress
  01 10:02  Consent to application (mail.read offline_access) by alice
  02 08:00  Add member to role: Global Administrator for bob (attacker escalation)
  plus normal activity: sign-ins from FR, FileDownloaded, UserLoggedIn records.
"""
from __future__ import annotations

import csv
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

T0 = datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc)
VICTIM = "alice@contoso.com"
ADMIN = "bob@contoso.com"
RU_IP = "185.220.101.44"
NL_IP = "45.83.64.12"
FR_IP = "82.64.10.3"


def _t(minutes: float, day: int = 0) -> str:
    return (T0 + timedelta(days=day, minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")


def _ual(op: str, workload: str, user: str, ip: str, minutes: float, day: int = 0, **extra: Any) -> dict[str, Any]:
    rec = {"CreationTime": _t(minutes, day), "Id": f"{op}-{minutes}-{day}", "Operation": op, "OrganizationId": "11111111-2222-3333-4444-555555555555",
           "RecordType": extra.pop("RecordType", 1), "ResultStatus": extra.pop("ResultStatus", "Succeeded"), "UserKey": user, "UserType": 0,
           "Version": 1, "Workload": workload, "ClientIP": ip, "UserId": user}
    rec.update(extra)
    return rec


def ual_records() -> list[dict[str, Any]]:
    recs: list[dict[str, Any]] = []
    # normal traffic
    for i in range(6):
        recs.append(_ual("UserLoggedIn", "AzureActiveDirectory", VICTIM, FR_IP, -120 + i * 15, RecordType=15,
                         ExtendedProperties=[{"Name": "UserAgent", "Value": "Mozilla/5.0 (Windows NT 10.0) Edge/128"}, {"Name": "RequestType", "Value": "OAuth2:Authorize"}, {"Name": "ResultStatusDetail", "Value": "Success"}],
                         Actor=[{"ID": VICTIM, "Type": 5}], Target=[{"ID": "Office 365 Exchange Online", "Type": 0}], ObjectId="Office 365 Exchange Online"))
        recs.append(_ual("FileAccessed", "SharePoint", VICTIM, FR_IP, -110 + i * 15, RecordType=6, ObjectId=f"https://contoso.sharepoint.com/sites/finance/Shared Documents/report-{i}.xlsx",
                         SiteUrl="https://contoso.sharepoint.com/sites/finance/", SourceFileName=f"report-{i}.xlsx", UserAgent="Mozilla/5.0"))
    # attacker: legacy sign-in from RU (UAL view of it)
    recs.append(_ual("UserLoggedIn", "AzureActiveDirectory", VICTIM, RU_IP, 20, RecordType=15,
                     ExtendedProperties=[{"Name": "UserAgent", "Value": "BAV2ROPC"}, {"Name": "RequestType", "Value": "OAuth2:Token"}, {"Name": "ResultStatusDetail", "Value": "Success"}],
                     Actor=[{"ID": VICTIM, "Type": 5}], Target=[{"ID": "Office 365 Exchange Online", "Type": 0}], ObjectId="Office 365 Exchange Online"))
    # mailbox enumeration burst
    for i in range(30):
        recs.append(_ual("MailItemsAccessed", "Exchange", VICTIM, RU_IP, 25 + i * 0.3, RecordType=50, MailboxOwnerUPN=VICTIM, LogonType=0,
                         ClientInfoString="Client=REST;Client=RESTSystem;;", ClientAppId="00000003-0000-0000-c000-000000000000",
                         OperationProperties=[{"Name": "MailAccessType", "Value": "Sync"}, {"Name": "IsThrottled", "Value": "False"}],
                         Folders=[{"Path": "\\Inbox", "FolderItems": [{"InternetMessageId": f"<m{i}-{j}@contoso.com>"} for j in range(8)]}]))
    # inbox rule: forward + delete + invoice subject
    recs.append(_ual("New-InboxRule", "Exchange", VICTIM, RU_IP, 31, RecordType=1, ObjectId="EURPR05A001.prod.outlook.com/Microsoft Exchange Hosted Organizations/contoso.onmicrosoft.com/alice\\.",
                     ExternalAccess=False, OriginatingServer="PAVPR05MB10277 (15.20.4200.000)",
                     Parameters=[{"Name": "Name", "Value": "."}, {"Name": "ForwardTo", "Value": "attacker@proton-mail.example"}, {"Name": "DeleteMessage", "Value": "True"},
                                 {"Name": "SubjectContainsWords", "Value": "invoice;payment;facture"}, {"Name": "StopProcessingRules", "Value": "True"}]))
    # mailbox forwarding
    recs.append(_ual("Set-Mailbox", "Exchange", VICTIM, RU_IP, 40, RecordType=1, ObjectId=f"contoso.onmicrosoft.com/alice",
                     Parameters=[{"Name": "Identity", "Value": VICTIM}, {"Name": "ForwardingSmtpAddress", "Value": "smtp:attacker@proton-mail.example"}, {"Name": "DeliverToMailboxAndForward", "Value": "True"}]))
    # consent phishing
    recs.append(_ual("Consent to application.", "AzureActiveDirectory", VICTIM, NL_IP, 62, RecordType=8, ObjectId="Mail Reader Pro",
                     Actor=[{"ID": VICTIM, "Type": 5}], Target=[{"ID": "Mail Reader Pro", "Type": 1}, {"ID": "ServicePrincipal_deadbeef", "Type": 2}],
                     ModifiedProperties=[{"Name": "ConsentContext.IsAdminConsent", "NewValue": "False", "OldValue": ""},
                                         {"Name": "ConsentAction.Permissions", "NewValue": "[] => [[Id: aaaa, ClientId: bbbb, PrincipalId: cccc, ResourceId: dddd, ConsentType: Principal, Scope: Mail.Read offline_access User.Read]]", "OldValue": ""}]))
    # privilege escalation next day
    recs.append(_ual("Add member to role.", "AzureActiveDirectory", VICTIM, NL_IP, 0, day=1, RecordType=8, ObjectId=ADMIN,
                     Actor=[{"ID": VICTIM, "Type": 5}], Target=[{"ID": ADMIN, "Type": 5}, {"ID": "User_" + ADMIN, "Type": 2}],
                     ModifiedProperties=[{"Name": "Role.DisplayName", "NewValue": "\"Global Administrator\"", "OldValue": ""},
                                         {"Name": "Role.ObjectID", "NewValue": "\"62e90394-69f5-4237-9190-012177145e10\"", "OldValue": ""}]))
    return recs


def entra_signins() -> list[dict[str, Any]]:
    def si(minutes: float, user: str, ip: str, country: str, city: str, app: str, client: str, err: int = 0, risk: str = "none", state: str = "none", day: int = 0, reason: str | None = None) -> dict[str, Any]:
        return {"id": f"si-{user}-{minutes}-{day}", "createdDateTime": _t(minutes, day) + "Z", "userDisplayName": user.split("@")[0].title(),
                "userPrincipalName": user, "userId": "u-" + user, "appId": "00000002-0000-0ff1-ce00-000000000000", "appDisplayName": app,
                "ipAddress": ip, "clientAppUsed": client, "conditionalAccessStatus": "notApplied", "isInteractive": True,
                "riskDetail": "none", "riskLevelAggregated": risk, "riskLevelDuringSignIn": risk, "riskState": state, "riskEventTypes_v2": [],
                "resourceDisplayName": "Office 365 Exchange Online", "userAgent": "Mozilla/5.0" if client == "Browser" else "BAV2ROPC",
                "status": {"errorCode": err, "failureReason": reason or ("Other." if err == 0 else "Error validating credentials due to invalid username or password."), "additionalDetails": None},
                "deviceDetail": {"deviceId": "", "displayName": "", "operatingSystem": "Windows 10", "browser": "Edge 128.0.0" if client == "Browser" else None, "isCompliant": False, "isManaged": False},
                "location": {"city": city, "state": None, "countryOrRegion": country, "geoCoordinates": {}}}

    out = []
    for i in range(5):
        out.append(si(-150 + i * 20, VICTIM, FR_IP, "FR", "Paris", "Office 365 Exchange Online", "Browser"))
        out.append(si(-140 + i * 20, ADMIN, FR_IP, "FR", "Lyon", "Microsoft Teams", "Mobile Apps and Desktop clients"))
    # password spray from RU against 9 accounts, then success against alice via legacy auth
    for i in range(9):
        out.append(si(10 + i * 0.5, f"user{i}@contoso.com", RU_IP, "RU", "Moscow", "Office 365 Exchange Online", "Other clients", err=50126))
    for i in range(11):
        out.append(si(14 + i * 0.3, VICTIM, RU_IP, "RU", "Moscow", "Office 365 Exchange Online", "Other clients", err=50126))
    out.append(si(20, VICTIM, RU_IP, "RU", "Moscow", "Office 365 Exchange Online", "Other clients"))
    out.append(si(60, VICTIM, NL_IP, "NL", "Amsterdam", "Azure Portal", "Browser", risk="high", state="atRisk"))
    return out


def write_all(out_dir: str) -> dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    recs = ual_records()
    paths = {}
    p = os.path.join(out_dir, "ual_export.csv")
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["CreationDate", "UserIds", "Operations", "AuditData", "RecordType", "ResultIndex", "ResultCount", "Identity", "IsValid", "ObjectState"])
        for i, r in enumerate(recs):
            w.writerow([r["CreationTime"], r["UserId"], r["Operation"], json.dumps(r, ensure_ascii=False), r.get("RecordType"), i + 1, len(recs), r["Id"], "True", "Unchanged"])
    paths["ual_csv"] = p
    p = os.path.join(out_dir, "ual_export.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(recs, fh, ensure_ascii=False, indent=1)
    paths["ual_json"] = p
    signins = entra_signins()
    p = os.path.join(out_dir, "entra_signins.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(signins, fh, ensure_ascii=False, indent=1)
    paths["entra_json"] = p
    p = os.path.join(out_dir, "entra_signins_portal.csv")
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["Date (UTC)", "Request ID", "User agent", "Correlation ID", "Conditional access", "Interactive", "Username", "User ID", "Sign-in identifier",
                    "Status", "Failure reason", "IP address", "Location", "Application", "Application ID", "Resource", "Client app", "Browser", "Operating System",
                    "Risk state", "Risk level (aggregate)", "Risk level (sign-in)", "Sign-in error code"])
        for s in signins:
            loc = s["location"]
            w.writerow([s["createdDateTime"].replace("T", " ").rstrip("Z"), s["id"], s["userAgent"], "c-1", s["conditionalAccessStatus"], "Yes", s["userPrincipalName"], s["userId"], s["userPrincipalName"],
                        "Success" if s["status"]["errorCode"] == 0 else "Failure", s["status"]["failureReason"] if s["status"]["errorCode"] else "", s["ipAddress"],
                        f"{loc['city']}, , {loc['countryOrRegion']}", s["appDisplayName"], s["appId"], s["resourceDisplayName"], s["clientAppUsed"], s["deviceDetail"]["browser"] or "",
                        s["deviceDetail"]["operatingSystem"], s["riskState"], s["riskLevelAggregated"], s["riskLevelDuringSignIn"], s["status"]["errorCode"]])
    paths["entra_csv"] = p
    return paths


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "m365")
    for k, v in write_all(out).items():
        print(k, v)
