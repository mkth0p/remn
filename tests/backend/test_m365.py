"""Microsoft 365 Unified Audit Log / Entra sign-in exports -> event rows -> BEC rules."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import make_m365
import pytest
import yaml
from django.test import Client

from services.ingest.pipeline import EvtxSource, detect_evtx_format
from services.parsers import m365
from services.store import rules as R
from services.store.casestore import StoreRegistry
from services.store.writers import EventWriter

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
RULES = Path(__file__).resolve().parents[2] / "rules" / "m365" / "bec.yaml"


@pytest.fixture(scope="module")
def exports(tmp_path_factory):
    return make_m365.write_all(str(tmp_path_factory.mktemp("m365")))


@pytest.fixture
def store(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    st = reg.get(str(uuid.uuid4()))
    yield st
    reg.close_all()


def _rows(path: str) -> list[dict]:
    src = EvtxSource(Path(path).name, path, None, str(Path(path).parent))
    return list(src), src


def test_format_detection(exports):
    for key, fmt in (("ual_csv", "m365-ual-csv"), ("ual_json", "m365-ual-json"), ("entra_json", "entra-signin-json"), ("entra_csv", "entra-signin-csv")):
        p = Path(exports[key])
        assert detect_evtx_format(p.name, p.read_bytes()[:512]) == fmt, key
    assert detect_evtx_format("System.evtx", b"ElfFile\x00" + b"\x00" * 100) == "evtx"
    assert m365.detect_format("random.csv", b"a,b,c\n1,2,3\n") is None


def test_ual_csv_rows(exports):
    rows, src = _rows(exports["ual_csv"])
    assert src.format == "m365-ual-csv" and src.stats.errors == 0
    assert len(rows) == len(make_m365.ual_records())
    rule = next(r for r in rows if r["operation"] == "New-InboxRule")
    assert rule["provider"] == m365.UAL_PROVIDER and rule["channel"] == "Exchange" and rule["category"] == "M365 Exchange"
    assert rule["subjectUser"] == make_m365.VICTIM and rule["ipAddress"] == make_m365.RU_IP and rule["objectName"] == "."
    assert rule["data"]["ForwardTo"] == "attacker@proton-mail.example" and rule["data"]["DeleteMessage"] == "True"
    assert "attacker@proton-mail.example" in rule["summary"] and rule["ts"] and rule["tsIso"].endswith("Z")
    assert rule["eventId"] is None and rule["recordId"] == 1
    role = next(r for r in rows if r["operation"] == "Add member to role.")
    assert role["data"]["Role.DisplayName"] == "Global Administrator" and role["targetUser"] == make_m365.ADMIN
    mia = [r for r in rows if r["operation"] == "MailItemsAccessed"]
    assert len(mia) == 30 and mia[0]["data"]["MailAccessType"] == "Sync" and mia[0]["data"]["FolderItemCount"] == 8 and mia[0]["targetUser"] == make_m365.VICTIM
    consent = next(r for r in rows if r["operation"] == "Consent to application.")
    assert "Mail.Read" in consent["data"]["ConsentAction.Permissions"] and consent["category"] == "M365 Entra"
    login = next(r for r in rows if r["operation"] == "UserLoggedIn")
    assert login["category"] == "M365 Entra" and login["data"]["UserAgent"].startswith("Mozilla")
    assert "raw" in rule and json.loads(rule["raw"])["Operation"] == "New-InboxRule"


def test_ual_json_and_entra_rows(exports):
    rows, src = _rows(exports["ual_json"])
    assert src.format == "m365-ual-json" and len(rows) == len(make_m365.ual_records())
    rows, src = _rows(exports["entra_json"])
    assert src.format == "entra-signin-json" and len(rows) == len(make_m365.entra_signins())
    ok = [r for r in rows if r["status"] == "0"]
    bad = [r for r in rows if r["status"] == "50126"]
    assert ok and bad and all(r["category"] == "Entra sign-in" and r["provider"] == m365.ENTRA_PROVIDER for r in rows)
    risky = next(r for r in rows if r["data"].get("riskState") == "atRisk")
    assert risky["data"]["country"] == "NL" and risky["data"]["riskLevelDuringSignIn"] == "high" and risky["ipAddress"] == make_m365.NL_IP
    assert "risk=high" in risky["summary"]
    legacy = next(r for r in rows if r["ipAddress"] == make_m365.RU_IP and r["status"] == "0")
    assert legacy["data"]["clientAppUsed"] == "Other clients" and legacy["data"]["country"] == "RU"
    # portal CSV carries the same facts
    rows2, src2 = _rows(exports["entra_csv"])
    assert src2.format == "entra-signin-csv" and len(rows2) == len(rows)
    r2 = next(r for r in rows2 if r["ipAddress"] == make_m365.NL_IP)
    assert r2["data"]["country"] == "NL" and r2["data"]["riskState"] == "atRisk" and r2["status"] == "0" and r2["data"]["appDisplayName"] == "Azure Portal"
    f2 = next(r for r in rows2 if r["status"] != "0")
    assert f2["status"] == "50126" and f2["statusText"]


def test_zip_of_exports_is_walked(exports, tmp_path):
    import zipfile

    z = tmp_path / "m365-acquisition.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.write(exports["ual_csv"], "ual/ual_export.csv")
        zf.write(exports["entra_json"], "entra/signins.json")
        zf.writestr("notes/readme.txt", "not a log")
    src = EvtxSource(z.name, str(z), None, str(tmp_path))
    rows = list(src)
    assert src.format == "zip" and len(rows) == len(make_m365.ual_records()) + len(make_m365.entra_signins())
    assert {f["format"] for f in src.files if f["status"] == "parsed"} == {"m365-ual-csv", "entra-signin-json"}
    # the note is not a log, and the member list says so rather than leaving it out
    assert [f for f in src.files if f["status"] == "skipped"] == [
        {"name": "notes/readme.txt", "size": 9, "status": "skipped", "reason": "not an event log or cloud export"}
    ]
    assert {r["sourceFile"] for r in rows} == {"ual/ual_export.csv", "entra/signins.json"}


def test_bec_rules_fire_on_the_scenario(exports, store):
    w = EventWriter(store, 1)
    for key in ("ual_csv", "entra_json"):
        for row in _rows(exports[key])[0]:
            w.add(row)
    w.flush()
    rules = [d for d in yaml.safe_load_all(RULES.read_text(encoding="utf-8")) if isinstance(d, dict)]
    settings = {"internal_domains": ["contoso.com"], "expected_countries": ["FR"]}
    fired: dict[str, list] = {}
    errors = []
    for rule in rules:
        try:
            hits = R.run_rule(store, rule, settings)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{rule['id']}: {exc}")
            continue
        if hits:
            fired[rule["id"]] = hits
    assert not errors, errors
    expected = {
        "m365-inbox-rule-forwarding",
        "m365-inbox-rule-hiding",
        "m365-inbox-rule-any",
        "m365-mailbox-forwarding",
        "m365-mailitemsaccessed-burst",
        "m365-app-consent",
        "m365-privileged-role-assigned",
        "m365-role-assigned-any",
        "m365-signin-risky",
        "m365-signin-legacy-auth",
        "m365-signin-unexpected-country",
        "m365-signin-two-countries-24h",
        "m365-signin-password-spray",
        "m365-signin-bruteforce-account",
    }
    missing = expected - set(fired)
    assert not missing, f"rules that should fire on the scenario: {missing}; fired={sorted(fired)}"
    # sanity: the quiet rules stay quiet
    assert "m365-audit-disabled" not in fired and "m365-transport-rule-exfil" not in fired
    # entities carry the pivot keys
    fwd = fired["m365-inbox-rule-forwarding"][0]
    assert fwd["entities"]["subjectUser"] == make_m365.VICTIM and fwd["entities"]["ipAddress"] == make_m365.RU_IP
    spray = fired["m365-signin-password-spray"][0]
    assert spray["entities"]["ipAddress"] == make_m365.RU_IP and spray["count"] >= 8
    brute = fired["m365-signin-bruteforce-account"][0]
    assert brute["severity"] == "critical" and "Successful sign-in" in brute["title"]


def test_ingest_endpoint_streams_ual(exports):
    c = Client()
    with open(exports["ual_csv"], "rb") as fh:
        resp = c.post("/api/ingest/evtx", {"file": fh, "raw": "1"}, **HDR)
    assert resp.status_code == 200
    lines = [json.loads(l) for l in resp.getvalue().decode("utf-8").splitlines() if l.strip()]
    assert lines[0]["type"] == "meta" and lines[0]["format"] == "m365-ual-csv"
    events = [l for l in lines if l["type"] == "event"]
    assert len(events) == len(make_m365.ual_records()) and events[0]["provider"] == m365.UAL_PROVIDER
    assert lines[-1]["type"] == "done" and lines[-1]["stats"]["errors"] == 0


def _fired(store, rows: list[dict]) -> dict[str, list]:
    w = EventWriter(store, 1)
    for row in rows:
        w.add(row)
    w.flush()
    rules = [d for d in yaml.safe_load_all(RULES.read_text(encoding="utf-8")) if isinstance(d, dict)]
    return {r["id"]: hits for r in rules if (hits := R.run_rule(store, r, {"internal_domains": ["contoso.com"]}))}


def test_ipv6_client_addresses_keep_their_last_group():
    assert m365.clean_ip("2a01:e0a:1f2:3450::12") == "2a01:e0a:1f2:3450::12"
    assert m365.clean_ip("2001:db8::1") == "2001:db8::1"
    assert m365.clean_ip("[2001:db8::1]:443") == "2001:db8::1"
    assert m365.clean_ip("203.0.113.5:51000") == "203.0.113.5"
    assert m365.clean_ip("not an address") == "not an address"


def test_a_culture_date_order_is_decided_per_file(tmp_path):
    """A fr-FR Export-Csv writes 05/01/2024 for 5 January. One date in the file with a day above
    12 settles the order for every row; a de-DE export uses dots and is always day-first."""
    fr = tmp_path / "signins-fr.csv"
    fr.write_text(
        "Date (UTC),Request ID,User,Username,IP address,Status,Sign-in error code,Application\n"
        "05/01/2024 10:11:12,r1,Alice,alice@contoso.com,203.0.113.5,Success,0,Office 365\n"
        "15/01/2024 10:11:12,r2,Alice,alice@contoso.com,203.0.113.5,Success,0,Office 365\n",
        encoding="utf-8",
    )
    rows = list(m365.iter_records(str(fr), None, "entra-signin-csv"))
    assert [r["tsIso"][:10] for r in rows] == ["2024-01-05", "2024-01-15"]
    assert m365.parse_ts("05.01.2024 10:11:12")[1] == "2024-01-05T10:11:12.000Z"
    # a file that cannot tell keeps the portal's month-first order
    assert m365.date_order(["05/01/2024 10:11:12", "06/01/2024 10:11:12"]) is None


def test_an_indented_graph_page_is_read_not_dropped(tmp_path):
    page = {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns", "value": make_m365.entra_signins()[:3]}
    f = tmp_path / "signins.json"
    f.write_text(json.dumps(page, indent=2), encoding="utf-8")
    assert m365.detect_format(f.name, f.read_bytes()[:4096]) == "entra-signin-json"
    assert len(list(m365.iter_records(str(f), None, "entra-signin-json"))) == 3


def test_an_ndjson_line_that_does_not_parse_is_counted():
    from services.parsers.evtx_parser import Stats

    stats = Stats()
    data = (json.dumps(make_m365.entra_signins()[0]) + "\n{broken\n").encode()
    rows = list(m365.iter_records(None, data, "entra-signin-json", stats=stats))
    assert len(rows) == 1 and stats.errors == 1


def _update_inbox_rules(actions: list[dict], condition: dict) -> dict:
    return m365.ual_row(
        {
            "CreationTime": "2026-09-01T10:00:00",
            "Operation": "UpdateInboxRules",
            "Workload": "Exchange",
            "UserId": "alice@contoso.com",
            "ClientIP": "198.51.100.23",
            "ResultStatus": "Succeeded",
            "OperationProperties": [
                {"Name": "RuleName", "Value": "."},
                {"Name": "RuleOperation", "Value": "AddMailboxRule"},
                {"Name": "RuleActions", "Value": json.dumps(actions)},
                {"Name": "RuleCondition", "Value": json.dumps(condition)},
            ],
        },
        1,
    )


def test_an_outlook_made_forward_and_delete_rule_raises_the_same_findings_as_the_cmdlet(store):
    """An attacker in a stolen Outlook session makes the rule over MAPI, logged as UpdateInboxRules
    with JSON RuleActions and RuleCondition; the forwarding and hiding rules read it."""
    row = _update_inbox_rules(
        [{"ActionType": "Forward", "Recipients": ["attacker@evil.example"]}, {"ActionType": "Delete"}],
        {"Type": "AndCondition", "SubConditions": [{"Type": "SubjectContainsCondition", "Words": ["invoice"]}]},
    )
    assert row["objectName"] == "." and row["data"]["ForwardTo"] == "attacker@evil.example"
    assert row["data"]["DeleteMessage"] == "True" and row["data"]["SubjectContainsWords"] == "invoice"
    fired = _fired(store, [row])
    assert {"m365-inbox-rule-forwarding", "m365-inbox-rule-hiding"} <= set(fired)


def test_mfa_interrupts_are_not_failures(store):
    """Every MFA-protected sign-in passes through 50074 or 50076 before it succeeds: nine users
    doing that from the office's own address is a normal morning, not a password spray."""
    rows = []
    for i in range(9):
        for status in ("50074", "0"):
            rows.append(
                m365.entra_row(
                    {
                        "createdDateTime": f"2026-09-01T08:{i:02d}:{10 if status != '0' else 40}Z",
                        "userPrincipalName": f"user{i}@contoso.com",
                        "ipAddress": "203.0.113.10",
                        "status": {"errorCode": int(status)},
                        "appDisplayName": "Office 365 Exchange Online",
                    }
                )
            )
    fired = _fired(store, rows)
    assert "m365-signin-password-spray" not in fired and "m365-signin-mfa-failed-then-success" not in fired


def test_a_record_exported_twice_is_kept_once(exports, tmp_path):
    """Search-UnifiedAuditLog's large-set pages repeat records, and time slices overlap: the same
    AuditData.Id read again, in the same file or another member of the upload, is one record."""
    import zipfile

    recs = make_m365.ual_records()
    doubled = tmp_path / "ual_pages.json"
    doubled.write_text(json.dumps(recs + recs[:5]), encoding="utf-8")
    rows, src = _rows(str(doubled))
    assert len(rows) == len(recs) and src.stats.duplicates == 5 and src.stats.to_dict()["duplicates"] == 5

    z = tmp_path / "slices.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.write(exports["ual_csv"], "slice-1/ual.csv")
        zf.write(exports["ual_json"], "slice-2/ual.json")
        zf.write(exports["entra_json"], "entra/a.json")
        zf.write(exports["entra_json"], "entra/b.json")
    src = EvtxSource(z.name, str(z), None, str(tmp_path))
    rows = list(src)
    assert len(rows) == len(recs) + len(make_m365.entra_signins())
    assert len({r["recordKey"] for r in rows}) == len(rows)
    dup = {f["name"]: f.get("duplicates") for f in src.files}
    assert dup == {"slice-1/ual.csv": None, "slice-2/ual.json": len(recs), "entra/a.json": None, "entra/b.json": len(make_m365.entra_signins())}


def test_a_record_without_a_guid_is_never_dropped():
    same = {"CreationTime": "2026-09-01T10:00:00", "Operation": "FileDownloaded", "Workload": "SharePoint", "UserId": "a@contoso.com", "Id": "not-a-guid"}
    data = (json.dumps(same) + "\n" + json.dumps(same) + "\n").encode()
    rows = list(m365.iter_records(None, data, "m365-ual-json"))
    assert len(rows) == 2 and rows[0]["recordKey"] is None
    assert m365.record_key("ual", "{A1B2C3D4-0000-1111-2222-333344445555}") == "ual:a1b2c3d4-0000-1111-2222-333344445555"


def test_a_record_already_in_the_case_is_not_written_again(exports, store):
    rows, _ = _rows(exports["ual_json"])
    first = EventWriter(store, 1)
    for r in rows:
        first.add(r)
    first.flush()
    again, _ = _rows(exports["ual_csv"])
    second = EventWriter(store, 2)
    for r in again:
        second.add(r)
    second.flush()
    assert first.count == len(rows) and second.count == 0 and second.duplicates == len(rows)
    n = store.cursor().execute('SELECT count(*), count(DISTINCT "recordKey") FROM events').fetchone()
    assert n == (len(rows), len(rows))
    # the indicators of the records not written are not counted a second time
    ip = store.cursor().execute("SELECT sum(count) FROM iocs WHERE kind = 'ip' AND value = ?", [make_m365.RU_IP]).fetchone()[0]
    assert ip == sum(1 for r in rows if r["ipAddress"] == make_m365.RU_IP)


def test_the_messages_a_record_read_or_deleted_are_named():
    """MailItemsAccessed names each item it read, SoftDelete each item it removed, by Internet
    message id: kept, so the mailbox answers which messages they were."""
    read = m365.ual_row(
        {
            "CreationTime": "2026-09-01T10:00:00",
            "Operation": "MailItemsAccessed",
            "Workload": "Exchange",
            "UserId": "alice@contoso.com",
            "OperationProperties": [{"Name": "MailAccessType", "Value": "Bind"}],
            "Folders": [
                {"Path": "\\Inbox", "FolderItems": [{"InternetMessageId": "<a@x>"}, {"InternetMessageId": "<b@x>"}]},
                {"Path": "\\Sent Items", "FolderItems": [{"InternetMessageId": "<a@x>"}, {"Id": "no-message-id"}]},
            ],
        }
    )
    assert read["data"]["InternetMessageId"] == "<a@x>, <b@x>" and read["data"]["FolderItemCount"] == 4
    gone = m365.ual_row(
        {
            "CreationTime": "2026-09-01T10:05:00",
            "Operation": "SoftDelete",
            "Workload": "Exchange",
            "UserId": "alice@contoso.com",
            "AffectedItems": [{"InternetMessageId": f"<m{i}@x>", "Subject": "s"} for i in range(m365.MAX_MESSAGE_IDS + 3)],
        }
    )
    ids = gone["data"]["InternetMessageId"].split(", ")
    assert len(ids) == m365.MAX_MESSAGE_IDS and ids[0] == "<m0@x>" and gone["data"]["InternetMessageId.total"] == m365.MAX_MESSAGE_IDS + 3


def test_a_sign_in_keeps_what_ties_it_to_its_token():
    """Session and token ids join a sign-in to the audit records its token made
    (AppAccessContext.AADSessionId, .UniqueTokenId); protocol and transfer method show device-code use."""
    g = {
        **make_m365.entra_signins()[0],
        "sessionId": "0f1e2d3c-0000-1111-2222-333344445555",
        "uniqueTokenIdentifier": "AbCdEfGh123",
        "authenticationProtocol": "deviceCode",
        "originalTransferMethod": "deviceCodeFlow",
        "incomingTokenType": "primaryRefreshToken",
        "autonomousSystemNumber": 12345,
        "authenticationDetails": [
            {"authenticationMethod": "Password", "succeeded": True},
            {"authenticationMethod": "Mobile app notification", "succeeded": False},
        ],
        "appliedConditionalAccessPolicies": [{"displayName": "Require MFA", "result": "success"}, {"displayName": "Block legacy", "result": "notApplied"}],
    }
    row = m365.entra_row(g)
    d = row["data"]
    assert d["sessionId"] == g["sessionId"] and d["uniqueTokenIdentifier"] == "AbCdEfGh123" and d["incomingTokenType"] == "primaryRefreshToken"
    assert d["authenticationProtocol"] == "deviceCode" and d["autonomousSystemNumber"] == 12345 and d["id"] == g["id"]
    assert d["authenticationMethods"] == "Password" and d["appliedConditionalAccessPolicies"] == "Require MFA=success"
    assert "[device code]" in row["summary"] and row["recordKey"] == "entra:" + g["id"]
    # the portal's CSV columns land on the same names
    portal = m365.entra_row(
        {
            "Date (UTC)": "2026-09-01T10:00:00Z",
            "Username": "a@contoso.com",
            "Session ID": "s-1",
            "Unique token identifier": "t-1",
            "Authentication Protocol": "deviceCode",
        }
    )
    assert portal["data"]["sessionId"] == "s-1" and portal["data"]["uniqueTokenIdentifier"] == "t-1" and "[device code]" in portal["summary"]


def _graph_record(operation: str, audit: dict, **top) -> dict:
    """An auditLogRecord as the Graph audit log query returns it (Microsoft-Extractor-Suite Get-UALGraph)."""
    return {
        "id": str(uuid.uuid4()),
        "createdDateTime": "2026-09-01T10:00:00Z",
        "auditLogRecordType": "exchangeAdmin",
        "operation": operation,
        "service": "Exchange",
        "userPrincipalName": "alice@contoso.com",
        "clientIp": "203.0.113.7",
        "auditData": audit,
        **top,
    }


def test_graph_audit_log_query_records_are_read(tmp_path):
    # The Graph API writes the record under auditData (lowercase a); such a file was detected as a
    # UAL export and then gave no row at all.
    full = _graph_record(
        "Set-Mailbox",
        {
            "CreationTime": "2026-09-01T10:00:00",
            "Id": str(uuid.uuid4()),
            "Operation": "Set-Mailbox",
            "Workload": "Exchange",
            "UserId": "alice@contoso.com",
            "ClientIP": "203.0.113.7",
            "ObjectId": "alice@contoso.com",
            "Parameters": [{"Name": "ForwardingSmtpAddress", "Value": "smtp:drop@evil.example"}],
        },
    )
    # a record whose auditData omits what the envelope already says
    sparse = _graph_record(
        "New-InboxRule", {"Id": str(uuid.uuid4()), "Parameters": [{"Name": "Name", "Value": "."}, {"Name": "DeleteMessage", "Value": "True"}]}
    )
    for name, data in (("graph.json", json.dumps([full, sparse])), ("graph.jsonl", json.dumps(full) + "\n" + json.dumps(sparse) + "\n")):
        f = tmp_path / name
        f.write_text(data, encoding="utf-8")
        assert m365.detect_format(f.name, f.read_bytes()[:4096]) == "m365-ual-json"
        rows = list(m365.iter_records(str(f), None, "m365-ual-json"))
        assert [r["operation"] for r in rows] == ["Set-Mailbox", "New-InboxRule"], name
        assert rows[0]["data"]["ForwardingSmtpAddress"] == "smtp:drop@evil.example"
        assert all(r["subjectUser"] == "alice@contoso.com" and r["ipAddress"] == "203.0.113.7" and r["ts"] for r in rows)
        assert rows[1]["channel"] == "Exchange" and rows[1]["data"]["DeleteMessage"] == "True"


def test_azure_monitor_sign_in_exports_are_read(tmp_path):
    # Entra's diagnostic settings (Log Analytics, Event Hub, storage account) write each sign-in
    # under "properties" of an Azure Monitor record; such a file was read as an event log and failed.
    def record(category: str, props: dict, time: str = "2026-09-01T10:00:00.1234567Z") -> str:
        return json.dumps(
            {"time": time, "operationName": "Sign-in activity", "category": category, "callerIpAddress": props.get("ipAddress"), "properties": props}
        )

    spray = {
        "id": str(uuid.uuid4()),
        "createdDateTime": "2026-09-01T10:00:05Z",
        "userPrincipalName": "alice@contoso.com",
        "appDisplayName": "Azure Active Directory PowerShell",
        "ipAddress": "35.93.126.71",
        "status": {"errorCode": 50126, "failureReason": "Invalid username or password."},
    }
    background = {"id": str(uuid.uuid4()), "userPrincipalName": "bob@contoso.com", "ipAddress": "10.1.2.3", "status": {"errorCode": 0}}
    audit = {"id": str(uuid.uuid4()), "activityDisplayName": "Add member to role"}
    f = tmp_path / "signins.log"
    f.write_text(
        "\n\n" + "\n".join([record("SignInLogs", spray), record("NonInteractiveUserSignInLogs", background), record("AuditLogs", audit)]) + "\n",
        encoding="utf-8",
    )
    assert m365.detect_format(f.name, f.read_bytes()[:512]) == "entra-signin-json"
    source = EvtxSource(f.name, str(f), None, str(tmp_path))
    rows = list(source)
    assert source.format == "entra-signin-json"
    assert [(r["user"], r["ipAddress"], r["status"]) for r in rows] == [("alice@contoso.com", "35.93.126.71", "50126"), ("bob@contoso.com", "10.1.2.3", "0")]
    assert rows[0]["tsIso"] == "2026-09-01T10:00:05.000Z" and rows[0]["objectName"] == "Azure Active Directory PowerShell"
    # the envelope's time stands in when the sign-in has none
    assert rows[1]["tsIso"] == "2026-09-01T10:00:00.123Z"
    assert rows[0]["recordKey"] == f"entra:{spray['id']}"
    # the audit record is not a sign-in: it is not read, and the file says so
    assert source.stats.errors == 1
