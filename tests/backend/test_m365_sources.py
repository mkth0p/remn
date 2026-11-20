"""Microsoft 365 exports beyond the audit log and the sign-ins: how they are written (UTF-16, the
"#TYPE" line), Entra directory audits, Entra ID Protection, the Exchange Online message trace, and
the date order and zone an evidence file is read in. Every record here is invented."""

from __future__ import annotations

import csv
import io
import json
import zipfile
from pathlib import Path

import make_m365
import pytest
import yaml

from services.ingest.pipeline import EvtxSource, detect_evtx_format
from services.parsers import m365
from services.parsers.evtx_parser import Stats
from services.store import rules as R
from services.store.casestore import StoreRegistry
from services.store.writers import EventWriter

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "m365"
RULES = Path(__file__).resolve().parents[2] / "rules" / "m365" / "bec.yaml"


@pytest.fixture
def store(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    yield reg.get("5a0c6c1e-3a52-4d1b-9a43-6f0e5b1d2c3a")
    reg.close_all()


def _fired(store, rows: list[dict], settings: dict | None = None) -> dict[str, list]:
    """The BEC rules that fire on these rows, with what they found."""
    w = EventWriter(store, 1)
    for row in rows:
        w.add(row)
    w.flush()
    rules = [d for d in yaml.safe_load_all(RULES.read_text(encoding="utf-8")) if isinstance(d, dict)]
    return {r["id"]: hits for r in rules if (hits := R.run_rule(store, r, settings or {"internal_domains": ["contoso.com"]}))}


def _fixture(tmp_path: Path, name: str, data: bytes | None = None) -> tuple[list[dict], EvtxSource]:
    """A fixture read through the event-log import, as a file of its own."""
    return _source(tmp_path, name, (FIXTURES / name).read_bytes() if data is None else data)


def _ual_csv(records: list[dict], type_line: bool = False) -> str:
    """Search-UnifiedAuditLog | Export-Csv: one AuditData JSON column per record."""
    out = io.StringIO()
    if type_line:
        out.write("#TYPE Deserialized.Microsoft.Exchange.Management.SystemConfigurationTasks.AuditRecord\r\n")
    w = csv.writer(out, quoting=csv.QUOTE_ALL)
    w.writerow(["RecordType", "CreationDate", "UserIds", "Operations", "AuditData", "ResultIndex", "ResultCount", "Identity", "IsValid", "ObjectState"])
    for r in records:
        w.writerow([r["RecordType"], r["CreationTime"], r["UserId"], r["Operation"], json.dumps(r), 1, len(records), r["Id"], "True", "Unchanged"])
    return out.getvalue()


def _source(tmp_path: Path, name: str, data: bytes) -> tuple[list[dict], EvtxSource]:
    f = tmp_path / name
    f.write_bytes(data)
    src = EvtxSource(name, str(f), None, str(tmp_path))
    return list(src), src


def _package(tmp_path: Path, name: str, data: bytes) -> tuple[list[dict], dict]:
    from services.ingest.package import PackageSource
    from services.parsers.mail.common import ParseContext

    f = tmp_path / name
    f.write_bytes(data)
    source = PackageSource(name, str(f), None, str(tmp_path), ParseContext(analyze_attachments=False))
    return list(source), source.stats()


# ---------------------------------------------------------------------------
# How the exports are written
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be", "utf-32-le"])
def test_an_audit_log_csv_written_in_utf_16_or_utf_32_is_read(tmp_path, encoding):
    """Windows PowerShell's Export-Csv -Encoding Unicode and Out-File write UTF-16 with a byte order
    mark. Read as UTF-8, such an export was unrecognised, and the whole file was not read."""
    records = make_m365.ual_records()[:6]
    bom = {"utf-16-le": b"\xff\xfe", "utf-16-be": b"\xfe\xff", "utf-32-le": b"\xff\xfe\x00\x00"}[encoding]
    data = bom + _ual_csv(records).encode(encoding)
    assert detect_evtx_format("audit.csv", data[:65536]) == "m365-ual-csv"
    rows, src = _source(tmp_path, "audit.csv", data)
    assert src.stats.errors == 0 and [r["recordKey"] for r in rows] == [m365.record_key("ual", r["Id"]) for r in records]
    assert rows[0]["operation"] == records[0]["Operation"]


def test_sign_ins_written_in_utf_16_are_read_as_json_and_as_csv(tmp_path):
    signins = make_m365.entra_signins()[:4]
    data = json.dumps(signins, indent=2).encode("utf-16")
    assert data[:2] == b"\xff\xfe" and m365.detect_format("SignIns.json", data[:65536]) == "entra-signin-json"
    rows, src = _source(tmp_path, "SignIns.json", data)
    assert src.stats.errors == 0 and [r["user"] for r in rows] == [s["userPrincipalName"] for s in signins]
    portal = "Date (UTC),Request ID,Username,IP address,Status,Sign-in error code,Application\r\n2026-09-01T10:00:00Z,r1,alice@contoso.com,203.0.113.5,Success,0,Office 365\r\n"
    rows, src = _source(tmp_path, "SignIns.csv", portal.encode("utf-16"))
    assert src.format == "entra-signin-csv" and [r["tsIso"] for r in rows] == ["2026-09-01T10:00:00.000Z"]


def test_the_type_line_windows_powershell_writes_above_the_header_is_passed_over(tmp_path):
    """Export-Csv without -NoTypeInformation writes "#TYPE <type name>" above the header: the file
    was unrecognised, and read anyway the type line would have been taken for the header."""
    records = make_m365.ual_records()[:3]
    data = b"\xff\xfe" + _ual_csv(records, type_line=True).encode("utf-16-le")
    rows, src = _source(tmp_path, "audit.csv", data)
    assert src.format == "m365-ual-csv" and src.stats.errors == 0 and len(rows) == 3


def test_a_utf_16_export_in_an_archive_or_a_package_is_read(tmp_path):
    records = make_m365.ual_records()[:5]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("export/audit.csv", b"\xff\xfe" + _ual_csv(records, type_line=True).encode("utf-16-le"))
        z.writestr("export/signins.json", json.dumps(make_m365.entra_signins()[:2]).encode("utf-16"))
    rows, src = _source(tmp_path, "export.zip", buf.getvalue())
    assert len(rows) == 7 and [f["format"] for f in src.files] == ["m365-ual-csv", "entra-signin-json"]
    rows, stats = _package(tmp_path, "package.zip", buf.getvalue())
    assert len(rows) == 7 and [f["status"] for f in stats["files"]] == ["parsed", "parsed"]


def test_a_dotnet_date_written_by_windows_powershell_is_read():
    """ConvertTo-Json in Windows PowerShell writes a date as "\\/Date(milliseconds)\\/"."""
    signin = {**make_m365.entra_signins()[0], "createdDateTime": "/Date(1788256800000)/"}
    data = json.dumps([signin]).replace("/Date(", "\\/Date(").replace(")/", ")\\/").encode()
    (row,) = list(m365.iter_records(None, data, "entra-signin-json"))
    assert row["tsIso"] == "2026-09-01T10:00:00.000Z"
    assert m365.parse_ts("/Date(1788256800000+0200)/")[1] == "2026-09-01T10:00:00.000Z"


# ---------------------------------------------------------------------------
# The date order and time zone of an evidence file
# ---------------------------------------------------------------------------
def _portal_signins(dates: list[str]) -> bytes:
    """An Entra portal sign-in CSV, as re-saved by a spreadsheet in some culture."""
    head = "Date (UTC),Request ID,Username,IP address,Status,Sign-in error code,Application\n"
    return (head + "".join(f"{d},r{i},alice@contoso.com,203.0.113.5,Success,0,Office 365\n" for i, d in enumerate(dates))).encode()


def _graph_signins(dates: list[str]) -> bytes:
    """Get-MgAuditLogSignIn | Export-Csv: the time as the session's culture writes a DateTime."""
    head = "CreatedDateTime,Id,IPAddress,UserPrincipalName,AppDisplayName,ClientAppUsed\n"
    return (head + "".join(f"{d},id-{i},203.0.113.5,alice@contoso.com,Office 365,Browser\n" for i, d in enumerate(dates))).encode()


def test_a_date_order_set_for_the_evidence_reads_its_dates_in_that_order():
    """Every day at 12 or below: the file cannot show its order, and main read it month-first. The
    analyst who knows the export is day-first says so, and the import says which order it used."""
    dates = m365.date_setting({"order": "day-first"})
    stats = Stats()
    rows = list(
        m365.iter_records(None, _portal_signins(["05/01/2024 10:11:12", "06/01/2024 10:11:12", "06/06/2024 10:11:12"]), "entra-signin-csv", stats, dates=dates)
    )
    assert [r["tsIso"][:10] for r in rows] == ["2024-01-05", "2024-01-06", "2024-06-06"]
    assert stats.date_order_set == 2 and stats.date_order_guessed == 0 and stats.to_dict()["dateOrderSet"] == 2
    assert m365.note(m365.counts(stats), dates) == "2 record(s) were dated day-first, the date order set for the evidence"


def test_a_date_the_set_order_cannot_read_is_said():
    dates = m365.date_setting({"order": "month-first"})
    stats = Stats()
    rows = list(m365.iter_records(None, _portal_signins(["05/01/2024 10:11:12", "13/01/2024 10:11:12"]), "entra-signin-csv", stats, dates=dates))
    assert [r["tsIso"] for r in rows] == ["2024-05-01T10:11:12.000Z", None]
    assert stats.undated == 1 and stats.date_order_contradicted == 1 and stats.date_order_set == 1
    assert "1 record(s) have a date that cannot be read month-first, the date order set for the evidence, but can be read the other way" in m365.note(
        m365.counts(stats), dates
    )


def test_a_time_zone_set_for_the_evidence_moves_only_the_times_that_say_none():
    """Export-Csv writes a DateTime in the culture of the session, without its zone. A time with an
    offset keeps it, and a column whose name says UTC is not moved."""
    dates = m365.date_setting({"zone": "Europe/Paris"})
    stats = Stats()
    data = _graph_signins(["9/1/2026 10:00:00 AM", "1/15/2026 10:00:00 AM", "9/1/2026 10:00:00 AM +01:00", "2026-09-01T10:00:00Z", "2026-09-01 10:00:00"])
    rows = list(m365.iter_records(None, data, "entra-signin-csv", stats, dates=dates))
    # summer time in September, winter time in January
    assert [r["tsIso"] for r in rows] == [
        "2026-09-01T08:00:00.000Z",
        "2026-01-15T09:00:00.000Z",
        "2026-09-01T09:00:00.000Z",
        "2026-09-01T10:00:00.000Z",
        "2026-09-01T08:00:00.000Z",
    ]
    assert stats.zone_set == 3 and stats.zone_assumed == 0 and stats.dates == {"zone": "Europe/Paris"} and stats.to_dict()["zoneSet"] == 3
    assert m365.note(m365.counts(stats), dates) == "3 record(s) were read in Europe/Paris, the time zone set for the evidence: their times say none"
    stats = Stats()
    rows = list(m365.iter_records(None, _portal_signins(["9/1/2026 10:00:00 AM"]), "entra-signin-csv", stats, dates=dates))
    assert rows[0]["tsIso"] == "2026-09-01T10:00:00.000Z" and stats.zone_set == 0


def test_times_that_say_no_zone_are_counted_when_none_is_set():
    stats = Stats()
    rows = list(m365.iter_records(None, _graph_signins(["9/15/2026 10:00:00 AM", "2026-09-01T10:00:00Z"]), "entra-signin-csv", stats))
    assert [r["tsIso"] for r in rows] == ["2026-09-15T10:00:00.000Z", "2026-09-01T10:00:00.000Z"]
    assert stats.zone_assumed == 1 and stats.to_dict()["zoneAssumed"] == 1 and "dates" not in stats.to_dict()
    assert m365.note(m365.counts(stats)) == "1 record(s) were read as UTC: their times say no time zone, and none is set for the evidence"


def test_a_date_setting_is_read_from_what_the_analyst_chose_or_refused():
    assert m365.date_setting(None) is None and m365.date_setting("") is None and m365.date_setting({"order": "", "zone": ""}) is None
    assert m365.date_setting('{"order": "day-first", "zone": "+02:00"}').to_dict() == {"order": "day-first", "zone": "+02:00"}
    assert m365.date_setting({"zone": "UTC"}).to_dict() == {"zone": "UTC"}
    assert m365.parse_ts("9/1/2026 10:00 AM", zone=m365.date_setting({"zone": "-05:30"}).zone)[1] == "2026-09-01T15:30:00.000Z"
    for bad, said in (
        ({"order": "year-first"}, "neither day-first nor month-first"),
        ({"zone": "Mars/Olympus"}, "is not known"),
        ({"zone": "+15:00"}, "not one a clock uses"),
        ({"zone": "../../etc/passwd"}, "is not known"),
        ("not json", "not JSON"),
        (["day-first"], "an object"),
    ):
        with pytest.raises(ValueError, match=said):
            m365.date_setting(bad)


def test_a_package_reads_its_cloud_exports_with_the_setting_and_says_so(tmp_path):
    from services.ingest.package import PackageSource
    from services.parsers.mail.common import ParseContext

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("tenant/signins.csv", _portal_signins(["05/01/2024 10:11:12", "06/01/2024 10:11:12"]))
        z.writestr("tenant/graph.csv", _graph_signins(["9/1/2026 10:00:00 AM"]))
    f = tmp_path / "tenant.zip"
    f.write_bytes(buf.getvalue())
    source = PackageSource(f.name, str(f), None, str(tmp_path), ParseContext(analyze_attachments=False))
    source.dates = m365.date_setting({"order": "day-first", "zone": "+02:00"})
    rows = list(source)
    stats = source.stats()
    assert [r["tsIso"] for r in rows] == ["2024-01-05T10:11:12.000Z", "2024-01-06T10:11:12.000Z", "2026-01-09T08:00:00.000Z"]
    assert stats["dates"] == {"order": "day-first", "zone": "+02:00"} and stats["dateOrderSet"] == 3 and stats["zoneSet"] == 1
    notes = {m["name"]: m.get("note") for m in stats["files"]}
    assert notes["tenant/signins.csv"] == "2 record(s) were dated day-first, the date order set for the evidence"
    assert notes["tenant/graph.csv"] == (
        "1 record(s) were dated day-first, the date order set for the evidence; "
        "1 record(s) were read in +02:00, the time zone set for the evidence: their times say none"
    )


def test_the_ingest_endpoints_take_the_date_setting(tmp_path):
    from django.test import Client

    hdr = {"HTTP_X_FORENSIC_CLIENT": "1"}
    c = Client()
    data = _portal_signins(["05/01/2024 10:11:12"])
    f = tmp_path / "signins.csv"
    f.write_bytes(data)
    for url in ("/api/ingest/evtx", "/api/ingest/package"):
        with f.open("rb") as fh:
            resp = c.post(url, {"file": fh, "dates": json.dumps({"order": "day-first"})}, **hdr)
        lines = [json.loads(line) for line in resp.getvalue().decode().splitlines() if line.strip()]
        rows = [line for line in lines if line.get("tsIso")]
        assert [r["tsIso"] for r in rows] == ["2024-01-05T10:11:12.000Z"], url
        assert lines[-1]["type"] == "done" and lines[-1]["stats"]["dates"] == {"order": "day-first"} and lines[-1]["stats"]["dateOrderSet"] == 1, url
        with f.open("rb") as fh:
            resp = c.post(url, {"file": fh, "dates": json.dumps({"zone": "Nowhere/Town"})}, **hdr)
        assert resp.status_code == 400 and "Nowhere/Town" in resp.json()["error"], url
    resp = c.post(
        "/api/store/00000000-0000-4000-8000-000000000000/ingest",
        json.dumps({"uploadId": "u", "kind": "evtx", "evidence": {"id": 1}, "options": {"dates": {"order": "sideways"}}}),
        content_type="application/json",
        **hdr,
    )
    assert resp.status_code == 400 and "sideways" in resp.json()["error"]


# ---------------------------------------------------------------------------
# Entra directory audits
# ---------------------------------------------------------------------------
def _by_op(rows: list[dict]) -> dict[str, dict]:
    return {r["operation"]: r for r in rows}


def test_a_graph_page_of_directory_audits_is_read(tmp_path):
    rows, src = _fixture(tmp_path, "entra-directory-audits.graph.json")
    assert src.format == "entra-audit-json" and src.stats.errors == 0 and len(rows) == 6
    ops = _by_op(rows)
    assert set(ops) == {
        "Consent to application.",
        "User registered security info.",
        "Register device.",
        "Add service principal credentials.",
        "Add app role assignment to service principal.",
        "Add member to role.",
    }
    consent = ops["Consent to application."]
    assert consent["provider"] == m365.AUDIT_PROVIDER and consent["channel"] == "Entra Audit" and consent["category"] == "Entra audit"
    assert consent["description"] == "Consent to application" and consent["data"]["activityDisplayName"] == "Consent to application"
    assert consent["subjectUser"] == "alice@contoso.com" and consent["ipAddress"] == "198.51.100.23" and consent["objectName"] == "Mail Sync Helper"
    assert consent["tsIso"] == "2026-09-01T10:05:12.481Z" and consent["status"] == "success" and consent["level"] == 4
    assert "Scope: Mail.Read Mail.Send offline_access" in consent["data"]["ConsentAction.Permissions"]
    assert consent["data"]["ConsentContext.IsAdminConsent"] == "False" and consent["workstation"].startswith("Mozilla/5.0")
    assert consent["data"]["initiatedBy.user.id"] == "5f1c2a3b-0d4e-4f60-8a71-92b3c4d5e6f7" and consent["data"]["Target.Type"] == "ServicePrincipal"
    assert consent["recordKey"] == "entra-audit:directory_8c1d4f2e-3b5a-4c6d-9e7f-0a1b2c3d4e5f_kx2rg_10234561"
    role = ops["Add member to role."]
    assert (
        role["data"]["Role.DisplayName"] == "Global Administrator" and role["targetUser"] == "bob@contoso.com" and role["objectName"] == "Global Administrator"
    )
    assert role["subjectUser"] == "admin@contoso.com" and "role Global Administrator on bob@contoso.com" in role["summary"]
    # an activity an application performed names the application
    granted = ops["Add app role assignment to service principal."]
    assert granted["subjectUser"] == "Mail Sync Helper" and granted["ipAddress"] is None and granted["data"]["AppRole.Value"] == "Mail.ReadWrite"
    failed = ops["Add service principal credentials."]
    assert failed["level"] == 3 and failed["status"] == "failure" and failed["statusText"] == "Microsoft.Online.Workflows.InsufficientPrivilegesException"
    device = ops["Register device."]
    assert device["objectName"] == "DESKTOP-EXAMPLE1" and device["objectType"] == "Device" and device["data"]["Device Trust Type"] == "Workplace"
    # read again, in this file or another of the upload, a record is kept once
    rows, src = _fixture(
        tmp_path, "twice.json", json.dumps({"value": json.loads((FIXTURES / "entra-directory-audits.graph.json").read_text())["value"] * 2}).encode()
    )
    assert len(rows) == 6 and src.stats.duplicates == 6


def test_the_portal_downloads_are_read_as_graph_records_are(tmp_path):
    graph = {r["description"]: r for r in _fixture(tmp_path, "entra-directory-audits.graph.json")[0]}
    rows, src = _fixture(tmp_path, "entra-directory-audits.portal.json")
    assert src.format == "entra-audit-json" and [r["operation"] for r in rows] == ["Consent to application.", "User registered security info."]
    rows, src = _fixture(tmp_path, "entra-directory-audits.portal.csv")
    assert src.format == "entra-audit-csv" and src.stats.errors == 0 and len(rows) == 6

    def seen(r: dict) -> tuple:
        return (
            r["operation"],
            r["tsIso"],
            r["subjectUser"],
            r["targetUser"],
            r["ipAddress"],
            r["objectName"],
            r["status"],
            r["level"],
            r["data"].get("Role.DisplayName"),
        )

    assert sorted(seen(r) for r in rows) == sorted(seen(r) for r in graph.values())
    consent = _by_op(rows)["Consent to application."]
    assert consent["data"]["ConsentAction.Permissions"] == graph["Consent to application"]["data"]["ConsentAction.Permissions"]
    assert (
        consent["data"]["ActorType"] == "User"
        and consent["data"]["loggedByService"] == "Core Directory"
        and consent["data"]["category"] == "ApplicationManagement"
    )
    # the portal writes the date, service, category, activity and result columns in its own
    # language: they are read by their place, whatever they are called
    text = (FIXTURES / "entra-directory-audits.portal.csv").read_bytes().decode("utf-8")
    head, rest = text.split("\r\n", 1)
    translated = (
        head.replace("日付 (UTC)", "Datum (UTC)")
        .replace("サービス", "Dienst")
        .replace("カテゴリ", "Kategorie")
        .replace("アクティビティ", "Aktivität")
        .replace("結果", "Ergebnis")
    )
    again, _ = _fixture(tmp_path, "audit-de.csv", (translated + "\r\n" + rest).encode("utf-16"))
    assert sorted(seen(r) for r in again) == sorted(seen(r) for r in rows)


def test_directory_audits_written_by_export_csv_are_read_without_what_it_could_not_write():
    """Get-MgAuditLogDirectoryAudit | Export-Csv writes the initiator, the targets and the details
    as .NET type names: the rows say what was done and when, and keep the columns REMN does not know."""
    model = "Microsoft.Graph.PowerShell.Models"
    data = (
        "#TYPE Microsoft.Graph.PowerShell.Models.MicrosoftGraphDirectoryAudit\r\n"
        '"ActivityDateTime","ActivityDisplayName","AdditionalDetails","Category","CorrelationId","Id","InitiatedBy","LoggedByService",'
        '"OperationType","Result","ResultReason","TargetResources","AdditionalProperties","ExportedBy"\r\n'
        f'"9/15/2026 10:05:12 AM","Consent to application","{model}.IMicrosoftGraphKeyValue[]","ApplicationManagement",'
        f'"8c1d4f2e-3b5a-4c6d-9e7f-0a1b2c3d4e5f","Directory_8c1d4f2e-3b5a-4c6d-9e7f-0a1b2c3d4e5f_KX2RG_1","{model}.MicrosoftGraphAuditActivityInitiator",'
        f'"Core Directory","Assign","success","","{model}.IMicrosoftGraphTargetResource[]",'
        '"System.Collections.Generic.Dictionary`2[System.String,System.Object]","responder"\r\n'
    ).encode("utf-16")
    assert m365.detect_format("audit.csv", data) == "entra-audit-csv"
    stats = Stats()
    (row,) = list(m365.iter_records(None, data, "entra-audit-csv", stats))
    assert row["operation"] == "Consent to application." and row["tsIso"] == "2026-09-15T10:05:12.000Z" and row["subjectUser"] is None
    assert row["data"]["ExportedBy"] == "responder" and not any("Microsoft.Graph" in str(v) or "System." in str(v) for v in row["data"].values())
    # the time is written as the session's culture writes it, without a zone
    assert stats.zone_assumed == 1


def test_a_record_that_is_not_a_directory_audit_is_counted_not_read(tmp_path):
    page = json.loads((FIXTURES / "entra-directory-audits.graph.json").read_text())
    page["value"] = page["value"][:2] + [make_m365.entra_signins()[0]]
    data = json.dumps(page).encode()
    rows, stats = _package(tmp_path, "audit.zip", _zip({"tenant/AuditLogs.json": data}))
    (member,) = stats["files"]
    assert len(rows) == 2 and member["status"] == "error" and member["note"] == "1 record(s) are not of the kind the file holds and were not read"
    rows, src = _fixture(tmp_path, "AuditLogs.json", data)
    assert len(rows) == 2 and src.stats.errors == 1 and src.stats.to_dict()["notRead"] == 1


def test_azure_monitor_records_of_the_audit_log_are_not_taken_for_graph_records():
    """Their schema may differ from Graph's, Microsoft says: they are not read, and said so."""
    record = {
        "time": "2026-09-01T10:05:12Z",
        "category": "AuditLogs",
        "operationName": "Consent to application",
        "properties": {"activityDisplayName": "Consent to application", "activityDateTime": "2026-09-01T10:05:12Z"},
    }
    assert m365.detect_format("audit.json", json.dumps(record).encode()) is None
    assert detect_evtx_format("audit.json", json.dumps(record).encode()) == "unrecognised"


def test_the_bec_rules_fire_on_directory_audits(tmp_path, store):
    """The rules know the audit log's names for these activities, and a directory audit is named
    the same way, so a consent, a role or new security info is found in either export."""
    rows, _ = _fixture(tmp_path, "entra-directory-audits.graph.json")
    fired = _fired(store, rows)
    assert {"m365-app-consent", "m365-privileged-role-assigned", "m365-role-assigned-any", "m365-mfa-or-password-change", "m365-app-registered"} <= set(fired)
    assert fired["m365-app-consent"][0]["entities"]["subjectUser"] == "alice@contoso.com"


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()
