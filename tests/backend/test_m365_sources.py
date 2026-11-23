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


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
def test_an_export_in_utf_16_without_a_byte_order_mark_is_read(tmp_path, encoding):
    """.NET's Encoding.Unicode written without its preamble, and a file cut from a longer one, are
    UTF-16 with nothing declaring it. Read as UTF-8 such an export was not recognised; the NUL
    beside each character of its text says how it is written."""
    records = make_m365.ual_records()[:4]
    data = _ual_csv(records).encode(encoding)
    assert data[:2] not in (b"\xff\xfe", b"\xfe\xff")
    assert detect_evtx_format("audit.csv", data[:65536]) == "m365-ual-csv"
    rows, src = _source(tmp_path, "audit.csv", data)
    assert src.stats.errors == 0 and [r["recordKey"] for r in rows] == [m365.record_key("ual", r["Id"]) for r in records]
    signins = make_m365.entra_signins()[:3]
    data = json.dumps(signins).encode(encoding)
    assert detect_evtx_format("SignIns.json", data[:65536]) == "entra-signin-json"
    rows, src = _source(tmp_path, "SignIns.json", data)
    assert src.stats.errors == 0 and [r["user"] for r in rows] == [s["userPrincipalName"] for s in signins]


@pytest.mark.parametrize("indent", [None, 2])
def test_a_graph_export_whose_last_page_links_to_a_next_one_says_the_pages_after_it_are_missing(tmp_path, indent):
    """A Graph page that ends with @odata.nextLink is one page of a longer list. An export that
    stops there was read as if it were whole: the records of the pages after it are not in the
    case, and the file now says so. A file whose last page has no link is whole, whatever its
    earlier pages say; the links are invented."""
    link = "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=invented"
    signins = make_m365.entra_signins()[:4]
    pages = [
        {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns", "@odata.nextLink": link, "value": signins[:2]},
        {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns", "value": signins[2:], "@odata.nextLink": link},
    ]
    sep = "\n" if indent is None else "\n\n"
    cut = sep.join(json.dumps(p, indent=indent) for p in pages).encode()
    stats = Stats()
    rows = list(m365.iter_records(None, cut, "entra-signin-json", stats=stats))
    assert len(rows) == 4 and stats.errors == 0 and stats.to_dict()["nextPage"] == 1
    assert m365.note(m365.counts(stats)) == (
        "1 file(s) end with a Graph page that links to a next one (@odata.nextLink): the pages after it were not downloaded, and their records are not in the case"
    )
    whole = sep.join(json.dumps(p, indent=indent) for p in [pages[0], {k: v for k, v in pages[1].items() if k != "@odata.nextLink"}]).encode()
    stats = Stats()
    assert len(list(m365.iter_records(None, whole, "entra-signin-json", stats=stats))) == 4 and "nextPage" not in stats.to_dict()
    # a directory audit page, in a package: the member says it
    audits = json.loads((FIXTURES / "entra-directory-audits.graph.json").read_text())
    audits["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=invented"
    rows, stats = _package(tmp_path, "audit.zip", _zip({"tenant/AuditLogs.json": json.dumps(audits, indent=indent).encode()}))
    (member,) = stats["files"]
    assert len(rows) == len(audits["value"]) and member["status"] == "parsed" and "@odata.nextLink" in member["note"]


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


def _monitor(category: str, operation: str, record: dict, time: str = "2026-09-01T12:00:00.1234567Z") -> dict:
    """An Azure Monitor record as Entra's diagnostic settings write one to an Event Hub or a storage
    account, the record under "properties" (learn.microsoft.com/entra/identity/monitoring-health,
    "Interpret the audit logs schema in Azure Monitor"). The tenant is invented."""
    return {
        "time": time,
        "resourceId": "/tenants/00000000-0000-4000-8000-000000000001/providers/Microsoft.aadiam",
        "operationName": operation,
        "operationVersion": "1.0",
        "category": category,
        "tenantId": "00000000-0000-4000-8000-000000000001",
        "resultSignature": "None",
        "durationMs": 0,
        "callerIpAddress": "203.0.113.7",
        "correlationId": record.get("correlationId") or "00000000-0000-4000-8000-000000000002",
        "Level": 4,
        "properties": record,
    }


def _same_rows(rows: list[dict]) -> list[dict]:
    return [{k: v for k, v in r.items() if k not in ("raw", "sourceFile")} for r in rows]


@pytest.mark.parametrize(
    ("fixture", "category", "operation", "fmt"),
    [
        ("entra-directory-audits.graph.json", "AuditLogs", "Add member to role", "entra-audit-json"),
        ("entra-risky-users.graph.json", "RiskyUsers", "Risky user", "entra-riskyuser-json"),
        ("entra-risk-detections.graph.json", "UserRiskEvents", "User Risk Detection", "entra-riskdetection-json"),
    ],
)
def test_azure_monitor_records_of_the_audit_and_risk_logs_are_read_as_their_graph_records(tmp_path, fixture, category, operation, fmt):
    """Entra's diagnostic settings write a directory audit, a risky user or a risk detection under
    "properties" of an Azure Monitor record, as they do a sign-in, with the Graph record's names;
    attack_data's Entra audit recordings are in that form. Such a file was not recognised. Each
    record now gives the row its Graph form gives."""
    graph = json.loads((FIXTURES / fixture).read_text())["value"]
    data = "\n".join(json.dumps(_monitor(category, operation, r)) for r in graph).encode()
    assert m365.detect_format("azure-audit.log", data[:4096]) == fmt
    rows, src = _source(tmp_path, "azure-audit.log", data)
    expected, _ = _fixture(tmp_path, fixture)
    assert src.format == fmt and src.stats.errors == 0
    assert _same_rows(rows) == _same_rows(expected) and len(rows) == len(graph)
    # the envelope's time stands in for a record that has none of its own
    bare = {k: v for k, v in graph[0].items() if k not in ("activityDateTime", "riskLastUpdatedDateTime", "detectedDateTime")}
    (row,) = list(m365.iter_records(None, json.dumps(_monitor(category, operation, bare)).encode(), fmt))
    assert row["tsIso"] == "2026-09-01T12:00:00.123Z"


def test_a_file_of_azure_monitor_records_is_of_the_category_of_its_first_record():
    """A capture of Entra's diagnostic settings holds records of several categories. The file is
    read as its first record's kind, and a record of another category in it is counted not read;
    a file that holds sign-ins is read as sign-ins, as before. The risks of service principals are
    not read."""
    audit = json.loads((FIXTURES / "entra-directory-audits.graph.json").read_text())["value"][0]
    risky = json.loads((FIXTURES / "entra-risky-users.graph.json").read_text())["value"][0]
    records = [_monitor("AuditLogs", "Add member to role", audit), _monitor("RiskyUsers", "Risky user", risky)]
    for order, fmt in ((records, "entra-audit-json"), (records[::-1], "entra-riskyuser-json")):
        data = "\n".join(json.dumps(r) for r in order).encode()
        assert m365.detect_format("azure.log", data) == fmt
        stats = Stats()
        rows = list(m365.iter_records(None, data, fmt, stats=stats))
        assert len(rows) == 1 and stats.errors == 1 and stats.to_dict()["notRead"] == 1
    data = "\n".join(json.dumps(r) for r in [*records, _monitor("SignInLogs", "Sign-in activity", make_m365.entra_signins()[0])]).encode()
    assert m365.detect_format("azure.log", data) == "entra-signin-json"
    other = _monitor(
        "ServicePrincipalRiskEvents", "Service principal risk detection", {"id": "1", "riskEventType": "x", "activityDateTime": "2026-09-01T10:00:00Z"}
    )
    assert m365.detect_format("azure.log", json.dumps(other).encode()) is None
    assert detect_evtx_format("azure.log", json.dumps(other).encode()) == "unrecognised"


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


# ---------------------------------------------------------------------------
# Entra ID Protection
# ---------------------------------------------------------------------------
def test_risk_detections_from_graph_are_read(tmp_path):
    rows, src = _fixture(tmp_path, "entra-risk-detections.graph.json")
    assert src.format == "entra-riskdetection-json" and src.stats.errors == 0 and len(rows) == 3
    unfamiliar, dismissed, forwarding = rows
    assert unfamiliar["provider"] == m365.RISK_PROVIDER and unfamiliar["channel"] == "Entra RiskDetection" and unfamiliar["category"] == "Entra risk"
    assert unfamiliar["operation"] == "RiskDetection" and unfamiliar["description"] == "unfamiliarFeatures"
    assert unfamiliar["subjectUser"] == "alice@contoso.com" and unfamiliar["ipAddress"] == "198.51.100.23" and unfamiliar["tsIso"] == "2026-09-01T09:58:20.000Z"
    assert unfamiliar["level"] == 3 and unfamiliar["status"] == "atRisk" and unfamiliar["data"]["riskLevel"] == "medium"
    assert unfamiliar["data"]["country"] == "NL" and unfamiliar["data"]["city"] == "Amsterdam" and unfamiliar["workstation"].startswith("Mozilla/5.0")
    # what ties it to its sign-in
    assert (
        unfamiliar["data"]["correlationId"] == "e1f2a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b"
        and unfamiliar["data"]["requestId"] == "9b8a7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
    )
    assert unfamiliar["recordKey"] == "entra-risk:6f2c8e1a9b4d7c3e5a0f1b2d4c6e8a0b9d1f3e5c7a9b0d2f4e6a8c0b1d3f5e7a"
    assert dismissed["level"] == 4 and dismissed["statusText"] == "adminDismissedAllRiskForUser" and "dismissed" in dismissed["summary"]
    # an offline detection is placed at the activity it rates, not at the time it was detected
    assert forwarding["tsIso"] == "2026-09-01T10:25:00.000Z" and forwarding["ipAddress"] is None
    assert (
        forwarding["data"]["additionalInfo.alertUrl"] == "https://security.example/alerts/1"
        and forwarding["data"]["detectedDateTime"] == "2026-09-01T11:40:00Z"
    )


def test_risk_detections_written_by_microsoft_extractor_suite_are_read_as_graph_ones_are(tmp_path):
    graph, _ = _fixture(tmp_path, "entra-risk-detections.graph.json")
    rows, src = _fixture(tmp_path, "entra-risk-detections.extractor.csv")
    assert src.format == "entra-riskdetection-csv" and src.stats.errors == 0

    def seen(r: dict) -> tuple:
        return (
            r["tsIso"],
            r["description"],
            r["subjectUser"],
            r["ipAddress"],
            r["status"],
            r["level"],
            r["recordKey"],
            r["data"].get("country"),
            r["workstation"],
        )

    assert [seen(r) for r in rows] == [seen(r) for r in graph]
    # one date past the 12th shows the file is day-first; the times say no zone and are read as UTC
    assert src.stats.date_order_guessed == 0 and src.stats.zone_assumed == 3
    # the analyst who knows the session that wrote it was two hours ahead of UTC says so
    stats = Stats()
    data = (FIXTURES / "entra-risk-detections.extractor.csv").read_bytes()
    rows = list(m365.iter_records(None, data, "entra-riskdetection-csv", stats, dates=m365.date_setting({"zone": "+02:00"})))
    assert rows[0]["tsIso"] == "2026-09-01T07:58:20.000Z" and stats.zone_set == 3 and stats.zone_assumed == 0


def test_risky_users_are_read_from_graph_and_from_microsoft_extractor_suite(tmp_path):
    graph, src = _fixture(tmp_path, "entra-risky-users.graph.json")
    assert src.format == "entra-riskyuser-json" and len(graph) == 2
    alice, bob = graph
    assert alice["channel"] == "Entra RiskyUser" and alice["operation"] == "RiskyUser" and alice["subjectUser"] == "alice@contoso.com"
    assert alice["tsIso"] == "2026-09-01T11:40:00.000Z" and alice["status"] == "atRisk" and alice["level"] == 3
    assert bob["level"] == 4 and bob["statusText"] == "userPerformedSecuredPasswordReset"
    assert alice["recordKey"] == "entra-riskyuser:5f1c2a3b-0d4e-4f60-8a71-92b3c4d5e6f7|2026-09-01T11:40:00.000Z"
    rows, src = _fixture(tmp_path, "entra-risky-users.extractor.csv")
    assert src.format == "entra-riskyuser-csv" and src.stats.errors == 0
    assert [(r["tsIso"], r["subjectUser"], r["status"], r["level"]) for r in rows] == [(r["tsIso"], r["subjectUser"], r["status"], r["level"]) for r in graph]
    assert rows[0]["data"]["isDeleted"] == "False"
    # the same user listed when the risk changed is another record
    later = json.dumps(
        [
            {
                **json.loads((FIXTURES / "entra-risky-users.graph.json").read_text())["value"][0],
                "riskLastUpdatedDateTime": "2026-09-02T08:00:00Z",
                "riskState": "remediated",
            }
        ]
    )
    rows, src = _fixture(tmp_path, "later.json", later.encode())
    assert len(rows) == 1 and rows[0]["status"] == "remediated"


def test_a_user_list_is_still_not_read_as_risky_users():
    users = b"Id,DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime,UserType,RiskLevel\n1d2c,Alice,alice@contoso.com,True,1/15/2024 10:11:12 AM,Member,none\n"
    assert m365.detect_format("Users.csv", users) is None


# ---------------------------------------------------------------------------
# Exchange Online message trace
# ---------------------------------------------------------------------------
def test_a_message_trace_from_get_messagetrace_is_read(tmp_path):
    rows, src = _fixture(tmp_path, "exo-messagetrace.get-messagetrace.csv")
    assert src.format == "exo-messagetrace-csv" and src.stats.errors == 0 and len(rows) == 5
    reply = rows[0]
    assert reply["provider"] == m365.TRACE_PROVIDER and reply["channel"] == "Exchange MessageTrace" and reply["category"] == "Exchange message trace"
    assert reply["operation"] == "MessageTrace" and reply["status"] == "Delivered" and reply["level"] == 4
    assert (
        reply["subjectUser"] == "alice@contoso.com"
        and reply["targetUser"] == "payments@attacker.example"
        and reply["objectName"] == "RE: Invoice 4471 - updated bank details"
    )
    assert reply["ipAddress"] == "198.51.100.23" and reply["destinationIp"] == "192.0.2.80" and reply["tsIso"] == "2026-09-01T10:31:02.000Z"
    assert reply["data"]["SenderDomain"] == "contoso.com" and reply["data"]["RecipientDomain"] == "attacker.example" and reply["data"]["Size"] == "48211"
    # the message opens the mailbox message and the audit records that name it
    assert reply["data"]["InternetMessageId"] == "<AM9PR01MB0001.example@AM9PR01MB0001.eurprd01.prod.outlook.com>"
    assert reply["recordKey"] == "exo-trace:1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d|payments@attacker.example|delivered"
    assert rows[4]["status"] == "FilteredAsSpam" and rows[4]["level"] == 3
    # the cmdlet writes its times in UTC, Microsoft says: they are not counted as assumed, and no zone moves them
    assert src.stats.zone_assumed == 0
    stats = Stats()
    data = (FIXTURES / "exo-messagetrace.get-messagetrace.csv").read_bytes()
    moved = list(m365.iter_records(None, data, "exo-messagetrace-csv", stats, dates=m365.date_setting({"zone": "Europe/Paris"})))
    assert [r["tsIso"] for r in moved] == [r["tsIso"] for r in rows] and stats.zone_set == 0
    # a column REMN does not know is kept
    text = data.decode("utf-16")
    head, rest = text.split("\r\n", 1)
    extra = (head + ',"PSComputerName"\r\n' + rest.replace("\r\n", ',"outlook.office365.com"\r\n')).encode("utf-16")
    (row, *_), _ = _fixture(tmp_path, "trace.csv", extra)
    assert row["data"]["PSComputerName"] == "outlook.office365.com"


def test_a_message_trace_from_get_messagetracev2_is_read_in_the_order_set_for_it(tmp_path):
    """Every date at day 12 or below: read month-first and counted, until the analyst says the
    export was written day-first."""
    rows, src = _fixture(tmp_path, "exo-messagetrace.get-messagetracev2.csv")
    assert src.format == "exo-messagetrace-csv" and len(rows) == 3
    assert rows[0]["tsIso"] == "2026-01-09T10:31:02.000Z" and src.stats.date_order_guessed == 3
    stats = Stats()
    data = (FIXTURES / "exo-messagetrace.get-messagetracev2.csv").read_bytes()
    rows = list(m365.iter_records(None, data, "exo-messagetrace-csv", stats, dates=m365.date_setting({"order": "day-first"})))
    v1, _ = _fixture(tmp_path, "exo-messagetrace.get-messagetrace.csv")
    assert [(r["tsIso"], r["subjectUser"], r["targetUser"], r["recordKey"]) for r in rows] == [
        (r["tsIso"], r["subjectUser"], r["targetUser"], r["recordKey"]) for r in v1[:3]
    ]
    assert stats.date_order_set == 3 and stats.date_order_guessed == 0


def test_the_downloadable_message_trace_reports_are_read_one_recipient_a_row(tmp_path):
    rows, src = _fixture(tmp_path, "exo-messagetrace.enhanced-summary.csv")
    assert src.format == "exo-messagetrace-report-csv" and src.stats.errors == 0
    assert [(r["subjectUser"], r["targetUser"], r["status"], r["direction"]) for r in rows] == [
        ("alice@contoso.com", "payments@attacker.example", "Receive, Send", "Outbound"),
        ("supplier@fabrikam.example", "alice@contoso.com", "Receive, Deliver", "Inbound"),
        ("supplier@fabrikam.example", "collect@attacker.example", "Receive, Send", "Inbound"),
    ]
    assert rows[1]["ipAddress"] == "192.0.2.25" and rows[1]["data"]["network_message_id"] == "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d"
    # a report is written in the zone of the admin who asked for it: a time that says none is
    # counted, and read in the zone set for the evidence
    assert rows[0]["tsIso"] == "2026-09-01T10:31:02.417Z" and src.stats.zone_assumed == 3
    stats = Stats()
    data = (FIXTURES / "exo-messagetrace.enhanced-summary.csv").read_bytes()
    rows = list(m365.iter_records(None, data, "exo-messagetrace-report-csv", stats, dates=m365.date_setting({"zone": "+02:00"})))
    assert rows[0]["tsIso"] == "2026-09-01T08:31:02.417Z" and stats.zone_set == 3
    # a column that says it is UTC is not moved
    utc = data.replace(b'"origin_timestamp"', b'"origin_timestamp_utc"')
    rows = list(m365.iter_records(None, utc, "exo-messagetrace-report-csv", dates=m365.date_setting({"zone": "+02:00"})))
    assert m365.detect_format("report.csv", utc) == "exo-messagetrace-report-csv" and rows[0]["tsIso"] == "2026-09-01T10:31:02.417Z"
    rows, src = _fixture(tmp_path, "exo-messagetrace.extended.csv")
    assert src.format == "exo-messagetrace-report-csv" and len(rows) == 4
    assert [(r["data"]["source"], r["status"], r["targetUser"]) for r in rows] == [
        ("SMTP", "RECEIVE", "alice@contoso.com"),
        ("STOREDRIVER", "DELIVER", "alice@contoso.com"),
        ("MAILBOXRULE", "RECEIVE", "collect@attacker.example"),
        ("SMTP", "SEND", "collect@attacker.example"),
    ]
    assert rows[3]["destinationIp"] == "192.0.2.80" and rows[2]["data"]["reference"] == "1201"


def test_a_message_trace_row_without_a_sender_or_a_recipient_is_counted_not_read():
    data = b'"Received","SenderAddress","RecipientAddress","Status"\r\n"9/1/2026 10:31:02 AM","","","Delivered"\r\n"9/1/2026 10:32:02 AM","alice@contoso.com","bob@contoso.com","Delivered"\r\n'
    stats = Stats()
    rows = list(m365.iter_records(None, data, "exo-messagetrace-csv", stats))
    assert len(rows) == 1 and stats.errors == 1 and stats.not_read == 1


def test_message_trace_directory_audit_and_risk_rows_are_cloud_rows_to_the_analysis(tmp_path):
    """A message trace row read as a host's event made a host of nobody in the stories and a host
    step in the chains; the tenant's rows are the tenant's."""
    from services.analysis import chains, relationships, stories

    rows = []
    for name in ("exo-messagetrace.get-messagetrace.csv", "entra-directory-audits.graph.json", "entra-risk-detections.graph.json"):
        rows += _fixture(tmp_path, name)[0]
    assert all(relationships.origin(r) == "m365" and stories._is_cloud(r) and chains._is_m365(r) for r in rows)
    # a message is a chain step only when a rule flags it; a consent is one whatever the rules say
    assert chains._m365_step(rows[0], {}, {}) is None
    consent = next(r for r in rows if r["operation"] == "Consent to application.")
    assert chains._m365_step(consent, {}, {})[1].startswith("OAuth consent granted")


# ---------------------------------------------------------------------------
# Rules for what these exports answer
# ---------------------------------------------------------------------------
def _passkey_added() -> dict:
    """A directory audit of a passkey added for alice, from the attacker's address."""
    return m365.audit_row(
        {
            "id": "Directory_7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f_Q2W3E_123456789",
            "category": "UserManagement",
            "correlationId": "8d2e3f4a-5b6c-4d7e-8f9a-0b1c2d3e4f5a",
            "result": "success",
            "resultReason": "",
            "activityDisplayName": "Add Passkey (device-bound)",
            "activityDateTime": "2026-09-01T10:11:05Z",
            "loggedByService": "Authentication Methods",
            "operationType": "Add",
            "initiatedBy": {"user": {"id": "5f1c2a3b-0d4e-4f60-8a71-92b3c4d5e6f7", "userPrincipalName": "alice@contoso.com", "ipAddress": "198.51.100.23"}},
            "targetResources": [
                {"id": "5f1c2a3b-0d4e-4f60-8a71-92b3c4d5e6f7", "type": "User", "userPrincipalName": "alice@contoso.com", "modifiedProperties": []}
            ],
            "additionalDetails": [],
        }
    )


def _inbox_rule(when: str) -> dict:
    """New-InboxRule by alice in the audit log, from the attacker's address."""
    return m365.ual_row(
        {
            "CreationTime": when,
            "Id": "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
            "Operation": "New-InboxRule",
            "RecordType": 1,
            "UserId": "alice@contoso.com",
            "Workload": "Exchange",
            "ClientIP": "198.51.100.23",
            "ResultStatus": "True",
            "Parameters": [{"Name": "Name", "Value": "."}, {"Name": "RedirectTo", "Value": "collect@attacker.example"}],
        }
    )


@pytest.mark.parametrize(("inbox_rule_at", "escalated"), [("2026-09-01T10:20:00", True), ("2026-09-03T10:20:00", False)])
def test_the_rules_for_risk_new_sign_in_methods_and_the_message_trace_fire_on_these_exports(tmp_path, store, inbox_rule_at, escalated):
    rows = [_passkey_added(), _inbox_rule(inbox_rule_at)]
    for name in (
        "entra-risk-detections.graph.json",
        "entra-risky-users.graph.json",
        "entra-directory-audits.graph.json",
        "exo-messagetrace.get-messagetrace.csv",
        "exo-messagetrace.extended.csv",
    ):
        rows += _fixture(tmp_path, name)[0]
    fired = _fired(store, rows)

    # the detections ID Protection rated medium, both alice's; bob's low and dismissed one is not
    assert sorted(f["entities"]["targetUser"] for f in fired["m365-risk-detection"]) == ["alice@contoso.com"] * 2
    assert [f["entities"]["targetUser"] for f in fired["m365-risky-user"]] == ["alice@contoso.com"]
    # a risk, then an inbox rule by the same account within a day
    (risk,) = fired["m365-risk-then-inbox-rule"]
    assert risk["entities"]["targetUser"] == "alice@contoso.com"
    assert (risk["severity"], bool(risk.get("escalation"))) == (("critical", True) if escalated else ("low", False))
    # a passkey added, a device registered, an application given a permission of its own
    assert [f["entities"]["targetUser"] for f in fired["m365-auth-method-added"]] == ["alice@contoso.com"]
    assert len(fired["m365-device-registered"]) == 1 and len(fired["m365-app-permission-granted"]) == 1
    # the supplier's invoice, sent on to the attacker: once in Get-MessageTrace, and in the
    # extended report once as the inbox rule's message and once as it left
    relayed = fired["m365-trace-external-relay"]
    assert len(relayed) == 3 and {f["entities"]["targetUser"] for f in relayed} == {"collect@attacker.example"}
    assert [f["entities"]["targetUser"] for f in fired["m365-trace-mailbox-rule-message"]] == ["collect@attacker.example"]
    # alice's own mail to the attacker and the spam bob received are not relays
    assert not any(f["entities"]["subjectUser"] in ("alice@contoso.com", "offers@bulk.example") for f in relayed)


def test_the_message_trace_rules_wait_for_the_internal_domains(tmp_path, store):
    """Every address is outside an empty list of internal domains: the rules say what they need
    rather than report every message."""
    rows, _ = _fixture(tmp_path, "exo-messagetrace.get-messagetrace.csv")
    fired = _fired(store, rows, {"expected_countries": ["FR"]})
    assert not {"m365-trace-external-relay", "m365-trace-mailbox-rule-message"} & set(fired)
