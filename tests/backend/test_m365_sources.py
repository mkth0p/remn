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

from services.ingest.pipeline import EvtxSource, detect_evtx_format
from services.parsers import m365
from services.parsers.evtx_parser import Stats


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
