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
