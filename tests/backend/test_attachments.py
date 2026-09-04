from __future__ import annotations

import io
import zipfile

import make_samples

from services.analysis.attachments.analyzer import analyze_attachment
from services.analysis.attachments.magic import analyze_name, extension_matches, identify


def test_identify_rtf_and_exe_and_html():
    assert identify(b"{\\rtf1\\ansi hello}", "a.rtf")["ext"] == "rtf"
    assert identify(b"MZ" + b"\x00" * 100, "photo.jpg")["ext"] == "exe"
    assert identify(b"<!DOCTYPE html><html><body>x</body></html>", "x.htm")["ext"] == "html"
    assert identify(b"%PDF-1.4\n", "x.pdf")["ext"] == "pdf"
    assert identify(make_samples.docm_with_macro(), "x.docm")["ext"] == "docx"


def test_extension_matches_equivalences():
    assert extension_matches("docm", "docx")
    assert extension_matches("jpg", "jpeg")
    assert not extension_matches("jpg", "exe")
    assert extension_matches("txt", "txt")


def test_name_tricks():
    assert "double_extension" in analyze_name("invoice.pdf.exe")["flags"]
    assert "rtlo_filename" in analyze_name("report‮gnp.exe")["flags"]
    assert analyze_name("readme.txt")["flags"] == []


def test_zip_with_disguised_exe():
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("Scan_Invoice.pdf.exe", b"MZ" + b"\x00" * 200)
    r = analyze_attachment("Invoice.zip", b.getvalue())
    assert r["realExt"] == "zip"
    assert {"archive_contains_executable", "archive_single_executable", "archive_entry_double_extension"} <= set(r["flags"])
    assert r["risk"] >= 90
    assert r["details"]["archive"]["entries"][0]["name"] == "Scan_Invoice.pdf.exe"
    assert r["details"]["archive"]["nested"][0]["realExt"] == "exe"


def test_encrypted_zip_flag():
    # minimal zip with the encryption bit set in the local header flags
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("secret.docx", b"x" * 10)
    data = bytearray(b.getvalue())
    # local file header general purpose flag at offset 6, central dir flag also needs the bit for infolist()
    idx = data.find(b"PK\x01\x02")
    data[idx + 8] |= 0x01
    r = analyze_attachment("archive.zip", bytes(data))
    assert "encrypted_archive" in r["flags"]


def test_docm_macro_dde_template():
    r = analyze_attachment("Facture.docm", make_samples.docm_with_macro())
    assert {"office_macro", "office_external_template"} <= set(r["flags"])
    assert r["risk"] >= 85
    rel = r["details"]["office"]["externalRelations"][0]
    assert rel["target"].startswith("http://cdn-update-templates.top/")


def test_pdf_javascript_and_uris():
    r = analyze_attachment("doc.pdf", make_samples.pdf_js())
    assert {"pdf_javascript", "pdf_auto_action"} <= set(r["flags"])
    assert any("bit.ly" in u for u in r["details"]["pdf"]["uris"])


def test_html_smuggling_and_credential_form():
    r = analyze_attachment("Document.html", make_samples.html_smuggle())
    assert {"html_smuggling", "html_embedded_payload", "html_password_form", "html_credential_harvest", "html_brand_lure", "html_prefilled_email"} <= set(r["flags"])
    assert "zip" in r["details"]["html"]["decodedBlobTypes"]
    assert r["risk"] >= 90


def test_exe_disguised_as_image():
    r = analyze_attachment("photo.jpg", b"MZ" + b"\x00" * 300)
    assert "extension_mismatch_executable" in r["flags"] and r["risk"] >= 90


def test_rtf_equation_editor():
    data = b"{\\rtf1{\\object\\objemb\\objupdate{\\*\\objclass Equation.3}{\\*\\objdata 01050000}}}"
    r = analyze_attachment("doc.rtf", data)
    assert r["realExt"] == "rtf"
    assert {"rtf_equation_editor", "rtf_objupdate"} <= set(r["flags"])


def test_lnk_strings():
    data = b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 12 + b"\xa1\x00\x00\x00" + b"\x00" * 50 + "powershell -w hidden -enc AAAA".encode("utf-16-le")
    r = analyze_attachment("readme.lnk", data)
    assert "shortcut" in r["flags"]
    assert "powershell" in r["details"]["lnk"]["suspicious"]


def test_benign_text():
    r = analyze_attachment("notes.txt", b"just some notes\n")
    assert r["flags"] == [] and r["risk"] == 0


def test_nested_eml_attachment():
    inner = make_samples.mail('"X" <x@evil.top>', "y@corp.fr", "fw", "hi", attachments=[("a.exe", b"MZ" + b"\x00" * 50, "application", "octet-stream")])
    r = analyze_attachment("forwarded.eml", inner, "message/rfc822")
    assert "nested_mail" in r["flags"]
    assert "nested_executable" in r["flags"]
