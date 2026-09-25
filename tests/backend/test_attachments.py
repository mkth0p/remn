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
    assert {"html_smuggling", "html_embedded_payload", "html_password_form", "html_credential_harvest", "html_brand_lure", "html_prefilled_email"} <= set(
        r["flags"]
    )
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


def _bz2_zeros(mib: int) -> bytes:
    import bz2

    comp = bz2.BZ2Compressor(9)
    return b"".join(comp.compress(b"\0" * 2**20) for _ in range(mib)) + comp.flush()


def test_bz2_bomb_is_bounded_and_flagged():
    import tracemalloc

    from services.analysis.attachments import archive

    bomb = _bz2_zeros(256)  # a few hundred bytes that expand to 256 MiB
    assert len(bomb) < 1024
    tracemalloc.start()
    r = analyze_attachment("report.bz2", bomb)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert peak < 4 * archive.MAX_NESTED_BYTES
    assert {"zip_bomb", "archive_partially_analyzed"} <= set(r["flags"])
    assert r["details"]["archive"]["truncatedAt"] == archive.MAX_NESTED_BYTES
    assert r["risk"] >= 80


def test_xz_bomb_is_bounded():
    import lzma

    from services.analysis.attachments.archive import MAX_NESTED_BYTES, bounded_decompress

    out, truncated = bounded_decompress("xz", lzma.compress(b"\0" * (64 * 2**20)), MAX_NESTED_BYTES)
    assert truncated and len(out) == MAX_NESTED_BYTES


def test_bounded_decompress_keeps_one_shot_semantics():
    import bz2

    import pytest

    from services.analysis.attachments.archive import bounded_decompress

    two_streams = bz2.compress(b"first ") + bz2.compress(b"second")
    assert bounded_decompress("bz2", two_streams, 1024) == (b"first second", False)
    assert bounded_decompress("bz2", bz2.compress(b"data") + b"trailing junk", 1024) == (b"data", False)
    with pytest.raises(EOFError):
        bounded_decompress("bz2", bz2.compress(b"x" * 10_000)[:-8], 1 << 20)


def test_zip_members_with_unbounded_compression_are_not_read():
    from services.common import read_zip_member

    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("deflated.txt", b"a" * 1000, compress_type=zipfile.ZIP_DEFLATED)
        z.writestr("bzip2.txt", b"a" * 1000, compress_type=zipfile.ZIP_BZIP2)
        z.writestr("big.txt", b"a" * 5000, compress_type=zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(io.BytesIO(b.getvalue())) as zf:
        assert read_zip_member(zf, zf.getinfo("deflated.txt"), 4096) == b"a" * 1000
        assert read_zip_member(zf, zf.getinfo("bzip2.txt"), 4096) is None
        assert read_zip_member(zf, zf.getinfo("big.txt"), 4096) is None


def test_oversized_ooxml_part_is_skipped_not_read():
    from services.analysis.attachments import office

    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", b"<w:document>" + b" " * (office.MAX_PART_BYTES + 1) + b"</w:document>")
    inv = office._ooxml_inventory(b.getvalue())
    assert inv["skippedParts"] == 1
