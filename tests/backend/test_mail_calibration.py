"""
Scoring calibration locked in from the first real Outlook export (2026-09-04, 2,487
messages of an ordinary corporate mailbox). Every test here is a false-positive class
that put normal mail at risk >= 45 before the fix.
"""

from __future__ import annotations

from services.analysis.body import analyze_body, html_to_text
from services.analysis.lookalike import analyze_domain
from services.parsers.mail.common import ParseContext, build_row, parse_message_bytes

CTX = ParseContext(internal_domains=["interne.fr"], vip_names=["Marie Lefevre"])


def _raw(headers, body, ctype="text/html; charset=utf-8"):
    head = "\n".join(f"{k}: {v}" for k, v in headers)
    return f"{head}\nMIME-Version: 1.0\nContent-Type: {ctype}\n\n{body}".encode()


def test_white_background_is_not_hidden_text():
    """'background-color: #fff' on <html>/<body> matched the white-on-white rule and hid the
    whole document: 46 % of the mailbox scored image_only + hidden_text with no visible text."""
    html = (
        '<html style="background-color: #fff; color: #262626"><body style="background-color:#ffffff">'
        '<table><tr><td><p>Bonjour<br>Votre rapport est disponible<img src="cid:x"></p>'
        '<div style="display:none">preview text</div><p>Cordialement</p></td></tr></table></body></html>'
    )
    text, hidden = html_to_text(html)
    assert "Votre rapport est disponible" in text and "Cordialement" in text
    assert hidden == ["preview text"]
    b = analyze_body(None, html, "Rapport")
    assert "image_only" not in b["flags"] and "hidden_text" in b["flags"] and "hidden_style" in b["flags"]
    # invisible preview padding (Teams: U+034F combining grapheme joiners) is not hidden content
    pad = '<div style="display:none">' + ("͏ " * 100) + "</div><p>Hello</p>"
    assert html_to_text(pad)[1] == []
    # unclosed <p> and void tags inside a hidden block must not hide the rest of the document
    t2, _ = html_to_text('<div style="display:none"><p>x<br><img src="a"></div><p>visible after</p>')
    assert "visible after" in t2
    # display:none in a <style> block (responsive e-mail CSS) is not an inline hiding style
    css = "<html><head><style>.m{display:none}</style></head><body><p>Hi</p></body></html>"
    assert "hidden_style" not in analyze_body(None, css)["flags"]


def test_data_scripts_are_not_html_script():
    card = '<html><body><script type="application/adaptivecard+json">{"type":"AdaptiveCard"}</script><p>Hi</p></body></html>'
    assert "html_script" not in analyze_body(None, card)["flags"]
    assert "html_script" in analyze_body(None, "<html><body><script>alert(1)</script><p>Hi</p></body></html>")["flags"]
    js = '<html><body><script type="text/javascript" src="x.js"></script></body></html>'
    assert "html_script" in analyze_body(None, js)["flags"]


def test_exchange_internal_mail_is_trusted():
    raw = _raw(
        [
            (
                "Received",
                "from PAVPR05MB10277.eurprd05.prod.outlook.com (2603:10a6:102:2f8::21) by "
                "DU0PR05MB9999.eurprd05.prod.outlook.com with HTTPS; Tue, 1 Sep 2026 09:00:00 +0000",
            ),
            ("Authentication-Results", "dkim=none (message not signed) header.d=none;dmarc=none action=none header.from=interne.fr;"),
            ("X-MS-Exchange-Organization-AuthSource", "PAVPR05MB10277.eurprd05.prod.outlook.com"),
            ("X-MS-Exchange-Organization-AuthAs", "Internal"),
            ("X-MS-Exchange-Organization-SCL", "1"),
            ("From", "Jean Dupont <jean.dupont@interne.fr>"),
            ("To", "Marie Lefevre <marie.lefevre@interne.fr>"),
            ("Subject", "Point budget"),
            ("Date", "Tue, 1 Sep 2026 11:00:00 +0200"),
            ("Message-ID", "<abc@PAVPR05MB10277.eurprd05.prod.outlook.com>"),
        ],
        "<html><body><p>Bonjour, merci de valider le budget avant vendredi.</p></body></html>",
    )
    row = parse_message_bytes(raw, CTX)
    f = set(row["flags"])
    assert "exchange_internal" in f
    assert not ({"dkim_none", "dmarc_none", "dkim_domain_unaligned", "helo_domain_mismatch", "message_id_domain_mismatch"} & f)
    assert row["auth"]["exoAuthAs"] == "internal" and row["auth"]["scl"] == 1 and row["auth"]["dkimDomain"] is None
    assert row["risk"] <= 12


def test_gateway_verdicts_and_helo_gating():
    base = [
        ("From", "News <news@vendor-news.com>"),
        ("To", "<user@interne.fr>"),
        ("Subject", "Offre"),
        ("Date", "Tue, 1 Sep 2026 11:00:00 +0200"),
        ("Message-ID", "<1@vendor-news.com>"),
    ]
    spam = _raw(
        base
        + [
            (
                "Received",
                "from mail.vendor-news.com ([185.220.101.4]) by DB1PEPF0003922E.mail.protection.outlook.com with SMTP; Tue, 1 Sep 2026 09:00:00 +0000",
            ),
            (
                "Authentication-Results",
                "spf=pass (sender IP is 185.220.101.4) smtp.mailfrom=vendor-news.com; "
                "dkim=pass header.d=vendor-news.com; dmarc=pass action=none header.from=vendor-news.com",
            ),
            ("X-Forefront-Antispam-Report", "CIP:185.220.101.4;CTRY:FR;LANG:fr;SCL:6;SRV:;IPV:NLI;SFV:SPM;H:mail.vendor-news.com;"),
            ("X-Microsoft-Antispam", "BCL:7;"),
        ],
        "<html><body><p>Promotion</p></body></html>",
    )
    row = parse_message_bytes(spam, CTX)
    assert {"gateway_spam_verdict", "gateway_bulk_verdict"} <= set(row["flags"])
    assert row["auth"]["scl"] == 6 and row["auth"]["sfv"] == "SPM" and row["auth"]["bcl"] == 7
    # HELO of an Exchange Online mailbox server, or any host once SPF passes: no helo_domain_mismatch
    exo = _raw(
        base
        + [
            (
                "Received",
                "from VI1PR05MB5821.eurprd05.prod.outlook.com (2603:10a6:803:1::20) by X.eurprd05.prod.outlook.com with HTTPS; Tue, 1 Sep 2026 09:00:00 +0000",
            )
        ],
        "<p>x</p>",
    )
    assert "helo_domain_mismatch" not in parse_message_bytes(exo, CTX)["flags"]
    spf_ok = _raw(
        base
        + [
            ("Received", "from smtp-relay.sendhost.net ([91.121.10.20]) by mx.interne.fr with ESMTP; Tue, 1 Sep 2026 09:00:00 +0000"),
            ("Authentication-Results", "spf=pass smtp.mailfrom=vendor-news.com"),
        ],
        "<p>x</p>",
    )
    assert "helo_domain_mismatch" not in parse_message_bytes(spf_ok, CTX)["flags"]
    random_host = _raw(
        base
        + [
            ("Received", "from vps-8123.cheaphost.net ([91.121.10.20]) by mx.interne.fr with ESMTP; Tue, 1 Sep 2026 09:00:00 +0000"),
            ("Authentication-Results", "spf=none smtp.mailfrom=vendor-news.com"),
        ],
        "<p>x</p>",
    )
    assert "helo_domain_mismatch" in parse_message_bytes(random_host, CTX)["flags"]


def test_brand_owned_domains_are_not_lookalikes():
    for d in ("teams.mail.microsoft", "engage.mail.microsoft", "contoso.onmicrosoft.com", "service-now.com", "credit-agricole.fr", "docs.google.com"):
        r = analyze_domain(d, ["interne.fr"])
        assert not r["matches"] and "lookalike_brand" not in r["flags"], d
    assert "lookalike_brand" in analyze_domain("rnicrosoft.com", [])["flags"]
    assert "lookalike_brand" in analyze_domain("microsoft-login.live", [])["flags"]  # .live is an open TLD


def test_calendar_items_have_no_undisclosed_recipients():
    headers = [("From", "Jean Dupont <jean.dupont@interne.fr>"), ("Subject", "Point hebdo"), ("Date", "Tue, 1 Sep 2026 11:00:00 +0200")]
    row = build_row(
        headers,
        "Salle 3",
        None,
        [],
        CTX,
        folder="Calendrier",
        size=None,
        extra={"sourceFormat": "pst", "messageClass": "IPM.Appointment", "syntheticHeaders": True},
    )
    assert "calendar_item" in row["flags"] and "undisclosed_recipients" not in row["flags"]


def test_domain_in_url_path_is_not_a_com_executable():
    """Viva Engage links end in /main/<tenant domain>.com: 36 of the 47 remaining risk>=80 mails."""
    from services.analysis.urls import analyze_url

    engage = analyze_url("https://engage.cloud.microsoft/main/contoso.com?trk_event=x&trk_sig=y")
    assert "executable_download" not in engage["flags"]
    assert "executable_download" in analyze_url("http://x.com/a/b/setup.exe")["flags"]
    assert "executable_download" not in analyze_url("http://x.com/u/contoso.com")["flags"]  # a tenant domain in the path
    assert "executable_download" in analyze_url("http://x.com/dl/invoice.pdf.com")["flags"]  # double extension trick
    assert "executable_download" in analyze_url("http://x.com/dl/report.zip")["flags"]


def test_own_domain_links_trackers_and_filenames():
    from services.analysis.urls import analyze_url

    # "password" in a path is a login_link unless the URL itself is suspicious; a fourth label is not
    u = analyze_url("https://account.security.microsoft.com/password/change?ref=1")
    assert "credential_keywords" not in u["flags"] and "login_link" in u["flags"]
    # a redirect that stays on the same registrable domain is navigation
    assert "open_redirect" not in analyze_url("https://account.microsoft.com/go?url=https%3A%2F%2Flogin.microsoft.com%2F")["flags"]
    assert "open_redirect" in analyze_url("https://portal.vendor-news.com/go?url=https://evil-login.net/")["flags"]
    # a file name shown as link text is not a domain claim
    assert "text_href_mismatch" not in analyze_url("https://drive.google.com/file/d/abc/view", "signalbackups.zip", "html")["flags"]
    assert "text_href_mismatch" not in analyze_url("https://contoso.sharepoint.com/sites/x/Doc.aspx", "Doc.aspx", "html")["flags"]
    # ESP click tracker: opaque redirect, recorded as such rather than as a lure
    t = analyze_url("https://x.sendibm1.com/mk/cl/f/abc", "https://zoom.us/j/123", "html")
    assert "tracker_redirect" in t["flags"] and "text_href_mismatch" not in t["flags"]
    assert "text_href_mismatch" in analyze_url("https://evil-login.net/x", "https://www.paypal.com/login", "html")["flags"]


def test_authenticated_vendor_mail_keeps_its_own_links():
    body = (
        '<html><body><div style="display:none">' + ("Security alert " * 30) + "</div>"
        '<p>Change your password: <a href="https://account.security.microsoft.com/password/change?url=https://aka.ms/x">here</a></p>'
        "<p>" + ("preheader " * 40) + "</p></body></html>"
    )
    raw = _raw(
        [
            ("Received", "from mail-eopbgr.outbound.protection.outlook.com ([40.107.1.2]) by mx.interne.fr; Tue, 1 Sep 2026 09:00:00 +0000"),
            (
                "Authentication-Results",
                "spf=pass smtp.mailfrom=microsoft.com; dkim=pass header.d=microsoft.com; dmarc=pass action=none header.from=microsoft.com",
            ),
            ("From", "Microsoft account team <account-security-noreply@accountprotection.microsoft.com>"),
            ("To", "<user@interne.fr>"),
            ("Subject", "Security info was added"),
            ("Date", "Tue, 1 Sep 2026 11:00:00 +0200"),
            ("Message-ID", "<1@accountprotection.microsoft.com>"),
        ],
        body,
    )
    row = parse_message_bytes(raw, CTX)
    f = set(row["flags"])
    # the redirect to aka.ms is an open_redirect on its own, but on the authenticated sender's own domain it is navigation
    assert "url_credential_keywords" not in f and "url_login_link" in f and "url_own_domain" in f and "url_open_redirect" not in f
    assert "hidden_text" not in f and "hidden_preheader" in f
    assert row["risk"] < 45
    # anchor text that names a brand keeps the mismatch even on an authenticated sender's own domain
    spoof = _raw(
        [
            ("Received", "from mx.evil-login.net ([91.121.10.20]) by mx.interne.fr; Tue, 1 Sep 2026 09:00:00 +0000"),
            ("Authentication-Results", "spf=pass smtp.mailfrom=evil-login.net; dkim=pass header.d=evil-login.net; dmarc=pass header.from=evil-login.net"),
            ("From", "Support <support@evil-login.net>"),
            ("To", "<user@interne.fr>"),
            ("Subject", "Verify"),
            ("Date", "Tue, 1 Sep 2026 11:00:00 +0200"),
            ("Message-ID", "<2@evil-login.net>"),
        ],
        '<html><body><a href="https://secure.evil-login.net/x">https://www.paypal.com/signin</a></body></html>',
    )
    assert "url_text_href_mismatch" in parse_message_bytes(spoof, CTX)["flags"]


def test_authenticated_phpmailer_newsletter_is_not_forged():
    raw = _raw(
        [
            ("Received", "from web.vendor-news.com ([91.121.10.20]) by mx.interne.fr; Tue, 1 Sep 2026 09:00:00 +0000"),
            ("Authentication-Results", "spf=pass smtp.mailfrom=vendor-news.com; dkim=pass header.d=vendor-news.com; dmarc=pass header.from=vendor-news.com"),
            ("X-Mailer", "PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)"),
            ("From", "Vendor <news@vendor-news.com>"),
            ("To", "<user@interne.fr>"),
            ("Subject", "Newsletter"),
            ("Date", "Tue, 1 Sep 2026 11:00:00 +0200"),
            ("Message-ID", "<2@vendor-news.com>"),
        ],
        "<html><body><p>Our monthly news.</p></body></html>",
    )
    row = parse_message_bytes(raw, CTX)
    assert "suspicious_mailer" not in row["flags"] and "scripted_mailer" in row["flags"] and row["risk"] < 45
    raw2 = _raw(
        [
            ("Received", "from vps-1.cheaphost.net ([91.121.10.20]) by mx.interne.fr; Tue, 1 Sep 2026 09:00:00 +0000"),
            ("X-Mailer", "PHPMailer 6.8.0"),
            ("From", "Vendor <news@vendor-news.com>"),
            ("To", "<user@interne.fr>"),
            ("Subject", "Newsletter"),
            ("Date", "Tue, 1 Sep 2026 11:00:00 +0200"),
            ("Message-ID", "<3@vendor-news.com>"),
        ],
        "<p>x</p>",
    )
    assert "suspicious_mailer" in parse_message_bytes(raw2, CTX)["flags"]


def test_zero_width_threshold():
    assert "zero_width_chars" not in analyze_body("Join the Teams\u200b meeting", None)["flags"]
    assert "zero_width_chars" in analyze_body("Ur\u200bge\u200bnt pa\u200byment", None)["flags"]
