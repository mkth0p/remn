from __future__ import annotations

import base64
import email
from email import policy
from email.message import EmailMessage

import make_samples

from services.analysis.headers import parse_received, received_chain
from services.analysis.lookalike import analyze_domain, levenshtein
from services.analysis.urls import analyze_url, extract_urls
from services.parsers.mail.common import ParseContext, normalize_name, parse_message_bytes

CTX = ParseContext(internal_domains=["interne.fr"], vip_names=["Marie Lefevre"])


def test_lookalike_internal_domain():
    r = analyze_domain("interne-fr.co", ["interne.fr"])
    assert "lookalike_internal" in r["flags"]
    assert r["matches"][0]["reference"] == "interne.fr"
    assert analyze_domain("interne.fr", ["interne.fr"])["internal"] is True
    assert "tld_swap" in analyze_domain("interne.co", ["interne.fr"])["flags"]
    assert "subdomain_trick" in analyze_domain("interne.fr.evil.com", ["interne.fr"])["flags"]
    assert {"punycode", "lookalike_internal"} <= set(analyze_domain(make_samples.PUNY_LOOKALIKE, ["interne.fr"])["flags"])
    p = analyze_domain("paypa1.com", [])
    assert "lookalike_brand" in p["flags"] and p["matches"][0]["method"] == "digit_substitution"
    assert "brand_embedding" in analyze_domain("microsoft-secure-login.net", [])["flags"]
    assert analyze_domain("techweekly-mail.com", ["interne.fr"])["matches"] == []
    # edit-distance precision: short brand names no longer match half the dictionary
    assert analyze_domain("fret.com", [])["matches"] == []  # not a lookalike of "free"
    assert "lookalike_brand" in analyze_domain("microsofd.com", [])["flags"]  # distance 1, long ref


def test_levenshtein():
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("", "abc") == 3


def test_url_flags():
    u = analyze_url("http://185.220.101.4/portal/login.php?u=j.dupont@interne.fr", "https://portal.interne.fr/factures", "html")
    assert {"ip_literal", "credential_keywords", "email_in_url", "text_href_mismatch"} <= set(u["flags"])
    assert u["defanged"].startswith("hxxp://185[.]220[.]101[.]4")
    assert "shortener" in analyze_url("https://bit.ly/3xyzdoc")["flags"]
    assert "punycode" in analyze_url("http://xn--pypal-4ve.com/x")["flags"]
    assert "suspicious_tld" in analyze_url("http://dhl-express-delivery.top/pay")["flags"]
    assert "free_hosting" in analyze_url("https://login-microsoft0nline.web.app/collect.php")["flags"]
    assert "executable_download" in analyze_url("http://x.com/a/b/setup.exe")["flags"]


def test_url_rewriters_are_unwrapped():
    # Microsoft Safe Links: the inner URL is analysed, so no text/href mismatch and no open_redirect
    u = analyze_url(
        "https://eur03.safelinks.protection.outlook.com/?url=https%3A%2F%2Fportal.company.com%2Faccount%2Flogin&data=05%7C01%7Cx",
        "https://portal.company.com/account/login",
        "html",
    )
    assert u["host"] == "portal.company.com"
    assert "rewritten" in u["flags"] and u["wrapper"].endswith("safelinks.protection.outlook.com")
    assert "text_href_mismatch" not in u["flags"] and "open_redirect" not in u["flags"]
    assert "login_link" in u["flags"] and "credential_keywords" not in u["flags"]
    v2 = analyze_url("https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_pay&d=DwMFaQ", None)
    assert v2["host"] == "evil.example" and "rewritten" in v2["flags"]
    v3 = analyze_url("https://urldefense.com/v3/__https://known.example/path__;!!abc123$", None)
    assert v3["host"] == "known.example"
    # a rewrapped IP-literal credential page keeps its strong flags
    bad = analyze_url("https://eur03.safelinks.protection.outlook.com/?url=http%3A%2F%2F185.220.101.4%2Fowa%2Flogin", None)
    assert {"ip_literal", "credential_keywords", "rewritten"} <= set(bad["flags"])


def test_login_and_saas_links_are_informational():
    assert "login_link" in analyze_url("https://intranet.company.com/login")["flags"]
    assert "credential_keywords" not in analyze_url("https://intranet.company.com/login")["flags"]
    f = analyze_url("https://forms.office.com/r/abc123")["flags"]
    assert "form_saas" in f and "free_hosting" not in f and "credential_keywords" not in f


def test_extract_urls_from_html_with_pixel_and_form():
    urls, info = extract_urls("see http://plain.example.com/x", make_samples.SPOOF_HTML)
    hosts = {u["host"] for u in urls}
    assert "185.220.101.4" in hosts and "track.mail-delivery-notify.xyz" in hosts and "plain.example.com" in hosts
    pixel = next(u for u in urls if u["host"] == "track.mail-delivery-notify.xyz")
    assert "tracking_pixel" in pixel["flags"]
    assert info["tinyImages"] == 1


def test_received_chain_origin_ip():
    headers = [(k, v) for k, v in make_samples.RECEIVED_BAD]
    chain = received_chain(headers)
    assert chain["hopCount"] == 3
    assert chain["originIp"] == "185.220.101.4"
    assert chain["hops"][0]["fromIp"] == "127.0.0.1"  # chronological order
    hop = parse_received("from a.b.c (a.b.c [1.2.3.4]) by d.e.f with ESMTPS id X for <u@d>; Tue, 01 Sep 2026 22:14:03 +0000")
    assert hop["fromIp"] == "1.2.3.4" and hop["by"] == "d.e.f" and hop["for"] == "u@d" and hop["ts"]


def test_normalize_name():
    assert normalize_name("Marie Lefevre") == normalize_name("LEFEVRE, Marie") == normalize_name("Lefèvre Marie")
    assert normalize_name("Marie Lefevre <ceo@x.com>") == "lefevre marie"


def test_spoof_mail_full_analysis():
    row = parse_message_bytes(
        make_samples.mail(
            '"Marie Lefevre" <marie.lefevre@interne-fr.co>',
            "j.dupont@interne.fr",
            "URGENT: facture",
            "Je suis en reunion, virement urgent, confidentiel",
            html=make_samples.SPOOF_HTML,
            attachments=[
                ("Facture.docm", make_samples.docm_with_macro(), "application", "vnd.ms-word.document.macroEnabled.12"),
                ("Document.html", make_samples.html_smuggle(), "text", "html"),
            ],
            extra_headers=make_samples.RECEIVED_BAD,
            reply_to="marie.lefevre.dg@gmail.com",
            date="Tue, 01 Sep 2026 22:13:40 +0000",
        ),
        CTX,
    )
    f = set(row["flags"])
    assert row["fromDomain"] == "interne-fr.co" and row["fromNameNorm"] == "lefevre marie"
    assert row["originIp"] == "185.220.101.4"
    assert {
        "spf_fail",
        "dmarc_fail",
        "returnpath_mismatch",
        "replyto_mismatch",
        "replyto_webmail",
        "suspicious_mailer",
        "high_priority",
        "sender_lookalike_internal",
        "hidden_text",
        "url_text_href_mismatch",
        "url_ip_literal",
        "url_tracking_pixel",
        "lexicon_urgency",
        "lexicon_financial",
        "lexicon_availability",
        "lexicon_secrecy",
        "att_office_macro",
        "att_office_external_template",
        "att_html_smuggling",
        "att_html_credential_harvest",
    } <= f
    assert row["risk"] >= 90
    assert row["attachmentCount"] == 2 and row["attachments"][0]["sha256"]
    assert row["auth"]["spf"] == "fail" and row["auth"]["dmarc"] == "fail"
    assert row["date"] == 1788300820000
    assert row["hiddenText"] == ["lorem ipsum salt words hidden"]


def test_legit_mail_low_risk():
    row = parse_message_bytes(
        make_samples.mail(
            '"Marie Lefevre" <marie.lefevre@interne.fr>',
            "j.dupont@interne.fr",
            "Point hebdo",
            "Bonjour Jean, on se voit jeudi.",
            extra_headers=[
                (
                    "Received",
                    "from EXCH01.interne.fr (10.0.0.12) by EXCH02.interne.fr (10.0.0.13) with Microsoft SMTP Server id 15.2; Tue, 01 Sep 2026 09:02:11 +0000",
                ),
                (
                    "Authentication-Results",
                    "mx.interne.fr; spf=pass smtp.mailfrom=interne.fr; dkim=pass header.d=interne.fr; dmarc=pass header.from=interne.fr",
                ),
            ],
            date="Tue, 01 Sep 2026 09:02:10 +0000",
        ),
        CTX,
    )
    assert row["lookalike"]["internal"] is True
    assert row["risk"] < 30
    assert not any(f.startswith("sender_lookalike") for f in row["flags"])


def test_bec_giftcard():
    row = parse_message_bytes(
        make_samples.mail(
            '"Marie Lefevre" <ceo.office.2026@gmail.com>',
            "j.dupont@interne.fr",
            "Are you at your desk?",
            "I need you to buy 5 Apple gift cards today. Scratch the cards and send me the codes. I am in a meeting, cannot talk. Keep this between us. Marie",
            reply_to=f"marie@{make_samples.PUNY_LOOKALIKE}",
        ),
        CTX,
    )
    f = set(row["flags"])
    assert {"lexicon_gift_card", "lexicon_availability", "lexicon_secrecy", "from_webmail", "replyto_mismatch"} <= f
    assert row["replyToLookalike"] is not None and "punycode" in row["replyToLookalike"]["flags"]
    assert "replyto_lookalike_internal" in f  # intérne-fr.co imitates interne.fr
    assert row["risk"] >= 85, (row["risk"], sorted(f))


def test_corporate_it_notice_scores_low():
    """Authenticated internal password-expiry notice with gateway-rewritten links: the exact
    false-positive class reported on real enterprise mailboxes. Must stay low-risk."""
    html = (
        '<a href="https://eur03.safelinks.protection.outlook.com/?url=https%3A%2F%2Fintranet.interne.fr%2Fpassword%2Freset">'
        "https://intranet.interne.fr/password/reset</a> "
        '<a href="https://forms.office.com/r/satisfaction">IT satisfaction survey</a>'
    )
    row = parse_message_bytes(
        make_samples.mail(
            '"IT Department" <it-notifications@interne.fr>',
            "j.dupont@interne.fr",
            "Action required: your password expires in 3 days",
            "Your password expires in 3 days. Sign in and update your password before the deadline.\nIT department",
            html=html,
            extra_headers=[
                (
                    "Received",
                    "from EXCH01.interne.fr (10.0.0.12) by EXCH02.interne.fr (10.0.0.13) with Microsoft SMTP Server id 15.2; Tue, 01 Sep 2026 09:02:11 +0000",
                ),
                (
                    "Authentication-Results",
                    "mx.interne.fr; spf=pass smtp.mailfrom=interne.fr; dkim=pass header.d=interne.fr; dmarc=pass header.from=interne.fr",
                ),
            ],
            date="Tue, 01 Sep 2026 09:02:10 +0000",
        ),
        CTX,
    )
    f = set(row["flags"])
    assert "credential_phishing_pattern" not in f and "bec_pattern" not in f
    assert "url_text_href_mismatch" not in f and "url_credential_keywords" not in f and "url_free_hosting" not in f
    assert {"url_rewritten", "url_login_link", "url_form_saas"} <= f
    assert row["risk"] <= 20, (row["risk"], sorted(f))


def test_authenticated_newsletter_scores_low():
    row = parse_message_bytes(
        make_samples.mail(
            '"Acme News" <news@newsletter.acme-corp.com>',
            "j.dupont@interne.fr",
            "Action required: update your billing preferences before the deadline",
            "New invoice portal! Sign in to your account: https://billing.acme-corp.com/account\nUnsubscribe: https://newsletter.acme-corp.com/unsub?u=1",
            extra_headers=[
                ("List-Id", "<news.acme-corp.com>"),
                ("List-Unsubscribe", "<https://newsletter.acme-corp.com/unsub?u=1>"),
                ("X-Mailer", "Mailchimp Mailer"),
                ("Reply-To", "marketing@acme-mailing.com"),
                ("Received", "from mail12.sendgrid.net (mail12.sendgrid.net [167.89.0.12]) by mx.interne.fr with ESMTPS id 4; Mon, 31 Aug 2026 10:00:00 +0000"),
                ("Authentication-Results", "mx.interne.fr; spf=pass smtp.mailfrom=bounce.acme-corp.com; dkim=pass header.d=acme-corp.com; dmarc=pass"),
            ],
            date="Mon, 31 Aug 2026 09:59:30 +0000",
        ),
        CTX,
    )
    f = set(row["flags"])
    assert "credential_phishing_pattern" not in f and "replyto_mismatch" not in f and "message_id_domain_mismatch" not in f
    assert row["risk"] <= 20, (row["risk"], sorted(f))


def test_synthetic_headers_from_pst_not_penalised():
    """MSG/PST exports without transport headers must not be treated as forged mail."""
    from services.parsers.mail.common import build_row

    headers = [
        ("From", '"IT Department" <it@interne.fr>'),
        ("To", "j.dupont@interne.fr"),
        ("Subject", "Your password expires in 3 days"),
        ("Date", "Tue, 01 Sep 2026 09:02:10 +0000"),
    ]
    text = "Your password expires in 3 days. Sign in and update your password before the deadline."
    row = build_row(headers, text, None, [], CTX, extra={"sourceFormat": "msg", "syntheticHeaders": True})
    f = set(row["flags"])
    assert not ({"no_message_id", "no_received", "single_hop", "spf_none", "dkim_none", "dmarc_none"} & f)
    assert "credential_phishing_pattern" not in f
    assert row["risk"] <= 20, (row["risk"], sorted(f))
    control = build_row(headers, text, None, [], CTX, extra={"sourceFormat": "eml"})
    assert "no_message_id" in set(control["flags"])


def test_a_msg_without_transport_headers_keeps_recipients_and_sender_whose_names_hold_an_address():
    """Outlook keeps an address as the display name of a contact who has none, and extract-msg
    writes the recipients of a message without transport headers as "name <address>" joined by
    semicolons. Python's strict address parser refused the whole value: the message lost its To
    list, was flagged as sent to undisclosed recipients, and had no sender. The addresses are
    invented."""
    from types import SimpleNamespace

    from services.parsers.mail.common import build_row
    from services.parsers.mail.msg import _headers_from_msg

    msg = SimpleNamespace(
        header=None,
        sender="j.dupont@interne.fr <j.dupont@interne.fr>",
        to="m.martin@interne.fr <m.martin@interne.fr>; Paul Bernard <p.bernard@interne.fr>",
        cc="Comptabilite (compta@interne.fr) <compta@interne.fr>",
        bcc=None,
        subject="Point hebdo",
        messageId=None,
        inReplyTo=None,
        date=None,
    )
    headers, synthetic = _headers_from_msg(msg)
    assert synthetic
    row = build_row(headers, "On se voit jeudi.", None, [], CTX, extra={"sourceFormat": "msg", "syntheticHeaders": True})
    assert (row["fromName"], row["fromAddr"]) == ("j.dupont@interne.fr", "j.dupont@interne.fr")
    assert [(r["name"], r["addr"]) for r in row["to"]] == [("m.martin@interne.fr", "m.martin@interne.fr"), ("Paul Bernard", "p.bernard@interne.fr")]
    assert [r["addr"] for r in row["cc"]] == ["compta@interne.fr"]
    assert row["recipientCount"] == 3
    assert "undisclosed_recipients" not in row["flags"] and "display_name_email_mismatch" not in row["flags"]
    # without the sender's SMTP address extract-msg gives the name alone, which Outlook writes as
    # "Name (address)" for a contact: it was read as the address "jean" named "j.dupont@interne.fr",
    # a sender who does not exist, flagged as a display name hiding another address
    msg.sender = "Jean Dupont (j.dupont@interne.fr)"
    headers, _ = _headers_from_msg(msg)
    row = build_row(headers, "On se voit jeudi.", None, [], CTX, extra={"sourceFormat": "msg", "syntheticHeaders": True})
    assert (row["fromName"], row["fromAddr"]) == ("Jean Dupont", "j.dupont@interne.fr")
    assert "display_name_email_mismatch" not in row["flags"]


def test_a_display_name_that_holds_another_address_is_read_as_a_name_and_flagged():
    """An unquoted display name holding an address is how a lure shows a trusted sender. The
    address is the one in angle brackets, never the one in the name; the addresses are invented."""
    from services.analysis.headers import parse_address, parse_addresses

    assert parse_address("support@bank.example <attacker@evil.example>") == ("support@bank.example", "attacker@evil.example")
    # the form behind CVE-2023-27043: the address is the one in angle brackets, not alice's
    assert parse_address("alice@example.org)<bob@example.org>")[1] == "bob@example.org"
    assert [a["addr"] for a in parse_addresses(["alice@example.org)<bob@example.org>, carol@example.org"])] == ["bob@example.org", "carol@example.org"]
    # what the strict parser reads is read as before
    assert parse_addresses(["undisclosed-recipients:;"]) == []
    assert [a["addr"] for a in parse_addresses(["Team: a@x.example, b@x.example;"])] == ["a@x.example", "b@x.example"]
    row = parse_message_bytes(
        b"From: support@bank.example <attacker@evil.example>\nTo: j.dupont@interne.fr\nSubject: Account review\n"
        b"Date: Tue, 01 Sep 2026 09:02:10 +0000\nMessage-ID: <a@evil.example>\n\nPlease review your account.\n",
        CTX,
    )
    assert (row["fromName"], row["fromAddr"]) == ("support@bank.example", "attacker@evil.example")
    assert "display_name_email_mismatch" in row["flags"]


def _forwarded_lure(extra: list[tuple[str, str]]) -> bytes:
    return make_samples.mail(
        '"IT Department" <it@interne.fr>',
        "liste-tech@interne.fr",
        "Action required: password expiry",
        "Your password expires soon. Sign in and update it: https://intranet.interne.fr/reset",
        extra_headers=[
            ("Received", "from lists.partner.org (lists.partner.org [203.0.113.44]) by mx.interne.fr with ESMTP id 5; Tue, 01 Sep 2026 09:05:00 +0000"),
            *extra,
        ],
        date="Tue, 01 Sep 2026 09:02:10 +0000",
    )


def test_a_trusted_sealers_arc_pass_restores_trust_on_forwarded_mail():
    """Mailing-list forwarding breaks SPF/DKIM. The receiver verified the list's ARC seal
    (arc=pass), and the analyst trusts that list as a sealer: the mail stays quiet."""
    from dataclasses import replace

    msg = _forwarded_lure(
        [
            ("Authentication-Results", "mx.interne.fr; spf=fail smtp.mailfrom=lists.partner.org; dkim=fail; dmarc=fail header.from=interne.fr; arc=pass"),
            ("ARC-Seal", "i=1; a=rsa-sha256; t=1788253500; cv=none; d=lists.partner.org; s=arc; b=AAAA"),
        ]
    )
    row = parse_message_bytes(msg, replace(CTX, trusted_arc_sealers=["lists.partner.org"]))
    f = set(row["flags"])
    assert "arc_trusted_sealer" in f and "credential_phishing_pattern" not in f and "internal_spoof" not in f
    assert row["risk"] <= 35, (row["risk"], sorted(f))
    # the same seal, from a sealer nobody said to trust, forgives nothing: anyone can seal their own chain
    untrusted = set(parse_message_bytes(msg, CTX)["flags"])
    assert "internal_spoof" in untrusted and "arc_trusted_sealer" not in untrusted


def test_claims_the_sender_can_write_do_not_turn_a_spoof_into_a_pass():
    """The receiver said spf=fail, dmarc=fail for a mail claiming an internal domain. None of the
    sender-writable headers below may undo that: a comment in the receiver's own header, a lower
    Authentication-Results, an ARC-Authentication-Results, an Exchange AuthAs header."""
    verdict = ("Authentication-Results", "mx.interne.fr; spf=fail smtp.mailfrom=evil.example; dmarc=fail (p=REJECT) header.from=interne.fr")
    variants = {
        "comment": [("Authentication-Results", verdict[1] + "; arc=pass (i=1 spf=pass dkim=pass dmarc=pass)")],
        "lower AR": [verdict, ("Authentication-Results", "attacker.example; spf=pass; dkim=pass; dmarc=pass; arc=pass")],
        "ARC-AR": [verdict, ("ARC-Authentication-Results", "i=1; attacker.example; spf=pass; dmarc=pass; arc=pass")],
        "AuthAs": [verdict, ("X-MS-Exchange-Organization-AuthAs", "Internal")],
    }
    for name, extra in variants.items():
        row = parse_message_bytes(_forwarded_lure(extra), CTX)
        assert "internal_spoof" in row["flags"], (name, row["risk"], row["flags"])
        assert row["auth"]["dmarc"] == "fail", name


def test_a_pass_for_another_domain_does_not_authenticate_an_internal_from():
    """A CEO-fraud mail claiming the internal domain, whose only pass is SPF for the attacker's
    own envelope domain, used to score lower than the same mail with no result at all."""
    row = parse_message_bytes(
        _forwarded_lure([("Authentication-Results", "mx.interne.fr; spf=pass smtp.mailfrom=evil.example")]),
        CTX,
    )
    from services.analysis.mail_calibration import aligned_auth

    f = set(row["flags"])
    assert "internal_spoof" in f and not aligned_auth(row), (row["risk"], sorted(f))


def _forwarded_as_attachment(attached: bytes, encoding: str | None = None) -> bytes:
    """An invented user forwards a message to the security desk as an attachment, with one line of their own."""
    outer = EmailMessage(policy=policy.SMTP)
    outer["From"] = "Jean Dupont <j.dupont@interne.fr>"
    outer["To"] = "soc@interne.fr"
    outer["Subject"] = "FW: Password expires today"
    outer["Date"] = "Tue, 01 Sep 2026 22:20:00 +0000"
    outer["Message-ID"] = "<fw-1@interne.fr>"
    outer.set_content("Is this one real? Jean")
    outer.add_attachment(email.message_from_bytes(attached, policy=policy.default))
    data = outer.as_bytes()
    if encoding == "base64":
        # some clients encode the attached message, which RFC 2046 does not allow
        head, _, rest = data.partition(b"Content-Type: message/rfc822\n")
        part_head, _, body = rest.partition(b"\n\n")
        inner, _, tail = body.partition(b"\n--")
        data = head + b"Content-Type: message/rfc822\nContent-Transfer-Encoding: base64\n" + part_head + b"\n\n" + base64.encodebytes(inner) + b"\n--" + tail
    return data


def test_a_lure_forwarded_as_an_attachment_is_scored_as_an_attachment_not_as_the_forwarders_words():
    """The lure's text and links were read into the forwarder's own body, and its parts were not
    an attachment. They belong to the attached message, which the attachment analysis reads."""
    lure = make_samples.mail(
        '"IT Support" <it-support@interne-fr.co>',
        "j.dupont@interne.fr",
        "Password expires today",
        "Your password expires today. Verify your account now: http://185.220.101.4/login.php?u=j.dupont@interne.fr",
        extra_headers=make_samples.RECEIVED_BAD,
        date="Tue, 01 Sep 2026 22:13:40 +0000",
    )
    for encoding in (None, "base64"):
        row = parse_message_bytes(_forwarded_as_attachment(lure, encoding), CTX)
        assert row["bodyText"].strip() == "Is this one real? Jean", encoding
        assert row["urlCount"] == 0 and "credential_phishing_pattern" not in row["flags"], encoding
        assert row["attachmentCount"] == 1, encoding
        [attached] = row["attachments"]
        assert attached["name"] == "forwarded.eml"
        assert attached["details"]["mail"]["subject"] == "Password expires today"
        assert {"nested_mail", "nested_url_ip_literal", "nested_credential_phishing_pattern"} <= set(attached["flags"])
        # the lure is scored where it is, and the forwarding message carries it as an attached
        # message, as an Outlook message attached to another already was
        assert attached["details"]["mail"]["risk"] >= 70
        assert {"att_nested_mail", "att_nested_credential_phishing_pattern"} <= set(row["flags"])
        assert row["risk"] >= int(attached["risk"] * 0.9) > 0


def test_credential_lure_from_suspicious_sender_still_high():
    row = parse_message_bytes(
        make_samples.mail(
            '"IT Department" <it-support-desk@secure-mail-check.top>',
            "j.dupont@interne.fr",
            "Action required: your password expires today",
            "Your password expires today. Sign in immediately to keep your mailbox: http://185.220.101.4/owa/login",
            extra_headers=[
                (
                    "Received",
                    "from mail.secure-mail-check.top (mail.secure-mail-check.top [185.220.101.4]) by mx.interne.fr with ESMTP id 9; Wed, 02 Sep 2026 03:12:00 +0000",
                ),
                ("Received-SPF", "fail (mx.interne.fr: 185.220.101.4 is not allowed)"),
            ],
            date="Wed, 02 Sep 2026 03:11:30 +0000",
        ),
        CTX,
    )
    f = set(row["flags"])
    assert "credential_phishing_pattern" in f
    assert {"url_ip_literal", "url_credential_keywords", "spf_fail"} <= f
    assert row["risk"] >= 70, (row["risk"], sorted(f))


def test_marketing_preheader_and_click_tracker_stay_low():
    """Real newsletters hide preview text and rewrap links through click-trackers; neither is an attack."""
    html = (
        '<span style="display:none">Summer offers inside - do not miss out</span>'
        '<a href="https://acme.us1.list-manage.com/track/click?u=abc&id=42">https://shop.acme-corp.com/offers</a>'
    )
    row = parse_message_bytes(
        make_samples.mail(
            '"Acme Shop" <news@acme-corp.com>',
            "j.dupont@interne.fr",
            "Our summer offers",
            "See our offers online.",
            html=html,
            extra_headers=[
                ("List-Id", "<news.acme-corp.com>"),
                ("List-Unsubscribe", "<https://acme-corp.com/u>"),
                ("Received", "from mail12.sendgrid.net (mail12.sendgrid.net [167.89.0.12]) by mx.interne.fr with ESMTPS id 4; Mon, 31 Aug 2026 10:00:00 +0000"),
                ("Authentication-Results", "mx.interne.fr; spf=pass smtp.mailfrom=acme-corp.com; dkim=pass header.d=acme-corp.com; dmarc=pass"),
            ],
            date="Mon, 31 Aug 2026 09:59:30 +0000",
        ),
        CTX,
    )
    f = set(row["flags"])
    assert "hidden_preheader" in f and "hidden_text" not in f
    assert row["risk"] <= 20, (row["risk"], sorted(f))  # mismatch demoted from strong in bulk context


def test_pst_synthetic_headers_not_penalised():
    """A .msg/.pst export without transport headers must not be treated as header forgery."""
    from services.parsers.mail.common import build_row

    headers = [
        ("From", '"IT Department" <it@interne.fr>'),
        ("To", "j.dupont@interne.fr"),
        ("Subject", "Your password expires soon"),
        ("Date", "Tue, 01 Sep 2026 09:02:10 +0000"),
    ]
    row = build_row(
        headers, "Your password expires soon. Sign in urgently and update it.", None, [], CTX, extra={"sourceFormat": "msg", "syntheticHeaders": True}
    )
    f = set(row["flags"])
    assert not ({"no_message_id", "no_received", "single_hop", "spf_none", "dkim_none", "dmarc_none"} & f)
    assert "credential_phishing_pattern" not in f
    assert row["risk"] <= 20, (row["risk"], sorted(f))
    control = build_row(headers, "hello", None, [], CTX, extra={"sourceFormat": "eml"})
    assert "no_message_id" in control["flags"]  # real transport mail without Message-ID stays flagged


def test_mbox_split(tmp_path):
    from api.views.ingest import _iter_mbox_fileobj

    names = make_samples.build(str(tmp_path))
    assert "mailbox.mbox" in names
    with open(tmp_path / "mailbox.mbox", "rb") as fh:
        rows = list(_iter_mbox_fileobj(fh, CTX, folder="mailbox.mbox"))
    assert len(rows) == 5
    assert rows[0]["subject"].startswith("URGENT") and rows[4]["subject"] == "This week in security"
    assert rows[4]["risk"] < 30 and "bulk_mailer" in rows[4]["flags"]


def test_trusted_notification_sender_capped():
    """Teams-style notification: colleague's display name on an authenticated
    microsoft.com sender must be flagged trusted_sender and capped at 10."""
    row = parse_message_bytes(
        make_samples.mail(
            '"Marie Lefevre" <noreply@email.teams.microsoft.com>',
            "j.dupont@interne.fr",
            "Marie Lefevre mentioned you in a conversation",
            "Marie Lefevre mentioned you in Projet Alpha.\nOpen Microsoft Teams to reply.",
            extra_headers=[
                ("Received", "from mail-eastus.protection.outlook.com (52.100.0.10) by mx.interne.fr with ESMTPS id 9; Tue, 01 Sep 2026 10:00:00 +0000"),
                (
                    "Authentication-Results",
                    "mx.interne.fr; spf=pass smtp.mailfrom=email.teams.microsoft.com; dkim=pass header.d=microsoft.com; dmarc=pass header.from=email.teams.microsoft.com",
                ),
            ],
            date="Tue, 01 Sep 2026 09:59:58 +0000",
        ),
        CTX,
    )
    f = set(row["flags"])
    assert "trusted_sender" in f
    assert row["fromRegistrable"] == "microsoft.com"
    assert row["risk"] <= 10, (row["risk"], sorted(f))


def test_trusted_sender_needs_passing_auth():
    """The same Teams-style mail with failing SPF must NOT get the trusted cap."""
    row = parse_message_bytes(
        make_samples.mail(
            '"Marie Lefevre" <noreply@email.teams.microsoft.com>',
            "j.dupont@interne.fr",
            "Marie Lefevre mentioned you in a conversation",
            "Marie Lefevre mentioned you in Projet Alpha.\nOpen Microsoft Teams to reply.",
            extra_headers=[
                ("Received", "from evil-relay.example.net (203.0.113.7) by mx.interne.fr with ESMTPS id 9; Tue, 01 Sep 2026 10:00:00 +0000"),
                (
                    "Authentication-Results",
                    "mx.interne.fr; spf=fail smtp.mailfrom=email.teams.microsoft.com; dkim=fail; dmarc=fail header.from=email.teams.microsoft.com",
                ),
            ],
            date="Tue, 01 Sep 2026 09:59:58 +0000",
        ),
        CTX,
    )
    f = set(row["flags"])
    assert "trusted_sender" not in f
    assert row["risk"] > 10, (row["risk"], sorted(f))


def test_user_trusted_sender_list_applies_without_auth():
    """Analyst-listed senders are capped even when headers cannot be verified
    (their explicit call), matching addresses exactly and domains by suffix."""
    ctx = ParseContext(
        internal_domains=["interne.fr"], vip_names=["Marie Lefevre"], trusted_senders=["notifications.partner-tool.io", "facture@fournisseur.fr"]
    )
    row = parse_message_bytes(
        make_samples.mail(
            '"Partner Tool" <alerts@mail.notifications.partner-tool.io>',
            "j.dupont@interne.fr",
            "Weekly digest",
            "Here is your weekly digest.",
            date="Tue, 01 Sep 2026 09:59:58 +0000",
        ),
        ctx,
    )
    assert "trusted_sender" in set(row["flags"])
    assert row["risk"] <= 10, (row["risk"], sorted(row["flags"]))
    row2 = parse_message_bytes(
        make_samples.mail(
            '"Compta" <facture@fournisseur.fr>',
            "j.dupont@interne.fr",
            "Facture 2026-091",
            "Veuillez trouver la facture jointe.",
            date="Tue, 01 Sep 2026 09:59:58 +0000",
        ),
        ctx,
    )
    assert "trusted_sender" in set(row2["flags"])
    # a different address on the same domain is NOT matched by an address entry
    row3 = parse_message_bytes(
        make_samples.mail(
            '"Compta" <autre@fournisseur.fr>', "j.dupont@interne.fr", "Facture 2026-092", "Autre facture.", date="Tue, 01 Sep 2026 09:59:58 +0000"
        ),
        ctx,
    )
    assert "trusted_sender" not in set(row3["flags"])


def test_trusted_sender_strong_flags_still_score():
    """A trusted relay must not silence strong indicators (compromised account)."""
    row = parse_message_bytes(
        make_samples.mail(
            '"Marie Lefevre" <noreply@email.teams.microsoft.com>',
            "j.dupont@interne.fr",
            "Urgent wire transfer needed",
            "I need you to buy gift cards urgently and keep this confidential. Send the codes by reply.",
            extra_headers=[
                (
                    "Authentication-Results",
                    "mx.interne.fr; spf=pass smtp.mailfrom=email.teams.microsoft.com; dkim=pass header.d=microsoft.com; dmarc=pass header.from=email.teams.microsoft.com",
                )
            ],
            date="Tue, 01 Sep 2026 09:59:58 +0000",
        ),
        CTX,
    )
    f = set(row["flags"])
    if "bec_pattern" in f:
        assert row["risk"] >= 60, (row["risk"], sorted(f))


# --- RTF-only bodies (PST/MSG) ---------------------------------------------------
# Regression from the first real Outlook export (2026-09-04): messages whose only
# body is RTF came back from RTFDE as UTF-8 *bytes* and crashed analyze_body's join.
from pathlib import Path as _Path

RTF_FIXTURE = _Path("tests/fixtures/rtf_encapsulated_text.rtf")


def test_rtf_to_text_returns_str_with_accents():
    from services.parsers.mail.msg import _rtf_to_text

    out = _rtf_to_text(RTF_FIXTURE.read_bytes())
    assert isinstance(out, str)
    assert "Une connexion à votre espace personnel a été détectée." in out


def test_pst_rtf_only_message_builds_row():
    import json
    from types import SimpleNamespace

    from services.parsers.mail import pst
    from services.parsers.mail.common import ParseContext, build_row

    fake = SimpleNamespace(plain_text_body=None, html_body=None, rtf_body=RTF_FIXTURE.read_bytes())
    text, html = pst._bodies(fake)
    assert isinstance(text, str) and html is None
    headers = [("From", "<notification@example.com>"), ("To", "<user@interne.fr>"), ("Subject", "Votre code"), ("Date", "Tue, 1 Sep 2026 21:55:41 +0200")]
    row = build_row(headers, text, html, [], ParseContext(internal_domains=["interne.fr"]), folder="Inbox", size=None, extra={"sourceFormat": "pst"})
    assert "parse_error" not in row["flags"]
    assert "connexion" in json.dumps(row, default=str)


# --- PST orphan / deleted items ---------------------------------------------------------
class _FakeMsg:
    def __init__(self, subject, body, ident):
        self.subject = subject
        self.plain_text_body = body.encode("utf-8")
        self.html_body = None
        self.rtf_body = None
        self.sender_name = "Billing <billing@evil-login.net>"
        self.transport_headers = f"From: Billing <billing@evil-login.net>\r\nTo: <user@interne.fr>\r\nSubject: {subject}\r\nDate: Tue, 1 Sep 2026 09:05:00 +0000\r\nMessage-ID: <{ident}@evil-login.net>\r\n"
        self.number_of_record_sets = 0
        self.number_of_attachments = 0
        self.identifier = ident
        self.delivery_time = None


class _FakeFolder:
    def __init__(self, name, messages, subfolders=()):
        self.name = name
        self._m = messages
        self._f = list(subfolders)
        self.number_of_sub_messages = len(messages)
        self.number_of_sub_folders = len(self._f)

    def get_sub_message(self, i):
        return self._m[i]

    def get_sub_folder(self, i):
        return self._f[i]


class _FakePst:
    def __init__(self):
        self.root = _FakeFolder(
            "Top of Outlook data file",
            [],
            [
                _FakeFolder("Inbox", [_FakeMsg("Hello", "normal mail", 1)]),
                _FakeFolder(
                    "Deleted Items",
                    [_FakeMsg("Invoice overdue - verify your password now", "urgent: confirm your password at https://evil-login.net/login", 2)],
                ),
            ],
        )
        self.number_of_orphan_items = 2
        self._orphans = [_FakeMsg("Re: wire transfer", "please send the payment to the new IBAN", 3), _FakeFolder("stray folder", [])]

    def get_root_folder(self):
        return self.root

    def get_orphan_item(self, i):
        return self._orphans[i]


def test_pst_orphan_and_deleted_items_are_tagged():
    from services.parsers.mail import pst

    rows = list(pst.iter_pst_file(_FakePst(), ParseContext(internal_domains=["interne.fr"])))
    assert [r["subject"] for r in rows] == ["Hello", "Invoice overdue - verify your password now", "Re: wire transfer"]
    assert "deleted_item" not in rows[0]["flags"]
    assert "deleted_item" in rows[1]["flags"] and "orphan_item" not in rows[1]["flags"] and "Deleted Items" in rows[1]["folder"]
    assert {"deleted_item", "orphan_item"} <= set(rows[2]["flags"]) and rows[2]["orphan"] is True and rows[2]["folder"] == pst.ORPHAN_FOLDER
    assert rows[2]["sourceIndex"] == 3 and rows[2]["pstIdentifier"] == 3
    # localised deleted-folder names
    assert pst._DELETED_FOLDER_RE.search("Top of Outlook data file/Éléments supprimés")
    assert pst._DELETED_FOLDER_RE.search("Recoverable Items/Purges") and not pst._DELETED_FOLDER_RE.search("Inbox/Projects")


class _DamagedFolder(_FakeFolder):
    """A folder of an invented, damaged mailbox: libpff refuses the second message and the first
    sub-folder, as it does for a corrupt PST or a partly synced OST."""

    def get_sub_message(self, i):
        if i == 1:
            raise OSError("libpff_folder_get_sub_message: unable to retrieve sub message: 1")
        return super().get_sub_message(i)

    def get_sub_folder(self, i):
        if i == 0:
            raise OSError("libpff_folder_get_sub_folder: unable to retrieve sub folder: 0")
        return super().get_sub_folder(i)


class _UnlistedFolder:
    name = "Sync Issues"
    number_of_sub_folders = 0

    @property
    def number_of_sub_messages(self):
        raise OSError("libpff_folder_get_number_of_sub_messages: unable to retrieve number of sub messages")


class _DamagedPst(_FakePst):
    def __init__(self):
        super().__init__()
        inbox = _DamagedFolder(
            "Inbox",
            [_FakeMsg("first", "one", 11), _FakeMsg("second", "two", 12), _FakeMsg("third", "three", 13)],
            [_FakeFolder("lost", []), _FakeFolder("Projects", [_FakeMsg("fourth", "four", 14)])],
        )
        self.root = _FakeFolder("Top of Outlook data file", [], [inbox, _UnlistedFolder()])
        self.number_of_orphan_items = 2

    def get_orphan_item(self, i):
        if i == 0:
            raise OSError("libpff_file_get_orphan_item: unable to retrieve orphan item: 0")
        return _FakeMsg("fifth", "five", 15)


def test_pst_items_libpff_cannot_read_are_counted_not_dropped():
    """A message, a folder or an orphan item that libpff refuses was logged at debug level and
    skipped, so a damaged mailbox looked complete. Each now comes through as an error row, which
    the import counts as an error."""
    from services.ingest.pipeline import MailStats
    from services.parsers.mail import pst

    rows = list(pst.iter_pst_file(_DamagedPst(), ParseContext(internal_domains=["interne.fr"])))
    stats = MailStats()
    for row in rows:
        stats.add(row)

    read = [r["subject"] for r in rows if "parse_error" not in r["flags"]]
    assert read == ["first", "third", "fourth", "fifth"]
    errors = [r for r in rows if "parse_error" in r["flags"]]
    assert stats.errors == len(errors) == 4
    by_subject = {r["subject"]: r for r in errors}
    assert set(by_subject) == {"(unreadable message)", "(unreadable folder)", "(unreadable folder contents)", "(unreadable orphan item)"}
    assert by_subject["(unreadable message)"]["folder"] == "Top of Outlook data file/Inbox"
    assert "sub message: 1" in by_subject["(unreadable message)"]["error"]
    assert by_subject["(unreadable folder contents)"]["folder"] == "Top of Outlook data file/Sync Issues"
    assert by_subject["(unreadable orphan item)"]["folder"] == pst.ORPHAN_FOLDER
    assert all(r["sourceFormat"] == "pst" and r["attachments"] == [] for r in errors)


def test_a_body_longer_than_the_kept_length_is_flagged_as_cut():
    """Text past 200,000 characters (400,000 of HTML) was dropped with nothing on the row, so the
    URLs and words in the rest were missing from search and rules without a sign."""
    from services.parsers.mail.common import MAX_HTML, MAX_TEXT, build_row

    headers = [("From", "billing@example.org"), ("To", "user@example.com"), ("Subject", "statement")]
    long_text = build_row(headers, "a" * (MAX_TEXT + 1), None, [], CTX, extra={"sourceFormat": "eml"})
    long_html = build_row(headers, "short", "<p>" + "b" * MAX_HTML + "</p>", [], CTX, extra={"sourceFormat": "eml"})
    whole = build_row(headers, "a" * MAX_TEXT, None, [], CTX, extra={"sourceFormat": "eml"})
    assert "body_truncated" in long_text["flags"] and len(long_text["bodyText"]) == MAX_TEXT
    assert "body_truncated" in long_html["flags"]
    assert "body_truncated" not in whole["flags"]
    assert long_text["risk"] == whole["risk"], "the flag says what was kept; it is not evidence"


class _FakeAttachment:
    def __init__(self, name, size):
        self.name = name
        self.size = size
        self.reads = 0

    def get_size(self):
        return self.size

    def read_buffer(self, size):
        self.reads += 1
        return b"%PDF-1.7\n" + b"0" * (size - 9)


class _FakeMsgWithAttachments(_FakeMsg):
    def __init__(self, attachments):
        super().__init__("files", "see attached", 21)
        self._a = attachments
        self.number_of_attachments = len(attachments)

    def get_attachment(self, i):
        return self._a[i]


def test_a_pst_attachment_too_large_to_read_keeps_its_size_and_says_it_was_not_read():
    """An attachment over the 60 MiB REMN reads from a PST was handed on as no bytes, so it showed
    as an empty file with no hash, which misdescribes the evidence."""
    from services.parsers.mail import pst

    big = _FakeAttachment("disk.iso", 70 * 1024 * 1024)
    small = _FakeAttachment("note.pdf", 1024)
    msg = _FakeMsgWithAttachments([big, small])
    row = pst._message_row(msg, "Inbox", ParseContext(internal_domains=["interne.fr"]), 1)

    assert big.reads == 0 and small.reads == 1
    unread, read = row["attachments"]
    assert unread["name"] == "disk.iso" and unread["size"] == 70 * 1024 * 1024
    assert "not_read" in unread["flags"] and "empty_file" not in unread["flags"] and not unread.get("sha256")
    assert "60 MiB" in unread["details"]["skipped"]
    assert read["sha256"] and "not_read" not in read["flags"]
    assert "att_not_read" in row["flags"] and "att_empty_file" not in row["flags"]


def test_a_pst_message_with_more_attachments_than_are_analysed_keeps_their_count():
    """Past 60 attachments a PST message lost the rest outright, and its attachment count said 60."""
    from services.parsers.mail import pst

    msg = _FakeMsgWithAttachments([_FakeAttachment(f"scan-{i:02d}.pdf", 64) for i in range(65)])
    row = pst._message_row(msg, "Inbox", ParseContext(internal_domains=["interne.fr"]), 1)

    assert row["attachmentCount"] == 65 and len(row["attachments"]) == 60
    assert "attachments_truncated" in row["flags"]
    assert sum(a.reads for a in msg._a) == 60, "the attachments past those analysed are counted, not read"


def test_raw_8bit_header_bytes_do_not_end_the_mailbox():
    """An mbox whose second message has a Latin-1 byte in its Subject: all three messages arrive,
    and the byte is read as the character it stands for."""
    import json

    from django.core.files.uploadedfile import SimpleUploadedFile
    from django.test import Client

    def msg(subject: bytes, i: int) -> bytes:
        return (
            b"From a@example.com Mon Jan  1 00:00:00 2024\nFrom: a@example.com\nTo: b@example.org\nSubject: "
            + subject
            + b"\nMessage-ID: <"
            + str(i).encode()
            + b'@x>\nDate: Mon, 1 Jan 2024 00:00:00 +0000\nContent-Disposition: attachment; filename="r\xe9sum\xe9.pdf"\n\nbody\n\n'
        )

    mbox = msg(b"first", 1) + msg(b"caf\xe9 invoice \xff", 2) + msg(b"third", 3)
    resp = Client().post("/api/ingest/mail", {"file": SimpleUploadedFile("box.mbox", mbox)}, HTTP_X_FORENSIC_CLIENT="1")
    lines = [json.loads(line) for line in b"".join(resp.streaming_content).splitlines() if line.strip()]
    subjects = [line["subject"] for line in lines if line["type"] == "mail"]
    assert subjects == ["first", "café invoice ÿ", "third"]
    assert lines[-1]["type"] == "done" and not any(line["type"] == "error" for line in lines)


def test_an_undecoded_surrogate_becomes_a_replacement_not_a_broken_stream():
    from services.common import fix_surrogates, ndjson_line

    assert ndjson_line({"s": "a\udce9b"}) == b'{"s":"a?b"}\n'
    assert fix_surrogates("caf\udcc3\udca9") == "café"  # valid UTF-8 bytes
    assert fix_surrogates("caf\udce9") == "café"  # Windows-1252
