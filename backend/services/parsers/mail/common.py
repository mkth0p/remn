"""
Shared mail model: turns headers + bodies + attachments (from any container
format) into one analysed row. Attachment bytes are analysed, never returned.
"""
from __future__ import annotations

import email
import logging
import re
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from typing import Any, Iterable

from services.analysis.attachments.analyzer import analyze_attachment
from services.analysis.body import analyze_body
from services.analysis.headers import (
    analyze_headers, decode_mime, domain_of, first_header, header_values, headers_to_text, parse_addresses,
)
from services.analysis.lookalike import DEFAULT_BRANDS, analyze_domain, display_name_looks_like_email, registrable, split_domain
from services.reference.brand_domains import BRAND_OWNED_DOMAINS
from services.reference.notification_senders import NOTIFICATION_SENDERS
from services.analysis.urls import extract_urls, _domain_in_text
from services.common import parse_timestamp

log = logging.getLogger(__name__)

Header = tuple[str, str]
MAX_TEXT = 200_000
MAX_HTML = 400_000

MAIL_WEIGHTS: dict[str, int] = {
    "spf_fail": 35, "dkim_fail": 30, "dmarc_fail": 45, "compauth_fail": 40, "spf_none": 10, "dkim_none": 5, "dmarc_none": 5,
    "dkim_domain_unaligned": 15, "spf_domain_unaligned": 15, "returnpath_mismatch": 25, "sender_mismatch": 20,
    "replyto_mismatch": 25, "replyto_webmail": 45, "no_message_id": 25, "malformed_message_id": 30,
    "message_id_domain_mismatch": 8, "no_date": 20, "date_skew": 25, "received_time_travel": 20, "no_received": 10,
    "single_hop": 5, "no_origin_ip": 2, "from_webmail": 8, "suspicious_mailer": 45, "bulk_mailer": 2,
    "high_priority": 5, "unsubscribe_without_list": 5, "email_in_display_name": 20, "display_name_email_mismatch": 70,
    "mixed_script_display_name": 55, "undisclosed_recipients": 20, "mass_recipients": 15, "helo_domain_mismatch": 15,
    "sender_punycode": 25, "sender_mixed_script": 55, "sender_confusable": 35, "sender_lookalike_internal": 90,
    "sender_lookalike_brand": 60, "sender_tld_swap": 70, "sender_subdomain_trick": 75, "sender_homoglyph": 75,
    "sender_digit_substitution": 70, "sender_edit_distance": 60, "sender_brand_embedding": 55,
    "replyto_lookalike_internal": 85, "replyto_lookalike_brand": 55,
    "lexicon_urgency": 10, "lexicon_financial": 12, "lexicon_gift_card": 45, "lexicon_credentials": 12,
    "lexicon_authority": 8, "lexicon_secrecy": 20, "lexicon_availability": 15, "lexicon_delivery": 8,
    "lexicon_document_lure": 10, "bec_pattern": 75, "credential_phishing_pattern": 65, "zero_width_chars": 40,
    "internal_spoof": 85,
    "bidi_override": 50, "hidden_text": 45, "hidden_preheader": 3, "hidden_style": 5, "base64_blob": 20, "obfuscated_html": 45,
    "html_script": 40, "html_form": 40, "html_embed": 30, "image_only": 40, "mixed_script_text": 30,
    "url_ip_literal": 50, "url_private_ip": 20, "url_punycode": 25, "url_suspicious_tld": 35, "url_many_subdomains": 12,
    "url_shortener": 30, "url_file_hosting": 8, "url_free_hosting": 35, "url_many_hyphens": 10, "url_long_host": 10,
    "url_userinfo": 55, "url_unusual_port": 30, "url_long_url": 3, "url_double_encoded": 25,
    "url_executable_download": 65, "url_credential_keywords": 40, "url_login_link": 5, "url_rewritten": 2,
    "url_form_saas": 10, "url_email_in_url": 40, "url_base64_in_url": 25,
    "url_open_redirect": 25, "url_text_href_mismatch": 60, "url_tracking_pixel": 5, "url_tracking": 3,
    "url_form_action": 55, "url_meta_refresh": 45, "url_data_uri": 50, "url_script_uri": 60, "url_file_uri": 40,
    "url_malformed": 10, "html_form_password": 70, "html_form_external": 50, "attachment_risky": 0,
    "empty_subject": 10, "reply_without_thread": 15, "subject_re_fwd_spoof": 20, "many_attachments": 5,
    "encrypted_body": 15, "calendar_invite": 5, "rtf_only_body": 10, "no_body": 10, "html_only": 5,
    "exchange_internal": 0, "calendar_item": 0, "gateway_spam_verdict": 40, "gateway_bulk_verdict": 5,
    "scripted_mailer": 8, "url_tracker_redirect": 2, "url_own_domain": 0, "deleted_item": 0, "orphan_item": 0,
}


# Flags that indicate the SENDER itself is suspect (used to gate wording-based patterns).
SENDER_SUSPICION = {
    "from_webmail", "replyto_webmail", "replyto_mismatch", "display_name_email_mismatch", "mixed_script_display_name",
    "suspicious_mailer", "spf_fail", "dkim_fail", "dmarc_fail", "compauth_fail", "no_message_id", "malformed_message_id",
    "received_time_travel", "sender_lookalike_internal", "sender_lookalike_brand", "sender_punycode", "sender_mixed_script",
    "sender_confusable", "sender_homoglyph", "sender_tld_swap", "sender_subdomain_trick", "sender_digit_substitution",
    "sender_edit_distance", "sender_brand_embedding", "replyto_lookalike_internal", "replyto_lookalike_brand",
}
URL_SUSPICION = {
    "url_text_href_mismatch", "url_ip_literal", "url_punycode", "url_free_hosting", "url_shortener",
    "url_executable_download", "url_credential_keywords", "url_userinfo", "url_data_uri", "url_script_uri",
    "url_suspicious_tld", "url_open_redirect",
}
# Strong indicators carry the score on their own. Without at least one of them (or a risky
# attachment), weak wording/link/header noise is capped so ordinary corporate mail stays low.
STRONG_FLAGS = {
    "sender_lookalike_internal", "sender_tld_swap", "sender_subdomain_trick", "sender_homoglyph",
    "sender_digit_substitution", "sender_mixed_script",
    "replyto_lookalike_internal", "display_name_email_mismatch", "mixed_script_display_name",
    "suspicious_mailer", "bec_pattern", "credential_phishing_pattern", "internal_spoof", "hidden_text", "bidi_override",
    "url_text_href_mismatch", "url_ip_literal", "url_userinfo", "url_data_uri", "url_script_uri",
    "url_executable_download", "url_credential_keywords", "html_form_password", "html_form_external",
}


@dataclass
class ParseContext:
    internal_domains: list[str] = field(default_factory=list)
    brands: list[str] = field(default_factory=list)
    vip_names: list[str] = field(default_factory=list)
    include_html: bool = True
    include_headers: bool = True
    analyze_attachments: bool = True
    evidence_id: str | None = None
    trusted_senders: list[str] = field(default_factory=list)


@dataclass
class RawAttachment:
    name: str | None
    data: bytes
    mime: str | None = None
    inline: bool = False
    content_id: str | None = None


def normalize_name(name: str | None) -> str:
    """Lower-case, accent-stripped, punctuation-free display name used to group senders."""
    if not name:
        return ""
    import unicodedata

    s = unicodedata.normalize("NFKD", name)
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = re.sub(r"<[^>]*>", " ", s)  # drop embedded addresses
    s = re.sub(r"[^a-z0-9 ]+", " ", s.lower())
    tokens = [t for t in s.split() if t]
    # "Dupont Jean" and "Jean Dupont" collapse together
    return " ".join(sorted(tokens))[:120]


def _user_trusted(addr: str, domain: str, registrable: str, entries: list[str]) -> bool:
    """Case-insensitive match of the case's trusted-senders list: full addresses
    match exactly; bare domains match the sender domain or any subdomain of it."""
    if not entries:
        return False
    a = (addr or "").lower()
    d = (domain or "").lower()
    r = (registrable or "").lower()
    for e in entries:
        e = e.strip().lower().lstrip("@")
        if not e:
            continue
        if "@" in e:
            if a == e:
                return True
        elif d == e or r == e or d.endswith("." + e):
            return True
    return False


def score_groups(flags: Iterable[str]) -> dict[str, int]:
    """Correlated observations contribute once; attachment evidence is scored separately."""
    groups: dict[str, int] = {}
    for f in set(flags):
        if f.startswith("att_") or f not in MAIL_WEIGHTS:
            continue
        group = ("authentication" if f.startswith(("spf_", "dkim_", "dmarc_", "compauth_", "returnpath_")) else
                 "identity" if f.startswith(("sender_", "replyto_", "display_name_", "mixed_script_display")) or f == "internal_spoof" else
                 "wording" if f.startswith("lexicon_") else
                 "links" if f.startswith("url_") else
                 "content" if f in {"bec_pattern", "credential_phishing_pattern", "html_form_password", "html_form_external", "hidden_text", "bidi_override"} else "context")
        groups[group] = max(groups.get(group, 0), MAIL_WEIGHTS[f])
    return groups


def _score(flags: Iterable[str], attachment_risk: int, trust: dict[str, bool] | None = None) -> int:
    """
    Strong indicators drive the score; weak wording/link/header noise only amplifies.
    Without any strong flag the score is capped, and further reduced for authenticated
    internal senders and authenticated bulk mail. Risky attachments always override.
    """
    fl = set(flags)
    trust = trust or {}
    ws = sorted(score_groups(fl).values(), reverse=True)
    score = 0
    if ws:
        score = ws[0] + sum(min(w, 30) // 4 for w in ws[1:8])
    strong = fl & STRONG_FLAGS
    if trust.get("bulk"):
        # newsletters rewrap every link through click-trackers: mismatch is expected there
        strong = strong - {"url_text_href_mismatch", "hidden_text"}
    if not strong:
        score = min(score, 45)
        if trust.get("authenticated"):
            if trust.get("internal"):
                score = min(score, 12)
            elif trust.get("bulk"):
                score = min(score, 20)
            else:
                score = min(score, 35)
        elif trust.get("synthetic_internal"):
            score = min(score, 20)
        if trust.get("notification") or trust.get("user_trusted"):
            # known notification relay with passing auth, or analyst-listed sender
            score = min(score, 10)
    score = max(score, int(attachment_risk * 0.9))
    return max(0, min(100, score))


def build_row(headers: list[Header], body_text: str | None, body_html: str | None,
              attachments: list[RawAttachment], ctx: ParseContext, folder: str = "",
              size: int | None = None, extra: dict[str, Any] | None = None, depth: int = 0) -> dict[str, Any]:
    """Assemble and analyse one message."""
    extra = extra or {}
    date_raw = first_header(headers, "Date")
    date_ms, date_iso = parse_timestamp(date_raw)
    if date_ms is None and extra.get("dateFallback"):
        date_ms, date_iso = parse_timestamp(extra["dateFallback"])
    hdr = analyze_headers(headers, date_ms)
    flags: set[str] = set(hdr["flags"])
    frm = hdr["from"]

    # Sender domain lookalike analysis
    look = analyze_domain(frm["domain"], ctx.internal_domains, ctx.brands or None) if frm["domain"] else {"flags": [], "matches": [], "internal": False}
    for f in look.get("flags", []):
        flags.add("sender_" + f)
    reply_look = None
    for rt in hdr["replyTo"]:
        if rt.get("domain"):
            rl = analyze_domain(rt["domain"], ctx.internal_domains, ctx.brands or None)
            if rl.get("flags") and not rl.get("internal"):
                reply_look = rl
                for f in rl["flags"]:
                    if f.startswith("lookalike") or f in ("punycode", "mixed_script", "confusable"):
                        flags.add("replyto_" + f)
            break
    if frm["name"]:
        emb = display_name_looks_like_email(frm["name"])
        if emb and frm["addr"] and registrable(domain_of(emb)) != frm["registrable"]:
            flags.add("display_name_email_mismatch")

    # Bodies
    text = (body_text or "")[:MAX_TEXT]
    html = (body_html or "")[:MAX_HTML] if body_html else ""
    subject = decode_mime(first_header(headers, "Subject") or extra.get("subject") or "")
    body = analyze_body(text, html or None, subject)
    flags.update(body["flags"])
    urls, html_info = extract_urls(text, html or None)
    # Links that stay on the authenticated sender's own domain are that sender's navigation, not a
    # lure ("change your password" on account.microsoft.com in DKIM-signed Microsoft mail, anchor
    # text "news.vendor.example" pointing at vendor.example). Anchor text that names a brand or one of the
    # organisation's domains keeps the mismatch: that is the spoof pattern itself.
    auth0 = hdr["auth"] or {}
    sender_auth_basic = bool(
        ((auth0.get("spf") == "pass" or auth0.get("dkim") == "pass") and auth0.get("dmarc") in ("pass", "bestguesspass", None)
         and not ({"spf_fail", "dkim_fail", "dmarc_fail", "compauth_fail"} & flags))
        or auth0.get("exoAuthAs") == "internal"
    )
    if sender_auth_basic and frm["registrable"]:
        internal_regs = {registrable(d) for d in ctx.internal_domains}
        brand_names = set(DEFAULT_BRANDS) | {b.lower() for b in (ctx.brands or [])}
        for u in urls:
            ufl = set(u["flags"])
            if u.get("domain") != frm["registrable"] or not (ufl & {"text_href_mismatch", "credential_keywords", "open_redirect"}):
                continue
            if "text_href_mismatch" in ufl:
                tdom = registrable(_domain_in_text(u.get("text") or "") or "")
                claims_brand = bool(tdom) and (tdom in BRAND_OWNED_DOMAINS or tdom in internal_regs or split_domain(tdom)[1] in brand_names)
                if not claims_brand:
                    ufl.discard("text_href_mismatch")
            ufl.discard("open_redirect")
            if "credential_keywords" in ufl:
                ufl = (ufl - {"credential_keywords"}) | {"login_link"}
            u["flags"] = sorted(ufl | {"own_domain"})
    url_flags: set[str] = set()
    for u in urls:
        for f in u["flags"]:
            url_flags.add("url_" + f)
    flags.update(url_flags)
    for form in html_info.get("forms", []):
        if form.get("hasPassword"):
            flags.add("html_form_password")
        if form.get("external"):
            flags.add("html_form_external")

    # ----- context ---------------------------------------------------------
    hits = body["keywordHits"]
    # PST / MSG exports often carry no transport headers at all: every header-forensics
    # flag would fire on every message of the mailbox. Suppress them for synthetic headers.
    synthetic = bool(extra.get("syntheticHeaders"))
    if synthetic:
        flags -= {"no_message_id", "malformed_message_id", "no_received", "single_hop", "no_origin_ip",
                  "spf_none", "dkim_none", "dmarc_none", "no_date", "helo_domain_mismatch"}
    auth_hdr = hdr["auth"] or {}
    # Exchange organisation headers survive on mailbox exports. AuthAs=Internal is an
    # authenticated submission by a tenant user: Exchange neither DKIM-signs nor DMARC-evaluates
    # intra-tenant traffic, so its "none" results and mailbox-server HELO names mean nothing.
    exo_auth_internal = auth_hdr.get("exoAuthAs") == "internal"
    if exo_auth_internal:
        flags -= {"spf_none", "dkim_none", "dmarc_none", "dkim_domain_unaligned", "spf_domain_unaligned",
                  "helo_domain_mismatch", "message_id_domain_mismatch", "single_hop", "no_origin_ip"}
        flags.add("exchange_internal")
    # without a configured internal-domain list, an authenticated tenant submission IS the organisation
    exo_internal = exo_auth_internal and (bool(look.get("internal")) or not ctx.internal_domains)
    # The gateway's own verdicts (Exchange Online Protection / on-prem Exchange)
    scl = auth_hdr.get("scl")
    if (isinstance(scl, int) and scl >= 5) or auth_hdr.get("sfv") in ("SPM", "SKS", "BLK"):
        flags.add("gateway_spam_verdict")
    bcl = auth_hdr.get("bcl")
    if isinstance(bcl, int) and bcl >= 4:
        flags.add("gateway_bulk_verdict")
    # Calendar objects (appointments, meeting requests/responses) are not mail: no recipients
    # on an own-calendar entry is normal, not "undisclosed recipients".
    mclass = str(extra.get("messageClass") or "").lower()
    if mclass.startswith(("ipm.appointment", "ipm.schedule.", "report.ipm.schedule")):
        flags.add("calendar_item")
        flags.discard("undisclosed_recipients")
    # Mailing lists / forwarders legitimately break SPF and DKIM; a valid ARC seal restores trust.
    arc_ok = auth_hdr.get("arc") == "pass"
    is_bulk_ctx = "bulk_mailer" in flags or bool(first_header(headers, "List-Id"))
    # PHPMailer & co. are what CMS newsletters are sent with; only unauthenticated use is a forgery signal
    if "suspicious_mailer" in flags and (sender_auth_basic or is_bulk_ctx):
        flags.discard("suspicious_mailer")
        flags.add("scripted_mailer")
    suspicion = set(flags) & SENDER_SUSPICION
    if arc_ok:
        suspicion -= {"spf_fail", "dkim_fail", "dmarc_fail", "compauth_fail"}
    sender_suspect = bool(suspicion)
    url_suspect = bool(flags & URL_SUSPICION)
    # Hidden preview text ("preheader") is standard in marketing and notification mail.
    # Only substantial hidden content from a suspect sender counts as content salting.
    if "hidden_text" in flags:
        hidden_join = " ".join(body.get("hiddenText") or [])
        preheaderish = len(hidden_join) < 300 and "http" not in hidden_join.lower()
        # Hidden text is content salting only when something else is already wrong with the mail
        # (sender or link). Newsletters, notifications and Outlook-generated internal mail hide
        # preview lines, mso-conditional blocks and "view in browser" sections routinely.
        if is_bulk_ctx or exo_auth_internal or (preheaderish and not sender_suspect) or not (sender_suspect or url_suspect):
            flags.discard("hidden_text")
            flags.add("hidden_preheader")

    # Composite patterns, gated on sender / URL legitimacy: wording alone marks ordinary
    # corporate mail (password-expiry notices, invoices, CEO newsletters).
    if (
        "authority" in hits
        and ({"financial", "gift_card"} & hits.keys())
        and ({"urgency", "secrecy", "availability"} & hits.keys())
        and (sender_suspect or ("gift_card" in hits and ({"secrecy", "availability"} & hits.keys()) and not is_bulk_ctx))
    ):
        flags.add("bec_pattern")
    if "credentials" in hits and "urgency" in hits and (sender_suspect or url_suspect):
        flags.add("credential_phishing_pattern")
    if look.get("internal") and not arc_ok and ({"spf_fail", "dmarc_fail", "compauth_fail"} & flags):
        flags.add("internal_spoof")
    if not text and not html:
        flags.add("no_body")
    elif not text and html:
        flags.add("html_only")
    if not subject.strip():
        flags.add("empty_subject")
    if re.match(r"(?i)^\s*(re|fw|fwd|tr)\s*:", subject) and not first_header(headers, "In-Reply-To") and not first_header(headers, "References"):
        flags.add("reply_without_thread")
    if first_header(headers, "Content-Type") and "application/pkcs7-mime" in (first_header(headers, "Content-Type") or "").lower():
        flags.add("encrypted_body")

    # Attachments
    att_rows: list[dict[str, Any]] = []
    max_att_risk = 0
    if ctx.analyze_attachments:
        for a in attachments[:60]:
            try:
                row = analyze_attachment(a.name, a.data, a.mime, depth=depth, inline=a.inline, content_id=a.content_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("attachment failed: %s", exc)
                row = {"name": a.name, "size": len(a.data), "flags": ["analysis_error"], "risk": 20, "details": {"error": str(exc)[:200]}}
            att_rows.append(row)
            max_att_risk = max(max_att_risk, row.get("risk", 0))
            for f in row.get("flags", []):
                flags.add("att_" + f)
        if len(attachments) > 60:
            flags.add("many_attachments")
    if len(attachments) > 10:
        flags.add("many_attachments")

    to_list = parse_addresses(header_values(headers, "To"))
    cc_list = parse_addresses(header_values(headers, "Cc"))
    bcc_list = parse_addresses(header_values(headers, "Bcc"))
    if not to_list and extra.get("to"):
        to_list = parse_addresses([extra["to"]])
    if not cc_list and extra.get("cc"):
        cc_list = parse_addresses([extra["cc"]])
    if not bcc_list and extra.get("bcc"):
        bcc_list = parse_addresses([extra["bcc"]])

    auth_res = hdr["auth"]
    trust = {
        "authenticated": (
            (auth_res.get("spf") == "pass" or auth_res.get("dkim") == "pass")
            and auth_res.get("dmarc") in ("pass", "bestguesspass", None)
            and not ({"spf_fail", "dkim_fail", "dmarc_fail", "compauth_fail"} & flags)
        )
        or (arc_ok and "compauth_fail" not in flags)
        or exo_internal,
        "internal": bool(look.get("internal")),
        "exchangeInternal": exo_internal,
        "bulk": is_bulk_ctx,
        # a PST/MSG export of the organisation's own mailbox: headers unverifiable but internal
        "synthetic_internal": synthetic and bool(look.get("internal")),
    }
    # Trusted senders: built-in notification relays need passing auth; the
    # analyst's own list applies regardless (their call). Strong flags still score.
    if frm["registrable"] and frm["registrable"] in NOTIFICATION_SENDERS and trust["authenticated"]:
        trust["notification"] = True
        flags.add("trusted_sender")
    if _user_trusted(frm["addr"], frm["domain"], frm["registrable"], ctx.trusted_senders):
        trust["user_trusted"] = True
        flags.add("trusted_sender")
    flag_list = sorted(flags)
    row: dict[str, Any] = {
        "folder": folder,
        "subject": subject[:500],
        "date": date_ms,
        "dateIso": date_iso,
        "dateRaw": (date_raw or "")[:80] or None,
        "fromName": frm["name"][:200],
        "fromNameNorm": normalize_name(frm["name"]),
        "fromAddr": frm["addr"][:300],
        "fromDomain": frm["domain"][:200],
        "fromRegistrable": frm["registrable"][:200],
        "sender": hdr["sender"],
        "replyTo": hdr["replyTo"][:10],
        "returnPath": hdr["returnPath"],
        "to": to_list[:100],
        "cc": cc_list[:100],
        "bcc": bcc_list[:100],
        "recipientCount": len(to_list) + len(cc_list) + len(bcc_list),
        "messageId": hdr["messageId"],
        "inReplyTo": (first_header(headers, "In-Reply-To") or "").strip()[:300] or None,
        "references": [r for r in re.split(r"\s+", (first_header(headers, "References") or "").strip()) if r][:30],
        "xMailer": hdr["xMailer"],
        "priority": hdr["priority"],
        "listId": (first_header(headers, "List-Id") or "").strip()[:200] or None,
        "originIp": hdr["chain"]["originIp"],
        "originIpSource": hdr["chain"]["originIpSource"],
        "originHelo": hdr["chain"]["originHelo"],
        "originRdns": hdr["chain"]["originRdns"],
        "hopCount": hdr["chain"]["hopCount"],
        "hops": hdr["chain"]["hops"][:30],
        "totalDelayS": hdr["chain"]["totalDelayS"],
        "auth": hdr["auth"],
        "headersText": headers_to_text(headers) if ctx.include_headers else None,
        "headerCount": len(headers),
        "bodyText": text or None,
        "bodyHtml": html if (ctx.include_html and html) else None,
        "hasHtml": bool(html),
        "hasText": bool(text),
        "visibleText": body.get("visibleText"),
        "textPreview": body["textPreview"],
        "keywordHits": body["keywordHits"],
        "hiddenText": body["hiddenText"],
        "urls": urls[:200],
        "urlCount": len(urls),
        "htmlInfo": {k: v for k, v in html_info.items() if k != "forms"} | {"forms": html_info.get("forms", [])[:10]},
        "attachments": att_rows,
        "attachmentCount": len(attachments),
        "maxAttachmentRisk": max_att_risk,
        "lookalike": look,
        "replyToLookalike": reply_look,
        "flags": flag_list,
        "risk": _score(flag_list, max_att_risk, trust),
        "size": size,
        "contentType": (first_header(headers, "Content-Type") or "").split(";")[0].strip().lower()[:100] or None,
        "depth": depth,
    }
    for k, v in extra.items():
        if k not in row and k not in ("dateFallback", "to", "cc", "bcc", "subject"):
            row[k] = v
    from services.analysis.mail_calibration import calibrate_mail

    return calibrate_mail(row, {"internal_domains": ctx.internal_domains, "trusted_senders": ctx.trusted_senders})


# ---------------------------------------------------------------------------
# email.message.Message -> build_row inputs
# ---------------------------------------------------------------------------
def _decode_part(part: Message) -> str:
    try:
        content = part.get_content()
        if isinstance(content, bytes):
            return content.decode(part.get_content_charset() or "utf-8", "replace")
        return str(content)
    except Exception:  # noqa: BLE001
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, "replace")
        except LookupError:
            return payload.decode("utf-8", "replace")


def split_message(msg: Message) -> tuple[str | None, str | None, list[RawAttachment]]:
    """Return (text, html, attachments) walking every MIME part."""
    texts: list[str] = []
    htmls: list[str] = []
    attachments: list[RawAttachment] = []
    for part in msg.walk():
        ctype = (part.get_content_type() or "").lower()
        if part.is_multipart():
            continue
        disp = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        try:
            filename = decode_mime(filename) if filename else None
        except Exception:  # noqa: BLE001
            pass
        cid = (part.get("Content-ID") or "").strip("<> ") or None
        if ctype == "message/rfc822" or (ctype.startswith("message/") and disp):
            try:
                payload = part.get_payload()
                inner = payload[0] if isinstance(payload, list) and payload else None
                data = inner.as_bytes() if inner is not None else (part.get_payload(decode=True) or b"")
            except Exception:  # noqa: BLE001
                data = part.get_payload(decode=True) or b""
            attachments.append(RawAttachment(filename or "forwarded.eml", data, "message/rfc822", False, cid))
            continue
        is_attachment = disp == "attachment" or (filename and disp != "inline" and not ctype.startswith("text/")) or (
            not ctype.startswith("text/") and not ctype.startswith("multipart/") and (filename or disp)
        )
        if is_attachment or (disp == "inline" and filename and not ctype.startswith("text/")):
            data = part.get_payload(decode=True) or b""
            attachments.append(RawAttachment(filename, data, ctype, disp == "inline", cid))
            continue
        if ctype == "text/plain":
            texts.append(_decode_part(part))
        elif ctype == "text/html":
            htmls.append(_decode_part(part))
        elif ctype.startswith("text/") and not filename:
            texts.append(_decode_part(part))
        elif not ctype.startswith("text/") and ctype != "multipart/alternative":
            # unnamed binary part (e.g. image without filename) -> still an attachment
            data = part.get_payload(decode=True) or b""
            if data:
                ext = ctype.split("/")[-1].split("+")[0]
                attachments.append(RawAttachment(filename or f"part.{ext}", data, ctype, disp == "inline", cid))
    text = "\n\n".join(t for t in texts if t) or None
    html = "\n".join(h for h in htmls if h) or None
    return text, html, attachments


_UNFOLD_RE = re.compile(r"\r?\n[ \t]")


def message_headers(msg: Message) -> list[Header]:
    # raw_items avoids the (expensive) lazy headerregistry parse that
    # policy.default triggers on every str(header); downstream consumers all
    # run values through decode_mime, which handles RFC2047 words itself.
    out: list[Header] = []
    for k, v in msg.raw_items():
        try:
            out.append((k, _UNFOLD_RE.sub(" ", str(v)).strip()))
        except Exception:  # noqa: BLE001
            out.append((k, repr(v)))
    return out


def parse_message_bytes(data: bytes, ctx: ParseContext, folder: str = "", depth: int = 0,
                        extra: dict[str, Any] | None = None) -> dict[str, Any]:
    msg = email.message_from_bytes(data, policy=policy.default)
    headers = message_headers(msg)
    text, html, attachments = split_message(msg)
    return build_row(headers, text, html, attachments, ctx, folder=folder, size=len(data), extra=extra, depth=depth)


def parse_nested_mail(name: str, data: bytes, depth: int) -> dict[str, Any]:
    """Compact parse of a forwarded message attached as .eml/.msg (used by the attachment analyzer)."""
    ctx = ParseContext(include_html=False, include_headers=False)
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        from services.parsers.mail.msg import parse_msg_bytes

        row = parse_msg_bytes(data, ctx, folder="nested", depth=depth)
    else:
        row = parse_message_bytes(data, ctx, folder="nested", depth=depth)
    compact = {k: row.get(k) for k in ("subject", "fromName", "fromAddr", "fromDomain", "date", "dateIso", "messageId",
                                        "originIp", "flags", "risk", "urlCount", "attachmentCount")}
    compact["attachments"] = [{k: a.get(k) for k in ("name", "size", "realExt", "sha256", "flags", "risk")} for a in row.get("attachments", [])]
    compact["urls"] = [u["defanged"] for u in row.get("urls", [])[:20]]
    return compact
