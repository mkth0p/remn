"""
Mail header analysis: Received chain (origin IP, hops, delays), authentication
results (SPF / DKIM / DMARC / ARC), sender consistency and header oddities.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr
from typing import Any

from services.analysis.lookalike import registrable
from services.common import is_public_ip, normalize_ip, parse_timestamp

Header = tuple[str, str]

_IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,}:[0-9a-fA-F:.]+)\]?")
_FROM_RE = re.compile(r"(?is)\bfrom\s+(?P<from>.+?)(?=\s+\b(?:by|with|id|for|via)\b|;|$)")
_BY_RE = re.compile(r"(?is)\bby\s+(?P<by>[^\s;()]+)")
_WITH_RE = re.compile(r"(?is)\bwith\s+(?P<with>[^\s;()]+(?:\s+\([^)]*\))?)")
_ID_RE = re.compile(r"(?is)\bid\s+(?P<id>[^\s;()]+)")
_FOR_RE = re.compile(r"(?is)\bfor\s+<?(?P<for>[^\s;<>()]+)>?")
_HELO_RE = re.compile(r"(?is)^(?P<helo>[^\s(]+)?\s*(?:\((?P<comment>[^)]*)\))?")
_AUTH_PAIR_RE = re.compile(r"(?i)\b(spf|dkim|dmarc|arc|compauth|iprev|auth|dara|x-sid)\s*=\s*([a-z]+)")
_AUTH_PROP_RE = re.compile(r"(?i)\b(header\.d|header\.i|header\.from|smtp\.mailfrom|smtp\.helo|reason|action|policy\.\w+)\s*=\s*([^\s;()]+)")

WEBMAIL_HINTS = (
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "protonmail.com",
    "proton.me",
    "icloud.com",
    "aol.com",
    "gmx.com",
    "gmx.fr",
    "laposte.net",
    "orange.fr",
    "free.fr",
    "sfr.fr",
    "wanadoo.fr",
    "yandex.com",
    "mail.ru",
    "zoho.com",
    "live.com",
    "live.fr",
    "msn.com",
)
BULK_MAILERS = (
    "sendgrid",
    "mailchimp",
    "mailgun",
    "amazonses",
    "sparkpost",
    "mandrill",
    "constantcontact",
    "sendinblue",
    "brevo",
    "mailjet",
    "hubspot",
    "salesforce",
    "zendesk",
    "postmark",
    "elasticemail",
)
# Registrable domains of mail platforms whose HELO names never match the sender's domain
# (Exchange Online mailbox servers, Google, ESPs, security gateways, big webmail).
MAIL_INFRA_DOMAINS = frozenset(
    {
        "outlook.com",
        "office365.com",
        "office.com",
        "microsoft.com",
        "svc.ms",
        "exchangelabs.com",
        "google.com",
        "googlemail.com",
        "gmail.com",
        "amazonses.com",
        "sendgrid.net",
        "mailgun.org",
        "mailgun.net",
        "mandrillapp.com",
        "sparkpostmail.com",
        "mcsv.net",
        "mcdlv.net",
        "rsgsv.net",
        "exacttarget.com",
        "salesforce.com",
        "mailjet.com",
        "sendinblue.com",
        "brevo.com",
        "postmarkapp.com",
        "mimecast.com",
        "pphosted.com",
        "ppe-hosted.com",
        "messagelabs.com",
        "iphmx.com",
        "mailanyone.net",
        "barracudanetworks.com",
        "proofpoint.com",
        "secureserver.net",
        "ovh.net",
        "gandi.net",
        "zendesk.com",
        "hubspotemail.net",
        "mailchimp.com",
        "constantcontact.com",
        "icloud.com",
        "apple.com",
        "yahoo.com",
        "yahoodns.net",
        "protonmail.ch",
        "proton.me",
    }
)
SUSPICIOUS_MAILERS = (
    "php",
    "python",
    "swiftmailer",
    "phpmailer",
    "nodemailer",
    "sendblaster",
    "mass",
    "bulk",
    "turbo",
    "the bat",
    "fastmail sender",
    "xmail",
    "gammadyne",
    "sendmail",
    "leaf",
    "advanced mass",
    "email spider",
    "mailbomber",
    "smtpsend",
)


def decode_mime(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value))).strip()
    except Exception:  # noqa: BLE001
        return str(value).strip()


def header_values(headers: Iterable[Header], name: str) -> list[str]:
    n = name.lower()
    return [v for k, v in headers if k.lower() == n]


def first_header(headers: Iterable[Header], name: str) -> str | None:
    vals = header_values(headers, name)
    return vals[0] if vals else None


def parse_address(value: str | None) -> tuple[str, str]:
    """Return (display name, address) with MIME decoding applied."""
    if not value:
        return "", ""
    name, addr = parseaddr(decode_mime(value))
    return name.strip().strip('"'), addr.strip().lower()


def parse_addresses(values: Iterable[str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    decoded = [decode_mime(v) for v in values if v]
    for name, addr in getaddresses(decoded):
        addr = addr.strip().lower()
        if addr or name:
            out.append({"name": name.strip().strip('"'), "addr": addr, "domain": addr.split("@")[-1] if "@" in addr else ""})
    return out


def domain_of(addr: str | None) -> str:
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].lower().strip("> ")


# ---------------------------------------------------------------------------
# Received chain
# ---------------------------------------------------------------------------
def parse_received(value: str) -> dict[str, Any]:
    v = re.sub(r"\s+", " ", value or "").strip()
    hop: dict[str, Any] = {
        "raw": v[:1000],
        "from": None,
        "fromHelo": None,
        "fromIp": None,
        "by": None,
        "with": None,
        "id": None,
        "for": None,
        "date": None,
        "ts": None,
    }
    if ";" in v:
        body, _, date = v.rpartition(";")
        hop["date"] = date.strip()
        ms, iso = parse_timestamp(date.strip())
        hop["ts"] = ms
        hop["dateIso"] = iso
    else:
        body = v
    m = _FROM_RE.search(body)
    if m:
        frm = m.group("from").strip()
        hop["from"] = frm[:300]
        hm = _HELO_RE.match(frm)
        if hm:
            hop["fromHelo"] = (hm.group("helo") or "").strip()
            comment = hm.group("comment") or ""
            ips = [normalize_ip(x) for x in _IP_RE.findall(comment)] or [normalize_ip(x) for x in _IP_RE.findall(frm)]
            ips = [x for x in ips if x]
            hop["fromIp"] = ips[0] if ips else None
            # rDNS name inside the comment (e.g. "mail.example.com [1.2.3.4]")
            rdns = re.match(r"\s*([A-Za-z0-9.-]+)\s*[\[(]", comment)
            if rdns:
                hop["fromRdns"] = rdns.group(1)
    m = _BY_RE.search(body)
    if m:
        hop["by"] = m.group("by")[:200]
    m = _WITH_RE.search(body)
    if m:
        hop["with"] = m.group("with")[:120]
    m = _ID_RE.search(body)
    if m:
        hop["id"] = m.group("id")[:120]
    m = _FOR_RE.search(body)
    if m:
        hop["for"] = m.group("for")[:200].lower()
    return hop


def received_chain(headers: list[Header]) -> dict[str, Any]:
    """
    Headers are in message order (top first = last hop). We return hops in
    chronological order (origin first) and derive the first external IP.
    """
    received = header_values(headers, "Received")
    hops = [parse_received(r) for r in reversed(received)]  # chronological
    for i, hop in enumerate(hops):
        hop["index"] = i
        if i > 0 and hop.get("ts") and hops[i - 1].get("ts"):
            hop["delayS"] = round((hop["ts"] - hops[i - 1]["ts"]) / 1000)
        else:
            hop["delayS"] = None
    origin_ip: str | None = None
    origin_hop: int | None = None
    for hop in hops:
        ip = hop.get("fromIp")
        if ip and is_public_ip(ip):
            origin_ip = ip
            origin_hop = hop["index"]
            break
    # Microsoft / other explicit origin headers take precedence when present.
    explicit = None
    for name in ("X-Originating-IP", "X-Sender-IP", "X-Original-IP", "X-Client-IP", "X-Real-IP", "X-MS-Exchange-Organization-OriginalClientIPAddress"):
        val = first_header(headers, name)
        if val:
            ips = [normalize_ip(x) for x in _IP_RE.findall(val)]
            ips = [x for x in ips if x]
            if ips:
                explicit = ips[0]
                break
    negative_delay = any((h.get("delayS") or 0) < -120 for h in hops)
    total_delay = None
    if len(hops) >= 2 and hops[0].get("ts") and hops[-1].get("ts"):
        total_delay = round((hops[-1]["ts"] - hops[0]["ts"]) / 1000)
    return {
        "hops": hops,
        "hopCount": len(hops),
        "originIp": explicit or origin_ip,
        "originIpSource": "header" if explicit else ("received" if origin_ip else None),
        "originHop": origin_hop,
        "originHelo": hops[origin_hop]["fromHelo"] if origin_hop is not None else None,
        "originRdns": hops[origin_hop].get("fromRdns") if origin_hop is not None else None,
        "negativeDelay": negative_delay,
        "totalDelayS": total_delay,
        "firstHopTs": hops[0]["ts"] if hops and hops[0].get("ts") else None,
    }


# ---------------------------------------------------------------------------
# Authentication results
# ---------------------------------------------------------------------------
def parse_auth_results(headers: list[Header]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "arc": None,
        "compauth": None,
        "dkimDomain": None,
        "spfDomain": None,
        "dmarcPolicy": None,
        "raw": [],
    }
    for name in ("Authentication-Results", "ARC-Authentication-Results", "X-MS-Exchange-Authentication-Results"):
        for val in header_values(headers, name):
            v = re.sub(r"\s+", " ", val)
            out["raw"].append(v[:600])
            for mech, res in _AUTH_PAIR_RE.findall(v):
                mech, res = mech.lower(), res.lower()
                key = {"arc": "arc", "compauth": "compauth"}.get(mech, mech)
                if key in out and out[key] is None:
                    out[key] = res
            for prop, pval in _AUTH_PROP_RE.findall(v):
                prop = prop.lower()
                if prop == "header.d" and not out["dkimDomain"] and pval.lower() not in ("none", "-", "null"):
                    out["dkimDomain"] = pval.lower()
                elif prop == "smtp.mailfrom" and not out["spfDomain"]:
                    out["spfDomain"] = domain_of(pval) or pval.lower()
                elif prop.startswith("policy.") and "dmarc" in v.lower() and not out["dmarcPolicy"]:
                    out["dmarcPolicy"] = pval.lower()
    if out["spf"] is None:
        spf = first_header(headers, "Received-SPF")
        if spf:
            m = re.match(r"\s*([A-Za-z]+)", spf)
            if m:
                out["spf"] = m.group(1).lower()
            out["raw"].append("Received-SPF: " + re.sub(r"\s+", " ", spf)[:300])
    sigs = header_values(headers, "DKIM-Signature")
    out["dkimSigned"] = bool(sigs)
    if sigs and not out["dkimDomain"]:
        m = re.search(r"(?i)\bd=([^;\s]+)", sigs[0])
        if m:
            out["dkimDomain"] = m.group(1).lower()
    # Exchange organisation headers. They are stripped at the organisation boundary, so on a
    # mailbox export they describe how *this* organisation accepted the message:
    # AuthAs=Internal is an authenticated submission by a tenant user; SCL/BCL/SFV are the
    # gateway's own spam / bulk verdicts (X-Forefront-Antispam-Report carries them on inbound mail).
    auth_as = first_header(headers, "X-MS-Exchange-Organization-AuthAs")
    out["exoAuthAs"] = auth_as.strip().lower()[:40] if auth_as else None
    src = first_header(headers, "X-MS-Exchange-Organization-AuthSource")
    out["exoAuthSource"] = src.strip().lower()[:200] if src else None
    report = first_header(headers, "X-Forefront-Antispam-Report") or ""
    out["scl"] = _int_or_none(first_header(headers, "X-MS-Exchange-Organization-SCL"))
    if out["scl"] is None:
        m = re.search(r"(?i)\bSCL:(-?\d+)", report)
        out["scl"] = int(m.group(1)) if m else None
    m = re.search(r"(?i)\bSFV:([A-Z]+)", report)
    out["sfv"] = m.group(1).upper() if m else None
    m = re.search(r"(?i)\bBCL:(\d+)", first_header(headers, "X-Microsoft-Antispam") or "") or re.search(r"(?i)\bBCL:(\d+)", report)
    out["bcl"] = int(m.group(1)) if m else None
    return out


def _int_or_none(value: str | None) -> int | None:
    try:
        return int((value or "").strip())
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Full header analysis
# ---------------------------------------------------------------------------
def analyze_headers(headers: list[Header], date_ms: int | None = None) -> dict[str, Any]:
    flags: list[str] = []
    from_name, from_addr = parse_address(first_header(headers, "From"))
    from_domain = domain_of(from_addr)
    sender_name, sender_addr = parse_address(first_header(headers, "Sender"))
    reply_to = parse_addresses(header_values(headers, "Reply-To"))
    return_path_raw = first_header(headers, "Return-Path")
    _, return_path = parse_address(return_path_raw) if return_path_raw else ("", "")
    chain = received_chain(headers)
    auth = parse_auth_results(headers)
    message_id = (first_header(headers, "Message-ID") or "").strip()
    x_mailer = decode_mime(first_header(headers, "X-Mailer") or first_header(headers, "User-Agent") or "")
    x_priority = first_header(headers, "X-Priority") or first_header(headers, "Importance") or first_header(headers, "X-MSMail-Priority")

    from_reg = registrable(from_domain) if from_domain else ""
    rp_domain = domain_of(return_path)
    # Bulk-mail context: newsletters and notification platforms legitimately use foreign
    # envelope domains, Message-IDs and Reply-To addresses. Only hard signals survive there.
    has_list = bool(first_header(headers, "List-Id") or first_header(headers, "List-Unsubscribe"))
    is_bulk = bool(x_mailer and any(s in x_mailer.lower() for s in BULK_MAILERS))
    dkim_reg = registrable(auth["dkimDomain"]) if auth.get("dkimDomain") else ""
    if return_path and from_domain and registrable(rp_domain) != from_reg:
        flags.append("returnpath_mismatch")
    if sender_addr and from_addr and registrable(domain_of(sender_addr)) != from_reg:
        flags.append("sender_mismatch")
    for rt in reply_to:
        if rt["addr"] and from_addr and registrable(rt["domain"]) != from_reg:
            if rt["domain"] in WEBMAIL_HINTS:
                flags.append("replyto_mismatch")
                flags.append("replyto_webmail")
            elif not (has_list or is_bulk) and registrable(rt["domain"]) != dkim_reg:
                flags.append("replyto_mismatch")
            break
    if auth["spf"] in ("fail", "softfail", "permerror", "temperror"):
        flags.append("spf_fail")
    elif auth["spf"] in ("none",):
        flags.append("spf_none")
    if auth["dkim"] in ("fail", "permerror", "temperror"):
        flags.append("dkim_fail")
    elif auth["dkim"] in ("none",) or (auth["dkim"] is None and not auth["dkimSigned"] and chain["hopCount"] > 0):
        flags.append("dkim_none")
    if auth["dmarc"] in ("fail", "permerror", "temperror"):
        flags.append("dmarc_fail")
    elif auth["dmarc"] in ("none", "bestguesspass"):
        flags.append("dmarc_none")
    if auth["compauth"] in ("fail",):
        flags.append("compauth_fail")
    if auth["dkimDomain"] and from_reg and registrable(auth["dkimDomain"]) != from_reg:
        flags.append("dkim_domain_unaligned")
    if auth["spfDomain"] and from_reg and registrable(auth["spfDomain"]) != from_reg:
        flags.append("spf_domain_unaligned")
    if not message_id:
        flags.append("no_message_id")
    else:
        mid_dom = message_id.strip("<>").split("@")[-1].lower() if "@" in message_id else ""
        if not re.match(r"^<[^<>@\s]+@[^<>@\s]+>$", message_id):
            flags.append("malformed_message_id")
        elif (
            mid_dom
            and from_reg
            and registrable(mid_dom) != from_reg
            and not (has_list or is_bulk)
            and (not dkim_reg or registrable(mid_dom) != dkim_reg)
            and mid_dom not in ("mail.gmail.com",)
            and not mid_dom.endswith(
                (
                    ".outlook.com",
                    ".prod.outlook.com",
                    "google.com",
                    ".amazonses.com",
                    ".sendgrid.net",
                    ".mcsv.net",
                    ".rsgsv.net",
                    ".mailchimpapp.net",
                    ".exchangelabs.com",
                    ".mimecast.com",
                    ".pphosted.com",
                    ".sfmc-content.com",
                    ".mktomail.com",
                )
            )
        ):
            flags.append("message_id_domain_mismatch")
    if not first_header(headers, "Date"):
        flags.append("no_date")
    if date_ms and chain.get("firstHopTs"):
        skew = abs(date_ms - chain["firstHopTs"]) / 1000
        if skew > 6 * 3600:
            flags.append("date_skew")
    if chain["negativeDelay"]:
        flags.append("received_time_travel")
    if chain["hopCount"] == 0:
        flags.append("no_received")
    if chain["hopCount"] == 1:
        flags.append("single_hop")
    if chain["originIp"] is None and chain["hopCount"]:
        flags.append("no_origin_ip")
    if from_domain and from_domain in WEBMAIL_HINTS:
        flags.append("from_webmail")
    xm = x_mailer.lower()
    if xm and any(s in xm for s in SUSPICIOUS_MAILERS):
        flags.append("suspicious_mailer")
    if xm and any(s in xm for s in BULK_MAILERS):
        flags.append("bulk_mailer")
    if x_priority and re.search(r"(?i)\b(1|high|urgent)\b", x_priority):
        flags.append("high_priority")
    if first_header(headers, "List-Unsubscribe") and not first_header(headers, "List-Id"):
        flags.append("unsubscribe_without_list")
    if from_name and "@" in from_name:
        flags.append("email_in_display_name")
        if from_addr and from_name.lower().strip() != from_addr:
            flags.append("display_name_email_mismatch")
    if from_name and re.search(r"[Ѐ-ӿͰ-Ͽ]", from_name) and re.search(r"[A-Za-z]", from_name):
        flags.append("mixed_script_display_name")
    to_count = len(parse_addresses(header_values(headers, "To")))
    cc_count = len(parse_addresses(header_values(headers, "Cc")))
    if to_count == 0 and cc_count == 0:
        flags.append("undisclosed_recipients")
    if to_count + cc_count > 30:
        flags.append("mass_recipients")
    helo = chain.get("originHelo") or ""
    rdns = chain.get("originRdns") or ""
    helo_reg = registrable(helo) if helo and "." in helo else ""
    # A foreign HELO is normal when SPF authorises the sending host, or when the host belongs to
    # a known mail platform (Exchange Online mailbox servers, Google, ESPs, security gateways).
    if helo_reg and from_reg and helo_reg != from_reg and not rdns and auth["spf"] != "pass" and helo_reg not in MAIL_INFRA_DOMAINS:
        flags.append("helo_domain_mismatch")

    return {
        "flags": sorted(set(flags)),
        "from": {"name": from_name, "addr": from_addr, "domain": from_domain, "registrable": from_reg},
        "sender": {"name": sender_name, "addr": sender_addr} if sender_addr else None,
        "replyTo": reply_to,
        "returnPath": return_path or None,
        "messageId": message_id or None,
        "xMailer": x_mailer or None,
        "priority": x_priority,
        "chain": chain,
        "auth": auth,
    }


def headers_to_text(headers: list[Header], limit: int = 64 * 1024) -> str:
    lines = [f"{k}: {v}" for k, v in headers]
    txt = "\n".join(lines)
    return txt if len(txt) <= limit else txt[:limit] + "\n…[truncated]"
