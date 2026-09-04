"""URL extraction from mail bodies (text + HTML) with local heuristics."""
from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import unquote, urlsplit

from services.analysis.lookalike import registrable, split_domain, to_unicode

URL_RE = re.compile(
    r"""(?ix)
    \b(?:
        (?:h[xX]{0,2}t{1,2}ps?|ftps?|hxxps?)://[^\s<>"'`\]\)\}]+   # scheme URLs (incl. defanged hxxp)
      | www\.[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:/[^\s<>"'`\]\)\}]*)?     # bare www.
    )
    """
)
DEFANG_RE = re.compile(r"(?i)h[xX]{2}ps?://|\[\.\]|\(\.\)|\{\.\}")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy",
    "rebrand.ly", "shorturl.at", "tiny.cc", "lnkd.in", "s.id", "t.ly", "bl.ink", "short.io",
    "urlz.fr", "lc.cx", "v.gd", "clck.ru", "qr.ae", "adf.ly", "bc.vc", "1url.com", "x.co",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "club", "work", "gq", "ml", "cf", "tk", "ga", "buzz", "cam",
    "rest", "surf", "icu", "click", "link", "monster", "quest", "cfd", "sbs", "cyou", "bond",
    "lol", "pw", "ru", "su", "cn", "ws", "info", "biz", "loan", "date", "racing", "stream",
}
FILE_HOSTING = {
    "drive.google.com", "docs.google.com", "dropbox.com", "onedrive.live.com", "1drv.ms",
    "sharepoint.com", "wetransfer.com", "we.tl", "mega.nz", "mediafire.com", "box.com",
    "sendspace.com", "transfer.sh", "file.io", "gofile.io", "anonfiles.com", "pcloud.link",
    "github.com", "raw.githubusercontent.com", "pastebin.com", "discord.com", "cdn.discordapp.com",
    "storage.googleapis.com", "s3.amazonaws.com", "blob.core.windows.net", "web.core.windows.net",
    "firebasestorage.googleapis.com", "ipfs.io", "cloudflare-ipfs.com", "dweb.link",
}
FORM_BUILDERS = {
    "weebly.com", "wix.com", "glitch.me", "netlify.app", "vercel.app", "pages.dev", "web.app",
    "firebaseapp.com", "github.io", "repl.co", "herokuapp.com", "000webhostapp.com",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "workers.dev", "r2.dev",
}
# Legitimate form / survey SaaS: abused by phishing sometimes, but everyday corporate tooling.
# Flagged informationally as form_saas, never as free_hosting.
FORM_SAAS = {
    "forms.office.com", "forms.gle", "docs.google.com", "typeform.com", "jotform.com", "formstack.com",
    "surveymonkey.com", "wufoo.com", "123formbuilder.com", "cognitoforms.com", "eventbrite.com", "doodle.com",
}
# E-mail security gateways rewrite every link (Safe Links, Proofpoint, Mimecast...). The wrapper is
# noise: we unwrap to the real destination and analyse that, otherwise every corporate mail trips
# text_href_mismatch / open_redirect / credential_keywords.
URL_REWRITERS = (
    "safelinks.protection.outlook.com", "urldefense.com", "urldefense.proofpoint.com",
    "protection.sophos.com", "mimecastprotect.com", "protect.mimecast.com", "url.emailprotection.link",
    "clicktime.symantec.com", "secure-web.cisco.com", "urlsand.esvalabs.com", "scanmail.trustwave.com",
    "linkprotect.cudasvc.com", "protect.checkpoint.com", "urlisolation.com", "swa.trendmicro.com",
)
EXEC_EXT_RE = re.compile(
    r"(?i)\.(exe|scr|msi|msp|bat|cmd|com|pif|vbs|vbe|js|jse|wsf|wsh|hta|ps1|jar|cpl|dll|lnk|iso|img|vhd|vhdx|zip|rar|7z|ace|cab|gz|tgz|bz2|docm|xlsm|pptm|dotm|xlam|one|xll|reg|url|chm|apk)(?:$|[?#])"
)
# A path ending in ".com" / ".one" is almost always a host name carried in the path
# (engage.cloud.microsoft/main/contoso.com, redirector "/u/example.com"), not a DOS executable.
# Only the double-extension trick (invoice.pdf.com) keeps the executable_download flag.
_TLD_LIKE_SEGMENT_RE = re.compile(r"(?i)\.(?:com|one)$")
_DOUBLE_EXT_COM_RE = re.compile(r"(?i)\.(?:pdf|docx?|xlsx?|pptx?|zip|rar|7z|jpe?g|png|gif|txt|html?|csv)\.(?:com|one)$")
CRED_KEYWORDS = (
    "login", "signin", "sign-in", "logon", "verify", "verification", "password", "passwd",
    "credential", "account", "secure", "update", "confirm", "auth", "sso", "webmail", "owa",
    "office365", "o365", "microsoft", "sharepoint", "onedrive", "docusign", "invoice", "payment",
    "billing", "wallet", "reset", "unlock", "suspend", "limited", "recover", "2fa", "mfa", "otp",
)
TRACKING_HINTS = ("track", "open", "pixel", "beacon", "utm_", "mailtrack", "sendgrid", "mailchimp", "list-manage")
# Registrable domains of e-mail service providers' click trackers: every link in the mail is
# rewritten to them, so anchor text never matches the href. Recorded as tracker_redirect.
TRACKER_DOMAINS = frozenset({
    "sendibm1.com", "sendibm2.com", "sendibm3.com", "sp1-brevo.net", "sendinblue.com", "brevo.com", "sendgrid.net",
    "awstrack.me", "list-manage.com", "mailchimp.com", "hubspotlinks.com", "hubspotemail.net", "exacttarget.com",
    "mandrillapp.com", "sparkpostmail.com", "mlsend.com", "cmail19.com", "cmail20.com", "createsend.com",
    "junglemailpages.com", "quadientcloud.eu", "mailjet.com", "mjt.lu", "elasticemail.com", "klclick.com",
    "klclick1.com", "emsecure.net", "mailgun.org", "postmarkapp.com", "customeriomail.com", "mkt5.net",
})
# Link text that is a file name ("report.zip", "Doc.aspx") is not a domain claim, even when the
# extension happens to be a TLD.
_FILENAME_EXT_RE = re.compile(
    r"(?i)\.(?:aspx?|php|html?|pdf|docx?|xlsx?|pptx?|zip|rar|7z|png|jpe?g|gif|svg|txt|csv|json|xml|mp4|mp3|msg|eml|ics|md|py|js|css|exe|msi)$"
)


_SCHEME_HOST_RE = re.compile(r"(?is)^([a-z][a-z0-9+.-]*)://([^/?#]*)(.*)$")


def defang(url: str) -> str:
    """hxxp://evil[.]example/path - only the scheme and the host are altered."""
    m = _SCHEME_HOST_RE.match(url)
    if m:
        scheme, host, rest = m.groups()
        scheme = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}.get(scheme.lower(), scheme)
        return f"{scheme}://{host.replace('.', '[.]')}{rest}"
    head, sep, tail = url.partition("/")
    return head.replace(".", "[.]") + sep + tail


def refang(url: str) -> str:
    u = re.sub(r"(?i)^hxxps://", "https://", url)
    u = re.sub(r"(?i)^hxxp://", "http://", u)
    u = re.sub(r"(?i)^fxp://", "ftp://", u)
    return u.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".").replace("[:]", ":")


def _is_rewriter(host: str) -> bool:
    return any(host == r or host.endswith("." + r) for r in URL_REWRITERS)


def unwrap_rewritten(url: str) -> tuple[str, str] | None:
    """If url is a security-gateway wrapper, return (inner url, wrapper host)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if not _is_rewriter(host):
        return None
    from urllib.parse import parse_qs

    qs = parse_qs(parts.query, keep_blank_values=True)
    for key in ("url", "u", "target", "dest", "redirect", "a"):
        for cand in qs.get(key, []):
            cand = unquote(cand)
            if cand.startswith(("http://", "https://")):
                return cand, host
            if key == "u" and "urldefense" in host:
                # Proofpoint v2: '-' encodes '%', '_' encodes '/'
                decoded = unquote(cand.replace("-", "%").replace("_", "/"))
                if decoded.startswith(("http://", "https://")):
                    return decoded, host
    m = re.search(r"/v3/__(.+?)__;", url)  # Proofpoint v3
    if m:
        inner = m.group(1).replace("*", "")
        if inner.startswith(("http://", "https://")):
            return inner, host
    return None


def _clean(url: str) -> str:
    u = url.strip().rstrip(".,;:!?'\"")
    # balance trailing parenthesis from prose like (https://x.y/z)
    while u.endswith(")") and u.count("(") < u.count(")"):
        u = u[:-1]
    return u


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, Any]] = []
        self.images: list[dict[str, Any]] = []
        self.forms: list[dict[str, Any]] = []
        self._current: dict[str, Any] | None = None
        self._text: list[str] = []
        self.has_script = False
        self.meta_refresh: str | None = None
        self.base_href: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        if t == "a" and a.get("href"):
            self._current = {"url": a["href"].strip(), "text": "", "title": a.get("title")}
            self._text = []
        elif t == "img":
            src = a.get("src", "")
            try:
                w = int(re.sub(r"\D", "", a.get("width", "")) or -1)
                h = int(re.sub(r"\D", "", a.get("height", "")) or -1)
            except ValueError:
                w = h = -1
            style = a.get("style", "").lower()
            tiny = (0 <= w <= 2 and 0 <= h <= 2) or ("width:0" in style or "width: 0" in style or "display:none" in style.replace(" ", ""))
            if src:
                self.images.append({"src": src.strip(), "tiny": tiny, "alt": a.get("alt", "")})
        elif t == "form":
            self.forms.append({"action": a.get("action", "").strip(), "method": a.get("method", "get").lower()})
        elif t == "script":
            self.has_script = True
        elif t == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh = a.get("content", "")
        elif t == "base" and a.get("href"):
            self.base_href = a["href"]
        elif t == "input" and self.forms:
            typ = a.get("type", "text").lower()
            self.forms[-1].setdefault("inputs", []).append({"type": typ, "name": a.get("name", "")})

    def handle_data(self, data: str) -> None:
        if self._current is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current is not None:
            self._current["text"] = re.sub(r"\s+", " ", "".join(self._text)).strip()[:300]
            self.links.append(self._current)
            self._current = None
            self._text = []


def parse_html(html: str) -> _LinkParser:
    p = _LinkParser()
    try:
        p.feed(html)
        p.close()
    except Exception:  # noqa: BLE001 - malformed HTML is expected in phishing mails
        pass
    return p


def _host_of(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    host = (parts.hostname or "").lower().strip(".")
    return host


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _domain_in_text(text: str) -> str | None:
    """If the visible anchor text looks like a URL or domain, return its host."""
    if not text:
        return None
    t = text.strip()
    if not re.match(r"(?i)(?:https?://|www\.)", t) and _FILENAME_EXT_RE.search(t.split("/")[0]):
        return None
    m = URL_RE.search(t)
    if m:
        return _host_of(refang(m.group(0)) if "://" in m.group(0) else "http://" + m.group(0))
    m2 = re.fullmatch(r"(?i)[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:/\S*)?", t)
    if m2:
        return t.split("/")[0].lower()
    return None


def analyze_url(url: str, text: str | None = None, source: str = "text", _depth: int = 0) -> dict[str, Any]:
    raw = _clean(url)
    was_defanged = bool(DEFANG_RE.search(raw))
    u = refang(raw)
    if u.lower().startswith("www."):
        u = "http://" + u
    if _depth < 3:
        unwrapped = unwrap_rewritten(u)
        if unwrapped and unwrapped[0] != u:
            inner = analyze_url(unwrapped[0], text, source, _depth + 1)
            inner["flags"] = sorted(set(inner["flags"]) | {"rewritten"})
            inner["wrapper"] = unwrapped[1]
            inner["wrappedUrl"] = raw[:500]
            return inner
    flags: list[str] = []
    scheme = ""
    host = ""
    path = ""
    query = ""
    port: int | None = None
    try:
        parts = urlsplit(u)
        scheme = (parts.scheme or "").lower()
        host = (parts.hostname or "").lower().strip(".")
        path = parts.path or ""
        query = parts.query or ""
        port = parts.port
        if parts.username or parts.password:
            flags.append("userinfo")
    except ValueError:
        flags.append("malformed")
    if scheme == "data":
        flags.append("data_uri")
        return {"url": raw[:2000], "normalized": u[:2000], "host": "", "domain": "", "scheme": scheme,
                "flags": flags, "text": (text or "")[:300], "source": source, "defanged": defang(u)[:2000]}
    if scheme in ("javascript", "vbscript"):
        flags.append("script_uri")
    if scheme == "file":
        flags.append("file_uri")
    if scheme in ("ftp", "ftps"):
        flags.append("ftp")
    if was_defanged:
        flags.append("was_defanged")

    dom = ""
    if host:
        if _is_ip(host):
            flags.append("ip_literal")
            dom = host
            try:
                ip = ipaddress.ip_address(host.strip("[]"))
                if not ip.is_global:
                    flags.append("private_ip")
            except ValueError:
                pass
        else:
            dom = registrable(host)
            sub, sld, suffix = split_domain(host)
            if "xn--" in host:
                flags.append("punycode")
            if suffix and suffix.split(".")[-1] in SUSPICIOUS_TLDS:
                flags.append("suspicious_tld")
            if sub and sub.count(".") >= 2:
                flags.append("many_subdomains")
            if dom in SHORTENERS or host in SHORTENERS:
                flags.append("shortener")
            if dom in FILE_HOSTING or host in FILE_HOSTING or any(host.endswith("." + f) for f in FILE_HOSTING):
                flags.append("file_hosting")
            if dom in FORM_BUILDERS or any(host.endswith("." + f) or host == f for f in FORM_BUILDERS):
                flags.append("free_hosting")
            if dom in FORM_SAAS or any(host.endswith("." + f) or host == f for f in FORM_SAAS):
                flags.append("form_saas")
            if host.count("-") >= 3:
                flags.append("many_hyphens")
            if len(host) > 60:
                flags.append("long_host")
            if "@" in u.split("://", 1)[-1].split("/", 1)[0]:
                flags.append("userinfo")
    if port and port not in (80, 443, 8080, 8443):
        flags.append("unusual_port")
    if len(u) > 250:
        flags.append("long_url")
    lowered = (path + "?" + query).lower()
    if "%25" in lowered or ("%" in lowered and "%" in unquote(lowered)):
        flags.append("double_encoded")
    if EXEC_EXT_RE.search(path) and not (_TLD_LIKE_SEGMENT_RE.search(path) and not _DOUBLE_EXT_COM_RE.search(path)):
        flags.append("executable_download")
    pq = unquote(lowered)
    if any(k in pq for k in CRED_KEYWORDS) and dom and dom not in FILE_HOSTING and "form_saas" not in flags:
        # "login"/"account"/"invoice" in a path is everyday corporate traffic; it is only a phishing
        # signal when the URL itself is already suspicious. Otherwise record it as an informational
        # login_link so rules can still combine it with sender suspicion.
        risky = {"ip_literal", "punycode", "shortener", "suspicious_tld", "userinfo", "free_hosting", "unusual_port"}
        flags.append("credential_keywords" if risky & set(flags) else "login_link")
    if re.search(r"[?&#](?:email|user|login|e|u|id)=[^&]*@", pq) or re.search(r"[A-Za-z0-9+/=]{20,}@", pq):
        flags.append("email_in_url")
    if re.search(r"(?:[?&#]|/)(?:[A-Za-z0-9+/]{40,}={0,2})(?:$|[&#/])", u):
        flags.append("base64_in_url")
    m_redir = re.search(r"(?i)(?:redirect|redir|url|goto|next|return|continue|dest|target|link|out)=(https?(?::|%3a)(?:/|%2f){2}[^&#]+)", u)
    if m_redir:
        # a redirect that stays on the same registrable domain is navigation, not an open-redirect lure
        target_host = _host_of(unquote(m_redir.group(1)))
        if not target_host or registrable(target_host) != dom:
            flags.append("open_redirect")
    # Anchor text vs href mismatch
    if text:
        tdom = _domain_in_text(text)
        if tdom and host and registrable(tdom) != dom:
            if dom in TRACKER_DOMAINS:
                flags.append("tracker_redirect")
            else:
                flags.append("text_href_mismatch")
    if any(h in pq for h in TRACKING_HINTS) and source == "image":
        flags.append("tracking")

    return {
        "url": raw[:2000],
        "normalized": u[:2000],
        "defanged": defang(u)[:2000],
        "host": host,
        "unicodeHost": to_unicode(host)[0] if "xn--" in host else None,
        "domain": dom,
        "scheme": scheme,
        "port": port,
        "path": path[:500],
        "flags": sorted(set(flags)),
        "text": (text or "")[:300],
        "source": source,
    }


def extract_urls(text: str | None, html: str | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Return (urls, html_info). URLs are deduplicated on the normalized form and
    carry the anchor text when they come from HTML.
    """
    found: dict[str, dict[str, Any]] = {}
    info: dict[str, Any] = {"forms": [], "images": 0, "tinyImages": 0, "hasScript": False, "metaRefresh": None}

    def add(u: dict[str, Any]) -> None:
        key = u["normalized"].lower().rstrip("/")
        if not key or key in ("http://", "https://"):
            return
        if key in found:
            existing = found[key]
            existing["flags"] = sorted(set(existing["flags"]) | set(u["flags"]))
            if not existing.get("text") and u.get("text"):
                existing["text"] = u["text"]
            if existing["source"] != u["source"]:
                existing["source"] = "both"
        else:
            found[key] = u

    if html:
        p = parse_html(html)
        info["hasScript"] = p.has_script
        info["metaRefresh"] = p.meta_refresh
        info["images"] = len(p.images)
        info["tinyImages"] = sum(1 for i in p.images if i["tiny"])
        for link in p.links:
            href = link["url"]
            if href.lower().startswith(("mailto:", "tel:", "#", "cid:")):
                continue
            add(analyze_url(href, link.get("text"), source="html"))
        for img in p.images:
            src = img["src"]
            if src.lower().startswith(("cid:", "data:")):
                continue
            u = analyze_url(src, None, source="image")
            if img["tiny"]:
                u["flags"] = sorted(set(u["flags"]) | {"tracking_pixel"})
            add(u)
        for f in p.forms:
            action = f.get("action") or ""
            entry = {"action": action[:500], "method": f.get("method"), "inputs": f.get("inputs", [])[:20]}
            entry["hasPassword"] = any(i["type"] == "password" for i in entry["inputs"])
            entry["external"] = action.lower().startswith(("http://", "https://"))
            info["forms"].append(entry)
            if action.lower().startswith(("http://", "https://")):
                u = analyze_url(action, None, source="form")
                u["flags"] = sorted(set(u["flags"]) | {"form_action"})
                add(u)
        if p.meta_refresh and "url=" in p.meta_refresh.lower():
            target = p.meta_refresh.split("=", 1)[1].strip().strip("'\"")
            u = analyze_url(target, None, source="meta")
            u["flags"] = sorted(set(u["flags"]) | {"meta_refresh"})
            add(u)
        # Also scan raw HTML text for URLs not in anchors (obfuscated / plain text)
        for m in URL_RE.finditer(re.sub(r"<[^>]+>", " ", html)):
            add(analyze_url(m.group(0), None, source="html"))
    if text:
        for m in URL_RE.finditer(text):
            add(analyze_url(m.group(0), None, source="text"))
    return list(found.values()), info
