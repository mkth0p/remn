"""
Sublime Security MQL -> REMN mail rule converter.

Sublime's open rule corpus (MIT, https://github.com/sublime-security/sublime-rules) is the
largest curated set of e-mail detections in the open. Its Message Query Language is an
expression language over a message model (sender.*, subject.*, body.*, headers.*, attachments,
recipients.*). REMN's mail rows carry the same information for the structural part of that
model, so the structural subset translates exactly:

* comparisons (==, !=, =~, in, in~, not in, is null) on sender / subject / headers fields
* strings.icontains / ilike / istarts_with / iends_with / iequals, regex.icontains / imatch
* any(body.links, ...) / any(attachments, ...) / any(recipients.to, ...) / any(headers.reply_to, ...)
* length(body.links), length(attachments), length(recipients.*), length(headers.references)
* $org_domains / $org_vips (case settings), $high_trust_sender_root_domains, $free_file_hosts,
  $url_shorteners, $suspicious_tlds, $free_email_providers, file-extension lists (built-in lists)
* coalesce(x, false) on authentication results, type.inbound

What is NOT translated (the rule is reported as skipped, never silently weakened):
ml.* (NLU classifier, link analysis, logo detection), beta.*, file.explode / screenshots,
profile.by_sender (sender history - see REMN's sender baselining), network.whois, html.xpath,
headers.hops, all(), filter()/distinct() counts, field-to-field comparisons, unknown $lists.

Approximations are reported as warnings on the converted rule: body.current_thread.text is the
whole body text, several predicates inside one any() match independently, .href_url.path is
matched inside the full URL, confusable normalisation is not applied.
"""
from __future__ import annotations

import re
import warnings
from typing import Any

import yaml

from services.analysis.headers import WEBMAIL_HINTS
from services.analysis.urls import FILE_HOSTING, SHORTENERS, SUSPICIOUS_TLDS
from services.reference.brand_domains import BRAND_OWNED_DOMAINS
from services.reference.notification_senders import NOTIFICATION_SENDERS


class Unsupported(Exception):
    """An MQL construct REMN cannot express without changing what the rule detects."""


TRUE: dict[str, Any] = {"__true__": True}  # placeholder for "always true" sub-expressions (type.inbound, dropped guards)

SEVERITIES = {"informational": "info", "info": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}

FREE_SUBDOMAIN_HOSTS = sorted({
    "weebly.com", "wixsite.com", "github.io", "blogspot.com", "wordpress.com", "godaddysites.com", "webflow.io",
    "glitch.me", "netlify.app", "vercel.app", "pages.dev", "web.app", "firebaseapp.com", "herokuapp.com",
    "azurewebsites.net", "000webhostapp.com", "sites.google.com", "square.site", "mystrikingly.com", "carrd.co",
    "yolasite.com", "webnode.page", "jimdosite.com", "bravesites.com", "tumblr.com", "wixsite.com", "duckdns.org",
    "repl.co", "replit.app", "surge.sh", "onrender.com", "fly.dev", "workers.dev", "r2.dev", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "myshopify.com", "notion.site", "canva.site", "hubspotpagebuilder.com", "wufoo.com",
})
FREE_EMAIL_PROVIDERS = sorted(set(WEBMAIL_HINTS) | {
    "yahoo.fr", "yahoo.co.uk", "outlook.fr", "hotmail.fr", "live.com", "icloud.com", "me.com", "gmx.net", "gmx.de",
    "web.de", "mail.com", "yandex.ru", "aol.com", "protonmail.com", "proton.me", "tutanota.com", "zoho.com", "fastmail.com",
})
FILE_EXTENSIONS_MACROS = ["docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm"]
FILE_EXTENSIONS_COMMON_ARCHIVES = ["zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "iso", "img", "cab", "ace", "arj", "lz", "lzh", "z", "vhd", "vhdx"]
FILE_EXTENSIONS_EXECUTABLES = ["exe", "scr", "msi", "msp", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "ps1", "jar", "cpl", "dll", "lnk"]
FILE_TYPES_IMAGES = ["png", "jpg", "jpeg", "gif", "bmp", "webp", "svg", "tiff", "tif", "ico", "heic"]

# $list -> ("setting", name) for case settings, or ("inline", values)
LISTS: dict[str, tuple[str, Any]] = {
    "$org_domains": ("setting", "internal_domains"),
    "$org_vips": ("setting", "vip_names"),
    "$org_display_names": ("setting", "org_display_names"),
    "$tenant_domains": ("setting", "internal_domains"),
    "$recipient_emails": ("setting_domain", "internal_domains"),  # the org's mailboxes ~ any address at an internal domain
    "$tranco_10k": ("setting", "tranco_10k"),  # built-in reference list (backend/services/reference)
    "$tranco_1m": ("setting", "tranco_10k"),
    "$high_trust_sender_root_domains": ("inline", sorted(set(BRAND_OWNED_DOMAINS) | set(NOTIFICATION_SENDERS))),
    "$free_file_hosts": ("inline", sorted(FILE_HOSTING)),
    "$url_shorteners": ("inline", sorted(SHORTENERS)),
    "$suspicious_tlds": ("inline", sorted(t.lstrip(".") for t in SUSPICIOUS_TLDS)),
    "$free_email_providers": ("inline", FREE_EMAIL_PROVIDERS),
    "$free_subdomain_hosts": ("inline", FREE_SUBDOMAIN_HOSTS),
    "$file_extensions_macros": ("inline", FILE_EXTENSIONS_MACROS),
    "$file_extensions_common_archives": ("inline", FILE_EXTENSIONS_COMMON_ARCHIVES),
    "$file_extensions_executables": ("inline", FILE_EXTENSIONS_EXECUTABLES),
    "$file_types_images": ("inline", FILE_TYPES_IMAGES),
    "$file_extensions_images": ("inline", FILE_TYPES_IMAGES),
}
LIST_WARNINGS = {"$high_trust_sender_root_domains": "$high_trust_sender_root_domains approximated with REMN's built-in trusted/brand domain list",
                 "$tranco_1m": "$tranco_1m approximated with the bundled Tranco top 10k (more domains count as unpopular)",
                 "$recipient_emails": "$recipient_emails approximated as any address at an internal domain (case setting internal_domains)"}
# address column -> its domain column, for lists of addresses approximated by domains
_DOMAIN_OF = {"fromAddr": "fromDomain", "to.addr": "to.domain", "cc.addr": "cc.domain", "bcc.addr": "bcc.domain", "replyTo.addr": "replyTo.domain"}

# top-level message paths -> (kind, column). kinds: text | auth | regex_local (local part of an
# address column) | regex_sld (second-level label of a registrable) | suffix (TLD of a domain column)
PATHS: dict[str, tuple[str, str]] = {
    "sender.email.email": ("text", "fromAddr"),
    "sender.email.domain.domain": ("text", "fromDomain"),
    "sender.email.domain.root_domain": ("text", "fromRegistrable"),
    "sender.email.domain.sld": ("regex_sld", "fromRegistrable"),
    "sender.email.domain.tld": ("suffix", "fromRegistrable"),
    "sender.email.local_part": ("regex_local", "fromAddr"),
    "sender.display_name": ("text", "fromName"),
    "subject.subject": ("text", "subject"),
    "subject.base": ("text", "subject"),
    "body.current_thread.text": ("text", "bodyText"),
    "body.plain.raw": ("text", "bodyText"),
    "body.html.raw": ("text", "bodyHtml"),
    "body.html.inner_text": ("text", "visibleText"),
    "body.html.display_text": ("text", "visibleText"),
    "headers.return_path.email": ("text", "returnPath"),
    "headers.return_path.domain.domain": ("regex_domain", "returnPath"),
    "headers.return_path.domain.root_domain": ("regex_domain", "returnPath"),
    "headers.return_path.local_part": ("regex_local", "returnPath"),
    "headers.message_id": ("text", "messageId"),
    "headers.in_reply_to": ("text", "inReplyTo"),
    "headers.mailer": ("text", "xMailer"),
    "headers.auth_summary.dmarc.pass": ("auth", "dmarc"),
    "headers.auth_summary.spf.pass": ("auth", "spf"),
    "headers.auth_summary.dkim.pass": ("auth", "dkim"),
    "headers.auth_summary.spf.details.designator": ("text", "auth.spfDomain"),
    "headers.return_path.domain.tld": ("suffix", "returnPath"),
    "sender.email.domain.valid": ("valid", "fromDomain"),
    "mailbox.email.email": ("text", "toList"),
}
PATH_WARNINGS = {
    "body.current_thread.text": "body.current_thread.text matched against the whole body text (quoted threads included)",
    "subject.base": "subject.base matched against the full subject",
    "headers.return_path.domain.domain": "return-path domain matched by regex on the address",
    "headers.return_path.domain.root_domain": "return-path domain matched by regex on the address",
    "headers.auth_summary.spf.details.designator": "SPF designator = the smtp.mailfrom domain of the Authentication-Results header",
}
BOOL_PATHS: dict[str, dict[str, Any]] = {
    "subject.is_reply": {"subject|re": r"^\s*(re|aw|sv|antw|vs|r)\s*:"},
    "subject.is_forward": {"subject|re": r"^\s*(fw|fwd|tr|wg|i|doorst)\s*:"},
    "sender.email.domain.valid": {"fromDomain|exists": True},
}

# collections for any()/length(): (child prefix, {lambda path: (kind, column)})
COLLECTIONS: dict[str, tuple[str, dict[str, tuple[str, str]]]] = {
    "body.links": ("urls", {
        ".href_url.domain.root_domain": ("text", "urls.domain"), ".href_url.domain.domain": ("text", "urls.host"),
        ".href_url.domain.sld": ("regex_sld", "urls.domain"), ".href_url.domain.tld": ("suffix", "urls.domain"),
        ".href_url.url": ("text", "urls.url"), ".href_url.path": ("text", "urls.url"), ".href_url.query_params": ("text", "urls.url"),
        ".display_text": ("text", "urls.text"), ".display_url.url": ("text", "urls.text"),
        ".display_url.domain.root_domain": ("regex_domain", "urls.text"), ".display_url.domain.domain": ("regex_domain", "urls.text"),
        ".href_url.scheme": ("text", "urls.scheme"),
        ".href_url.domain.subdomain": ("text", "urls.subdomain"), ".href_url.fragment": ("text", "urls.fragment"),
        ".href_url.domain.valid": ("valid", "urls.domain"),
    }),
    "attachments": ("attachments", {
        ".file_extension": ("text", "attachments.ext"), ".file_type": ("text", "attachments.realExt"),
        ".file_name": ("text", "attachments.name"), ".content_type": ("text", "attachments.realMime"),
        ".size": ("num", "attachments.size"), ".sha256": ("text", "attachments.sha256"), ".md5": ("text", "attachments.md5"),
    }),
    "recipients.to": ("to", {".email.email": ("text", "to.addr"), ".email.domain.domain": ("text", "to.domain"),
                             ".email.domain.root_domain": ("text", "to.domain"), ".display_name": ("text", "to.name"), ".email.domain.valid": ("valid", "to.domain")}),
    "recipients.cc": ("cc", {".email.email": ("text", "cc.addr"), ".email.domain.domain": ("text", "cc.domain"),
                             ".email.domain.root_domain": ("text", "cc.domain"), ".display_name": ("text", "cc.name"), ".email.domain.valid": ("valid", "cc.domain")}),
    "recipients.bcc": ("bcc", {".email.email": ("text", "bcc.addr"), ".email.domain.domain": ("text", "bcc.domain"),
                               ".email.domain.root_domain": ("text", "bcc.domain"), ".display_name": ("text", "bcc.name"), ".email.domain.valid": ("valid", "bcc.domain")}),
    "headers.reply_to": ("replyTo", {".email.email": ("text", "replyTo.addr"), ".email.domain.domain": ("text", "replyTo.domain"),
                                     ".email.domain.root_domain": ("regex_domain", "replyTo.domain"), ".email.domain.valid": ("valid", "replyTo.domain")}),
}
COLLECTIONS["body.current_thread.links"] = COLLECTIONS["body.links"]
COLLECTIONS["headers.domains"] = ("headersText", {".root_domain": ("contains_in", "headersText"), ".domain": ("contains_in", "headersText"),
                                                  ".sld": ("contains_in", "headersText")})
COLLECTION_WARNINGS = {".href_url.path": ".href_url.path matched inside the full URL", "headers.domains": "headers.domains matched as text anywhere in the raw headers", ".email.domain.root_domain": "recipient root domain matched on the full recipient domain", ".href_url.query_params": "query parameters matched inside the full URL",
                       "body.current_thread.links": "body.current_thread.links = all links of the message",
                       ".email.domain.root_domain": "reply-to root domain matched on the reply-to domain"}
LENGTH_COUNTERS = {"body.links": "urlCount", "body.current_thread.links": "urlCount", "attachments": "attachmentCount",
                   "recipients.to": "recipientCount", "recipients.cc": "recipientCount", "recipients.bcc": "recipientCount"}
LENGTH_WARNINGS = {"recipients.to": "length(recipients.*) approximated with the total recipient count",
                   "recipients.cc": "length(recipients.*) approximated with the total recipient count",
                   "recipients.bcc": "length(recipients.*) approximated with the total recipient count"}

CMP_OPS = {"==": "eq", "=~": "eq", "==~": "eq", "!=": "ne", "!=~": "ne", "!~": "ne", "<": "lt", ">": "gt", "<=": "lte", ">=": "gte"}
ARITH = {"+", "-", "*", "/"}


# ---------------------------------------------------------------------------
# Tokenizer / parser
# ---------------------------------------------------------------------------
_TOKEN = re.compile(
    r"""(?P<ws>\s+|//[^\n]*|/\*.*?\*/)
      | (?P<str>"(?:[^"\\]|\\.|"")*"|'(?:[^'\\]|\\.|'')*')
      | (?P<num>\d+(?:\.\d+)?)
      | (?P<list>\$[A-Za-z_]\w*)
      | (?P<pdot>\.\.[A-Za-z_][\w.]*|\.\.(?![\w.]))
      | (?P<dot>\.[A-Za-z_][\w.]*|\.(?![\w.]))
      | (?P<ident>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)
      | (?P<op>==~|!=~|!~|=~|==|!=|<=|>=|<|>|~|\(|\)|\[|\]|,|=|\+|-|\*|/)
    """,
    re.X | re.S,
)


def tokenize(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    i = 0
    while i < len(text):
        m = _TOKEN.match(text, i)
        if not m:
            raise Unsupported(f"syntax near {text[i:i + 25]!r}")
        i = m.end()
        kind = m.lastgroup or ""
        if kind == "ws":
            continue
        out.append((kind, m.group(kind)))
    return out


def _unquote(s: str) -> str:
    """MQL strings keep backslashes literally (regexes are written as-is); the quote is escaped by
    doubling it ('I''ll') or with a backslash."""
    q = s[0]
    return s[1:-1].replace(q + q, q).replace("\\" + q, q)


class Parser:
    def __init__(self, text: str):
        self.toks = tokenize(text)
        self.i = 0

    def peek(self, k: int = 0) -> tuple[str, str] | None:
        j = self.i + k
        return self.toks[j] if j < len(self.toks) else None

    def take(self) -> tuple[str, str]:
        t = self.peek()
        if t is None:
            raise Unsupported("unexpected end of expression")
        self.i += 1
        return t

    def is_kw(self, word: str, k: int = 0) -> bool:
        t = self.peek(k)
        return bool(t) and t[0] == "ident" and t[1].lower() == word

    def parse(self) -> Any:
        node = self.parse_or()
        if self.peek() is not None:
            raise Unsupported(f"syntax near {self.peek()[1]!r}")
        return node

    def parse_arg(self) -> Any:
        # keyword argument (mode="aggressive") -> kept as a tagged node the translator can reject or ignore
        t, t2 = self.peek(), self.peek(1)
        if t and t[0] == "ident" and t2 and t2[0] == "op" and t2[1] == "=":
            self.take()
            self.take()
            return ("kwarg", t[1], self.parse_or())
        return self.parse_or()

    def parse_or(self) -> Any:
        parts = [self.parse_and()]
        while self.is_kw("or"):
            self.take()
            parts.append(self.parse_and())
        return parts[0] if len(parts) == 1 else ("or", parts)

    def parse_and(self) -> Any:
        parts = [self.parse_not()]
        while self.is_kw("and"):
            self.take()
            parts.append(self.parse_not())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def parse_not(self) -> Any:
        if self.is_kw("not"):
            self.take()
            return ("not", self.parse_not())
        t = self.peek()
        if t and t[0] == "num" and self.is_kw("of", 1):
            self.take()
            self.take()
            if not (self.peek() and self.peek()[0] == "op" and self.peek()[1] == "("):
                raise Unsupported("'N of' must be followed by a parenthesised list")
            self.take()
            items = [self.parse_or()]
            while self.peek() and self.peek()[0] == "op" and self.peek()[1] == ",":
                self.take()
                if self.peek() and self.peek()[0] == "op" and self.peek()[1] == ")":
                    break
                items.append(self.parse_or())
            if self.take()[1] != ")":
                raise Unsupported("unbalanced parentheses in 'N of'")
            return ("nof", int(float(t[1])), items)
        return self.parse_cmp()

    def parse_cmp(self) -> Any:
        left = self.parse_primary()
        t = self.peek()
        if t is None:
            return left
        if t[0] == "op" and t[1] in ARITH:
            raise Unsupported("arithmetic expression")
        if t[0] == "op" and t[1] in CMP_OPS:
            self.take()
            right = self.parse_primary()
            t2 = self.peek()
            if t2 and t2[0] == "op" and t2[1] in ARITH:
                raise Unsupported("arithmetic expression")
            node = ("cmp", t[1], left, right)
            if t2 and t2[0] == "op" and t2[1] in CMP_OPS:
                # chained comparison 0 < length(x) <= 8
                self.take()
                right2 = self.parse_primary()
                return ("and", [node, ("cmp", t2[1], right, right2)])
            return node
        if self.is_kw("is"):
            self.take()
            neg = False
            if self.is_kw("not"):
                self.take()
                neg = True
            if not self.is_kw("null"):
                raise Unsupported("'is' must be followed by null")
            self.take()
            return ("isnull", neg, left)
        neg = False
        if self.is_kw("not") and self.is_kw("in", 1):
            self.take()
            neg = True
        if self.is_kw("in"):
            self.take()
            ci = False
            if self.peek() and self.peek()[0] == "op" and self.peek()[1] == "~":
                self.take()
                ci = True
            return ("in", neg, ci, left, self.parse_primary())
        return left

    def parse_primary(self) -> Any:
        node = self.parse_atom()
        # postfix: .member on a call result / parenthesised value, [index] on a path
        while True:
            t = self.peek()
            if t and t[0] == "dot" and node[0] in ("call", "member", "index", "tuple"):
                self.take()
                node = ("member", node, t[1])
            elif t and t[0] == "op" and t[1] == "[":
                self.take()
                idx = self.parse_or()
                if self.take()[1] != "]":
                    raise Unsupported("unbalanced brackets")
                node = ("index", node, idx)
                t2 = self.peek()
                if t2 and t2[0] == "dot":
                    self.take()
                    node = ("member", node, t2[1])
            else:
                return node

    def parse_atom(self) -> Any:
        kind, val = self.take()
        if kind == "pdot":
            raise Unsupported("parent-scope path (..) inside a nested any()")
        if kind == "str":
            return ("str", _unquote(val))
        if kind == "num":
            return ("num", float(val) if "." in val else int(val))
        if kind == "list":
            return ("list", val)
        if kind == "dot":
            return ("path", val)
        if kind == "op" and val == "[":
            items: list[Any] = []
            if not (self.peek() and self.peek()[0] == "op" and self.peek()[1] == "]"):
                items.append(self.parse_or())
                while self.peek() and self.peek()[0] == "op" and self.peek()[1] == ",":
                    self.take()
                    if self.peek() and self.peek()[0] == "op" and self.peek()[1] == "]":
                        break
                    items.append(self.parse_or())
            if self.take()[1] != "]":
                raise Unsupported("unbalanced brackets")
            return ("array", items)
        if kind == "op" and val == "(":
            # parenthesised expression or a tuple literal ("a", "b")
            items = [self.parse_or()]
            while self.peek() and self.peek()[0] == "op" and self.peek()[1] == ",":
                self.take()
                if self.peek() and self.peek()[0] == "op" and self.peek()[1] == ")":
                    break  # trailing comma
                items.append(self.parse_or())
            if self.take()[1] != ")":
                raise Unsupported("unbalanced parentheses")
            return items[0] if len(items) == 1 else ("tuple", items)
        if kind == "ident":
            low = val.lower()
            if low in ("true", "false"):
                return ("bool", low == "true")
            if low == "null":
                return ("null",)
            if self.peek() and self.peek()[0] == "op" and self.peek()[1] == "(":
                self.take()
                args: list[Any] = []
                if not (self.peek() and self.peek()[0] == "op" and self.peek()[1] == ")"):
                    args.append(self.parse_arg())
                    while self.peek() and self.peek()[0] == "op" and self.peek()[1] == ",":
                        self.take()
                        if self.peek() and self.peek()[0] == "op" and self.peek()[1] == ")":
                            break
                        args.append(self.parse_arg())
                if self.take()[1] != ")":
                    raise Unsupported(f"unbalanced parentheses in {val}()")
                return ("call", val, args)
            return ("path", val)
        raise Unsupported(f"syntax near {val!r}")


# ---------------------------------------------------------------------------
# Translation
# ---------------------------------------------------------------------------
class Field:
    def __init__(self, kind: str, col: str):
        self.kind = kind
        self.col = col


def _is_true(c: dict[str, Any]) -> bool:
    return c is TRUE or c == TRUE


class Translator:
    def __init__(self) -> None:
        self.warnings: list[str] = []
        self.scope: dict[str, tuple[str, str]] | None = None  # lambda element paths

    def warn(self, msg: str) -> None:
        if msg not in self.warnings:
            self.warnings.append(msg)

    # ---- fields ---------------------------------------------------------
    PROFILE_MEMBERS = {".prevalence": ("text", "senderPrevalence"), ".solicited": ("bool", "senderSolicited"),
                       ".days_known": ("num", "senderDaysKnown"), ".days_since_first_seen": ("num", "senderDaysKnown"),
                       ".first_seen": ("num", "senderFirstSeen"), ".message_count": ("num", "senderPriorCount")}

    def field(self, node: Any) -> Field:
        if node[0] == "member":
            base = node[1]
            while base[0] in ("member", "index"):
                base = base[1]
            # profile.by_sender().prevalence / .solicited / .days_known -> REMN's sender-baseline columns
            if base[0] == "call" and base[1].lower() in ("profile.by_sender", "profile.by_sender_email") and node[1][0] == "call":
                member = self.PROFILE_MEMBERS.get(node[2])
                if member:
                    self.warn("profile.by_sender() uses REMN's sender baseline (run 'baseline senders' first)")
                    return Field(member[0], member[1])
                raise Unsupported(f"profile.by_sender(){node[2]}")
            raise Unsupported(f"{base[1]}() result field" if base[0] == "call" else f"member access on {base[0]}")
        if node[0] == "index":
            raise Unsupported("indexed access ([0])")
        if node[0] == "call":
            raise Unsupported(f"{node[1]}() as a field")
        if node[0] != "path":
            raise Unsupported(f"expected a field, got {node[0]}")
        p = node[1]
        if p == ".":
            if self.scope is None or "." not in self.scope:
                raise Unsupported("lone '.' outside an array any()")
            kind, col = self.scope["."]
            return Field(kind, col)
        if p.startswith("."):
            if self.scope is None:
                raise Unsupported(f"element path {p} outside any()")
            if p in self.scope:
                if p in COLLECTION_WARNINGS:
                    self.warn(COLLECTION_WARNINGS[p])
                kind, col = self.scope[p]
                return Field(kind, col)
            raise Unsupported(f"element field {p}")
        if p in PATHS:
            if p in PATH_WARNINGS:
                self.warn(PATH_WARNINGS[p])
            kind, col = PATHS[p]
            return Field(kind, col)
        raise Unsupported(f"field {p}")

    def _values(self, node: Any) -> list[Any]:
        if node[0] in ("call", "member", "index"):
            base = node
            while base[0] in ("member", "index"):
                base = base[1]
            raise Unsupported(f"{base[1]}() as a value" if base[0] == "call" else "computed value")
        if node[0] == "kwarg":
            raise Unsupported(f"keyword argument {node[1]}")
        if node[0] == "str":
            return [node[1]]
        if node[0] == "num":
            return [node[1]]
        if node[0] == "tuple":
            return [v for it in node[1] for v in self._values(it)]
        if node[0] == "list":
            kind, payload = self._list(node[1])
            if kind != "inline":
                raise Unsupported(f"{node[1]} cannot be used here")
            return list(payload)
        raise Unsupported(f"unsupported value {node[0]}")

    def _list(self, name: str) -> tuple[str, Any]:
        if name not in LISTS:
            raise Unsupported(f"unknown list {name}")
        if name in LIST_WARNINGS:
            self.warn(LIST_WARNINGS[name])
        return LISTS[name]

    def cond(self, f: Field, op: str, value: Any) -> dict[str, Any]:
        """One DSL condition on a mapped field, handling the derived kinds."""
        vals = value if isinstance(value, list) else [value]
        if f.kind == "auth":
            # pass-boolean of an authentication mechanism
            if op in ("eq", "ne"):
                v = vals[0]
                want_pass = bool(v) if isinstance(v, bool) else str(v).lower() in ("true", "pass")
                if (op == "eq") == want_pass:
                    return {f"auth.{f.col}": "pass"}
                return {f"auth.{f.col}|ne": "pass"}
            if op == "exists":
                return {f"auth.{f.col}|exists": vals[0]}
            raise Unsupported(f"{op} on an authentication result")
        if f.kind == "num":
            if op not in ("eq", "ne", "lt", "gt", "lte", "gte", "in", "nin"):
                raise Unsupported(f"{op} on a numeric field")
            return {f"{f.col}|{op}" if op != "eq" else f.col: value}
        if f.kind == "bool":
            if op not in ("eq", "ne"):
                raise Unsupported(f"{op} on a boolean field")
            v = vals[0]
            truth = bool(v) if isinstance(v, bool) else str(v).lower() in ("true", "1", "yes")
            return {f.col: truth if op == "eq" else (not truth)}
        if f.kind == "valid":
            if op not in ("eq", "ne"):
                raise Unsupported(f"{op} on domain.valid")
            v = vals[0]
            truth = bool(v) if isinstance(v, bool) else str(v).lower() in ("true", "1", "yes")
            return {f"{f.col}|exists": truth if op == "eq" else (not truth)}
        if f.kind == "contains_in":
            # a value list matched as substrings of a text blob (headers.domains -> raw headers)
            m = {"eq": "contains", "in": "contains_any", "ne": "not_contains", "nin": "not_contains",
                 "contains": "contains", "contains_any": "contains_any", "startswith": "contains", "endswith": "contains"}
            if op not in m:
                raise Unsupported(f"{op} on headers.domains")
            strs = [str(v) for v in vals]
            key = f"{f.col}|{m[op]}"
            return {key: strs if len(strs) > 1 else strs[0]}
        if f.kind == "regex_local":
            return self._derived_regex(f.col, op, vals, lambda s: r"^" + re.escape(s) + r"@")
        if f.kind == "regex_sld":
            return self._derived_regex(f.col, op, vals, lambda s: r"^" + re.escape(s) + r"\.")
        if f.kind == "regex_domain":
            return self._derived_regex(f.col, op, vals, lambda s: r"(^|@|\.)" + re.escape(s) + r"$")
        if f.kind == "suffix":
            if op in ("eq", "in"):
                s = ["." + str(v).lstrip(".") for v in vals]
                return {f"{f.col}|endswith": s if len(s) > 1 else s[0]}
            if op in ("ne", "nin"):
                s = ["." + str(v).lstrip(".") for v in vals]
                return {f"{f.col}|not_endswith": s if len(s) > 1 else s[0]}
            raise Unsupported(f"{op} on a TLD")
        # plain text column
        if op == "eq" and len(vals) > 1:
            op = "in"
        if op == "ne" and len(vals) > 1:
            op = "nin"
        key = f.col if op == "eq" else f"{f.col}|{op}"
        return {key: vals if len(vals) > 1 or op in ("in", "nin", "contains_any", "contains_all") else vals[0]}

    def _derived_regex(self, col: str, op: str, vals: list[Any], build) -> dict[str, Any]:
        """Match a part of an address/domain column (local part, second-level label, domain) by regex."""
        kind = {"^": "local"}  # placeholder to keep signature; the builders below are chosen by build()
        if op in ("eq", "in"):
            pats = [build(str(v)) for v in vals]
            return {f"{col}|re": pats if len(pats) > 1 else pats[0]}
        if op in ("ne", "nin"):
            pats = [build(str(v)) for v in vals]
            return {f"{col}|not_re": pats if len(pats) > 1 else pats[0]}
        if op in ("contains", "contains_any"):
            return {f"{col}|contains_any" if len(vals) > 1 else f"{col}|contains": vals if len(vals) > 1 else vals[0]}
        if op in ("startswith", "endswith"):
            # build() yields the exact-match regex "<prefix>ESC<suffix>": keep only the relevant anchor
            pats = []
            for v in vals:
                exact = build(str(v))
                esc = re.escape(str(v))
                head, tail = exact.split(esc, 1)
                pats.append(head + esc if op == "startswith" else esc + tail)
            return {f"{col}|re": pats if len(pats) > 1 else pats[0]}
        if op == "re":
            self.warn(f"regex on a derived address part applied to the whole {col}")
            return {f"{col}|re": vals if len(vals) > 1 else vals[0]}
        raise Unsupported(f"{op} on a derived address part")

    # ---- expressions ----------------------------------------------------
    def expr(self, node: Any) -> dict[str, Any]:
        t = node[0]
        if t == "and":
            parts = [self.expr(n) for n in node[1]]
            parts = [p for p in parts if not _is_true(p)]
            return _all_of(parts) if parts else TRUE
        if t == "or":
            parts = [self.expr(n) for n in node[1]]
            if any(_is_true(p) for p in parts):
                raise Unsupported("an always-true alternative (type.inbound / dropped guard) inside an OR")
            return _any_of(parts)
        if t == "not":
            inner = self.expr(node[1])
            if _is_true(inner):
                raise Unsupported("negation of an always-true expression")
            return {"not": inner}
        if t == "nof":
            _, n, items = node
            parts = [self.expr(x) for x in items]
            if n == 1:
                return _any_of(parts)
            if n >= len(parts):
                return _all_of(parts)
            raise Unsupported(f"{n} of {len(parts)} (only 1 of / all of translate exactly)")
        if t == "cmp":
            return self.compare(node)
        if t == "in":
            return self.membership(node)
        if t == "isnull":
            _, neg, left = node
            f = self.field(left)
            if f.kind == "auth":
                return {f"auth.{f.col}|exists": neg}
            return {f"{f.col}|exists": neg}
        if t == "call":
            return self.call(node)
        if t in ("member", "index"):
            f = self.field(node)  # raises Unsupported unless it is a mapped profile member
            if f.kind == "bool":
                return {f.col: True}
            return {f"{f.col}|exists": True}
        if t == "path":
            return self.bool_path(node)
        if t == "bool":
            if node[1]:
                return TRUE
            raise Unsupported("rule disabled upstream (source is 'false')")
        raise Unsupported(f"expression {t}")

    def bool_path(self, node: Any) -> dict[str, Any]:
        p = node[1]
        if p == "type.inbound":
            return TRUE
        if p == "type.outbound":
            raise Unsupported("type.outbound")
        if p in BOOL_PATHS:
            return dict(BOOL_PATHS[p])
        f = self.field(node)
        if f.kind == "auth":
            return {f"auth.{f.col}": "pass"}
        return {f"{f.col}|exists": True}

    def compare(self, node: Any) -> dict[str, Any]:
        _, op, left, right = node
        if left[0] in ("str", "num", "bool", "tuple") and right[0] not in ("str", "num", "bool", "tuple"):
            left, right = right, left
            op = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}.get(op, op)
        if left[0] == "call" and left[1].lower() == "length":
            return self.length_cmp(left, op, right)
        if left[0] == "call" and left[1].lower() in ("strings.ilevenshtein", "strings.levenshtein"):
            if len(left[2]) != 2 or right[0] != "num":
                raise Unsupported("levenshtein form")
            f = self._target(left[2][0])
            needle = self._values(left[2][1])[0]
            n = int(right[1])
            if op in ("<=", "=="):
                dist = n
            elif op == "<":
                dist = n - 1
            else:
                raise Unsupported(f"levenshtein {op}")
            if f.kind != "text":
                raise Unsupported("levenshtein on a derived field")
            return {f"{f.col}|levenshtein": [str(needle), dist]}
        if left[0] == "call" and left[1].lower() == "coalesce":
            return self.compare(("cmp", op, left[2][0], right)) if self._coalesce_default(left) is False else self.compare(("cmp", op, left[2][0], right))
        if right[0] == "path" or right[0] == "call":
            raise Unsupported("field-to-field comparison")
        f = self.field(left)
        if right[0] == "bool":
            return self.cond(f, CMP_OPS[op], right[1])
        if right[0] == "null":
            return {f"{f.col}|exists": op in ("!=", "!=~")}
        vals = self._values(right)
        return self.cond(f, CMP_OPS[op], vals if len(vals) > 1 else vals[0])

    def _coalesce_default(self, node: Any) -> Any:
        args = node[2]
        if len(args) != 2 or args[1][0] not in ("bool", "str", "num"):
            raise Unsupported("coalesce() form")
        return args[1][1]

    def membership(self, node: Any) -> dict[str, Any]:
        _, neg, _ci, left, right = node
        if left[0] == "str":
            what = right[1] if isinstance(right[1], str) else "a computed list"
            raise Unsupported(f"string membership in {what}")
        f = self.field(left)
        if right[0] == "list":
            kind, payload = self._list(right[1])
            if kind == "setting_domain":
                dom_col = _DOMAIN_OF.get(f.col) if f.kind == "text" else None
                if not dom_col:
                    raise Unsupported(f"{right[1]} on {f.col}")
                return {f"{dom_col}|{'nin_setting' if neg else 'in_setting'}": payload}
            if kind == "setting":
                if f.kind == "text" and f.col == "fromName" and payload in ("vip_names", "org_display_names"):
                    f = Field("text", "fromNameNorm")
                if f.kind != "text":
                    raise Unsupported(f"{right[1]} on a derived field")
                return {f"{f.col}|{'nin_setting' if neg else 'in_setting'}": payload}
            return self.cond(f, "nin" if neg else "in", list(payload))
        vals = self._values(right)
        return self.cond(f, "nin" if neg else "in", vals)

    def length_cmp(self, call: Any, op: str, right: Any) -> dict[str, Any]:
        args = call[2]
        if len(args) != 1 or right[0] != "num":
            raise Unsupported("length() form")
        n = right[1]
        target = args[0]
        dsl = CMP_OPS[op]
        if target[0] == "call" and target[1].lower() == "filter" and len(target[2]) == 2:
            # length(filter(coll, p)) == 0  <=>  not any(coll, p);  > 0  <=>  any(coll, p)
            anyc = self.any_call(list(target[2]))
            if (dsl, n) in (("eq", 0), ("lt", 1), ("lte", 0)):
                return {"not": anyc}
            if (dsl, n) in (("gt", 0), ("gte", 1), ("ne", 0)):
                return anyc
            raise Unsupported("length(filter(...)) bound other than 0")
        if target[0] == "call":
            raise Unsupported(f"length({target[1]}(...))")
        if target[0] != "path":
            raise Unsupported("length() of a non-field")
        p = target[1]
        if p in LENGTH_COUNTERS:
            if p in LENGTH_WARNINGS:
                self.warn(LENGTH_WARNINGS[p])
            col = LENGTH_COUNTERS[p]
            return {col if dsl == "eq" else f"{col}|{dsl}": n}
        if p == "headers.references":
            if (dsl, n) in (("eq", 0), ("lt", 1), ("lte", 0)):
                return {"references|exists": False}
            if (dsl, n) in (("gt", 0), ("gte", 1), ("ne", 0)):
                return {"references|exists": True}
            raise Unsupported("length(headers.references) bound")
        if p in PATHS and PATHS[p][0] == "text":
            sym = {"eq": "=", "ne": "!=", "lt": "<", "gt": ">", "lte": "<=", "gte": ">="}[dsl]
            if p in PATH_WARNINGS:
                self.warn(PATH_WARNINGS[p])
            return {f"{PATHS[p][1]}|length": f"{sym} {int(n)}"}
        if p == "headers.reply_to":
            if (dsl, n) in (("eq", 0), ("lt", 1), ("lte", 0)):
                return {"replyTo.addr|exists": False}
            if (dsl, n) in (("gt", 0), ("gte", 1), ("ne", 0)):
                return {"replyTo.addr|exists": True}
            raise Unsupported("length(headers.reply_to) bound")
        if p == "body.previous_threads":
            self.warn("length(body.previous_threads) approximated with the In-Reply-To header")
            if (dsl, n) in (("eq", 0), ("lt", 1), ("lte", 0)):
                return {"inReplyTo|exists": False}
            if (dsl, n) in (("gt", 0), ("gte", 1), ("ne", 0)):
                return {"inReplyTo|exists": True}
            raise Unsupported("length(body.previous_threads) bound")
        if p in PATHS and PATHS[p][0] == "text":
            col = PATHS[p][1]
            if (dsl, n) in (("eq", 0), ("lt", 1), ("lte", 0)):
                return {f"{col}|empty": True}
            if (dsl, n) in (("gt", 0), ("gte", 1), ("ne", 0)):
                return {f"{col}|exists": True}
            if dsl in ("lt", "lte") and col in ("bodyText", "bodyHtml", "visibleText", "subject"):
                self.warn(f"length({p}) < {n} upper-bound guard dropped")
                return TRUE
            raise Unsupported(f"length({p}) {op} {n}")
        raise Unsupported(f"length({p})")

    def call(self, node: Any) -> dict[str, Any]:
        _, name, args = node
        low = name.lower()
        if any(a[0] == "kwarg" for a in args):
            raise Unsupported(f"{name}() keyword arguments")
        if low == "any":
            return self.any_call(args)
        if low == "all":
            return self.all_call(args)
        if low == "filter":
            raise Unsupported("filter() as a boolean")
        if low == "coalesce":
            default = self._coalesce_default(node)
            inner = self.expr(args[0])
            if default is False:
                return inner
            if default is True:
                f = self.field(args[0]) if args[0][0] == "path" else None
                if f is None:
                    raise Unsupported("coalesce(expr, true)")
                return _any_of([{f"{'auth.' + f.col if f.kind == 'auth' else f.col}|exists": False}, inner])
            raise Unsupported("coalesce() default")
        if low in ("strings.replace_confusables", "strings.lower", "strings.upper", "strings.strip"):
            raise Unsupported(f"{name}() as a boolean")
        if low.startswith(("strings.", "regex.")):
            return self.string_fn(low, args)
        raise Unsupported(f"{name}()")

    def any_call(self, args: list[Any]) -> dict[str, Any]:
        # any(filter(coll, p1), p2) == any(coll, p1 and p2)
        while len(args) == 2 and args[0][0] == "call" and args[0][1].lower() == "filter" and len(args[0][2]) == 2:
            inner_coll, p1 = args[0][2]
            args = [inner_coll, ("and", [p1, args[1]])]
        if len(args) == 2 and args[0][0] == "array":
            # any([subject.subject, body.current_thread.text], regex.icontains(., 'x')): the predicate
            # applied to each listed field, OR-ed
            if self.scope is not None:
                raise Unsupported("nested any()")
            alts: list[dict[str, Any]] = []
            for item in args[0][1]:
                f = self.field(item)
                self.scope = {".": (f.kind, f.col)}
                try:
                    alts.append(self.expr(args[1]))
                finally:
                    self.scope = None
            return _any_of(alts)
        if len(args) == 2 and args[0][0] in ("call", "member", "index"):
            base = args[0]
            while base[0] in ("member", "index"):
                base = base[1]
            raise Unsupported(f"any({base[1]}(...))" if base[0] == "call" else "any() over a computed list")
        if len(args) != 2 or args[0][0] != "path":
            raise Unsupported("any() form")
        coll = args[0][1]
        if coll not in COLLECTIONS:
            raise Unsupported(f"any({coll})")
        if coll in COLLECTION_WARNINGS:
            self.warn(COLLECTION_WARNINGS[coll])
        prefix, scope = COLLECTIONS[coll]
        if self.scope is not None:
            raise Unsupported("nested any()")
        self.scope = scope
        try:
            inner = self.expr(args[1])
        finally:
            self.scope = None
        if _is_true(inner):
            return {f"{prefix + '.' if prefix in ('urls', 'attachments') else prefix + '.'}{'url' if prefix == 'urls' else 'name' if prefix == 'attachments' else 'addr'}|exists": True}
        if len(_leaf_keys(inner)) > 1:
            self.warn(f"any({coll}) with several predicates: each predicate matches independently")
        return inner

    NEGATIVE_OPS = {"ne", "nin", "not_contains", "not_startswith", "not_endswith", "not_re", "nin_setting"}

    def all_call(self, args: list[Any]) -> dict[str, Any]:
        """all(coll, P) is exact only when P is negative: the DSL's negative child operators mean
        "no element matches the positive form", i.e. every element satisfies the negation."""
        if len(args) != 2 or args[0][0] != "path" or args[0][1] not in COLLECTIONS:
            raise Unsupported("all() form")
        pred = args[1]
        if pred[0] == "not":
            pred = pred[1]
            cond = self.any_call([args[0], pred])
            leaves = _leaf_keys(cond)
            if len(leaves) != 1 or any(k in cond for k in ("any_of", "not")):
                raise Unsupported("all(not ...) with a compound predicate")
            key, val = next(iter(cond.items()))
            field, _, op = key.partition("|")
            neg = {"eq": "ne", "": "ne", "in": "nin", "contains": "not_contains", "contains_any": "not_contains", "startswith": "not_startswith",
                   "endswith": "not_endswith", "re": "not_re", "in_setting": "nin_setting",
                   "contains_cs": "not_contains", "startswith_cs": "not_startswith", "endswith_cs": "not_endswith"}.get(op)
            if op.endswith("_cs"):
                self.warn("all(not strings.contains(...)) matched case-insensitively (no negated case-sensitive operator)")
            if op == "exists":
                return {f"{field}|exists": not bool(val)}
            if neg is None:
                raise Unsupported(f"all(not {op})")
            return {f"{field}|{neg}": val}
        cond = self.any_call([args[0], pred])
        leaves = _leaf_keys(cond)
        if len(leaves) == 1 and leaves[0].partition("|")[2] in self.NEGATIVE_OPS:
            return cond
        raise Unsupported("all() with a positive predicate")

    def _target(self, node: Any) -> Field:
        # unwrap normalisation wrappers that do not change what is matched
        while node[0] == "call" and node[1].lower() in ("strings.replace_confusables", "strings.lower", "strings.upper", "strings.strip", "strings.trim"):
            if node[1].lower() == "strings.replace_confusables":
                self.warn("confusable-character normalisation not applied")
            node = node[2][0]
        if node[0] == "call" and node[1].lower() == "coalesce":
            node = node[2][0]
        return self.field(node)

    def string_fn(self, name: str, args: list[Any]) -> dict[str, Any]:
        if len(args) < 2:
            raise Unsupported(f"{name}() needs a field and a value")
        f = self._target(args[0])
        needles: list[Any] = []
        for a in args[1:]:
            needles.extend(self._values(a))
        strs = [str(n) for n in needles]
        # strings.contains / starts_with / ends_with are case-sensitive in MQL. On a plain text column the
        # DSL's *_cs operators keep that exactly ("hTTPs://" must not match every https link); derived
        # kinds (local part, TLD, headers blob) only have case-insensitive matching, so they fall back.
        cs = f.kind == "text" and name in ("strings.contains", "strings.starts_with", "strings.ends_with")
        if name in ("strings.contains", "strings.starts_with", "strings.ends_with", "strings.like", "regex.contains", "regex.match") and not cs:
            self.warn(f"{name} is case-sensitive in MQL; REMN matches case-insensitively")
        if name in ("strings.icontains", "strings.contains"):
            op = "contains_cs" if cs else ("contains_any" if len(strs) > 1 else "contains")
            return self.cond(f, op, strs if len(strs) > 1 else strs[0])
        if name in ("strings.istarts_with", "strings.starts_with"):
            return self.cond(f, "startswith_cs" if cs else "startswith", strs if len(strs) > 1 else strs[0])
        if name in ("strings.iends_with", "strings.ends_with"):
            return self.cond(f, "endswith_cs" if cs else "endswith", strs if len(strs) > 1 else strs[0])
        if name in ("strings.iequals", "strings.equals"):
            return self.cond(f, "eq", strs if len(strs) > 1 else strs[0])
        if name in ("strings.ilike", "strings.like"):
            parsed = [_glob(s) for s in strs]
            ops = {op for op, _ in parsed}
            if len(ops) == 1:
                op = ops.pop()
                vals = [v for _, v in parsed]
                if op == "contains":
                    op = "contains_any" if len(vals) > 1 else "contains"
                return self.cond(f, op, vals if len(vals) > 1 else vals[0])
            return _any_of([self.cond(f, op, v) for op, v in parsed])
        if name in ("regex.icontains", "regex.contains", "regex.imatch", "regex.match"):
            pats = strs
            if name.endswith("match"):
                pats = [f"^(?:{p})$" for p in pats]
            for p in pats:
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")  # "possible nested set" on Sublime's [[...]] classes
                        re.compile(p)
                except re.error as exc:
                    raise Unsupported(f"regex {p[:40]!r}: {exc}") from None
            return self.cond(f, "re", pats if len(pats) > 1 else pats[0])
        raise Unsupported(f"{name}()")


def _glob(pattern: str) -> tuple[str, str]:
    """MQL ilike: * = any string, ? = one char (like Sigma bare strings)."""
    core = pattern
    lead = trail = False
    while core.startswith("*"):
        core = core[1:]
        lead = True
    while core.endswith("*") and not core.endswith("\\*"):
        core = core[:-1]
        trail = True
    if "*" in core or "?" in core:
        rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in core)
        return "re", ("" if lead else "^") + rx + ("" if trail else "$")
    if lead and trail:
        return "contains", core
    if trail:
        return "startswith", core
    if lead:
        return "endswith", core
    return "eq", core


_COMBINATOR_RE = re.compile(r"^(any_of|all_of)(_\d+)?$")


def _leaf_keys(cond: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for k, v in cond.items():
        if _COMBINATOR_RE.match(k):
            for alt in v if isinstance(v, list) else [v]:
                out.extend(_leaf_keys(alt))
        elif k == "not":
            out.extend(_leaf_keys(v))
        else:
            out.append(k)
    return out


def _all_of(parts: list[dict[str, Any]]) -> dict[str, Any]:
    flat: list[dict[str, Any]] = []
    for p in parts:
        if not p or _is_true(p):
            continue
        if len(p) == 1 and "all_of" in p:
            flat.extend(p["all_of"])
        else:
            flat.append(p)
    if not flat:
        return TRUE
    if len(flat) == 1:
        return flat[0]
    merged: dict[str, Any] = {}
    for p in flat:
        for k, v in p.items():
            key = k
            if _COMBINATOR_RE.match(k):
                base = "_".join(k.split("_")[:2])
                n = 2
                while key in merged:
                    key = f"{base}_{n}"
                    n += 1
            elif key in merged:
                return {"all_of": flat}
            merged[key] = v
    return merged


def _any_of(parts: list[dict[str, Any]]) -> dict[str, Any]:
    flat: list[dict[str, Any]] = []
    for p in parts:
        if not p:
            continue
        if len(p) == 1 and "any_of" in p:
            flat.extend(p["any_of"])
        else:
            flat.append(p)
    if not flat:
        raise Unsupported("empty OR")
    return flat[0] if len(flat) == 1 else {"any_of": flat}


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------
def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60] or "rule"


def _kebab(items: Any) -> list[str]:
    return [re.sub(r"[^a-z0-9]+", "-", str(x).lower()).strip("-") for x in (items or []) if str(x).strip()]


def convert_rule(doc: dict[str, Any]) -> dict[str, Any]:
    name = str(doc.get("name") or doc.get("title") or "").strip()
    rid = str(doc.get("id") or "").strip()
    out_id = f"sublime-{rid or _slug(name)}"
    try:
        if not name:
            raise Unsupported("no name")
        if str(doc.get("type") or "rule").lower() not in ("rule", "query"):
            raise Unsupported(f"type {doc.get('type')}")
        src = doc.get("source")
        if not isinstance(src, str) or not src.strip():
            raise Unsupported("no MQL source")
        tr = Translator()
        where = tr.expr(Parser(src).parse())
        if _is_true(where):
            raise Unsupported("rule matches every message")
        _strip_true(where)
        rule: dict[str, Any] = {
            "id": out_id,
            "title": name,
            "description": " ".join(str(doc.get("description") or "").split()) or None,
            "severity": SEVERITIES.get(str(doc.get("severity") or "medium").lower(), "medium"),
            "source": "mails",
            "tags": ["sublime"] + _kebab(doc.get("attack_types")) + _kebab(doc.get("tactics_and_techniques")),
            "references": [str(r) for r in (doc.get("references") or [])] or None,
            "where": where,
            "sublime": {k: v for k, v in {
                "id": rid or None, "attack_types": doc.get("attack_types"), "tactics_and_techniques": doc.get("tactics_and_techniques"),
                "detection_methods": doc.get("detection_methods"), "source": src.strip(),
            }.items() if v},
        }
        rule = {k: v for k, v in rule.items() if v is not None}
        text = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=120)
        return {"ok": True, "id": out_id, "title": name, "rule": rule, "yaml": text, "warnings": tr.warnings}
    except Unsupported as exc:
        return {"ok": False, "id": out_id, "title": name or "(unnamed)", "error": str(exc), "warnings": []}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "id": out_id, "title": name or "(unnamed)", "error": f"{type(exc).__name__}: {exc}"[:200], "warnings": []}


def _strip_true(cond: dict[str, Any]) -> None:
    """Remove leftover TRUE placeholders from all_of lists (they are the identity of AND)."""
    for k, v in list(cond.items()):
        if _COMBINATOR_RE.match(k) and isinstance(v, list):
            v[:] = [x for x in v if not _is_true(x)]
            for x in v:
                _strip_true(x)
        elif k == "not" and isinstance(v, dict):
            _strip_true(v)


def convert_text(text: str, source_name: str = "") -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except yaml.YAMLError as exc:
        return [{"ok": False, "id": source_name or "?", "title": source_name or "(invalid yaml)", "error": f"yaml: {str(exc)[:160]}", "warnings": []}]
    for doc in docs:
        res = convert_rule(doc)
        if source_name:
            res["file"] = source_name
        out.append(res)
    return out
