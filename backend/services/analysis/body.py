"""Mail body heuristics: social engineering lexicon (FR + EN), hidden text, encoding tricks."""

from __future__ import annotations

import re
from functools import lru_cache
from html.parser import HTMLParser
from typing import Any

LEXICON: dict[str, tuple[str, ...]] = {
    "urgency": (
        # EN
        "urgent",
        "immediately",
        "as soon as possible",
        "asap",
        "right away",
        "within 24 hours",
        "final notice",
        "last warning",
        "act now",
        "expires today",
        "time sensitive",
        "deadline",
        "your account will be",
        "suspended",
        "locked",
        "deactivated",
        "terminated",
        "unusual activity",
        "unauthorized",
        "security alert",
        "action required",
        "verify your",
        "confirm your",
        # FR
        "urgent",
        "immédiatement",
        "dès que possible",
        "au plus vite",
        "sous 24h",
        "sous 24 heures",
        "dernier rappel",
        "dernier avertissement",
        "dernière relance",
        "expire aujourd'hui",
        "votre compte sera",
        "suspendu",
        "bloqué",
        "désactivé",
        "activité inhabituelle",
        "non autorisé",
        "alerte de sécurité",
        "action requise",
        "vérifiez votre",
        "confirmez votre",
        "mise à jour obligatoire",
        "régularisation",
        "mise en demeure",
    ),
    "financial": (
        "wire transfer",
        "bank transfer",
        "bank details",
        "iban",
        "swift",
        "account number",
        "routing number",
        "invoice",
        "overdue",
        "payment",
        "pay now",
        "outstanding balance",
        "purchase order",
        "remittance",
        "change of bank",
        "new bank account",
        "w-9",
        "ach",
        "virement",
        "virement bancaire",
        "coordonnées bancaires",
        "rib",
        "facture",
        "impayé",
        "paiement",
        "règlement",
        "solde",
        "bon de commande",
        "changement de rib",
        "nouveau rib",
        "relevé",
        "remboursement",
        "refund",
        "tax refund",
        "impôts",
        "taxe",
    ),
    "gift_card": (
        "gift card",
        "gift cards",
        "itunes",
        "google play card",
        "steam card",
        "amazon card",
        "scratch the card",
        "carte cadeau",
        "cartes cadeaux",
        "carte prépayée",
        "code de la carte",
        "transcash",
        "pcs",
        "neosurf",
        "paysafecard",
    ),
    "credentials": (
        "password",
        "passcode",
        "username",
        "login",
        "log in",
        "sign in",
        "credentials",
        "one-time code",
        "verification code",
        "2fa",
        "mfa",
        "authenticator",
        "otp",
        "pin",
        "mot de passe",
        "identifiant",
        "identifiants",
        "connexion",
        "se connecter",
        "code de vérification",
        "code à usage unique",
        "double authentification",
        "authentification",
    ),
    "authority": (
        "ceo",
        "cfo",
        "chief executive",
        "managing director",
        "president",
        "board",
        "legal department",
        "hr department",
        "it department",
        "helpdesk",
        "help desk",
        "system administrator",
        "microsoft",
        "office 365",
        "it support",
        "administrator",
        "police",
        "gendarmerie",
        "tribunal",
        "huissier",
        "direction générale",
        "directeur général",
        "pdg",
        "dg",
        "daf",
        "service juridique",
        "service informatique",
        "service rh",
        "ressources humaines",
        "administrateur",
    ),
    "secrecy": (
        "confidential",
        "do not share",
        "keep this between us",
        "discreet",
        "discretion",
        "private matter",
        "don't tell",
        "confidentiel",
        "ne pas divulguer",
        "entre nous",
        "discret",
        "discrétion",
        "ne parlez",
        "n'en parlez",
        "personnel",
    ),
    "availability": (
        "in a meeting",
        "can't talk",
        "cannot talk",
        "can't call",
        "unreachable",
        "on a call",
        "reply by email only",
        "text me",
        "send me your number",
        "are you available",
        "are you at your desk",
        "en réunion",
        "je ne peux pas",
        "injoignable",
        "répondez par mail",
        "envoyez-moi votre numéro",
        "êtes-vous disponible",
        "es-tu disponible",
        "tu es là",
        "êtes-vous au bureau",
    ),
    "delivery": (
        "package",
        "parcel",
        "shipment",
        "delivery",
        "tracking number",
        "customs fee",
        "undelivered",
        "colis",
        "livraison",
        "numéro de suivi",
        "frais de douane",
        "non livré",
        "en attente de livraison",
        "reprogrammer",
        "reschedule",
    ),
    "document_lure": (
        "shared a document",
        "shared a file",
        "view document",
        "open document",
        "review the attached",
        "see attached",
        "please find attached",
        "attached invoice",
        "attached file",
        "voicemail",
        "voice message",
        "fax received",
        "scanned document",
        "encrypted message",
        "secure message",
        "a partagé un document",
        "a partagé un fichier",
        "voir le document",
        "ouvrir le document",
        "ci-joint",
        "veuillez trouver ci-joint",
        "pièce jointe",
        "message vocal",
        "messagerie vocale",
        "document numérisé",
        "message sécurisé",
        "message chiffré",
    ),
}

ZERO_WIDTH = "​‌‍⁠﻿᠎⁡⁢⁣⁤"
RTLO = "‮‭‫‪⁦⁧⁨"
BASE64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{200,}={0,2}(?![A-Za-z0-9+/])")
HEX_BLOB_RE = re.compile(r"(?i)(?:\\x[0-9a-f]{2}){20,}|(?:%[0-9a-f]{2}){20,}|(?:&#x?[0-9a-f]+;){20,}")
HIDDEN_STYLE_RE = re.compile(
    r"(?i)(?:font-size\s*:\s*0(?:px|pt|em|%)?\b|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\b"
    r"|(?<![-\w])color\s*:\s*(?:#f{3,6}(?![0-9a-f])|white\b|transparent|rgba?\(\s*255\s*,\s*255\s*,\s*255)|max-height\s*:\s*0(?![.\d])|line-height\s*:\s*0(?![.\d])"
    r"|text-indent\s*:\s*-\d{3,}|position\s*:\s*absolute;?\s*(?:left|top)\s*:\s*-\d{3,})"
)


_VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
# Invisible characters mailers use to pad the preview line (U+034F combining grapheme joiner,
# zero-width spaces/joiners, NBSP, soft hyphen, braille blank): padding, not hidden text.
_INVISIBLE_RE = re.compile("[\u034f\u200b\u200c\u200d\u2060-\u2064\ufeff\u00ad\u2800\u00a0\u200e\u200f\u180e\u061c]+")
_STYLE_ATTR_RE = re.compile(r"""(?is)\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')""")
_SCRIPT_TAG_RE = re.compile(r"(?is)<script\b([^>]*)>")
_SCRIPT_TYPE_RE = re.compile(r"""(?is)\btype\s*=\s*["']?\s*([^"'\s>]+)""")


def _has_inline_hidden_style(html: str) -> bool:
    """Hiding CSS on an element's own style attribute. <style> blocks are ignored: responsive
    e-mail CSS (display:none for the mobile/desktop variant) is in almost every newsletter."""
    for m in _STYLE_ATTR_RE.finditer(html):
        if HIDDEN_STYLE_RE.search(m.group(1) or m.group(2) or ""):
            return True
    return False


def _has_executable_script(html: str) -> bool:
    """A <script> that can run. JSON / template payloads (Microsoft actionable messages,
    schema.org ld+json in notification mail) are data, not code."""
    for m in _SCRIPT_TAG_RE.finditer(html):
        tm = _SCRIPT_TYPE_RE.search(m.group(1) or "")
        if not tm:
            return True
        t = tm.group(1).lower()
        if "json" in t or "template" in t or t in ("text/plain", "text/html", "text/x-template", "text/x-handlebars-template"):
            continue
        return True
    return False


class _TextExtractor(HTMLParser):
    _SKIP = {"script", "style", "head", "title", "noscript", "template"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0
        self.hidden_chunks: list[str] = []
        # Open-element stack (tag, hidden?). A plain depth counter went out of sync on void
        # tags (<br>, <img>) and unclosed <p>/<td>, leaving the rest of the document "hidden":
        # every HTML mail with a white background scored image_only / hidden_text.
        self._stack: list[tuple[str, bool]] = []
        self._hidden = 0
        self.title: str | None = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        if t in self._SKIP:
            self._skip += 1
            if t == "title":
                self._in_title = True
        a = {k.lower(): (v or "") for k, v in attrs}
        style = a.get("style", "")
        hidden = bool(style and HIDDEN_STYLE_RE.search(style)) or "hidden" in a
        if t not in _VOID_TAGS:
            self._stack.append((t, hidden))
            if hidden:
                self._hidden += 1
        if t in ("br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "td", "table"):
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in self._SKIP and self._skip:
            self._skip -= 1
            if t == "title":
                self._in_title = False
        # pop to the matching open element; browsers implicitly close whatever was left open
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == t:
                for _, h in self._stack[i:]:
                    if h:
                        self._hidden -= 1
                del self._stack[i:]
                break
        if t in ("p", "div", "tr", "li", "h1", "h2", "h3", "h4", "table"):
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title = (self.title or "") + data
            return
        if self._skip:
            return
        if self._hidden:
            chunk = _INVISIBLE_RE.sub("", data).strip()
            if chunk:
                self.hidden_chunks.append(chunk[:200])
            return
        self.parts.append(data)


def html_to_text(html: str | None) -> tuple[str, list[str]]:
    """Return (visible text, hidden text chunks)."""
    if not html:
        return "", []
    p = _TextExtractor()
    try:
        p.feed(html)
        p.close()
    except Exception:  # noqa: BLE001
        pass
    text = "".join(p.parts)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    return text, p.hidden_chunks


@lru_cache(maxsize=2048)
def _term_pattern(term: str) -> re.Pattern[str]:
    # word-boundary-ish match, tolerant of accents already in the term
    return re.compile(r"(?<![a-z0-9à-ÿ])" + re.escape(term) + r"(?![a-z0-9à-ÿ])")


def _count_hits(text: str) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    low = text.lower()
    for cat, terms in LEXICON.items():
        found: list[str] = []
        for term in terms:
            # cheap C-speed substring precheck before the boundary regex
            if term in low and _term_pattern(term).search(low):
                found.append(term)
        if found:
            hits[cat] = sorted(set(found))
    return hits


def analyze_body(text: str | None, html: str | None, subject: str | None = None) -> dict[str, Any]:
    visible_html_text, hidden_chunks = html_to_text(html)
    plain = text or ""
    combined = "\n".join(s for s in (subject or "", plain, visible_html_text) if s)
    flags: list[str] = []

    hits = _count_hits(combined)
    for cat in hits:
        flags.append(f"lexicon_{cat}")
    # Note: the composite bec_pattern / credential_phishing_pattern flags are derived in
    # parsers/mail/common.py where sender legitimacy (auth results, reply-to, lookalikes)
    # is known - wording alone marks half of ordinary corporate mail.

    zw = sum(combined.count(c) for c in ZERO_WIDTH)
    # one or two zero-width characters are Outlook/Teams link-wrapping artefacts; salting uses dozens
    if zw >= 3:
        flags.append("zero_width_chars")
    if any(c in combined for c in RTLO):
        flags.append("bidi_override")
    if hidden_chunks:
        flags.append("hidden_text")
    if html and _has_inline_hidden_style(html):
        flags.append("hidden_style")
    b64 = len(BASE64_BLOB_RE.findall(combined)) + (len(BASE64_BLOB_RE.findall(html)) if html else 0)
    if b64:
        flags.append("base64_blob")
    if html and HEX_BLOB_RE.search(html):
        flags.append("obfuscated_html")
    if html and _has_executable_script(html):
        flags.append("html_script")
    if html and re.search(r"(?i)<form\b", html):
        flags.append("html_form")
    if html and re.search(r"(?i)<(?:iframe|object|embed)\b", html):
        flags.append("html_embed")
    # Extremely image-heavy body with almost no text (image-only phishing)
    if html:
        n_img = len(re.findall(r"(?i)<img\b", html))
        if n_img and len(visible_html_text.strip()) < 40:
            flags.append("image_only")
    # Mixed scripts (Cyrillic/Greek mixed with Latin) in visible text
    if re.search(r"[Ѐ-ӿͰ-Ͽ]", combined) and re.search(r"[A-Za-z]{3,}", combined):
        flags.append("mixed_script_text")
    words = re.findall(r"\w+", combined)
    return {
        "flags": sorted(set(flags)),
        "keywordHits": hits,
        "hiddenText": hidden_chunks[:10],
        "zeroWidthCount": zw,
        "base64Blobs": b64,
        "wordCount": len(words),
        "textPreview": (plain or visible_html_text)[:400],
        "visibleText": visible_html_text if not plain else None,
    }
