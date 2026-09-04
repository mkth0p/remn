"""
Lookalike / spoofed domain detection.

Works fully offline: tldextract runs on its bundled public-suffix snapshot
(no network fetch), confusable_homoglyphs on its bundled Unicode tables.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Any, Iterable

import idna
import tldextract
from confusable_homoglyphs import confusables

_extract = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

from services.reference.brand_domains import BRAND_OWNED_DOMAINS, BRAND_TLDS  # noqa: E402

# Small default brand list: registrable second-level labels that phishing
# campaigns imitate most often. The UI settings can extend it.
DEFAULT_BRANDS: tuple[str, ...] = (
    "microsoft", "office365", "office", "outlook", "onedrive", "sharepoint", "live", "hotmail",
    "google", "gmail", "apple", "icloud", "amazon", "paypal", "docusign", "dropbox", "adobe",
    "dhl", "ups", "fedex", "chronopost", "laposte", "colissimo", "netflix", "facebook",
    "instagram", "linkedin", "whatsapp", "orange", "sfr", "free", "bouygues", "ameli",
    "impots", "gouv", "caf", "edf", "engie", "bnpparibas", "societegenerale", "creditagricole",
    "lcl", "caisse-epargne", "boursorama", "banquepopulaire", "cic", "creditmutuel",
    "labanquepostale", "ing", "revolut", "n26", "visa", "mastercard", "ovh", "zoom", "teams",
    "webex", "okta", "github", "slack", "servicenow", "salesforce", "hubspot", "sap",
)

_DIGIT_SWAPS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})
_STRIP_RE = re.compile(r"[^a-z0-9]")
_LOOKALIKE_TOKENS = (
    "secure", "security", "login", "signin", "verify", "verification", "account", "update",
    "support", "service", "billing", "invoice", "portal", "auth", "sso", "mail", "webmail",
    "helpdesk", "it", "admin", "notice", "alert", "confirm", "pay", "payment",
)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


@lru_cache(maxsize=4096)
def split_domain(domain: str) -> tuple[str, str, str]:
    """Return (subdomain, sld, suffix) using the offline public-suffix list."""
    d = (domain or "").strip().strip(".").lower()
    if not d:
        return "", "", ""
    ext = _extract(d)
    return ext.subdomain, ext.domain, ext.suffix


def registrable(domain: str) -> str:
    _, sld, suffix = split_domain(domain)
    if sld and suffix:
        return f"{sld}.{suffix}"
    return sld or domain.lower()


def to_unicode(domain: str) -> tuple[str, bool]:
    """Decode punycode labels. Returns (unicode_form, was_punycode)."""
    d = (domain or "").lower()
    if "xn--" not in d:
        return d, False
    try:
        return idna.decode(d), True
    except (idna.IDNAError, UnicodeError, ValueError):
        # Fall back label by label
        out = []
        for label in d.split("."):
            if label.startswith("xn--"):
                try:
                    out.append(label[4:].encode("ascii").decode("punycode"))
                except Exception:  # noqa: BLE001
                    out.append(label)
            else:
                out.append(label)
        return ".".join(out), True


def strip_accents(s: str) -> str:
    import unicodedata

    n = unicodedata.normalize("NFKD", s)
    return "".join(c for c in n if not unicodedata.combining(c))


def skeleton(label: str) -> str:
    """Normalise a label so that visually similar strings collapse together."""
    s = strip_accents(label).lower().translate(_DIGIT_SWAPS)
    s = s.replace("rn", "m").replace("vv", "w").replace("cl", "d")
    return _STRIP_RE.sub("", s)


_skeleton_cached = lru_cache(maxsize=8192)(skeleton)


def _norm_list(values: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    for v in values or ():
        v = (v or "").strip().lower().lstrip("@")
        if v:
            out.append(v)
    return out


def analyze_domain(
    domain: str | None,
    internal_domains: Iterable[str] | None = None,
    brands: Iterable[str] | None = None,
    max_distance: int = 2,
) -> dict[str, Any]:
    """
    Compare a sender domain with the organisation's domains and a brand list.

    Returns a dict with ``flags`` (list of str) and structured details. Flags:
      punycode, mixed_script, confusable, lookalike_internal, lookalike_brand,
      tld_swap, subdomain_trick, brand_embedding, digit_substitution
    """
    result: dict[str, Any] = {
        "domain": (domain or "").lower(),
        "registrable": None,
        "unicode": None,
        "flags": [],
        "matches": [],
        "internal": False,
    }
    if not domain:
        return result
    dom = domain.strip().lower().strip(".")
    result["domain"] = dom
    uni, was_puny = to_unicode(dom)
    if was_puny:
        result["unicode"] = uni
        result["flags"].append("punycode")
    sub, sld, suffix = split_domain(dom)
    reg = registrable(dom)
    result["registrable"] = reg

    internal = _norm_list(internal_domains)
    internal_regs = {registrable(d) for d in internal}
    if reg in internal_regs or dom in internal:
        result["internal"] = True
        # Still report homoglyph problems, but skip lookalike comparisons.
    # Unicode checks on the decoded form
    check_uni = uni if was_puny else dom
    try:
        if confusables.is_mixed_script(check_uni.replace(".", "")):
            result["flags"].append("mixed_script")
        if confusables.is_dangerous(check_uni.replace(".", "")):
            result["flags"].append("confusable")
    except Exception:  # noqa: BLE001 - never fail the mail on a Unicode edge case
        pass

    if result["internal"]:
        return result
    # Domains a brand actually owns (onmicrosoft.com, service-now.com, credit-agricole.fr) and
    # names under a brand's own closed TLD (teams.mail.microsoft) are the brand, not a lookalike
    # of one: on a real mailbox they were 80 % of the "lookalike" findings.
    if reg in BRAND_OWNED_DOMAINS or suffix in BRAND_TLDS:
        result["brandOwned"] = True
        return result

    candidates: list[tuple[str, str]] = []  # (kind, reference registrable/brand)
    for d in internal_regs:
        candidates.append(("internal", d))
    for b in _norm_list(brands) or DEFAULT_BRANDS:
        candidates.append(("brand", b))

    seen_flags = set(result["flags"])
    # Labels to compare: the ASCII label and, for punycode, the accent-stripped Unicode label
    labels: list[tuple[str, bool]] = [(sld, False)]
    if was_puny:
        uni_sld = split_domain(uni)[1]
        if uni_sld:
            ascii_uni = _STRIP_RE.sub("", strip_accents(uni_sld).lower().replace("-", "-")) or uni_sld
            labels.append((strip_accents(uni_sld).lower(), True))
            if ascii_uni != labels[-1][0]:
                labels.append((ascii_uni, True))

    for kind, ref in candidates:
        ref_sub, ref_sld, ref_suffix = split_domain(ref) if "." in ref else ("", ref, "")
        ref_sld = ref_sld or ref
        if not ref_sld or not sld:
            continue
        match: dict[str, Any] | None = None
        # 1. same registrable label, different TLD (interne.fr -> interne.co)
        if ref_suffix and sld == ref_sld and suffix != ref_suffix:
            match = {"kind": kind, "reference": ref, "method": "tld_swap", "distance": 0}
        # 2. reference appears as a subdomain of something else (interne.fr.evil.com)
        elif ref_suffix and sub and (f"{ref_sld}.{ref_suffix}" in f"{sub}.{sld}.{suffix}") and reg != ref:
            match = {"kind": kind, "reference": ref, "method": "subdomain_trick", "distance": 0}
        else:
            ref_sk = _skeleton_cached(ref_sld)
            for label, from_unicode in labels:
                # 3. homoglyph / digit substitution: skeleton equality
                if _skeleton_cached(label) == ref_sk and label != ref_sld:
                    method = "homoglyph" if from_unicode or not any(c.isdigit() for c in label) else "digit_substitution"
                    match = {"kind": kind, "reference": ref, "method": method, "distance": 0}
                    break
                # 4. edit distance on the second-level label. Short references match half the
                # dictionary at distance 2 ("free" ~ "fret"), so the allowed distance scales
                # with the reference length and references under 5 chars are skipped.
                # levenshtein >= |len(a)-len(b)|: skip the DP when it cannot pass.
                dist_limit = min(max_distance, 1 if len(ref_sld) <= 6 else 2)
                if len(ref_sld) >= 5 and abs(len(label) - len(ref_sld)) <= dist_limit:
                    dist = levenshtein(label, ref_sld)
                    if 0 < dist <= dist_limit:
                        match = {"kind": kind, "reference": ref, "method": "homoglyph" if from_unicode else "edit_distance", "distance": dist}
                        break
                # 5. brand embedded with a lookalike token (paypal-secure.com, interne-fr-login.net)
                if len(ref_sld) >= 4 and ref_sld in label and label != ref_sld:
                    rest = label.replace(ref_sld, "")
                    tokens = [t for t in re.split(r"[-_.]", rest) if t]
                    if not tokens or any(t in _LOOKALIKE_TOKENS for t in tokens) or len(rest) <= 3:
                        match = {"kind": kind, "reference": ref, "method": "brand_embedding", "distance": len(rest)}
                        break
        if match:
            result["matches"].append(match)
            flag = "lookalike_internal" if kind == "internal" else "lookalike_brand"
            seen_flags.add(flag)
            seen_flags.add(match["method"])

    result["flags"] = sorted(seen_flags)
    # Prefer internal matches first, then smallest distance
    result["matches"].sort(key=lambda m: (m["kind"] != "internal", m["distance"]))
    return result


def display_name_looks_like_email(name: str | None) -> str | None:
    """If the display name contains an e-mail address, return it (spoof trick)."""
    if not name:
        return None
    m = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", name)
    return m.group(0).lower() if m else None
