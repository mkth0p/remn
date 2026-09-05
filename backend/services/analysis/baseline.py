"""
Sender baselining and campaign clustering - an enrichment pass over the mails of a case.

Parse-time scoring judges one message on its own. A mailbox (or a whole export) also tells
*history*: whether this sender ever wrote before, whether we wrote to them first, whether their
mail used to pass authentication, and whether the same lure was sent to many people. Those are
the signals BEC and phishing triage actually turns on, and they are cheap once all the rows
are in one place. The pass writes per-mail columns the rules and the DSL can use:

    senderPrevalence      new | rare | common   (prior mails from the same address, chronological)
    senderPriorCount      how many earlier mails from the address
    senderFirstSeen       first date seen for the address (ms)
    senderDaysKnown       days between that first mail and this one
    senderSolicited       an internal sender wrote to this address *before* this mail (Sent Items)
    senderAuthRegression  the sender's domain passed authentication >= 3 times before and fails now
    campaignId            fingerprint shared by mails with the same subject skeleton + link domains /
                          attachment hashes (only when at least two mails share it)
    campaignSize          number of mails in the campaign
    campaignSenders       distinct sender addresses in the campaign (rotation = automation)

Pure over plain dict rows, so it serves the DuckDB store and rows posted from a browser case.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from typing import Any, Iterable

from services.analysis.lookalike import registrable

ENRICH_COLUMNS = ("senderPrevalence", "senderPriorCount", "senderFirstSeen", "senderDaysKnown", "senderSolicited", "senderAuthRegression",
                  "campaignId", "campaignSize", "campaignSenders")

_PREFIX_RE = re.compile(r"^\s*(?:(?:re|fw|fwd|tr|aw|sv|vs|wg|r|i)\s*:\s*)+", re.I)
_WS_RE = re.compile(r"\s+")
_DIGITS_RE = re.compile(r"\d+")


def subject_skeleton(subject: str | None) -> str:
    s = _PREFIX_RE.sub("", str(subject or "").lower())
    s = _DIGITS_RE.sub("#", s)
    s = _WS_RE.sub(" ", s).strip()
    return s[:80]


def _addrs(v: Any) -> list[str]:
    out: list[str] = []
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            return [v.lower()] if "@" in v else []
    if isinstance(v, list):
        for it in v:
            if isinstance(it, dict) and it.get("addr"):
                out.append(str(it["addr"]).lower())
            elif isinstance(it, str) and "@" in it:
                out.append(it.lower())
    return out


def _loads(v: Any) -> Any:
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return None
    return v


def _auth_pass(m: dict[str, Any]) -> bool | None:
    """True = authenticated, False = failed, None = no information."""
    auth = _loads(m.get("auth")) or {}
    spf = str(m.get("spf") or auth.get("spf") or "").lower()
    dkim = str(m.get("dkim") or auth.get("dkim") or "").lower()
    dmarc = str(m.get("dmarc") or auth.get("dmarc") or "").lower()
    flags = set(m.get("flags") or [])
    if "exchange_internal" in flags:
        return True
    if dmarc == "fail" or spf in ("fail", "softfail") or dkim == "fail" or "compauth_fail" in flags:
        return False
    if (spf == "pass" or dkim == "pass") and dmarc in ("pass", "bestguesspass", "", "none"):
        return True
    return None


def fingerprint(m: dict[str, Any]) -> str | None:
    skel = subject_skeleton(m.get("subject"))
    domains: set[str] = set()
    for u in _loads(m.get("urls")) or []:
        if isinstance(u, dict) and u.get("domain"):
            domains.add(str(u["domain"]).lower())
    hashes: set[str] = set()
    for a in _loads(m.get("attachments")) or []:
        if isinstance(a, dict):
            h = a.get("sha256") or a.get("name")
            if h:
                hashes.add(str(h).lower())
    if not skel and not domains and not hashes:
        return None
    if not domains and not hashes and len(skel) < 8:
        return None  # "hi", "re:" - too generic to be a campaign key
    if not domains and not hashes and (_PREFIX_RE.match(str(m.get("subject") or "")) or m.get("inReplyTo")):
        return None  # a reply in a thread shares the subject by nature; only links/attachments make it a lure
    key = skel + "|" + ",".join(sorted(domains)[:5]) + "|" + ",".join(sorted(hashes)[:5])
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def enrich(mails: Iterable[dict[str, Any]], settings: dict[str, Any] | None = None) -> dict[int, dict[str, Any]]:
    """Per-mail enrichment keyed by mail id."""
    settings = settings or {}
    internal = {registrable(str(d).lower().lstrip("@")) for d in (settings.get("internal_domains") or settings.get("internalDomains") or []) if d}
    rows = [m for m in mails if isinstance(m, dict) and m.get("id") is not None]
    dated = sorted((m for m in rows if m.get("date") is not None), key=lambda m: int(m["date"]))
    out: dict[int, dict[str, Any]] = {}

    first_seen: dict[str, int] = {}
    prior: dict[str, int] = defaultdict(int)
    contacted: set[str] = set()  # addresses an internal sender wrote to so far
    dom_pass: dict[str, int] = defaultdict(int)
    for m in dated:
        mid = int(m["id"])
        t = int(m["date"])
        frm = str(m.get("fromAddr") or "").lower()
        reg = str(m.get("fromRegistrable") or (registrable(frm.split("@", 1)[1]) if "@" in frm else "")).lower()
        flags = set(m.get("flags") or [])
        is_internal = bool(reg and reg in internal) or "exchange_internal" in flags
        e: dict[str, Any] = {}
        if frm:
            n = prior[frm]
            e["senderPrevalence"] = "new" if n == 0 else "rare" if n < 5 else "common"
            e["senderPriorCount"] = n
            fs = first_seen.setdefault(frm, t)
            e["senderFirstSeen"] = fs
            e["senderDaysKnown"] = max(0, int((t - fs) / 86_400_000))
            e["senderSolicited"] = (frm in contacted) if not is_internal else True
            prior[frm] = n + 1
        ap = _auth_pass(m)
        e["senderAuthRegression"] = bool(reg and ap is False and dom_pass.get(reg, 0) >= 3 and not is_internal)
        if reg and ap is True:
            dom_pass[reg] += 1
        if is_internal:
            for a in _addrs(m.get("to")) + _addrs(m.get("cc")) + _addrs(m.get("bcc")) + _addrs(m.get("toList")) + _addrs(m.get("ccList")):
                contacted.add(a)
        out[mid] = e
    # campaigns (dates not needed)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for m in rows:
        fp = fingerprint(m)
        if fp:
            groups[fp].append(m)
    for fp, members in groups.items():
        if len(members) < 2:
            continue
        senders = {str(m.get("fromAddr") or "").lower() for m in members}
        for m in members:
            e = out.setdefault(int(m["id"]), {})
            e["campaignId"] = fp
            e["campaignSize"] = len(members)
            e["campaignSenders"] = len(senders)
    return out


def summarize(enrichment: dict[int, dict[str, Any]]) -> dict[str, Any]:
    camps = {e["campaignId"]: e["campaignSize"] for e in enrichment.values() if e.get("campaignId")}
    return {
        "mails": len(enrichment),
        "newSenders": sum(1 for e in enrichment.values() if e.get("senderPrevalence") == "new"),
        "unsolicitedNew": sum(1 for e in enrichment.values() if e.get("senderPrevalence") == "new" and e.get("senderSolicited") is False),
        "authRegressions": sum(1 for e in enrichment.values() if e.get("senderAuthRegression")),
        "campaigns": len(camps),
        "largestCampaign": max(camps.values(), default=0),
    }


def enrich_store(store: Any, settings: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run the pass over a DuckDB case store and write the columns back."""
    from services.store.casestore import rows_to_dicts

    cur = store.cursor()
    cur.execute('SELECT id, date, "fromAddr", "fromRegistrable", "toList", "ccList", "bccList", subject, spf, dkim, dmarc, flags, urls, attachments FROM mails')
    rows = rows_to_dicts(cur)
    enrichment = enrich(rows, settings)
    n = store.apply_mail_enrichment([{"id": mid, **e} for mid, e in enrichment.items()])
    return {**summarize(enrichment), "updated": n}
