"""
Cross-source attack chains.

A chain starts from a suspicious mail (the *seed*) and follows what the same identity did
next, across the three sources REMN holds in one case:

* the mailbox itself      - the victim replying to the phisher, further mails in the thread
* Microsoft 365 / Entra   - sign-ins (country, legacy client, risk), MailItemsAccessed bursts,
                            inbox rules, mailbox forwarding, consent grants, role changes ...
* Windows host events     - logons, process creation under Outlook / a browser, DNS queries,
                            network connections and file writes that match the mail's URLs or
                            attachment names, Defender detections

Identity is the link: a recipient address ``alice@contoso.com``, a Windows ``CONTOSO\\alice`` /
``alice`` and a UAL ``UserId`` all normalise to the key ``alice``. Artifacts of the seed mail
(URL domains, attachment file names, sender address) give *strong* links when they reappear
in an event (a DNS query for the phishing domain, a process whose command line names the
attachment). Steps are ordered in time, bursts of the same operation are collapsed, findings
of the rule run are attached to the steps they reference, and the chain is scored.

Pure functions over plain dict rows so the same code serves the DuckDB store and rows posted
from a browser-stored case.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
_SKIP_IDENTITIES = {
    "",
    "-",
    "system",
    "anonymous logon",
    "local service",
    "network service",
    "local system",
    "administrateur",
    "administrator",
    "window manager",
    "font driver host",
    "nt authority",
    "unknown",
    "null",
    "none",
}


def identity_key(value: Any) -> str | None:
    """alice@contoso.com | CONTOSO\\alice | alice -> 'alice'. Machine and well-known accounts -> None."""
    if value is None:
        return None
    s = str(value).strip().strip('"').strip("'").lower()
    if not s or s.endswith("$"):
        return None
    if "\\" in s:
        s = s.rsplit("\\", 1)[1]
    if "@" in s:
        s = s.split("@", 1)[0]
    s = s.strip()
    if s in _SKIP_IDENTITIES or s.startswith(("dwm-", "umfd-", "s-1-")) or len(s) < 2:
        return None
    return s


def _addr_list(v: Any) -> list[str]:
    out: list[str] = []
    if isinstance(v, list):
        for it in v:
            if isinstance(it, dict):
                a = it.get("addr") or it.get("email")
                if a:
                    out.append(str(a))
            elif isinstance(it, str):
                out.append(it)
    elif isinstance(v, str) and v:
        out.append(v)
    return out


def mail_recipients(mail: dict[str, Any]) -> list[str]:
    addrs: list[str] = []
    for k in ("to", "cc", "bcc"):
        addrs += _addr_list(mail.get(k))
    for k in ("toList", "ccList", "bccList"):
        addrs += _addr_list(mail.get(k))
    seen: set[str] = set()
    out: list[str] = []
    for a in addrs:
        a = a.strip().lower()
        if a and a not in seen:
            seen.add(a)
            out.append(a)
    return out


def identity_realm(value: Any, domain_field: Any = None) -> tuple[str | None, str]:
    """
    The scope of an account name: ('northstar.example', 'dns') for a UPN or address,
    ('northstar', 'netbios') for CONTOSO\\alice or a separate domain field, (None, 'none') for a bare name.
    """
    s = "" if value is None else str(value).strip().strip('"').strip("'").lower()
    if "\\" in s:
        dom, user = s.rsplit("\\", 1)
        if "@" in user:
            return user.split("@", 1)[1].strip(".") or None, "dns"
        dom = dom.strip()
        return (dom, "netbios") if dom and dom not in ("nt authority", "nt service", "window manager", "font driver host") else (None, "none")
    if "@" in s:
        return s.split("@", 1)[1].strip(".") or None, "dns"
    if domain_field:
        d = str(domain_field).strip().strip('"').strip("'").lower()
        if d and d not in ("nt authority", "nt service", "window manager", "font driver host", "-"):
            return (d, "dns") if "." in d else (d, "netbios")
    return None, "none"


def same_org_domain(a: str, b: str, internal: set[str] | None = None) -> bool:
    """northstar.example and corp.northstar.example are one organisation; other-tenant.example is not."""
    a, b = a.lower().strip("."), b.lower().strip(".")
    if a == b or a.endswith("." + b) or b.endswith("." + a):
        return True
    return bool(internal) and a in internal and b in internal


def realm_matches(
    seed_domain: str | None,
    realm: str | None,
    kind: str,
    internal: set[str],
    known_labels: set[str],
    netbios_map: dict[str, set[str]] | None = None,
) -> bool:
    """
    Does an account seen on an event belong to the recipient's organisation? A DNS realm must be the
    same organisation as the recipient's domain. A NetBIOS name matches when it is the first label of
    that domain or of an internal domain, or when the case showed it next to a UPN of that organisation;
    it does not match when the case tied it to another organisation, by that same co-occurrence or as
    the first label of another domain seen; an unknown short name is accepted, since nothing says it
    is foreign.
    """
    if not seed_domain or not realm:
        return True
    if kind == "dns":
        return same_org_domain(seed_domain, realm, internal)
    labels = {seed_domain.split(".")[0]} | {d.split(".")[0] for d in internal}
    if realm in labels:
        return True
    resolved = (netbios_map or {}).get(realm)
    if resolved:
        return any(same_org_domain(seed_domain, d, internal) for d in resolved)
    return realm not in known_labels


def netbios_hints(ev: dict[str, Any]) -> list[tuple[str, str]]:
    """(NetBIOS name, DNS domain) pairs an event shows together: a UPN with a domain field, or DOM\\user with a UPN."""
    out: list[tuple[str, str]] = []
    data = ev.get("data") if isinstance(ev.get("data"), dict) else {}
    upn_domains = [identity_realm(v)[0] for v in (ev.get("upn"), data.get("UserId")) if identity_realm(v)[1] == "dns"]
    for user, dom in ((ev.get("targetUser"), ev.get("targetDomain")), (ev.get("subjectUser"), ev.get("subjectDomain"))):
        u_realm, u_kind = identity_realm(user)
        d_realm, d_kind = identity_realm(None, dom)
        if d_kind != "netbios" or not d_realm:
            continue
        if u_kind == "dns" and u_realm:
            out.append((d_realm, u_realm))
        elif u_kind == "none":
            out.extend((d_realm, d) for d in upn_domains if d)
    u_realm, u_kind = identity_realm(ev.get("user"))
    if u_kind == "netbios" and u_realm:
        out.extend((u_realm, d) for d in upn_domains if d)
    return out


def event_identities(ev: dict[str, Any]) -> list[tuple[str, str, str | None, str]]:
    """Every account an event names: (identity key, raw label, realm, realm kind)."""
    out: list[tuple[str, str, str | None, str]] = []
    seen: set[tuple[str, str | None]] = set()
    data = ev.get("data") if isinstance(ev.get("data"), dict) else {}
    for raw, dom in (
        (ev.get("upn"), None),
        (data.get("UserId"), None),
        (ev.get("targetUser"), ev.get("targetDomain")),
        (ev.get("subjectUser"), ev.get("subjectDomain")),
        (ev.get("user"), None),
        (data.get("MailboxOwnerUPN"), None),
    ):
        k = identity_key(raw)
        if not k:
            continue
        realm, kind = identity_realm(raw, dom)
        if (k, realm) in seen:
            continue
        seen.add((k, realm))
        out.append((k, str(raw), realm, kind))
    scoped = {k for k, _, realm, _ in out if realm}
    return [entry for entry in out if entry[2] or entry[0] not in scoped]


# ---------------------------------------------------------------------------
# Seed artifacts
# ---------------------------------------------------------------------------
_MAIL_CLIENTS_RE = re.compile(
    r"(?i)(outlook|winword|excel|powerpnt|onenote|acrord32|acrobat|msedge|chrome|firefox|iexplore|brave|opera|thunderbird|teams)\.exe"
)
_LOLBIN_RE = re.compile(r"(?i)\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|curl|wmic|hh|installutil|msbuild)\.exe")
_LEGACY_CLIENT_RE = re.compile(r"(?i)^(other clients|imap|pop|smtp|authenticated smtp|exchange activesync|exchange web services|exchange online powershell)")


def _own_domains(settings: dict[str, Any] | None) -> set[str]:
    out: set[str] = set()
    for key in ("internal_domains", "internalDomains", "trusted_senders", "trustedSenders"):
        for d in (settings or {}).get(key) or []:
            s = str(d).lower().strip().lstrip("@")
            if s and "@" not in s:
                out.add(s)
    return out


def _is_own(host: str, own: set[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in own)


def seed_artifacts(mail: dict[str, Any], settings: dict[str, Any] | None = None) -> dict[str, set[str]]:
    """Link domains / hosts and attachment names worth looking for in the events. Links to the
    organisation's own domains (the intranet portal in a supplier invoice) are not artifacts:
    every workstation resolves them all day."""
    own = _own_domains(settings)
    domains: set[str] = set()
    hosts: set[str] = set()
    for u in mail.get("urls") or []:
        if not isinstance(u, dict):
            continue
        host = str(u.get("host") or "").lower()
        dom = str(u.get("domain") or "").lower()
        if (host and _is_own(host, own)) or (dom and _is_own(dom, own)):
            continue
        if dom:
            domains.add(dom)
        if host:
            hosts.add(host)
    names: set[str] = set()
    for a in mail.get("attachments") or []:
        if isinstance(a, dict) and a.get("name"):
            n = str(a["name"]).lower().strip()
            if len(n) >= 5:
                names.add(n)
    senders: set[str] = set()
    if mail.get("fromAddr"):
        senders.add(str(mail["fromAddr"]).lower())
    for rt in mail.get("replyTo") or []:
        if isinstance(rt, dict) and rt.get("addr"):
            senders.add(str(rt["addr"]).lower())
    return {"domains": domains, "hosts": hosts, "attachments": names, "senders": senders}


# ---------------------------------------------------------------------------
# Step classification
# ---------------------------------------------------------------------------
SEV_WEIGHT = {"critical": 5, "high": 4, "medium": 2, "low": 1, "info": 0}

# Artifacts that tie a step to the seed mail (as opposed to attribute notes such as "unexpected country").
_LINK_ARTIFACTS = ("victim engaged with the sender", "same thread")


def is_link(artifact: str) -> bool:
    return artifact.startswith("mail ") or artifact in _LINK_ARTIFACTS


def score_chain(
    seed_risk: int, steps: list[dict[str, Any]], routine_ids: set[int], artifact_links: int, top_seed: int, top_step: int
) -> tuple[int, dict[str, Any]]:
    """Bounded, additive score with the contribution of each part, so the interface can explain it.

    seed 0-30 (mail risk), links 0-30 (steps tied to the mail by an artifact), steps 0-20 (weight of
    the non-routine steps, diminishing), findings 0-15 (worst finding on the seed and on a step),
    sources 0-5 (more than one source involved). Without any artifact link the chain cannot be
    critical (cap 79), and without a link, a finding-bearing step or a strong step it stays medium
    at most (cap 54): activity of the recipient that nothing ties to the mail is context.
    """
    link_steps = [s for s in steps if any(is_link(a) for a in s["artifacts"])]
    routine = [s for s in steps if id(s) in routine_ids]
    strong_weight = sum(min(int(s["weight"]), 6) for s in steps if id(s) not in routine_ids) + min(len(routine), 3)
    seed_pts = min(30, round(seed_risk * 0.3))
    links_pts = min(30, 12 * len(link_steps) + 3 * max(0, artifact_links - len(link_steps)))
    steps_pts = min(20, int(round(5 * math.log2(1 + strong_weight))))
    findings_pts = min(15, 2 * top_seed + 2 * top_step)
    sources = {"mail" if s["kind"] == "mail" else s.get("origin") for s in steps}
    sources_pts = 5 if len(sources) > 1 else 0
    total = seed_pts + links_pts + steps_pts + findings_pts + sources_pts
    cap = None
    if not artifact_links:
        linked = any(s["findings"] for s in steps)
        cap = 79 if linked or max(int(s["weight"]) for s in steps) >= 3 else 54
    score = min(100, total, cap or 100)
    return score, {
        "seed": seed_pts,
        "links": links_pts,
        "steps": steps_pts,
        "findings": findings_pts,
        "sources": sources_pts,
        "cap": cap,
        "linkSteps": len(link_steps),
    }


_M365_WEIGHTS = {
    "new-inboxrule": (4, "inbox rule created"),
    "set-inboxrule": (4, "inbox rule changed"),
    "updateinboxrules": (3, "inbox rules updated"),
    "set-mailbox": (3, "mailbox settings changed"),
    "consent to application.": (4, "OAuth consent granted"),
    "add oauth2permissiongrant.": (4, "OAuth permission granted"),
    "add app role assignment grant to user.": (3, "app role granted"),
    "add member to role.": (5, "directory role assigned"),
    "add-mailboxpermission": (4, "mailbox permission granted"),
    "add-mailboxfolderpermission": (3, "folder permission granted"),
    "add-recipientpermission": (4, "send-as granted"),
    "update user.": (3, "user account updated"),
    "user registered security info.": (4, "security info registered"),
    "reset user password.": (3, "password reset"),
    "change user password.": (2, "password changed"),
    "set-casmailbox": (3, "protocol settings changed"),
    "new-transportrule": (5, "transport rule created"),
    "set-transportrule": (5, "transport rule changed"),
    "set-mailboxjunkemailconfiguration": (2, "junk configuration changed"),
    "searchcreated": (2, "eDiscovery search"),
    "searchexportdownloaded": (3, "eDiscovery export"),
    "mailitemsaccessed": (1, "mailbox items accessed"),
    "userloggedin": (1, "sign-in"),
    "userloginfailed": (1, "failed sign-in"),
    "filedownloaded": (1, "file downloaded"),
    "filesyncdownloadedfull": (1, "files synced down"),
    "sharingset": (2, "sharing changed"),
    "anonymouslinkcreated": (3, "anonymous link created"),
    "update conditional access policy.": (4, "conditional access changed"),
    "add service principal.": (3, "service principal added"),
    "add application.": (3, "application registered"),
}
_COLLAPSE_OPS = {
    "mailitemsaccessed",
    "filedownloaded",
    "filesyncdownloadedfull",
    "fileaccessed",
    "filemodified",
    "filepreviewed",
    "userloggedin",
    "userloginfailed",
    "signin",
    "4624",
    "4625",
    "4672",
    "4634",
    "4647",
    "4776",
    "4768",
    "4769",
    "5140",
    "5145",
    "3",
    "22",
    "7",
    "11",
    "10",
}


def _lower(v: Any) -> str:
    return str(v or "").lower()


def _m365_step(ev: dict[str, Any], art: dict[str, set[str]], settings: dict[str, Any]) -> tuple[int, str, list[str]] | None:
    """(weight, title, notes) for a Microsoft 365 / Entra row, None if uninteresting."""
    data = ev.get("data") if isinstance(ev.get("data"), dict) else {}
    op = _lower(ev.get("operation"))
    cat = _lower(ev.get("category"))
    notes: list[str] = []
    if cat == "entra sign-in" or op == "signin":
        ok = str(ev.get("status") or "0") == "0"
        w = 1 if ok else 0
        title = "sign-in" if ok else f"failed sign-in ({ev.get('status')})"
        country = str(data.get("country") or "")
        if country:
            title += f" from {country}"
            expected = [str(c).upper() for c in (settings.get("expected_countries") or settings.get("expectedCountries") or [])]
            if expected and country.upper() not in expected:
                w += 2
                notes.append("unexpected country")
        client = str(data.get("clientAppUsed") or "")
        if client:
            title += f" via {client}"
            if _LEGACY_CLIENT_RE.match(client):
                w += 1
                notes.append("legacy authentication")
        risk = str(data.get("riskLevelDuringSignIn") or data.get("riskLevelAggregated") or "").lower()
        state = str(data.get("riskState") or "").lower()
        if risk in ("medium", "high") or state in ("atrisk", "confirmedcompromised"):
            w += 3
            notes.append(f"identity protection risk {risk or state}")
        if data.get("appDisplayName"):
            title += f" to {data['appDisplayName']}"
        return (w, title, notes) if (ok or w > 0) else (0, title, notes)
    if op in _M365_WEIGHTS:
        w, title = _M365_WEIGHTS[op]
        if op in ("new-inboxrule", "set-inboxrule", "updateinboxrules"):
            bits = []
            for k in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo"):
                if data.get(k):
                    bits.append(f"forward to {data[k]}")
                    w += 1
                    notes.append("forwarding rule")
            if _lower(data.get("DeleteMessage")) == "true":
                bits.append("deletes messages")
                w += 1
            if data.get("MoveToFolder"):
                bits.append(f"moves to {data['MoveToFolder']}")
            if data.get("SubjectContainsWords"):
                bits.append(f"subject contains {str(data['SubjectContainsWords'])[:50]}")
            if ev.get("objectName"):
                title += f" '{ev['objectName']}'"
            if bits:
                title += ": " + ", ".join(bits)
        elif op == "set-mailbox":
            if data.get("ForwardingSmtpAddress") or data.get("ForwardingAddress"):
                w = 5
                title = f"mailbox forwarding to {data.get('ForwardingSmtpAddress') or data.get('ForwardingAddress')}"
                notes.append("mailbox forwarding")
            elif _lower(data.get("AuditEnabled")) == "false":
                w = 5
                title = "mailbox auditing disabled"
        elif op == "mailitemsaccessed":
            title = f"mailbox items accessed ({data.get('MailAccessType') or 'bind'})"
            if _lower(data.get("MailAccessType")) == "sync":
                w += 1
        elif op == "add member to role.":
            title = f"role assigned: {data.get('Role.DisplayName') or ''} -> {ev.get('targetUser') or ''}"
        elif op in ("consent to application.", "add oauth2permissiongrant."):
            title += f" ({ev.get('objectName') or data.get('Target') or 'app'})"
            perms = str(data.get("ConsentAction.Permissions") or "")
            m = re.search(r"Scope:\s*([^\]]+)", perms)
            if m:
                title += f" scope {m.group(1).strip()[:80]}"
        elif op == "update user." and not any(str(k).startswith("StrongAuthentication") for k in data):
            w = 1
        return (w, title, notes)
    if op:
        return (1, op, notes)
    return None


def _host_step(ev: dict[str, Any], art: dict[str, set[str]]) -> tuple[int, str, list[str]] | None:
    """(weight, title, artifact notes) for a Windows event."""
    eid = ev.get("eventId")
    chan = _lower(ev.get("channel"))
    notes: list[str] = []
    cmd = _lower(ev.get("commandLine"))
    image = _lower(ev.get("image") or ev.get("processName"))
    parent = _lower(ev.get("parentImage") or ev.get("parentProcessName"))
    sysmon = "sysmon" in chan

    def art_hits(text: str) -> None:
        for d in art["domains"] | art["hosts"]:
            if d and d in text:
                notes.append(f"mail URL domain {d}")
        for n in art["attachments"]:
            if n and n in text:
                notes.append(f"mail attachment {n}")

    if (sysmon and eid == 1) or eid == 4688:
        w = 1
        title = f"process {image.rsplit(chr(92), 1)[-1] or '?'}"
        if parent and _MAIL_CLIENTS_RE.search(parent):
            w += 2
            title += f" spawned by {parent.rsplit(chr(92), 1)[-1]}"
            notes.append("child of a mail client / browser / document viewer")
        if _LOLBIN_RE.search(image):
            w += 1
        art_hits(cmd + " " + image)
        if cmd:
            title += f": {ev.get('commandLine')}"[:200]
        return (w, title, notes)
    if sysmon and eid == 22:
        q = _lower(ev.get("query"))
        title = f"DNS query {q}"
        art_hits(q)
        return (1, title, notes)
    if sysmon and eid == 3:
        dest = _lower(ev.get("destinationHostname")) + " " + _lower(ev.get("destinationIp"))
        title = f"network connection {image.rsplit(chr(92), 1)[-1]} -> {ev.get('destinationHostname') or ev.get('destinationIp') or '?'}:{ev.get('destinationPort') or ''}"
        art_hits(dest)
        return (1, title, notes)
    if sysmon and eid == 11:
        tf = _lower(ev.get("targetFilename"))
        title = f"file created {ev.get('targetFilename')}"
        art_hits(tf)
        w = 1 + (1 if re.search(r"\.(exe|dll|js|vbs|hta|lnk|ps1|bat|cmd|scr|iso|img|zip)$", tf) else 0)
        return (w, title, notes)
    if "windows defender" in chan or eid in (1116, 1117, 1006, 1007):
        return (4, f"Defender: {ev.get('summary') or 'threat detected'}"[:200], ["antivirus detection"])
    if eid == 4624:
        lt = ev.get("logonTypeName") or ev.get("logonType")
        return (1, f"logon ({lt}) on {ev.get('computer') or '?'} from {ev.get('ipAddress') or 'local'}", notes)
    if eid == 4625:
        return (0, f"failed logon on {ev.get('computer') or '?'}", notes)
    if eid == 4648:
        return (2, f"logon with explicit credentials on {ev.get('computer') or '?'}", notes)
    if eid in (4672,):
        return (1, f"special privileges assigned on {ev.get('computer') or '?'}", notes)
    if eid in (4720, 4722, 4724, 4728, 4732, 4756, 4738, 4740):
        return (3, f"account / group change ({eid}) on {ev.get('computer') or '?'}: {ev.get('summary') or ''}"[:200], notes)
    if eid in (4698, 4702, 7045, 4697):
        return (3, f"persistence ({eid}): {ev.get('summary') or ev.get('taskName') or ev.get('serviceName') or ''}"[:200], notes)
    if eid == 1102 or (eid == 104 and "system" in chan):
        return (4, "event log cleared", ["anti-forensics"])
    if eid == 4104:
        sb = _lower(ev.get("scriptBlockText"))
        art_hits(sb)
        return (2, f"PowerShell script block: {(ev.get('scriptBlockText') or '')[:120]}", notes)
    return None


def _is_m365(ev: dict[str, Any]) -> bool:
    p = _lower(ev.get("provider"))
    return "unified audit" in p or "entra" in p or _lower(ev.get("category")).startswith(("m365", "entra"))


# ---------------------------------------------------------------------------
# Chain building
# ---------------------------------------------------------------------------
def _collapse_key(ev: dict[str, Any]) -> str:
    if _is_m365(ev):
        return f"m365|{_lower(ev.get('operation'))}|{ev.get('ipAddress') or ''}|{ev.get('status') or ''}"
    return f"host|{ev.get('eventId')}|{_lower(ev.get('computer'))}|{_lower(ev.get('image') or ev.get('processName'))}"


def build_chains(
    mails: Iterable[dict[str, Any]],
    events: Iterable[dict[str, Any]],
    findings: Iterable[dict[str, Any]] | None = None,
    settings: dict[str, Any] | None = None,
    *,
    seed_min_risk: int = 45,
    window_hours: float = 72.0,
    before_minutes: float = 5.0,
    collapse_minutes: float = 10.0,
    min_score: int = 20,
    max_chains: int = 100,
) -> dict[str, Any]:
    settings = settings or {}
    mails = [m for m in mails if isinstance(m, dict)]
    events = [e for e in events if isinstance(e, dict) and e.get("ts") is not None]
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    window_ms = int(window_hours * 3600_000)
    before_ms = int(before_minutes * 60_000)
    collapse_ms = int(collapse_minutes * 60_000)

    # findings by referenced row (per source)
    f_by_ref: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        src = f.get("source") or "events"
        for ref in f.get("refs") or []:
            try:
                f_by_ref[(src, int(ref))].append(f)
            except (TypeError, ValueError):
                continue

    # seeds: risky mails, or mails carrying a medium+ finding
    seeds: list[dict[str, Any]] = []
    for m in mails:
        if m.get("date") is None:
            continue
        mid = m.get("id")
        fs = f_by_ref.get(("mails", int(mid))) if mid is not None else None
        top_f = max((SEV_WEIGHT.get(str(f.get("severity")), 0) for f in (fs or [])), default=0)
        if int(m.get("risk") or 0) >= seed_min_risk or top_f >= 2:
            seeds.append(m)
    seeds.sort(key=lambda m: -(int(m.get("risk") or 0)))
    seeds_truncated = len(seeds) > 300
    seeds = seeds[:300]

    # index events and mails by identity; each entry keeps the realm the account was seen in
    internal = {d for d in _own_domains(settings) if "." in d}
    ev_by_id: dict[str, list[tuple[dict[str, Any], str | None, str]]] = defaultdict(list)
    known_labels: set[str] = set()
    netbios_map: dict[str, set[str]] = defaultdict(set)
    for ev in events:
        for k, _label, realm, kind in event_identities(ev):
            ev_by_id[k].append((ev, realm, kind))
            if kind == "dns" and realm:
                known_labels.add(realm.split(".")[0])
        for nb, dns in netbios_hints(ev):
            netbios_map[nb].add(dns)
    for lst in ev_by_id.values():
        lst.sort(key=lambda e: e[0]["ts"])
    mails_by_sender: dict[str, list[tuple[dict[str, Any], str | None, str]]] = defaultdict(list)
    for m in mails:
        k = identity_key(m.get("fromAddr"))
        if k and m.get("date") is not None:
            realm, kind = identity_realm(m.get("fromAddr"))
            mails_by_sender[k].append((m, realm, kind))
            if kind == "dns" and realm:
                known_labels.add(realm.split(".")[0])

    chains: list[dict[str, Any]] = []
    for seed in seeds:
        t0 = int(seed["date"])
        art = seed_artifacts(seed, settings)
        seed_findings = f_by_ref.get(("mails", int(seed["id"]))) if seed.get("id") is not None else []
        for rcpt in mail_recipients(seed):
            ident = identity_key(rcpt)
            if not ident:
                continue
            rcpt_domain, _ = identity_realm(rcpt)
            steps: list[dict[str, Any]] = []
            last_by_key: dict[str, dict[str, Any]] = {}
            # victim replies / forwards to the phisher
            for m, m_realm, m_kind in mails_by_sender.get(ident, []):
                if m is seed or not (t0 - before_ms <= int(m["date"]) <= t0 + window_ms):
                    continue
                if not realm_matches(rcpt_domain, m_realm, m_kind, internal, known_labels, netbios_map):
                    continue
                to_phisher = bool(set(mail_recipients(m)) & art["senders"])
                same_thread = bool(m.get("inReplyTo") and seed.get("messageId") and str(m["inReplyTo"]).strip() == str(seed["messageId"]).strip())
                if to_phisher or same_thread:
                    steps.append(
                        {
                            "kind": "mail",
                            "source": "mails",
                            "id": m.get("id"),
                            "ts": int(m["date"]),
                            "tsEnd": int(m["date"]),
                            "count": 1,
                            "title": f"reply to the sender: {m.get('subject') or ''}"[:200],
                            "weight": 4,
                            "artifacts": ["victim engaged with the sender"] + (["same thread"] if same_thread else []),
                            "findings": _fsum(f_by_ref.get(("mails", int(m["id"])) if m.get("id") is not None else ("mails", -1)) or []),
                        }
                    )
            # events of that identity in the window, in the recipient's organisation
            seen_events: set[int] = set()
            for ev, ev_realm, ev_kind in ev_by_id.get(ident, []):
                ts = int(ev["ts"])
                if ts < t0 - before_ms:
                    continue
                if ts > t0 + window_ms:
                    break
                if not realm_matches(rcpt_domain, ev_realm, ev_kind, internal, known_labels, netbios_map):
                    continue
                if id(ev) in seen_events:
                    continue
                seen_events.add(id(ev))
                cls = _m365_step(ev, art, settings) if _is_m365(ev) else _host_step(ev, art)
                if cls is None:
                    continue
                w, title, notes = cls
                fs = f_by_ref.get(("events", int(ev["id"]))) if ev.get("id") is not None else []
                w += max((SEV_WEIGHT.get(str(f.get("severity")), 0) for f in (fs or [])), default=0)
                w += 2 * len([n for n in notes if n.startswith("mail ")])
                if w <= 0 and not fs:
                    continue
                key = _collapse_key(ev)
                # bursts of the same operation from the same client merge into one step (kept at the
                # first timestamp) even when other steps interleave, so a 30-row MailItemsAccessed run
                # reads as one line while an inbox rule created in the middle keeps its own place
                # attribute notes (unexpected country, legacy auth ...) describe the step and may repeat;
                # mail-artifact links and attached findings make an event unique
                unique = bool(fs) or any(n.startswith(("mail ", "child of", "antivirus", "anti-forensics")) for n in notes)
                last = last_by_key.get(key)
                if last is not None and ts - last["tsEnd"] <= collapse_ms and not unique and last["artifacts"] == notes:
                    last["count"] += 1
                    last["tsEnd"] = ts
                    last["refs"].append(ev.get("id"))
                    continue
                step = {
                    "kind": "event",
                    "source": "events",
                    "id": ev.get("id"),
                    "refs": [ev.get("id")],
                    "ts": ts,
                    "tsEnd": ts,
                    "count": 1,
                    "title": title,
                    "weight": w,
                    "artifacts": notes,
                    "findings": _fsum(fs or []),
                    "_key": key,
                    "ipAddress": ev.get("ipAddress"),
                    "computer": ev.get("computer"),
                    "origin": "m365" if _is_m365(ev) else "host",
                    "operation": ev.get("operation") or ev.get("eventId"),
                }
                steps.append(step)
                if not unique:
                    last_by_key[key] = step
            if not steps:
                continue
            steps.sort(key=lambda s: s["ts"])
            for s in steps:
                s.pop("_key", None)
                s["offsetMin"] = round((s["ts"] - t0) / 60_000, 1)
                if s["count"] > 1:
                    s["title"] = f"{s['title']} ×{s['count']}"
            artifact_links = sum(1 for s in steps for a in s["artifacts"] if is_link(a))
            # Routine activity (logons, sign-ins, DNS, mailbox reads at weight 1, without a link to the
            # mail or a finding) is context, not evidence: it contributes at most 3 points however long
            # the window is, and a chain made only of it is not a chain at all.
            linked = {id(s) for s in steps if s["findings"] or any(is_link(a) for a in s["artifacts"])}
            routine = [s for s in steps if s["weight"] <= 1 and id(s) not in linked]
            if not artifact_links and not any(id(s) in linked or s["weight"] >= 2 for s in steps):
                continue
            routine_ids = {id(s) for s in routine}
            top_seed = max((SEV_WEIGHT.get(str(f.get("severity")), 0) for f in (seed_findings or [])), default=0)
            top_step = max((SEV_WEIGHT.get(str(f.get("severity")), 0) for s in steps for f in s["findings"]), default=0)
            score, breakdown = score_chain(int(seed.get("risk") or 0), steps, routine_ids, artifact_links, top_seed, top_step)
            if score < min_score:
                continue
            severity = "critical" if score >= 80 else "high" if score >= 55 else "medium" if score >= 35 else "low"
            ips = sorted({str(s["ipAddress"]) for s in steps if s.get("ipAddress")})
            hosts = sorted({str(s["computer"]) for s in steps if s.get("computer")})
            attacker = sorted(art["senders"])
            for s in steps:
                m = re.search(r"forward(?:ing)? to ([^\s,]+)", s["title"])
                if m:
                    attacker.append(m.group(1).strip("smtp:"))
            chains.append(
                {
                    "identity": rcpt.lower(),
                    "identityLabel": rcpt,
                    "seed": {
                        "source": "mails",
                        "id": seed.get("id"),
                        "ts": t0,
                        "subject": (seed.get("subject") or "")[:200],
                        "fromAddr": seed.get("fromAddr"),
                        "risk": int(seed.get("risk") or 0),
                        "flags": list(seed.get("flags") or [])[:12],
                        "findings": _fsum(seed_findings or []),
                        "urlDomains": sorted(art["domains"])[:10],
                        "attachments": sorted(art["attachments"])[:10],
                    },
                    "steps": steps,
                    "start": t0,
                    "end": max(s["tsEnd"] for s in steps),
                    "score": score,
                    "severity": severity,
                    "artifactLinks": artifact_links,
                    "scoreBreakdown": breakdown,
                    "entities": {
                        "user": rcpt,
                        "ips": ips[:20],
                        "hosts": hosts[:20],
                        "attackerAddresses": sorted(set(attacker))[:10],
                        "domains": sorted(art["domains"])[:10],
                    },
                }
            )
    # one chain per identity per 24 h: keep the best, attach the others as related seeds
    chains.sort(key=lambda c: -c["score"])
    kept: list[dict[str, Any]] = []
    for c in chains:
        dup = next((k for k in kept if k["identity"] == c["identity"] and abs(k["seed"]["ts"] - c["seed"]["ts"]) <= 86_400_000), None)
        if dup:
            dup.setdefault("relatedSeeds", []).append(c["seed"])
            continue
        kept.append(c)
    coverage = [{r for s in c["steps"] if s["source"] == "events" for r in (s.get("refs") or [s.get("id")])} for c in kept]
    for campaign in authentication_chains(events, f_by_ref):
        refs = {r for s in campaign["steps"] for r in s["refs"]}
        if not any(refs <= covered for covered in coverage):
            kept.append(campaign)
    kept.sort(key=lambda c: -c["score"])
    chains_truncated = len(kept) > max_chains
    kept = kept[:max_chains]
    for c in kept:
        c.setdefault("id", f"chain-{c['identity']}-{c['seed']['id']}")
        c.setdefault("summary", _summary(c))
    return {
        "chains": kept,
        "stats": {
            "seeds": len(seeds),
            "identities": len(ev_by_id),
            "events": len(events),
            "mails": len(mails),
            "chains": len(kept),
            "seedsTruncated": int(seeds_truncated),
            "chainsTruncated": int(chains_truncated),
        },
    }


def authentication_outcome(ev: dict[str, Any]) -> str | None:
    """Only explicit authentication outcomes; MFA challenges and unrelated errors are not password guesses."""
    if not _is_m365(ev):
        return {4625: "failure", 4624: "success"}.get(ev.get("eventId"))
    op = str(ev.get("operation") or "").lower()
    status = str(ev.get("status") or "").lower()
    if op == "userloginfailed":
        return "failure"
    if op == "userloggedin":
        return "success" if status in ("success", "succeeded", "0") else None
    if "signin" in op or "sign-in" in op:
        if status in ("50126", "50034", "50053"):
            return "failure"
        if status == "0":
            return "success"
    return None


def authentication_chains(events: list[dict[str, Any]], findings: dict) -> list[dict[str, Any]]:
    """Ten failures in thirty minutes for the same scoped account, source IP and destination.

    A following success is evidence to investigate, not proof of compromise. Failure-only
    campaigns stay medium. No mail, cross-source event or pre-existing finding is required.
    """
    groups: dict[tuple[str, str, str, str], list[tuple[dict, str]]] = defaultdict(list)
    for ev in events:
        outcome = authentication_outcome(ev)
        ip = str(ev.get("ipAddress") or "").strip()
        raw = ev.get("upn") or (ev.get("data") or {}).get("UserId") or ev.get("targetUser")
        if not outcome or not raw or not ip or ip in ("-", "0.0.0.0", "::"):
            continue
        # Administrator is a valid brute-force target, even though mail-led chains skip it.
        user = str(raw).strip().lower()
        if user in ("-", "system", "anonymous logon") or user.endswith("$"):
            continue
        if "@" not in user and "\\" not in user:
            user = str(ev.get("targetDomain") or ev.get("computer") or "unknown").lower() + "\\" + user
        origin = "m365" if _is_m365(ev) else "host"
        host = str(ev.get("computer") or "").lower()
        groups[(user, ip, host, origin)].append((ev, outcome))
    out = []
    for (user, ip, host, origin), rows in groups.items():
        rows.sort(key=lambda r: (r[0]["ts"], r[0].get("id") or 0))
        start = 0
        while start < len(rows):
            if rows[start][1] != "failure":
                start += 1
                continue
            stop = start
            deadline = rows[start][0]["ts"] + 30 * 60_000
            while stop < len(rows) and rows[stop][0]["ts"] <= deadline:
                stop += 1
            window = rows[start:stop]
            failed = [r for r, outcome in window if outcome == "failure"]
            if len(failed) < 10:
                start += 1
                continue
            threshold_ts = failed[9]["ts"]
            successes = [r for r, outcome in window if outcome == "success" and r["ts"] > threshold_ts]
            seed = failed[0]
            steps = []
            for title, batch, weight in [
                ("Repeated authentication failures", failed, 5),
                ("Successful login after repeated failures — verify legitimacy", successes, 10),
            ]:
                if not batch:
                    continue
                refs = [r["id"] for r in batch if r.get("id") is not None]
                steps.append(
                    {
                        "kind": "event",
                        "source": "events",
                        "origin": origin,
                        "id": refs[0] if refs else None,
                        "refs": refs,
                        "ts": batch[0]["ts"],
                        "tsEnd": batch[-1]["ts"],
                        "count": len(batch),
                        "title": title,
                        "weight": weight,
                        "artifacts": [f"same account, source IP {ip} and destination"],
                        "findings": _fsum([f for ref in refs for f in findings.get(("events", ref), [])]),
                        "offsetMin": (batch[0]["ts"] - seed["ts"]) / 60_000,
                        "ipAddress": ip,
                        "computer": host,
                    }
                )
            score = 75 if successes else 50
            out.append(
                {
                    "id": f"auth-chain-{origin}-{user}-{ip}-{host}-{seed.get('id')}",
                    "identity": f"auth:{origin}:{user}:{ip}:{host}",
                    "identityLabel": user,
                    "kind": "authentication",
                    "seed": {
                        "source": "events",
                        "id": seed.get("id"),
                        "ts": seed["ts"],
                        "subject": "Authentication campaign",
                        "fromAddr": None,
                        "risk": score,
                        "flags": [],
                        "findings": [],
                        "urlDomains": [],
                        "attachments": [],
                    },
                    "steps": steps,
                    "start": seed["ts"],
                    "end": max(s["tsEnd"] for s in steps),
                    "score": score,
                    "severity": "high" if successes else "medium",
                    "artifactLinks": 0,
                    "entities": {"user": user, "ips": [ip], "hosts": [host] if host else [], "attackerAddresses": [], "domains": []},
                    "summary": f"{len(failed)} authentication failures for {user} from {ip} within 30 minutes"
                    + (
                        f", followed by {len(successes)} successful login(s). Verify whether the success was legitimate."
                        if successes
                        else ". No subsequent successful login observed in this window."
                    ),
                }
            )
            start = stop
    return out


def _fsum(fs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for f in fs[:6]:
        out.append({"ruleId": f.get("ruleId"), "title": f.get("title"), "severity": f.get("severity")})
    return out


def _summary(c: dict[str, Any]) -> str:
    """The seed, then the six weightiest steps in time order."""
    parts = [f"{c['identityLabel']}: mail from {c['seed'].get('fromAddr') or '?'} (risk {c['seed']['risk']})"]
    top = sorted(c["steps"], key=lambda s: (-s["weight"], s["ts"]))[:6]
    for s in sorted(top, key=lambda s: s["ts"]):
        parts.append(f"{s['title'][:70]} (+{s['offsetMin']:g} min)")
    return " → ".join(parts)[:900]


# ---------------------------------------------------------------------------
# DuckDB store adapter
# ---------------------------------------------------------------------------
# events considered per build; beyond it the window is cut and the stats say so
EVENT_CAP = 50_000
_IDENT_SQL = "lower(regexp_extract(coalesce({col}, ''), '^(?:[^\\\\]*\\\\)?([^@]+)', 1))"


def chains_for_store(store: Any, settings: dict[str, Any] | None, findings: list[dict[str, Any]] | None = None, **opts: Any) -> dict[str, Any]:
    """Select seeds, the identities' events and their replies from a case store, then build."""
    from services.store import queries as Q
    from services.store.casestore import rows_to_dicts

    seed_min_risk = int(opts.get("seed_min_risk", 45))
    window_hours = float(opts.get("window_hours", 72.0))
    ref_ids = sorted({int(r) for f in (findings or []) if f.get("source") == "mails" for r in (f.get("refs") or []) if str(r).lstrip("-").isdigit()})[:500]
    seeds = Q.search(
        store, "mails", {"conditions": [{"field": "risk", "op": "gte", "value": seed_min_risk}]}, limit=300, sort={"field": "risk", "dir": "desc"}, full=True
    )["rows"]
    if ref_ids:
        extra = Q.search(store, "mails", {"conditions": [{"field": "id", "op": "in", "value": ref_ids}]}, limit=500, full=True)["rows"]
        have = {m["id"] for m in seeds}
        seeds += [m for m in extra if m["id"] not in have]
    idents = sorted({k for m in seeds for r in mail_recipients(m) for k in [identity_key(r)] if k})
    idents = idents or ["__no_mail_recipient__"]
    t_min = min((int(m["date"]) for m in seeds if m.get("date") is not None), default=0) - 300_000
    t_max = max((int(m["date"]) for m in seeds if m.get("date") is not None), default=0) + int(window_hours * 3600_000)
    cur = store.cursor()
    ph = ", ".join("?" for _ in idents)
    ident_cond = " OR ".join(_IDENT_SQL.format(col=f'"{c}"') + f" IN ({ph})" for c in ("targetUser", "subjectUser", "user", "upn"))
    params: list[Any] = [t_min, t_max] + idents * 4
    cur.execute(f"SELECT * FROM events WHERE ts BETWEEN ? AND ? AND ({ident_cond}) ORDER BY ts LIMIT {EVENT_CAP + 1}", params)
    events = rows_to_dicts(cur)
    events_truncated = len(events) > EVENT_CAP
    events = events[:EVENT_CAP]
    # Authentication-only cases have no seed mail. Keep their selection independent of
    # mail windows and of the much larger pool of unrelated host/cloud activity.
    cur.execute(
        f"SELECT * FROM events WHERE ts IS NOT NULL AND (\"eventId\" IN (4624,4625) OR lower(operation) IN ('signin','sign-in','userloginfailed','userloggedin')) ORDER BY ts, id LIMIT {EVENT_CAP + 1}"
    )
    auth = rows_to_dicts(cur)
    auth_truncated = len(auth) > EVENT_CAP
    have_events = {r["id"] for r in events}
    events.extend(r for r in auth[:EVENT_CAP] if r["id"] not in have_events)
    for r in events:
        if isinstance(r.get("data"), str):
            try:
                import json

                r["data"] = json.loads(r["data"])
            except ValueError:
                pass
    cur.execute(
        f"SELECT * FROM mails WHERE date BETWEEN ? AND ? AND {_IDENT_SQL.format(col='"fromAddr"')} IN ({ph}) ORDER BY date, id LIMIT 5001",
        [t_min, t_max] + idents,
    )
    replies = Q._parse_json_cols(rows_to_dicts(cur), "mails") if hasattr(Q, "_parse_json_cols") else rows_to_dicts(cur)
    replies_truncated = len(replies) > 5000
    replies = replies[:5000]
    have = {m["id"] for m in seeds}
    mails = seeds + [m for m in replies if m["id"] not in have]
    result = build_chains(
        mails,
        events,
        findings,
        settings,
        seed_min_risk=seed_min_risk,
        window_hours=window_hours,
        **{k: v for k, v in opts.items() if k in ("before_minutes", "collapse_minutes", "min_score", "max_chains")},
    )
    result["stats"]["eventsTruncated"] = events_truncated
    result["stats"]["authEventsTruncated"] = int(auth_truncated)
    result["stats"]["repliesTruncated"] = int(replies_truncated)
    result["stats"]["seedsTruncated"] = int(result["stats"]["seedsTruncated"] or len(seeds) >= 300 or len(ref_ids) >= 500)
    return result
