"""
Stories: what happened to each person and each host, read as ATT&CK phases.

A story is an incident: the records about one person (an identity of the resolver) or, when the
records name no person, one host, over a stretch of time. It starts from what raised a flag: a
finding of medium severity or more, or a phishing mail and what followed it (the mail-led chains).
A mail received, or a password guessed wrong, starts no story on its own: it joins the story of
its person when there is one, and otherwise stays with its campaign.

Every step says why it belongs to the story and how surely:

- **strong**: the record names the person by a form a record joined to them, or it is activity
  of their logon session (its logon id), a process started by one in the story, or evidence of
  their way into a host (the service installed after their admin share, for one);
- **medium**: the record names the person by a form the organisation rules joined, it happened on
  a host of the story while the person's session there was open, it came from an address the
  story's findings name, or it follows the phishing mail's link or attachment (the chains' notes).

Weak ties never put a record in a story, and a person's name alone never puts a program they ran
in one: it must run in the story's session or process tree, or carry a finding. One person's
flags that start a story more than two days apart are two incidents; a mail received or a failed
logon joins the nearest, never two. A step reads as a phase from its rule's tactic, else its
technique, else what the record is: a phishing mail is initial access, a log cleared is defense
impairment, a scheduled task is persistence. Routine records (logons, sign-ins, mailbox reads
without a finding) are folded into one step per run. A story past its step cap keeps its flags
and the steps that change what an intruder holds first, and says how many it cut.

Stories that share the attacker's infrastructure (an address, a sender domain, a link domain, an
attachment, a forwarding address, a consented application) form a campaign; so do the mails a
phishing sender sent and the accounts a password spray tried. An address most of the
organisation's users sign in from (its NAT, its VPN) is not the attacker's.
"""

from __future__ import annotations

import hashlib
import re
from bisect import bisect_left
from collections import Counter, defaultdict
from collections.abc import Collection, Iterable
from typing import Any

from .chains import _IDENT_SQL, authentication_outcome, build_chains, mail_recipients, same_org_domain
from .identity import CONFIDENCE_RANK, MEDIUM, STRONG, WEAK, Form, Record, Resolver, account_forms, base_name, event_record, kind_of, mail_record, resolve
from .lineage import Lineage, build_lineage, host_key, ip_of, is_internal_ip

VERSION = 1
# ATT&CK v19's tactics in the order an intrusion reads (Defense Evasion is now Stealth and Defense Impairment)
PHASES: list[tuple[str, str]] = [
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource development"),
    ("initial-access", "Initial access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege escalation"),
    ("stealth", "Stealth"),
    ("defense-impairment", "Defense impairment"),
    ("credential-access", "Credential access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]
PHASE_LABEL = dict(PHASES)
PHASE_ORDER = {p: i for i, (p, _) in enumerate(PHASES)}
# rule tags that name a tactic, beyond the tactic's own name
_TAG_PHASE = {p: p for p, _ in PHASES} | {
    "defense-evasion": "stealth",
    "evasion": "stealth",
    "log-tampering": "defense-impairment",
    "phishing": "initial-access",
    "brute-force": "credential-access",
    "mailbox": "collection",
    "forwarding": "collection",
}
# each technique's tactic, where a technique has several the one it plays in an intrusion story
_TECHNIQUE_PHASE: dict[str, str] = {}
for _phase, _ids in {
    "reconnaissance": "T1589 T1590 T1591 T1592 T1593 T1594 T1595 T1596 T1597 T1598",
    "resource-development": "T1583 T1584 T1585 T1586 T1587 T1588 T1608 T1650",
    "initial-access": "T1078 T1091 T1133 T1189 T1190 T1195 T1199 T1200 T1566 T1659",
    "execution": "T1047 T1059 T1072 T1106 T1129 T1203 T1204 T1559 T1569 T1609 T1610 T1648",
    "persistence": "T1037 T1053 T1098 T1136 T1137 T1176 T1197 T1505 T1542 T1543 T1546 T1547 T1554 T1574",
    "privilege-escalation": "T1068 T1134 T1484 T1548 T1611",
    "stealth": "T1006 T1014 T1027 T1036 T1055 T1070 T1112 T1127 T1140 T1202 T1207 T1211 T1216 T1218 T1220 T1221 T1222 T1480 T1497 T1553 "
    "T1564 T1599 T1600 T1601 T1620 T1622 T1684",
    "defense-impairment": "T1562 T1685 T1686 T1687 T1688 T1689 T1690",
    "credential-access": "T1003 T1040 T1056 T1110 T1111 T1187 T1212 T1528 T1539 T1552 T1555 T1556 T1557 T1558 T1606 T1621 T1649",
    "discovery": "T1007 T1010 T1012 T1016 T1018 T1033 T1046 T1049 T1057 T1069 T1082 T1083 T1087 T1120 T1124 T1135 T1201 T1217 T1482 "
    "T1518 T1526 T1538 T1580 T1613 T1614 T1615 T1619 T1652",
    "lateral-movement": "T1021 T1080 T1210 T1534 T1550 T1563 T1570",
    "collection": "T1005 T1025 T1039 T1074 T1113 T1114 T1115 T1119 T1123 T1125 T1185 T1213 T1530 T1560 T1602",
    "command-and-control": "T1001 T1008 T1071 T1090 T1092 T1095 T1102 T1104 T1105 T1132 T1205 T1219 T1568 T1571 T1572 T1573",
    "exfiltration": "T1011 T1020 T1029 T1030 T1041 T1048 T1052 T1537 T1567",
    "impact": "T1485 T1486 T1489 T1490 T1491 T1495 T1496 T1498 T1499 T1529 T1531 T1561 T1565 T1657",
}.items():
    for _t in _ids.split():
        _TECHNIQUE_PHASE[_t] = _phase

SEV_WEIGHT = {"critical": 5, "high": 4, "medium": 2, "low": 1, "info": 0}
_SEV_NAME = {5: "critical", 4: "high", 2: "medium", 1: "low", 0: "info"}
# what a Unified Audit Log or Entra operation is, as a phase (with no finding on it)
_OP_PHASE = {
    "mailitemsaccessed": ("collection", "mail read"),
    "new-inboxrule": ("collection", "an inbox rule"),
    "set-inboxrule": ("collection", "an inbox rule"),
    "updateinboxrules": ("collection", "an inbox rule"),
    "set-mailbox": ("collection", "mailbox settings changed"),
    "add-mailboxpermission": ("persistence", "mailbox permission granted"),
    "consent to application.": ("credential-access", "consent to an application"),
    "add app role assignment grant to user.": ("credential-access", "consent to an application"),
    "add member to role.": ("privilege-escalation", "a directory role granted"),
    "add user.": ("persistence", "an account created"),
    "reset user password.": ("persistence", "a password reset"),
    "filedownloaded": ("collection", "a file downloaded"),
    "filesyncdownloadedfull": ("collection", "files synced down"),
    "anonymouslinkcreated": ("exfiltration", "an anonymous link created"),
    "update conditional access policy.": ("defense-impairment", "conditional access changed"),
}
_ROUTINE_OPS = {"mailitemsaccessed", "fileaccessed", "filepreviewed", "filemodified", "filedownloaded", "userloggedin", "signin"}
_ROUTINE_EVENTS = {4624, 4625, 4634, 4647, 4672, 4776, 4768, 4769, 5140, 5145, 3, 22, 11, 7, 10}
_ACCOUNT_EVENTS = {4720: "an account created", 4722: "an account enabled", 4724: "a password reset", 4738: "an account changed"}
_GROUP_EVENTS = {4728, 4732, 4756}
_FOLD_MS = 10 * 60_000
_CONTEXT_BEFORE = 60 * 60_000


def _sev(v: Any) -> int:
    return SEV_WEIGHT.get(str(v or "").lower(), 0)


def _eid(ev: dict[str, Any]) -> int:
    try:
        return int(ev.get("eventId") or 0)
    except (TypeError, ValueError):
        return 0


def _ts(row: dict[str, Any]) -> int:
    v = row.get("ts") if row.get("ts") is not None else row.get("date")
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _hid(*parts: Any) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


def _is_cloud(ev: dict[str, Any]) -> bool:
    p = str(ev.get("provider") or "").lower()
    return "unified audit" in p or "entra" in p or str(ev.get("category") or "").lower().startswith(("m365", "entra"))


def _op(ev: dict[str, Any]) -> str:
    return str(ev.get("operation") or "").strip().lower()


def _is_process_creation(ev: dict[str, Any]) -> bool:
    """A program started (4688, Sysmon 1): what a person's routine day is mostly made of."""
    eid = _eid(ev)
    return eid == 4688 or (eid == 1 and "sysmon" in (str(ev.get("provider") or "") + str(ev.get("channel") or "")).lower())


# --- phases ---------------------------------------------------------------------------------------


def finding_phase(f: dict[str, Any]) -> tuple[str | None, str]:
    """A finding's phase: its rule's first tactic tag, else its first technique's tactic."""
    by_technique = None
    for t in f.get("attack") or []:
        m = re.match(r"(?i)(?:attack\.)?(t\d{4})", str(t))
        if m and m.group(1).upper() in _TECHNIQUE_PHASE:
            by_technique = (_TECHNIQUE_PHASE[m.group(1).upper()], f"technique {str(t).upper()}")
            break
    for t in f.get("tags") or []:
        p = _TAG_PHASE.get(str(t).lower())
        if p:
            # ATT&CK v19 split Defense Evasion into Stealth and Defense Impairment: the technique says which
            if str(t).lower() in ("defense-evasion", "evasion") and by_technique and by_technique[0] in ("stealth", "defense-impairment"):
                return by_technique[0], f"rule tag {t}, {by_technique[1]}"
            return p, f"rule tag {t}"
    return by_technique if by_technique else (None, "")


def record_phase(row: dict[str, Any], source: str, attacker: set[str]) -> tuple[str | None, str]:
    """A record's phase from what it is, for a record no finding reads; None for context."""
    if source == "mails":
        return "initial-access", "a phishing mail"
    eid = _eid(row)
    prov = (str(row.get("provider") or "") + str(row.get("channel") or "")).lower()
    ip = ip_of(row.get("ipAddress"))
    if _is_cloud(row):
        op = _op(row)
        outcome = authentication_outcome(row)
        if outcome == "failure":
            return "credential-access", "a failed sign-in"
        if outcome == "success" or op in ("signin", "userloggedin"):
            return ("initial-access", "a sign-in from an address the story's findings name") if ip in attacker else (None, "a sign-in")
        hit = _OP_PHASE.get(op)
        return hit if hit else (None, op or "a cloud record")
    if eid == 4625:
        return "credential-access", "a failed logon"
    if eid == 4624:
        lt = int(row.get("logonType") or 0)
        if lt in (10, 12):
            return ("initial-access", "an RDP logon from outside") if ip and not is_internal_ip(ip) else ("lateral-movement", "an RDP logon")
        if ip in attacker:
            return "initial-access", "a logon from an address the story's findings name"
        return None, "a logon"
    if eid in (1102, 104):
        return "defense-impairment", "a log cleared"
    if eid in (4698, 4702):
        return "persistence", "a scheduled task"
    if eid in (7045, 4697) and "sysmon" not in prov:
        return "persistence", "a service installed"
    if eid in _GROUP_EVENTS:
        return "persistence", "a member added to a group"
    if eid in _ACCOUNT_EVENTS:
        return "persistence", _ACCOUNT_EVENTS[eid]
    if eid == 4648:
        return "lateral-movement", "explicit credentials"
    if eid in (5140, 5145) and re.search(r"(?i)\\(admin\$|[a-z]\$)$", str(row.get("shareName") or "")):
        return "lateral-movement", "an admin share opened"
    if eid == 4104:
        return "execution", "a PowerShell script block"
    if _is_process_creation(row):
        return "execution", "a program ran"
    return None, ""


# --- steps ----------------------------------------------------------------------------------------


def _title(row: dict[str, Any], source: str) -> str:
    if source == "mails":
        who = ", ".join(mail_recipients(row)[:3])
        return f"Mail from {row.get('fromAddr') or '?'} to {who or '?'}: {row.get('subject') or '(no subject)'}"[:240]
    s = str(row.get("summary") or "").strip()
    if s and not re.fullmatch(r"Event \d+", s):
        return s[:240]
    eid = _eid(row)
    return f"{row.get('description') or ('Event ' + str(eid)) if eid else (row.get('operation') or 'record')}"[:240]


def _fold_key(row: dict[str, Any], source: str) -> str | None:
    """Records that fold into one step when they repeat: logons, sign-ins, mailbox reads, share access."""
    if source == "mails":
        return None
    if _is_cloud(row):
        op = _op(row)
        if op in _ROUTINE_OPS or authentication_outcome(row):
            return f"cloud|{op}|{row.get('ipAddress') or ''}|{authentication_outcome(row) or row.get('status') or ''}"
        return None
    eid = _eid(row)
    if eid in _ROUTINE_EVENTS:
        return f"host|{eid}|{host_key(row.get('computer'))}|{row.get('ipAddress') or ''}|{row.get('logonType') or ''}|{row.get('shareName') or ''}"
    return None


def _addr_of(forms: list[Form]) -> list[str]:
    return [f.value for f in forms if f.kind == "addr"]


class _Case:
    """What the builder reads: rows, findings and the accounts each record names, the identities and the lineage."""

    def __init__(
        self,
        events: list[dict[str, Any]],
        mails: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        settings: dict[str, Any],
        resolver: Resolver | None = None,
    ):
        self.settings = settings
        self.internal = {str(d).lower().strip(".") for d in (settings.get("internal_domains") or settings.get("internalDomains") or []) if d}
        self.rows: dict[str, tuple[dict[str, Any], str]] = {}
        for e in events:
            if e.get("id") is not None:
                self.rows[f"event:{e['id']}"] = (e, "events")
        for m in mails:
            if m.get("id") is not None:
                self.rows[f"mail:{m['id']}"] = (m, "mails")
        self.f_by_ref: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for f in findings:
            prefix = "mail" if f.get("source") == "mails" else "event"
            for r in f.get("refs") or []:
                ref = f"{prefix}:{r}"
                if ref in self.rows:
                    self.f_by_ref[ref].append(f)
        # a server case resolves the whole case's accounts, not only the rows selected around its flags
        self.resolver = resolver or resolve(events, mails, settings)
        self.lineage: Lineage = build_lineage(events, settings)
        # the people each record names, and each person's and address's records in time order
        self.named: dict[str, dict[str, tuple[str, str]]] = {}
        self.by_identity: dict[str, list[tuple[int, str]]] = defaultdict(list)
        self.by_ip: dict[str, list[tuple[int, str]]] = defaultdict(list)
        for ref, (row, source) in self.rows.items():
            rec = mail_record(row) if source == "mails" else event_record(row)
            got: dict[str, tuple[str, str]] = {}
            for iid, role, conf in self.resolver.of_record(rec):
                if conf != WEAK and self.storied(iid) and (iid not in got or CONFIDENCE_RANK[conf] > CONFIDENCE_RANK[got[iid][0]]):
                    got[iid] = (conf, role)
            self.named[ref] = got
            if source == "events":
                ts = _ts(row)
                for iid in got:
                    self.by_identity[iid].append((ts, ref))
                ip = ip_of(row.get("ipAddress"))
                if ip:
                    self.by_ip[ip].append((ts, ref))
        for lst in (*self.by_identity.values(), *self.by_ip.values()):
            lst.sort()

    def kind(self, iid: str) -> str:
        return self.resolver.by_id[iid]["kind"] if iid in self.resolver.by_id else "person"

    def storied(self, iid: str) -> bool:
        """A person or service account the case gives a name: a SID or an object id alone is no one to tell a story of."""
        ident = self.resolver.by_id.get(iid)
        return bool(ident) and ident["kind"] in ("person", "service") and any(f["kind"] in ("addr", "netbios", "dn", "name") for f in ident["forms"])

    def internal_addr(self, addr: str) -> bool:
        dom = addr.split("@", 1)[-1]
        return bool(self.internal) and any(same_org_domain(dom, d, self.internal) for d in self.internal)

    def people(self, ref: str) -> list[tuple[str, str, str]]:
        """(identity, confidence, how) for each person a record is about: whom it names, or whose session, process or hop it is."""
        row, source = self.rows[ref]
        named = self.named.get(ref, {})
        if source == "mails":
            # an inbound mail is about the organisation's recipients; a mail they send, about its sender
            rcpts = {i: c for i, (c, role) in named.items() if role == "recipient"}
            inside = {i: c for i, c in rcpts.items() if not self.internal or any(self.internal_addr(a) for a in _addr_of(self.resolver.forms(i)))}
            if self.internal and not inside:
                inside = {i: c for i, (c, role) in named.items() if role == "sender" and any(self.internal_addr(a) for a in _addr_of(self.resolver.forms(i)))}
            return [(i, c, "the mail was sent to them" if i in rcpts else "they sent the mail") for i, c in inside.items()]
        out = [(i, c, f"the record names them ({role})") for i, (c, role) in named.items()]
        if not out:
            out = [(i, STRONG, how) for i, how in self._lineage_people(ref, row)]
        return out

    def window(self, lst: list[tuple[int, str]], lo: int, hi: int) -> list[str]:
        i = bisect_left(lst, (lo, ""))
        out = []
        while i < len(lst) and lst[i][0] <= hi:
            out.append(lst[i][1])
            i += 1
        return out

    def account(self, user: Any, domain: Any = None, sid: Any = None) -> str | None:
        """The person a session, a process or a hop is of: never a machine account (a client push over ADMIN$) or Windows' own."""
        forms = account_forms(user, domain, sid)
        if not forms:
            return None
        got = [i for i, _, c in self.resolver.of_record(Record([forms], ["target"])) if c != WEAK and self.storied(i)]
        return got[0] if len(got) == 1 else None

    def _lineage_people(self, ref: str, row: dict[str, Any]) -> list[tuple[str, str]]:
        lin = self.lineage
        out = []
        for h in lin.hops_of(ref):
            iid = self.account(h.get("user"), h.get("domain"))
            if iid:
                out.append((iid, f"it is part of their way into {h['to']} ({h['kind']})"))
        s = lin.session_of(ref)
        if s:
            iid = self.account(s.get("user"), s.get("domain"), s.get("sid"))
            if iid:
                out.append((iid, f"it happened in their logon session {s['logonId']} on {s['host']}"))
        p = lin.process_of(ref) or lin.process_of_guid(row.get("processGuid"))
        depth = 0
        while p and depth < 6:
            if p.get("session") and p["session"] in lin.sessions:
                s2 = lin.sessions[p["session"]]
                iid = self.account(s2.get("user"), s2.get("domain"), s2.get("sid"))
                if iid:
                    out.append((iid, f"its process descends from {p['name']} in their session on {p['host']}"))
                    break
            p = lin.processes.get(p.get("parent") or "")
            depth += 1
        return out


def _anchor_kind(case: _Case, ref: str) -> str | None:
    """start: a flag that opens a story; support: one that only joins one (a mail received, a failed logon); None: not a flag."""
    row, source = case.rows[ref]
    fs = case.f_by_ref.get(ref, [])
    if not fs or max(_sev(f.get("severity")) for f in fs) < 2:
        return None
    if source == "mails" or authentication_outcome(row) == "failure":
        return "support"
    return "start"


# --- building -------------------------------------------------------------------------------------


def build_stories(
    events: Iterable[dict[str, Any]],
    mails: Iterable[dict[str, Any]],
    findings: Iterable[dict[str, Any]] | None = None,
    settings: dict[str, Any] | None = None,
    *,
    chains: dict[str, Any] | None = None,
    resolver: Resolver | None = None,
    gap_hours: float = 48.0,
    max_stories: int = 200,
    max_steps: int = 400,
) -> dict[str, Any]:
    """The stories, campaigns and unstoried flags of a case (or of the rows selected for it)."""
    settings = settings or {}
    events = list(events)
    mails = list(mails)
    findings = [f for f in (findings or []) if f.get("status") != "false_positive" and f.get("ruleId") != "chain"]
    case = _Case(events, mails, findings, settings, resolver)
    # the phishing chains read the same rows: the page keeps them for the review and the report
    chain_result = chains if chains is not None else build_chains(mails, events, findings, settings)
    chains = chain_result.get("chains") or []
    gap = int(gap_hours * 3600_000)

    flags: dict[str, list[tuple[int, str, str, str]]] = defaultdict(list)  # identity -> (ts, ref, kind, why)
    host_flags: dict[str, list[tuple[int, str, str, str]]] = defaultdict(list)
    unstoried: dict[str, str] = {}
    ties: dict[tuple[str, str], tuple[str, str]] = {}
    for ref in case.f_by_ref:
        kind = _anchor_kind(case, ref)
        if not kind:
            continue
        row, _ = case.rows[ref]
        people = case.people(ref)
        for iid, conf, how in people:
            flags[iid].append((_ts(row), ref, kind, how))
            ties[(iid, ref)] = (conf, how)
        if not people:
            if kind == "start" and host_key(row.get("computer")):
                host_flags[host_key(row.get("computer"))].append((_ts(row), ref, kind, ""))
            else:
                unstoried[ref] = "names no person, and no host a story could follow"
    chain_of: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in chains:
        if c.get("kind") == "authentication":
            continue
        iid = case.resolver.of_form(Form("addr", str(c.get("identity") or "").lower()))
        if not iid or not case.storied(iid):
            continue
        chain_of[iid].append(c)
        seed_ref = f"mail:{c['seed']['id']}"
        if seed_ref in case.rows:
            # the chain starts a story when the person did something with the mail (the link
            # resolved, the attachment saved, a reply); a flagged mail and routine activity around
            # it is still a mail received
            kind = "start" if c.get("artifactLinks") else "support"
            flags[iid].append((int(c["seed"]["ts"]), seed_ref, kind, "the phishing mail that starts the chain"))
            ties[(iid, seed_ref)] = (STRONG, "the phishing mail that starts the chain")

    # an address most of the organisation's users sign in from is its own, not the attacker's
    shared = _shared_egress(case)
    # each story with the flags that anchor it, so a flag its story cannot keep is still listed
    built: list[tuple[dict[str, Any], list[str]]] = []
    for iid, fl in flags.items():
        fl.sort()
        clusters, alone = _clusters(fl, gap)
        for _, ref, _, _ in alone:
            unstoried.setdefault(ref, "a mail received or a failed logon, and nothing more of this person's in the same days")
        for cluster in clusters:
            story = _person_story(case, iid, cluster, chain_of.get(iid, []), ties, gap, max_steps, shared)
            built.append((story, [ref for _, ref, _, _ in cluster]))
    for host, fl in host_flags.items():
        fl.sort()
        for cluster in _clusters(fl, gap)[0]:
            built.append((_host_story(case, host, cluster, max_steps), [ref for _, ref, _, _ in cluster]))
    built.sort(key=lambda b: (-b[0]["score"], b[0]["start"]))
    truncated = len(built) > max_stories
    stories = [s for s, _ in built[:max_stories]]
    # what is storied is what the kept stories hold: the flags of a story cut, or cut from its story's steps, are listed
    storied = {r for s in stories for st in s["steps"] for r in st["refs"]}
    lost: dict[str, str] = {}
    for n, (_, anchors) in enumerate(built):
        why = (
            f"its story passed {max_steps} steps and this one was cut"
            if n < max_stories
            else f"its story was cut: a case keeps its {max_stories} highest-scoring stories"
        )
        for ref in anchors:
            if ref not in storied:
                lost.setdefault(ref, why)
    campaigns = _campaigns(case, stories, unstoried, gap)
    by_id = {s["id"]: s for s in stories}
    for camp in campaigns:
        for sid in camp["stories"]:
            by_id[sid]["campaigns"].append(camp["id"])
    idents = sorted({s["subject"]["id"] for s in stories if s["kind"] == "person"} | {i for c in campaigns for i in c["people"]})
    hosts = sorted({h for s in stories for h in s["hosts"]})
    un = [
        {"ref": ref, "why": why, "findings": sorted({f.get("ruleId") for f in case.f_by_ref.get(ref, [])})[:5]}
        for ref, why in sorted({**unstoried, **lost}.items())
        if ref not in storied
    ]
    return {
        "version": VERSION,
        "stories": stories,
        "campaigns": campaigns,
        "chains": chain_result,
        "identities": [case.resolver.by_id[i] for i in idents if i in case.resolver.by_id],
        "hosts": [case.lineage.hosts[h] for h in hosts if h in case.lineage.hosts],
        "unstoried": un[:2000],
        "stats": {
            "events": len(events),
            "mails": len(mails),
            "findings": len(findings),
            "identities": len(case.resolver.identities),
            "sessions": len(case.lineage.sessions),
            "hops": len(case.lineage.hops),
            "processes": len(case.lineage.processes),
            "stories": len(stories),
            "storiesTruncated": int(truncated),
            # the stories that passed max_steps: each says how many of its steps it cut
            "stepsTruncated": sum(1 for s in stories if s["stepsTruncated"]),
            "campaigns": len(campaigns),
            "unstoried": len(un),
        },
    }


def _clusters(flags: list[tuple[int, str, str, str]], gap: int) -> tuple[list[list[tuple[int, str, str, str]]], list[tuple[int, str, str, str]]]:
    """One person's flags (in time order) as incidents, and the supporting flags near none.

    The flags that start a story are cut where two follow each other by more than the gap; a
    supporting flag (a mail received, a failed logon) then joins the incident nearest it, within
    the gap. Supports never bridge two incidents: a spray's daily failures between two intrusions
    three weeks apart leave them two stories."""
    out: list[list[tuple[int, str, str, str]]] = []
    for f in flags:
        if f[2] != "start":
            continue
        if out and f[0] - out[-1][-1][0] <= gap:
            out[-1].append(f)
        else:
            out.append([f])
    spans = [(c[0][0], c[-1][0]) for c in out]
    alone = []
    for f in flags:
        if f[2] == "start":
            continue
        near = min(range(len(spans)), key=lambda i: max(spans[i][0] - f[0], f[0] - spans[i][1], 0), default=None)
        if near is not None and max(spans[near][0] - f[0], f[0] - spans[near][1], 0) <= gap:
            out[near].append(f)
        else:
            alone.append(f)
    for c in out:
        c.sort()
    return out, alone


class _Members(dict):
    """The records of a story, each with the tie that put it there; the surest tie wins."""

    def take(self, ref: str, tie: str, conf: str, basis: str, notes: Iterable[str] = ()) -> None:
        cur = self.get(ref)
        notes = [n for n in notes if n]
        if cur and (cur["tie"] in ("flag", "chain") or CONFIDENCE_RANK[cur["confidence"]] >= CONFIDENCE_RANK[conf]):
            # a flag keeps its own reason; a surer tie found later raises its confidence and is added to it
            if CONFIDENCE_RANK[conf] > CONFIDENCE_RANK[cur["confidence"]]:
                cur["confidence"] = conf
                cur["also"] = basis
            cur["notes"].extend(n for n in notes if n not in cur["notes"])
            return
        self[ref] = {"tie": tie, "confidence": conf, "basis": basis, "notes": notes + [n for n in (cur["notes"] if cur else []) if n not in notes]}


def _person_story(
    case: _Case,
    iid: str,
    cluster: list[tuple[int, str, str, str]],
    chains: list[dict[str, Any]],
    ties: dict[tuple[str, str], tuple[str, str]],
    gap: int,
    max_steps: int,
    shared: Collection[str] = frozenset(),
) -> dict[str, Any]:
    ident = case.resolver.by_id[iid]
    start, end = cluster[0][0], cluster[-1][0]
    members = _Members()

    def mine(ref: str) -> bool:
        """A record in this person's story names them, or no person at all."""
        named = case.named.get(ref, {})
        return not named or iid in named

    for _, ref, _kind, how in cluster:
        conf, basis = ties.get((iid, ref), (STRONG, how))
        members.take(ref, "flag", conf, basis)
    # the phishing chains of this person in this incident: the steps with a finding, a link to the mail or weight
    used_chains = []
    for c in chains:
        if not (start - gap <= int(c["start"]) <= end + gap):
            continue
        used_chains.append(c)
        for st in c.get("steps", []):
            links = [a for a in st.get("artifacts", []) if a and (a.startswith("mail ") or "engaged" in a or a == "same thread")]
            if not (st.get("findings") or links or int(st.get("weight") or 0) >= 3):
                continue
            prefix = "mail" if st.get("source") == "mails" else "event"
            for r in st.get("refs") or ([st["id"]] if st.get("id") is not None else []):
                ref = f"{prefix}:{r}"
                if ref in case.rows and mine(ref):
                    members.take(ref, "chain", STRONG if links else MEDIUM, "a step of the phishing chain" + (f": {links[0]}" if links else ""), links)
        start, end = min(start, int(c["start"])), max(end, int(c["end"]))
    # the addresses the story's findings name as a source, but for the organisation's own shared egress
    attacker: set[str] = set()
    named_shared: set[str] = set()
    for ref in list(members):
        for f in case.f_by_ref.get(ref, []):
            if _sev(f.get("severity")) < 2:
                continue
            ents = f.get("entities") or {}
            for k in ("ipAddress", "sourceIp"):
                ip = ip_of(ents.get(k))
                if ip and not is_internal_ip(ip):
                    (named_shared if ip in shared else attacker).add(ip)
    _lineage_context(case, members)
    lin = case.lineage
    # the story's logon sessions and processes: a program run with no finding belongs to it only through them
    sessions = {s["id"] for ref in members if (s := lin.session_of(ref))}
    procs = {p["id"] for ref in members if (p := _process(case, ref))}
    lo, hi = start - _CONTEXT_BEFORE, end + gap // 2
    # the person's own records in the window: from those addresses, or that are something (a task, a rule, a clear)
    for ref in case.window(case.by_identity.get(iid, []), lo, hi):
        if ref in members:
            continue
        row, source = case.rows[ref]
        ip = ip_of(row.get("ipAddress"))
        phase, basis = record_phase(row, source, attacker)
        conf = case.named[ref][iid][0]
        if ip and ip in attacker:
            members.take(ref, "address", MEDIUM, f"it came from {ip}, a source the story's findings name")
        elif phase and _eid(row) not in (4624, 4625) and not _is_routine_cloud(row):
            if _is_process_creation(row) and not case.f_by_ref.get(ref):
                # a person's name alone does not make every program of their day part of the incident
                how = _in_story_tree(case, ref, sessions, procs)
                if not how:
                    continue
                basis = f"{basis}, {how}"
                if p := _process(case, ref):
                    procs.add(p["id"])
            members.take(ref, "identity", conf, f"it names {ident['label']}: {basis}")
    # what else those addresses did in the window: the other accounts they tried, the flags they raised
    for ip in sorted(attacker):
        for ref in case.window(case.by_ip.get(ip, []), lo, hi):
            if ref in members:
                continue
            row, _ = case.rows[ref]
            if authentication_outcome(row) == "failure" or case.f_by_ref.get(ref):
                if mine(ref) or authentication_outcome(row) == "failure":
                    members.take(ref, "address", MEDIUM, f"the same source, {ip}, in the same days" + ("; it tried another account" if not mine(ref) else ""))
    steps, cut = _steps(case, members, attacker, max_steps)
    subject = {"kind": "person", "id": iid, "label": ident["label"], "org": ident.get("org")}
    return _story(case, "person", subject, steps, attacker, used_chains, cut=cut, shared=named_shared)


def _is_routine_cloud(row: dict[str, Any]) -> bool:
    return _is_cloud(row) and (_op(row) in _ROUTINE_OPS or bool(authentication_outcome(row)))


def _process(case: _Case, ref: str) -> dict[str, Any] | None:
    row, source = case.rows[ref]
    if source != "events":
        return None
    return case.lineage.process_of(ref) or case.lineage.process_of_guid(row.get("processGuid"))


def _in_story_tree(case: _Case, ref: str, sessions: set[str], procs: set[str]) -> str | None:
    """How a program run with no finding is part of a story: it ran in one of the story's logon
    sessions, or it is, or descends from, one of the story's processes. None when only its name ties it."""
    lin = case.lineage
    s = lin.session_of(ref)
    if s and s["id"] in sessions:
        return f"in the story's logon session {s['logonId']} on {s['host']}"
    p = _process(case, ref)
    depth = 0
    while p and depth < 6:
        if p["id"] in procs:
            return "a process of the story" if depth == 0 else f"its process descends from {p['name']}, a process of the story"
        p = lin.processes.get(p.get("parent") or "")
        depth += 1
    return None


def _shared_egress(case: _Case) -> set[str]:
    """Outside addresses most of an organisation's users sign in from (an office's NAT, a VPN's egress).

    An address is shared when at least five people of one organisation signed in from it with no
    finding on any of their records from it, and they are more than half of that organisation's
    people seen signing in from outside. It is then no attacker's infrastructure: it ties no
    record to a story and joins no stories into a campaign."""
    signers: dict[Any, set[str]] = defaultdict(set)  # organisation -> people who signed in from an outside address
    clean: dict[str, set[str]] = defaultdict(set)  # address -> people who signed in from it
    flagged: dict[str, set[str]] = defaultdict(set)  # address -> people with a finding on a record from it
    for ip, lst in case.by_ip.items():
        if is_internal_ip(ip):
            continue
        for _, ref in lst:
            row, _ = case.rows[ref]
            fs = any(_sev(f.get("severity")) >= 2 for f in case.f_by_ref.get(ref, []))
            ok = authentication_outcome(row) == "success"
            for iid in case.named.get(ref, {}):
                if fs:
                    flagged[ip].add(iid)
                if ok:
                    clean[ip].add(iid)
                    signers[case.resolver.by_id.get(iid, {}).get("org")].add(iid)
    out = set()
    for ip, people in clean.items():
        by_org: dict[Any, int] = defaultdict(int)
        for iid in people - flagged[ip]:
            by_org[case.resolver.by_id.get(iid, {}).get("org")] += 1
        if any(n >= 5 and 2 * n > len(signers[org]) for org, n in by_org.items()):
            out.add(ip)
    return out


def _lineage_context(case: _Case, members: _Members) -> None:
    """Add what lineage ties to the members: the logon of their session, the rest of their hop, the processes that started theirs."""
    lin = case.lineage
    for ref in list(members):
        s = lin.session_of(ref)
        if s and s.get("logonRef") and s["logonRef"] != ref:
            members.take(s["logonRef"], "session", STRONG, f"the logon of session {s['logonId']} on {s['host']}, in which it happened")
        for h in lin.hops_of(ref):
            for r in h["refs"][:10]:
                if r != ref and r in case.rows:
                    members.take(r, "hop", STRONG, f"part of the same way into {h['to']} ({h['kind']}: {h['basis']})")
        p = lin.process_of(ref)
        depth = 0
        while p and p.get("parent") and depth < 3:
            p = lin.processes.get(p["parent"])
            depth += 1
            if p and p["refs"][0] in case.rows:
                members.take(p["refs"][0], "process", STRONG, f"the process that started it ({p['name']})")


def _host_story(case: _Case, host: str, cluster: list[tuple[int, str, str, str]], max_steps: int) -> dict[str, Any]:
    members = _Members()
    for _, ref, _, _ in cluster:
        members.take(ref, "flag", STRONG, f"a finding on {host}")
    _lineage_context(case, members)
    name = case.lineage.hosts.get(host, {}).get("name") or host
    steps, cut = _steps(case, members, set(), max_steps)
    return _story(case, "host", {"kind": "host", "id": host, "label": name, "org": None}, steps, set(), [], cut=cut)


def _phase_of(case: _Case, row: dict[str, Any], source: str, fs: list[dict[str, Any]], m: dict[str, Any], attacker: set[str]) -> tuple[str | None, str]:
    own, own_basis = record_phase(row, source, attacker)
    if source == "mails" and m["tie"] not in ("flag", "chain"):
        return None, "a mail"
    # a successful logon is initial access or lateral movement whatever the brute force before it reads as
    if authentication_outcome(row) == "success" and own:
        return own, own_basis
    phase, basis = None, ""
    for f in sorted(fs, key=lambda f: -_sev(f.get("severity"))):
        phase, basis = finding_phase(f)
        if phase:
            break
    if phase == "lateral-movement" and ip_of(row.get("ipAddress")) and not is_internal_ip(ip_of(row.get("ipAddress"))):
        return "initial-access", f"{basis}, from an address outside the network (external remote services)"
    if phase:
        return phase, basis
    if any(n.startswith("mail ") for n in m["notes"]):
        return "execution", "the phishing mail's link or attachment reached the host (user execution)"
    return own, own_basis


def _steps(case: _Case, members: _Members, attacker: set[str], max_steps: int) -> tuple[list[dict[str, Any]], int]:
    """The members as steps in time order, folded where they repeat, and how many were cut past max_steps."""
    lin = case.lineage
    raw = []
    for ref, m in members.items():
        row, source = case.rows[ref]
        fs = case.f_by_ref.get(ref, [])
        top = max((_sev(f.get("severity")) for f in fs), default=0)
        phase, basis = _phase_of(case, row, source, fs, m, attacker)
        s = lin.session_of(ref)
        p = lin.process_of(ref) or lin.process_of_guid(row.get("processGuid"))
        named = case.named.get(ref, {})
        # a sign-in from an Entra device named like a host of the case happened on that host
        dev = lin.device_of(row) if source == "events" and _is_cloud(row) else None
        where = [
            f"from the Entra device {dev['name']}"
            + (f" ({', '.join(dev['trustTypes'])})" if dev["trustTypes"] else "")
            + ("" if dev.get("host") else ", a device the case has no logs of")
        ] if dev else []  # fmt: skip
        raw.append(
            {
                "id": ref,
                "refs": [ref],
                "source": source,
                "ts": _ts(row),
                "tsEnd": _ts(row),
                "count": 1,
                "title": _title(row, source),
                "host": host_key(row.get("computer")) or (dev["host"] if dev else None),
                "ip": ip_of(row.get("ipAddress")) or None,
                "origin": "mail" if source == "mails" else "cloud" if _is_cloud(row) else "host",
                "phase": phase,
                "phaseBasis": basis,
                "findings": [{"ruleId": f.get("ruleId"), "title": f.get("title"), "severity": f.get("severity"), "key": f.get("key")} for f in fs][:8],
                "severity": _SEV_NAME.get(top) if fs else None,
                "tie": {"kind": m["tie"], "basis": m["basis"] + (f"; also {m['also']}" if m.get("also") else ""), "confidence": m["confidence"]},
                "notes": (m["notes"] + where)[:6],
                "accounts": sorted(named)[:10],
                "session": s["id"] if s else None,
                "process": p["id"] if p else None,
                "hops": [h["id"] for h in lin.hops_of(ref)][:5],
                "routine": not fs and m["tie"] != "flag" and _fold_key(row, source) is not None,
                "_fold": _fold_key(row, source),
            }
        )
    raw.sort(key=lambda s: (s["ts"], s["id"]))
    entered: dict[str, str] = {}
    for st in raw:
        ip = st["ip"]
        if not ip or st["origin"] != "host":
            continue
        if st["phase"] == "initial-access" and "outside the network" in st["phaseBasis"] and ip in entered and entered[ip] != st["host"]:
            st["phase"], st["phaseBasis"] = (
                "lateral-movement",
                f"{st['phaseBasis'].split(', from an address')[0]}; the same outside source was already in on {entered[ip]}",
            )
        elif st["phase"] == "initial-access":
            entered.setdefault(ip, st["host"] or "")
    steps: list[dict[str, Any]] = []
    last: dict[tuple[str, str, str], dict[str, Any]] = {}
    for st in raw:
        key = (st["_fold"], st["tie"]["kind"], ",".join(sorted({f["ruleId"] or "" for f in st["findings"]}))) if st["_fold"] else None
        prev = last.get(key) if key else None
        if prev and st["ts"] - prev["tsEnd"] <= _FOLD_MS:
            prev["refs"].append(st["id"])
            prev["count"] += 1
            prev["tsEnd"] = st["ts"]
            prev["accounts"] = sorted(set(prev["accounts"]) | set(st["accounts"]))[:50]
            continue
        steps.append(st)
        if key:
            last[key] = st
    for st in steps:
        st.pop("_fold", None)
    cut = max(0, len(steps) - max_steps)
    if cut:
        keep = sorted(steps, key=lambda s: (_keep_rank(s), -max((_sev(f["severity"]) for f in s["findings"]), default=0), s["ts"]))[:max_steps]
        ids = {id(s) for s in keep}
        steps = [s for s in steps if id(s) in ids]
    return steps, cut


# the phases a story keeps first when it has too many steps: what changes what an intruder holds
# (a way in, a foothold, privileges, credentials, another host, the logs, the data)
_KEEP_FIRST = {"initial-access", "persistence", "privilege-escalation", "defense-impairment", "credential-access", "lateral-movement", "exfiltration", "impact"}


def _keep_rank(st: dict[str, Any]) -> int:
    """Which steps a story past max_steps keeps first: its flags; persistence, privilege, credential and
    lateral steps and the like; its sessions, hops, process parents and sources; other steps with a
    phase (a program run with no finding among them); and last routine records and context."""
    if st["findings"] or st["tie"]["kind"] in ("flag", "chain"):
        return 0
    if st["phase"] in _KEEP_FIRST:
        return 1
    if st["tie"]["kind"] in ("session", "hop", "process", "address"):
        return 2
    if st["phase"] and not st["routine"]:
        return 3
    return 4


def _story(
    case: _Case,
    kind: str,
    subject: dict[str, Any],
    steps: list[dict[str, Any]],
    attacker: set[str],
    chains: list[dict[str, Any]],
    *,
    cut: int = 0,
    shared: Collection[str] = frozenset(),
) -> dict[str, Any]:
    lin = case.lineage
    refs = [r for s in steps for r in s["refs"]]
    start = min((s["ts"] for s in steps), default=0)
    end = max((s["tsEnd"] for s in steps), default=0)
    by_phase: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in steps:
        if s["phase"]:
            by_phase[s["phase"]].append(s)
    phases = []
    for p, ss in sorted(by_phase.items(), key=lambda kv: (min(s["ts"] for s in kv[1]), PHASE_ORDER[kv[0]])):
        top = max((_sev(f["severity"]) for s in ss for f in s["findings"]), default=0)
        phases.append(
            {
                "phase": p,
                "label": PHASE_LABEL[p],
                "first": min(s["ts"] for s in ss),
                "last": max(s["tsEnd"] for s in ss),
                "steps": len(ss),
                "records": sum(s["count"] for s in ss),
                "findings": len({f["key"] or f["ruleId"] for s in ss for f in s["findings"]}),
                "severity": _SEV_NAME.get(top) if top else None,
            }
        )
    fkeys = sorted({f["key"] or f["ruleId"] for s in steps for f in s["findings"] if f.get("key") or f.get("ruleId")})
    top = max((_sev(f["severity"]) for s in steps for f in s["findings"]), default=0)
    flagged_phases = {p["phase"] for p in phases if p["severity"] in ("medium", "high", "critical")}
    score = min(100, sum(SEV_WEIGHT[p["severity"]] * 4 for p in phases if p["severity"]) + (10 if chains else 0) + min(10, len(flagged_phases) * 2))
    severity = _SEV_NAME.get(top) or "low"
    # three phases or more, each with a finding of medium or more, is an intrusion however each rule reads alone
    if len(flagged_phases) >= 3 and SEV_WEIGHT[severity] < 4:
        severity = "high"
    confidence = STRONG if all(s["tie"]["confidence"] == STRONG for s in steps if s["tie"]["kind"] in ("flag", "chain")) else MEDIUM
    hosts = sorted({s["host"] for s in steps if s["host"]})
    accounts = sorted({a for s in steps for a in s["accounts"]})
    lineage = lin.to_dict(refs=refs, hosts=hosts)
    gaps = [lim for h in lineage["hosts"] for lim in h["limits"]]
    if cut:
        gaps.append(
            f"The story keeps {len(steps)} of its {len(steps) + cut} steps: its flags first, then persistence, privilege, credential and "
            "lateral steps, then its sessions, hops and sources; the programs run with no finding and the routine records are cut first, "
            "so a step absent from it is not a negative result."
        )
    anchor = min((r for s in steps if s["tie"]["kind"] in ("flag", "chain") for r in s["refs"]), default=str(start))
    headline, summary = _describe(subject, steps, phases, attacker, hosts, shared)
    return {
        "id": "story-" + _hid(kind, subject["id"], anchor),
        "kind": kind,
        "subject": subject,
        "title": subject["label"],
        "headline": headline,
        "summary": summary,
        "start": start,
        "end": end,
        "severity": severity,
        "score": score,
        "confidence": confidence,
        "phases": phases,
        "steps": steps,
        "records": len(refs),
        "hosts": hosts,
        "accounts": accounts,
        "ips": sorted({s["ip"] for s in steps if s["ip"]}),
        "attackerAddresses": sorted(attacker),
        # addresses the findings name that most of the organisation's users sign in from: no tie, no campaign
        "sharedAddresses": sorted(shared),
        "chains": [c["id"] for c in chains if c.get("id")],
        "findings": fkeys,
        "campaigns": [],
        "gaps": gaps,
        "stepsTruncated": cut,
        "lineage": {"sessions": lineage["sessions"], "hops": lineage["hops"], "processes": lineage["processes"]},
    }


def _describe(
    subject: dict[str, Any],
    steps: list[dict[str, Any]],
    phases: list[dict[str, Any]],
    attacker: set[str],
    hosts: list[str],
    shared: Collection[str] = frozenset(),
) -> tuple[str, str]:
    """A headline (the worst finding of each phase, in order) and a few plain sentences, from the story's own steps only."""
    parts = []
    for p in phases:
        cands = [s for s in steps if s["phase"] == p["phase"] and s["findings"]]
        if not cands:
            continue
        best = max(cands, key=lambda s: (max(_sev(f["severity"]) for f in s["findings"]), -s["ts"]))
        f = max(best["findings"], key=lambda f: _sev(f["severity"]))
        t = str(f.get("title") or f.get("ruleId") or "")
        if t and t not in parts:
            parts.append(t)
    headline = " → ".join(parts[:4]) + (f" → {len(parts) - 4} more" if len(parts) > 4 else "") if parts else "No phase is flagged"
    lines = []
    first = next((s for s in steps if s["tie"]["kind"] in ("flag", "chain")), steps[0] if steps else None)
    if first:
        lines.append(f"It starts with: {first['title'][:180]}.")
    flagged = [s for s in steps if s["findings"]]
    if phases:
        lines.append(f"{len(phases)} phase{'s' if len(phases) != 1 else ''}: {', '.join(p['label'].lower() for p in phases)}.")
    if flagged:
        lines.append(f"{len(flagged)} of its {len(steps)} steps carry findings.")
    if attacker:
        lines.append(f"The findings name {', '.join(sorted(attacker)[:3])} as a source.")
    if shared:
        lines.append(f"Most of the organisation's users sign in from {', '.join(sorted(shared)[:3])}, which the findings name: it ties nothing to the story.")
    if hosts:
        lines.append(f"Hosts: {', '.join(hosts[:5])}{' and more' if len(hosts) > 5 else ''}.")
    return headline[:300], " ".join(lines)[:900]


def _campaigns(case: _Case, stories: list[dict[str, Any]], unstoried: dict[str, str], gap: int) -> list[dict[str, Any]]:
    """Stories that share the attacker's infrastructure, with the accounts the same sources reached outside any story around them."""
    arts_of = {s["id"]: _artifacts(case, s) for s in stories}
    artifacts: dict[tuple[str, str], set[str]] = defaultdict(set)
    for sid, arts in arts_of.items():
        for a in arts:
            artifacts[a].add(sid)
    parent = {s["id"]: s["id"] for s in stories}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for ids in artifacts.values():
        first, *rest = sorted(ids)
        for other in rest:
            parent[find(other)] = find(first)
    groups: dict[str, list[str]] = defaultdict(list)
    for s in stories:
        groups[find(s["id"])].append(s["id"])
    by_id = {s["id"]: s for s in stories}
    out = []
    for members in groups.values():
        mset = set(members)
        arts = sorted({a for m in members for a in arts_of[m]})
        shared = [(a, sorted(artifacts[a])) for a in arts if len(artifacts[a]) > 1]
        people = {s["subject"]["id"] for m in members if (s := by_id[m])["kind"] == "person"}
        # an address can be someone else's a week later (a proxy, a reassigned lease): what it reached counts near the stories only
        spans = [(by_id[m]["start"] - gap, by_id[m]["end"] + gap) for m in members]
        targets = _targets(case, arts, people, unstoried, spans)
        if len(members) < 2 and not targets:
            continue
        ss = sorted((by_id[m] for m in members), key=lambda s: s["start"])
        # named by what the stories share, else by what reached the targets
        label_art = (
            max(shared, key=lambda a: (len(a[1]), a[0][0] == "ip"))[0]
            if shared
            else next(
                (a for a in arts if a[0] in ("ip", "sender-domain") and any(a[1] in t["via"] for t in targets)), arts[0] if arts else ("story", ss[0]["title"])
            )
        )
        out.append(
            {
                "id": "campaign-" + _hid(*sorted(members)),
                "label": label_art[1],
                "labelKind": label_art[0],
                "artifacts": [{"kind": k, "value": v, "stories": sorted(artifacts[(k, v)] & mset)} for k, v in arts][:40],
                "stories": [s["id"] for s in ss],
                "people": sorted(people),
                "targets": targets[:300],
                "start": min(s["start"] for s in ss),
                "end": max(s["end"] for s in ss),
                "severity": max((s["severity"] for s in ss), key=lambda v: SEV_WEIGHT.get(v, 0)),
            }
        )
    # flags in no story and no campaign above: mails from one sender domain, failed logons from one address
    covered = {r for c in out for t in c["targets"] for r in t["refs"]} | {r for s in stories for st in s["steps"] for r in st["refs"]}
    loose: dict[tuple[str, str], list[str]] = defaultdict(list)
    for ref in sorted(unstoried):
        if ref in covered:
            continue
        row, source = case.rows[ref]
        if source == "mails":
            frm = str(row.get("fromAddr") or "").lower()
            if "@" in frm:
                loose[("sender-domain", frm.split("@", 1)[1])].append(ref)
        elif ip_of(row.get("ipAddress")):
            loose[("ip", ip_of(row.get("ipAddress")))].append(ref)
    for (k, v), refs in sorted(loose.items()):
        targets: dict[str, dict[str, Any]] = {}
        for ref in refs:
            row, source = case.rows[ref]
            how = "received a flagged mail" if source == "mails" else "failed logon" if authentication_outcome(row) == "failure" else "flagged record"
            for iid, _, _ in case.people(ref) or [(i, None, None) for i in case.named.get(ref, {})]:
                t = targets.setdefault(iid, {"id": iid, "account": case.resolver.by_id[iid]["label"], "how": [how], "via": [v], "refs": []})
                if how not in t["how"]:
                    t["how"].append(how)
                if len(t["refs"]) < 20:
                    t["refs"].append(ref)
        if not targets:
            continue
        times = [_ts(case.rows[r][0]) for r in refs]
        out.append(
            {
                "id": "campaign-" + _hid(k, v),
                "label": v,
                "labelKind": k,
                "artifacts": [{"kind": k, "value": v, "stories": []}],
                "stories": [],
                "people": [],
                "targets": sorted(targets.values(), key=lambda t: t["account"])[:300],
                "start": min(times),
                "end": max(times),
                "severity": _SEV_NAME.get(max(_sev(f.get("severity")) for r in refs for f in case.f_by_ref.get(r, [])), "low"),
            }
        )
    out.sort(key=lambda c: (-len(c["stories"]), -len(c["targets"]), c["start"]))
    return out


def _artifacts(case: _Case, story: dict[str, Any]) -> list[tuple[str, str]]:
    """The attacker's infrastructure a story's flags show: addresses, sender and link domains, attachments, forwarding addresses, applications."""
    out: list[tuple[str, str]] = [("ip", ip) for ip in story["attackerAddresses"]]
    for s in story["steps"]:
        if s["tie"]["kind"] not in ("flag", "chain"):
            continue
        row, source = case.rows[s["id"]]
        if source == "mails":
            frm = str(row.get("fromAddr") or "").lower()
            if "@" in frm and not case.internal_addr(frm) and s["findings"]:
                out.append(("sender-domain", frm.split("@", 1)[1]))
            if not s["findings"]:
                continue
            for u in row.get("urls") or []:
                d = str(u.get("domain") if isinstance(u, dict) else "").lower()
                if d and not any(same_org_domain(d, i, case.internal) for i in case.internal):
                    out.append(("link-domain", d))
            for a in row.get("attachments") or []:
                h = a.get("sha256") if isinstance(a, dict) else None
                if h:
                    out.append(("attachment", str(h).lower()))
        else:
            text = str(row.get("summary") or "")
            for m in re.finditer(r"(?i)(?:forwardto|forwardingsmtpaddress|redirectto)=(?:smtp:)?([\w.+-]+@[\w.-]+)", text):
                out.append(("forwarding", m.group(1).lower()))
            if _op(row) in ("consent to application.", "add app role assignment grant to user.") and row.get("objectName"):
                out.append(("application", str(row["objectName"])))
    return sorted(set(out))


def _targets(case: _Case, arts: list[tuple[str, str]], people: set[str], unstoried: dict[str, str], spans: list[tuple[int, int]]) -> list[dict[str, Any]]:
    """Accounts outside the campaign's stories that its sources reached within the gap of one of them:
    the recipients of its mails, the accounts its addresses tried."""
    ips = {v for k, v in arts if k == "ip"}
    senders = {v for k, v in arts if k == "sender-domain"}
    out: dict[str, dict[str, Any]] = {}

    def near(ts: int) -> bool:
        return any(lo <= ts <= hi for lo, hi in spans)

    def add(iid: str, how: str, via: str, ref: str) -> None:
        if iid in people:
            return
        t = out.setdefault(
            iid, {"id": iid, "account": case.resolver.by_id[iid]["label"] if iid in case.resolver.by_id else iid, "how": set(), "via": set(), "refs": []}
        )
        t["how"].add(how)
        t["via"].add(via)
        if len(t["refs"]) < 20:
            t["refs"].append(ref)

    for ip in sorted(ips):
        for ts, ref in case.by_ip.get(ip, []):
            if not near(ts):
                continue
            row, _ = case.rows[ref]
            outcome = authentication_outcome(row)
            if outcome is None and not case.f_by_ref.get(ref):
                continue
            how = "failed logon" if outcome == "failure" else "logged on" if outcome == "success" else "flagged record"
            for iid in case.named.get(ref, {}):
                add(iid, how, ip, ref)
    for ref in unstoried:
        row, source = case.rows[ref]
        if source != "mails":
            continue
        frm = str(row.get("fromAddr") or "").lower()
        if "@" in frm and frm.split("@", 1)[1] in senders and near(_ts(row)):
            for iid, _, _ in case.people(ref):
                add(iid, "received a flagged mail", frm.split("@", 1)[1], ref)
    return sorted(({**t, "how": sorted(t["how"]), "via": sorted(t["via"])} for t in out.values()), key=lambda t: t["account"])


# --- selecting the rows of a case ------------------------------------------------------------------

# events read per build (each selection below); beyond it the stats say the stories were cut
EVENT_CAP = 50_000
MAIL_CAP = 5_000
# before and after a flag, the time whose records a story may hold
WINDOW_BEFORE_MS = 24 * 3600_000
WINDOW_AFTER_MS = 72 * 3600_000
# the records lineage reads on a flagged host: logons and sessions, processes, shares, services, tasks, RDP
LINEAGE_EVENT_IDS = (
    1, 3, 21, 23, 24, 25, 104, 1102, 1116, 1117, 1149, 4624, 4625, 4634, 4647, 4648, 4672, 4688, 4697, 4698, 4702,
    4720, 4722, 4724, 4728, 4732, 4738, 4756, 4778, 4779, 4781, 5140, 5145, 7045,
)  # fmt: skip
# and, by channel, WinRM's session records, WMI's failed calls and the DNS client's answers; the
# script blocks that name a remote computer; the DNS answers that give a private address (their own
# cap); the DHCP server's leases (no time, so case-wide)
LINEAGE_CHANNEL_EVENTS = (("winrm", (6, 91)), ("wmi-activity", (5858,)), ("dns-client", (3008,)))
REMOTE_SCRIPT = r"-computername|-cn\s|enter-pssession|/node:"
PRIVATE_ANSWER = r"(^|;)\s*(::ffff:)?(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"
DNS_CAP = 20_000
DHCP_CAP = 20_000
# the account names, flagged hosts and outside addresses a selection reads around the flags
NAME_KEYS = 2_000
HOST_KEYS = 500
ADDRESS_KEYS = 500
# a selection past its cap reads first the records that are something (a task, a service, an account
# or group changed, a log cleared, explicit credentials, a mailbox rule or permission, a consent),
# then the records nearest a flag, so a late phase is not what a cut loses first
WEIGHTY_EVENT_IDS = (104, 1102, 4648, 4697, 4698, 4702, 4720, 4722, 4724, 4728, 4732, 4738, 4756, 4781, 7045)
WEIGHTY_OPERATIONS = tuple(sorted(op for op in _OP_PHASE if op not in _ROUTINE_OPS))


def _lineage_extra_sql() -> str:
    """The records beyond LINEAGE_EVENT_IDS lineage reads on a flagged host, as SQL (stories.ts has the same test)."""
    parts = [
        f"(\"eventId\" IN ({', '.join(str(i) for i in ids)}) AND strpos(lower(coalesce(\"channel\", '')), '{chan}') > 0)"
        for chan, ids in LINEAGE_CHANNEL_EVENTS
    ]
    parts.append(f"(\"eventId\" = 4104 AND regexp_matches(lower(coalesce(\"scriptBlockText\", '')), '{REMOTE_SCRIPT}'))")
    return " OR ".join(parts)


def flagged_refs(findings: Iterable[dict[str, Any]]) -> tuple[list[int], list[int]]:
    """The event and mail ids the findings cite."""
    ev, ml = set(), set()
    for f in findings:
        if f.get("status") == "false_positive" or f.get("ruleId") == "chain":
            continue
        for r in f.get("refs") or []:
            try:
                (ml if f.get("source") == "mails" else ev).add(int(r))
            except (TypeError, ValueError):
                continue
    return sorted(ev), sorted(ml)


def windows(times: Iterable[int], before: int = WINDOW_BEFORE_MS, after: int = WINDOW_AFTER_MS, most: int = 40) -> list[tuple[int, int]]:
    """The flags' times widened and merged; too many windows become one from the first to the last."""
    spans: list[list[int]] = []
    for t in sorted(t for t in times if t):
        if spans and t - before <= spans[-1][1]:
            spans[-1][1] = max(spans[-1][1], t + after)
        else:
            spans.append([t - before, t + after])
    if len(spans) > most:
        spans = [[spans[0][0], spans[-1][1]]]
    return [(a, b) for a, b in spans]


def selection_keys(
    rows: Iterable[dict[str, Any]], mails: Iterable[dict[str, Any]], findings: Iterable[dict[str, Any]], settings: dict[str, Any]
) -> dict[str, list[str]]:
    """What to read around the flags: the account names the flagged records name, the outside addresses the findings name, the flagged hosts.

    Past its cap a kind keeps the keys the most flags name, and "cut" names each kind that was cut
    (name-keys, host-keys, address-keys)."""
    names: Counter[str] = Counter()
    hosts: Counter[str] = Counter()
    ips: Counter[str] = Counter()
    for row in rows:
        for g in event_record(row).groups:
            for f in g:
                n = base_name(f)
                if n and not n.endswith("$") and len(n) > 1 and kind_of(f) not in ("builtin", "machine"):
                    names[n] += 1
        if row.get("computer"):
            hosts[str(row["computer"]).lower()] += 1
        ip = ip_of(row.get("ipAddress"))
        if ip and not is_internal_ip(ip):
            ips[ip] += 1
    for m in mails:
        for a in mail_recipients(m) + [str(m.get("fromAddr") or "").lower()]:
            if "@" in a:
                names[a.split("@", 1)[0]] += 1
    for f in findings:
        if _sev(f.get("severity")) >= 2:
            ip = ip_of((f.get("entities") or {}).get("ipAddress"))
            if ip and not is_internal_ip(ip):
                ips[ip] += 1

    def top(c: Counter[str], most: int) -> list[str]:
        return sorted(sorted(c, key=lambda k: (-c[k], k))[:most])

    kinds = (("names", "name-keys", names, NAME_KEYS), ("hosts", "host-keys", hosts, HOST_KEYS), ("ips", "address-keys", ips, ADDRESS_KEYS))
    out = {key: top(c, most) for key, _, c, most in kinds}
    out["cut"] = [cut for _, cut, c, most in kinds if len(c) > most]
    return out


def _sql_str(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _nearest_first(table: str, col: str, where: str, first: str = "") -> str:
    """SELECT a table's rows matching `where`, those `first` ranks 0 before the others, then the
    nearest a flag's time before the farther: the flags' times are the first parameter, a list.
    Each row finds the flag before it and the flag after it by an ASOF join, so the order costs
    a sort, not a comparison with every flag."""
    c = f'r."{col}"'
    return (
        f"WITH flag_times AS (SELECT DISTINCT unnest(?::BIGINT[]) AS t) SELECT r.* FROM {table} r "
        f"ASOF LEFT JOIN flag_times fb ON {c} >= fb.t ASOF LEFT JOIN flag_times fa ON {c} <= fa.t "
        f"WHERE {where} ORDER BY {first + ', ' if first else ''}"
        f"least(coalesce({c} - fb.t, {2**62}), coalesce(fa.t - {c}, {2**62})), {c}, r.id"
    )


def stories_for_store(store: Any, settings: dict[str, Any] | None, findings: list[dict[str, Any]] | None = None, **opts: Any) -> dict[str, Any]:
    """Select the flagged records of a server case and what surrounds them by SQL, then build its stories."""
    import json as _json

    from services.store import queries as Q
    from services.store.casestore import rows_to_dicts

    from .identity import records_for_store

    settings = settings or {}
    findings = [f for f in (findings or []) if f.get("status") != "false_positive" and f.get("ruleId") != "chain"]
    ev_ids, ml_ids = flagged_refs(findings)
    cur = store.cursor()
    truncated: dict[str, int] = {}

    def fetch(sql: str, params: list[Any], cap: int, name: str) -> list[dict[str, Any]]:
        cur.execute(f"{sql} LIMIT {cap + 1}", params)
        rows = rows_to_dicts(cur)
        if len(rows) > cap:
            truncated[name] = 1
        return rows[:cap]

    events: dict[int, dict[str, Any]] = {}
    for i in range(0, min(len(ev_ids), EVENT_CAP), 5_000):
        chunk = ev_ids[i : i + 5_000]
        for r in fetch(f"SELECT * FROM events WHERE id IN ({', '.join('?' for _ in chunk)})", chunk, 5_000, "flagged"):
            events[r["id"]] = r
    if len(ev_ids) > EVENT_CAP:
        truncated["flagged"] = 1
    mails = {}
    if ml_ids:
        for m in Q.search(store, "mails", {"conditions": [{"field": "id", "op": "in", "value": ml_ids[:MAIL_CAP]}]}, limit=MAIL_CAP, full=True)["rows"]:
            mails[m["id"]] = m
    seeds = Q.search(
        store,
        "mails",
        {"conditions": [{"field": "risk", "op": "gte", "value": int(opts.get("seed_min_risk", 45))}]},
        limit=300,
        sort={"field": "risk", "dir": "desc"},
        full=True,
    )["rows"]
    for m in seeds:
        mails.setdefault(m["id"], m)
    for r in events.values():
        if isinstance(r.get("data"), str):
            try:
                r["data"] = _json.loads(r["data"])
            except ValueError:
                pass
    keys = selection_keys(events.values(), mails.values(), findings, settings)
    for name in keys["cut"]:
        truncated[name] = 1
    times = [int(r.get("ts") or 0) for r in events.values()] + [int(m.get("date") or 0) for m in mails.values()]
    flag_times = sorted({t for t in times if t})
    spans = windows(times)
    if spans:
        when = " OR ".join("ts BETWEEN ? AND ?" for _ in spans)
        wparams: list[Any] = [x for s in spans for x in s]
        names = keys["names"] or ["__no_name__"]
        ph = ", ".join("?" for _ in names)
        ident = " OR ".join(_IDENT_SQL.format(col=f'"{c}"') + f" IN ({ph})" for c in ("targetUser", "subjectUser", "user", "upn"))
        picks = [(f"({ident})", names * 4, "identities")]
        if keys["ips"]:
            picks.append((f'"ipAddress" IN ({", ".join("?" for _ in keys["ips"])})', list(keys["ips"]), "addresses"))
        if keys["hosts"]:
            hph = ", ".join("?" for _ in keys["hosts"])
            picks.append(
                (
                    f'lower("computer") IN ({hph}) AND ("eventId" IN ({", ".join(str(i) for i in LINEAGE_EVENT_IDS)}) OR {_lineage_extra_sql()})',
                    list(keys["hosts"]),
                    "hosts",
                )
            )
            picks.append(
                (
                    f'lower("computer") IN ({hph}) AND "eventId" = 22 AND strpos(lower(coalesce("provider", \'\')), \'sysmon\') > 0 '
                    f"AND regexp_matches(coalesce(\"queryResults\", ''), '{PRIVATE_ANSWER}')",
                    list(keys["hosts"]),
                    "dns",
                )
            )
        weighty = (
            f'CASE WHEN "eventId" IN ({", ".join(str(i) for i in WEIGHTY_EVENT_IDS)}) '
            f"OR lower(coalesce(\"operation\", '')) IN ({', '.join(_sql_str(op) for op in WEIGHTY_OPERATIONS)}) THEN 0 ELSE 1 END"
        )
        for cond, params, name in picks:
            cap = DNS_CAP if name == "dns" else EVENT_CAP
            for r in fetch(_nearest_first("events", "ts", f"({when}) AND ({cond})", weighty), [flag_times, *wparams, *params], cap, name):
                if r["id"] not in events:
                    if isinstance(r.get("data"), str):
                        try:
                            r["data"] = _json.loads(r["data"])
                        except ValueError:
                            pass
                    events[r["id"]] = r
        # the DHCP server's leases: they have no time, so they are read whatever the windows
        for r in fetch('SELECT * FROM events WHERE "artifactType" = \'dhcp\' AND "ipAddress" IS NOT NULL ORDER BY id', [], DHCP_CAP, "dhcp"):
            if r["id"] not in events:
                if isinstance(r.get("data"), str):
                    try:
                        r["data"] = _json.loads(r["data"])
                    except ValueError:
                        pass
                events[r["id"]] = r
        # replies: mails the flagged people sent in the windows
        mph = ", ".join("?" for _ in names)
        sender = _IDENT_SQL.format(col='"fromAddr"')
        cur.execute(
            _nearest_first("mails", "date", f"({when.replace('ts BETWEEN', 'date BETWEEN')}) AND {sender} IN ({mph})") + f" LIMIT {MAIL_CAP + 1}",
            [flag_times, *wparams, *names],
        )
        replies = Q._parse_json_cols(rows_to_dicts(cur), "mails") if hasattr(Q, "_parse_json_cols") else rows_to_dicts(cur)
        if len(replies) > MAIL_CAP:
            truncated["replies"] = 1
        for m in replies[:MAIL_CAP]:
            mails.setdefault(m["id"], m)
    # who is who is read on the whole case: a bare name is judged against every account of that name,
    # and a SID in a script block's header joins its account whatever logon stated the two together
    records, pairs, istats = records_for_store(store)
    if istats["truncated"]:
        # the rarest combinations were cut: the selected rows' own are read too, so each names someone
        truncated["accounts"] = 1
        resolver = resolve(events.values(), mails.values(), settings, records=records, netbios_pairs=pairs)
    else:
        resolver = resolve(settings=settings, records=records, netbios_pairs=pairs)
    result = build_stories(
        list(events.values()),
        list(mails.values()),
        findings,
        settings,
        resolver=resolver,
        **{k: v for k, v in opts.items() if k in ("gap_hours", "max_stories", "max_steps")},
    )
    result["stats"]["truncated"] = sorted(truncated)
    return result


def stories_for_rows(body: dict[str, Any]) -> dict[str, Any]:
    """The API's entry for a browser case: rows, findings and settings posted by the page."""
    return build_stories(body.get("events") or [], body.get("mails") or [], body.get("findings") or [], body.get("settings") or {})


__all__ = ["PHASES", "PHASE_LABEL", "build_stories", "finding_phase", "record_phase", "stories_for_rows", "stories_for_store"]
