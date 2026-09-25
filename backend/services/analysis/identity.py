"""
Who is who: the forms a case names one account by, joined into identities.

An identity collects the forms the evidence uses for one account: its address or UPN
(alice@contoso.com), its Windows form (CONTOSO\\alice), its SID, its Entra object id, its
distinguished name, and the display names the directory gives it. Two forms join, and every join
says why:

- **strong**: one record states both (a logon's account name and SID, a sign-in's UPN and
  object id), or renames one to the other (4781);
- **medium**: the organisation rules of the chains say they are one account: CONTOSO\\alice and
  alice@contoso.com when CONTOSO is the first label of contoso.com or of an internal domain, or
  when the case showed the two side by side; CN=alice,DC=contoso,DC=com and alice@contoso.com;
  a bare account name when only one account of that name is in the case;
- **weak**: only a display name, or a bare name several accounts share, matches. It reads
  "possibly the same" and never merges two identities.

Accounts of two organisations never join: alice@other-tenant.example is not
alice@contoso.com, whatever else matches; the resolver names it a namesake, kept apart. A machine
account (NAME$) never joins a user account unless one record renames one to the other, which is
then said. Built-in accounts and well-known SIDs are identities of their own kind.

The resolver reads identity records, not whole rows: the few fields an event or a mail names
accounts by. A server-store case gives it the distinct combinations from SQL, so millions of
events are a few thousand records.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .chains import identity_realm, mail_recipients, netbios_hints, same_org_domain

STRONG, MEDIUM, WEAK = "strong", "medium", "weak"
CONFIDENCE_RANK = {STRONG: 2, MEDIUM: 1, WEAK: 0}
# events whose target is a group: the account acted on, when there is one, is the member
GROUP_TARGET_EVENTS = frozenset(
    {4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, *range(4744, 4765), 4799},
)
RENAME_EVENT = 4781
_DOMAIN_SID = re.compile(r"^s-1-5-21-\d+-\d+-\d+-(\d+)$")
_GUID = re.compile(r"^\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?$")
# the realms Windows writes its own accounts under, in English and French
_BUILTIN_REALMS = frozenset(
    {"nt authority", "autorite nt", "autorité nt", "nt service", "font driver host", "window manager", "iis apppool", "builtin", "nt virtual machine"}
)
_BUILTIN_NAMES = frozenset(
    {
        "system",
        "local system",
        "local service",
        "network service",
        "anonymous logon",
        "système",
        "systeme",
        "service local",
        "service réseau",
        "service reseau",
        "ouverture de session anonyme",
        "window manager",
        "font driver host",
        "krbtgt",
        "defaultaccount",
        "wdagutilityaccount",
    }
)
_SERVICE_PREFIXES = ("svc", "healthmailbox", "msol_", "aad_", "sm_", "$", "iusr_", "iwam_")
_EMPTY = frozenset({"", "-", "n/a", "unknown", "null", "none", "%%1793"})
_SCOPED = frozenset({"addr", "netbios", "dn", "object", "sid"})
_ROLE_RANK = {"subject": 0, "target": 1, "member": 2, "user": 3, "sender": 4, "reply-to": 5, "recipient": 6}


def _clean(v: Any) -> str:
    return "" if v is None else str(v).strip().strip('"').strip("'")


def _int(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


@dataclass(frozen=True)
class Form:
    """One way an account is written: kind is addr, netbios, dn, object, sid or name (a bare account name)."""

    kind: str
    value: str


@dataclass
class Record:
    """The accounts one record names: each group is one account, its forms stated together, with its role in the record."""

    groups: list[list[Form]]
    roles: list[str]
    ref: str | None = None
    # (display name, the form it names, whether the sender chose it: a mail header)
    displays: list[tuple[str, Form, bool]] = field(default_factory=list)
    # (old name, new name) of one account renamed by the record
    renames: list[tuple[Form, Form]] = field(default_factory=list)
    # how many records this one stands for (a distinct combination read from the server store)
    weight: int = 1


# --- the forms a record names ---------------------------------------------------------------------


def account_forms(user: Any, domain: Any = None, sid: Any = None) -> list[Form]:
    """
    The forms of one account as a record writes it: 'CONTOSO\\alice' or ('alice', 'CONTOSO') gives
    netbios contoso\\alice; 'alice@contoso.com', or ('alice', 'contoso.com'), gives addr; a bare
    'alice' gives name; a SID gives sid.
    """
    raw = _clean(user).lower()
    dom = _clean(domain).lower()
    out: list[Form] = []
    if raw not in _EMPTY:
        base = raw.rsplit("\\", 1)[1].strip() if "\\" in raw else raw
        prefix = raw.rsplit("\\", 1)[0].strip() if "\\" in raw else dom
        realm, kind = identity_realm(raw, domain)
        if not base or base in _EMPTY:
            pass
        elif "@" in base:
            out.append(Form("addr", base))
        elif prefix in _BUILTIN_REALMS:
            out.append(Form("netbios", f"{prefix}\\{base}"))
        elif kind == "netbios" and realm:
            out.append(Form("netbios", f"{realm}\\{base}"))
        elif kind == "dns" and realm:
            out.append(Form("addr", f"{base}@{realm}"))
        else:
            out.append(Form("name", base))
    s = _clean(sid).lower()
    if s.startswith("s-1-") and s not in ("s-1-0-0", "s-1-5-18", "s-1-5-19", "s-1-5-20"):
        out.append(Form("sid", s))
    return out


def dn_domain(dn: str) -> str | None:
    parts = [p.split("=", 1)[1].strip() for p in dn.split(",") if p.strip().lower().startswith("dc=") and "=" in p]
    return ".".join(parts).lower() or None


def dn_cn(dn: str) -> str:
    return dn.split(",", 1)[0][3:].strip().lower() if dn.lower().startswith("cn=") else ""


def base_name(form: Form) -> str:
    """The account name a form writes: alice for alice@contoso.com, CONTOSO\\alice and CN=alice,..."""
    if form.kind == "dn":
        return dn_cn(form.value)
    if form.kind in ("sid", "object"):
        return ""
    return form.value.rsplit("\\", 1)[-1].split("@", 1)[0].strip()


def kind_of(form: Form, service_names: set[str] | frozenset[str] = frozenset()) -> str | None:
    """machine, builtin, service or person from one form; None when the form does not say (a user's SID, an object id)."""
    v = form.value
    if form.kind == "sid":
        m = _DOMAIN_SID.match(v)
        if m:
            rid = int(m.group(1))
            # the built-in Administrator and Guest are accounts people log on with; krbtgt,
            # DefaultAccount, WDAGUtilityAccount and the domain's groups are not
            return None if rid >= 1000 or rid in (500, 501) else "builtin"
        return None if v.startswith("s-1-12-1-") else "builtin"
    if form.kind == "object":
        return None
    if form.kind == "netbios" and v.rsplit("\\", 1)[0] in _BUILTIN_REALMS:
        return "builtin"
    base = base_name(form)
    if base.endswith("$") and len(base) > 1:
        return "machine"
    if base in _BUILTIN_NAMES or base.startswith(("dwm-", "umfd-")):
        return "builtin"
    if base in service_names or base.startswith(_SERVICE_PREFIXES):
        return "service"
    return "person"


def _coalesce(groups: list[list[Form]], roles: list[str]) -> tuple[list[list[Form]], list[str]]:
    """Merge the groups of one record that share a form (the subject and the User field naming one account)."""
    out: list[tuple[list[Form], str]] = []
    for g, role in zip(groups, roles, strict=True):
        if not g:
            continue
        merged, best = list(dict.fromkeys(g)), role
        keep: list[tuple[list[Form], str]] = []
        for og, orole in out:
            if set(og) & set(merged):
                merged = list(dict.fromkeys(og + merged))
                best = min(best, orole, key=lambda r: _ROLE_RANK.get(r, 9))
            else:
                keep.append((og, orole))
        out = keep + [(merged, best)]
    return [g for g, _ in out], [r for _, r in out]


def event_record(ev: dict[str, Any]) -> Record:
    """The accounts an event (Windows, Sysmon, Entra, Unified Audit Log) names, one group per account."""
    data = ev.get("data") if isinstance(ev.get("data"), dict) else {}
    eid = _int(ev.get("eventId"))
    groups: list[list[Form]] = []
    roles: list[str] = []
    displays: list[tuple[str, Form, bool]] = []
    renames: list[tuple[Form, Form]] = []

    def add(forms: list[Form], role: str) -> None:
        groups.append(forms)
        roles.append(role)

    add(account_forms(ev.get("subjectUser"), ev.get("subjectDomain"), ev.get("subjectSid")), "subject")
    user = _clean(ev.get("user"))
    # an address in the User field is read with the cloud fields below
    if user and ("\\" in user or "@" not in user):
        add(account_forms(user), "user")
    if eid == RENAME_EVENT:
        dom = data.get("TargetDomainName") or ev.get("targetDomain")
        old, new = account_forms(data.get("OldTargetUserName"), dom), account_forms(data.get("NewTargetUserName"), dom)
        add(new + account_forms(None, None, data.get("TargetSid") or ev.get("targetSid")), "target")
        if old and new and old[0] != new[0]:
            renames.append((old[0], new[0]))
    elif eid in GROUP_TARGET_EVENTS:
        dn = _clean(ev.get("memberName")).lower()
        add(([Form("dn", dn)] if dn.startswith("cn=") else []) + account_forms(None, None, ev.get("memberSid")), "member")
    else:
        target = account_forms(ev.get("targetUser"), ev.get("targetDomain"), ev.get("targetSid"))
        add(target, "target")
        shown = _clean(ev.get("displayName") or data.get("DisplayName"))
        if target and shown.lower() not in _EMPTY and eid in (4720, 4738, 4741, 4742):
            displays.append((shown.lower(), target[0], False))
    actor: list[Form] = []
    for raw in (ev.get("upn"), user, data.get("UserId"), data.get("userPrincipalName")):
        r = _clean(raw).lower()
        if "@" in r and " " not in r and "\\" not in r:
            actor.append(Form("addr", r))
    actor = list(dict.fromkeys(actor))
    objects = list(dict.fromkeys(Form("object", m.group(1)) for raw in (data.get("userId"), ev.get("userObjectId")) if (m := _GUID.match(_clean(raw).lower()))))
    if len(actor) <= 1:
        add(actor + objects, "subject")
    else:
        # two addresses for the actor: which one the object id belongs to is not known
        for f in actor:
            add([f], "subject")
    owner = _clean(data.get("MailboxOwnerUPN")).lower()
    if "@" in owner and " " not in owner:
        add([Form("addr", owner)], "target")
    display = _clean(data.get("userDisplayName") or data.get("UserDisplayName"))
    if display and len(actor) == 1:
        displays.append((display.lower(), actor[0], False))
    groups, roles = _coalesce(groups, roles)
    return Record(groups, roles, _ref(ev), displays, renames)


def mail_record(m: dict[str, Any]) -> Record:
    """A mail names its sender, its reply-to addresses and its recipients; their display names are the sender's word."""
    groups: list[list[Form]] = []
    roles: list[str] = []
    displays: list[tuple[str, Form, bool]] = []
    frm = _clean(m.get("fromAddr")).lower()
    if "@" in frm:
        groups.append([Form("addr", frm)])
        roles.append("sender")
        name = _clean(m.get("fromName"))
        if name and "@" not in name:
            displays.append((name.lower(), Form("addr", frm), True))
    reply = m.get("replyTo") or []
    for a in reply if isinstance(reply, list) else [reply]:
        addr = _clean(a.get("addr") if isinstance(a, dict) else a).lower()
        if "@" in addr:
            groups.append([Form("addr", addr)])
            roles.append("reply-to")
    for a in mail_recipients(m):
        if "@" in a:
            groups.append([Form("addr", a)])
            roles.append("recipient")
    mid = m.get("id") if m.get("id") is not None else m.get("messageId")
    groups, roles = _coalesce(groups, roles)
    return Record(groups, roles, f"mail:{mid}" if mid is not None else None, displays)


def _ref(ev: dict[str, Any]) -> str | None:
    if ev.get("id") is not None:
        return f"event:{ev['id']}"
    return str(ev["recordKey"]) if ev.get("recordKey") else None


# --- the server store -----------------------------------------------------------------------------

# the fields an event names accounts by; the resolver reads their distinct combinations
_RECORD_COLUMNS = (
    "eventId",
    "subjectUser",
    "subjectDomain",
    "subjectSid",
    "user",
    "targetUser",
    "targetDomain",
    "targetSid",
    "memberName",
    "memberSid",
    "upn",
    "displayName",
)
_RECORD_DATA = (
    "UserId",
    "userPrincipalName",
    "MailboxOwnerUPN",
    "userId",
    "userDisplayName",
    "UserDisplayName",
    "OldTargetUserName",
    "NewTargetUserName",
    "TargetDomainName",
    "TargetSid",
)


def records_for_store(store: Any, limit: int = 200_000) -> tuple[list[Record], list[tuple[str, str]], dict[str, Any]]:
    """
    The identity records of a server-store case, one per distinct combination of the fields that
    name accounts, with the NetBIOS-to-DNS pairs they show. The count of each combination is kept.
    """
    from services.store.casestore import rows_to_dicts

    cols = ", ".join(f'"{c}"' for c in _RECORD_COLUMNS)
    datas = ", ".join(f'json_extract_string(data, \'$."{k}"\') AS "d_{k}"' for k in _RECORD_DATA)
    cur = store.cursor()
    cur.execute(f"SELECT {cols}, {datas}, count(*) AS n, min(id) AS first FROM events GROUP BY ALL ORDER BY n DESC LIMIT {limit + 1}")
    rows = rows_to_dicts(cur)
    truncated = len(rows) > limit
    records: list[Record] = []
    pairs: set[tuple[str, str]] = set()
    for row in rows[:limit]:
        ev = {c: row.get(c) for c in _RECORD_COLUMNS}
        ev["data"] = {k: row.get(f"d_{k}") for k in _RECORD_DATA if row.get(f"d_{k}") is not None}
        ev["id"] = row.get("first")
        rec = event_record(ev)
        rec.weight = max(1, int(row.get("n") or 1))
        records.append(rec)
        pairs.update(netbios_hints(ev))
    cur.execute(
        'SELECT "fromAddr", "fromName", "replyToList", "toList", "ccList", "bccList", min(id) AS id, count(*) AS n FROM mails GROUP BY ALL LIMIT ?',
        [limit + 1],
    )
    mails = rows_to_dicts(cur)
    truncated = truncated or len(mails) > limit
    for m in mails[:limit]:
        m["replyTo"] = m.pop("replyToList", None) or []
        rec = mail_record(m)
        rec.weight = max(1, int(m.get("n") or 1))
        records.append(rec)
    return records, sorted(pairs), {"records": len(records), "truncated": truncated}


# --- resolving ------------------------------------------------------------------------------------


@dataclass
class _Join:
    a: Form
    b: Form
    basis: str
    confidence: str
    ref: str | None
    count: int = 1


class Resolver:
    """The identities of a case, the identity each form belongs to and how surely."""

    def __init__(self, identities: list[dict[str, Any]], by_form: dict[Form, str], confidence: dict[Form, str], possibly: dict[Form, list[str]]):
        self.identities = identities
        self.by_id = {i["id"]: i for i in identities}
        self._by_form = by_form
        self._confidence = confidence
        self._possibly = possibly

    def of_form(self, form: Form) -> str | None:
        return self._by_form.get(form)

    def confidence(self, form: Form) -> str:
        """How surely the form belongs to its identity: the weakest join on the surest path from the identity's label."""
        return self._confidence.get(form, WEAK)

    def forms(self, identity_id: str) -> list[Form]:
        ident = self.by_id.get(identity_id)
        return [Form(f["kind"], f["value"]) for f in ident["forms"] if f["kind"] != "display"] if ident else []

    def of_record(self, rec: Record) -> list[tuple[str, str, str]]:
        """The identities a record names: (identity id, role, confidence), the confidence strong, medium or weak."""
        out: dict[tuple[str, str], str] = {}
        for g, role in zip(rec.groups, rec.roles, strict=True):
            ids: dict[str, str] = {}
            for f in g:
                iid = self._by_form.get(f)
                if iid:
                    c = self.confidence(f)
                    if CONFIDENCE_RANK[c] > CONFIDENCE_RANK.get(ids.get(iid, ""), -1):
                        ids[iid] = c
            if len(ids) == 1:
                iid, c = next(iter(ids.items()))
                if CONFIDENCE_RANK[c] > CONFIDENCE_RANK.get(out.get((iid, role), ""), -1):
                    out[(iid, role)] = c
            # a bare name several accounts write: possibly each of them
            for f in g:
                for pid in self._possibly.get(f, []):
                    out.setdefault((pid, role), WEAK)
        return [(iid, role, c) for (iid, role), c in out.items()]

    def of_event(self, ev: dict[str, Any]) -> list[tuple[str, str, str]]:
        return self.of_record(event_record(ev))

    def of_mail(self, m: dict[str, Any]) -> list[tuple[str, str, str]]:
        return self.of_record(mail_record(m))

    def to_list(self) -> list[dict[str, Any]]:
        return self.identities


def resolve(
    events: Iterable[dict[str, Any]] = (),
    mails: Iterable[dict[str, Any]] = (),
    settings: dict[str, Any] | None = None,
    records: Iterable[Record] = (),
    netbios_pairs: Iterable[tuple[str, str]] = (),
) -> Resolver:
    """Resolve the accounts events and mails name (or ready-made records) into identities."""
    settings = settings or {}
    internal = {str(d).lower().strip(".") for d in (settings.get("internal_domains") or settings.get("internalDomains") or []) if d}
    service_names = frozenset(str(s).lower() for s in (settings.get("service_accounts") or settings.get("serviceAccounts") or []) if s)
    recs: list[Record] = list(records)
    netbios_map: dict[str, set[str]] = {}
    for nb, dns in netbios_pairs:
        netbios_map.setdefault(nb, set()).add(dns)
    for ev in events:
        recs.append(event_record(ev))
        for nb, dns in netbios_hints(ev):
            netbios_map.setdefault(nb, set()).add(dns)
    for m in mails:
        recs.append(mail_record(m))

    joins: dict[tuple[Form, Form, str], _Join] = {}
    seen: dict[Form, int] = {}
    first_ref: dict[Form, str | None] = {}
    display_of: dict[Form, set[str]] = {}
    spoofed: list[tuple[str, Form, str | None]] = []

    def add_join(a: Form, b: Form, basis: str, conf: str, ref: str | None, n: int = 1) -> None:
        if a == b:
            return
        a, b = sorted((a, b), key=lambda f: (f.kind, f.value))
        key = (a, b, basis)
        if key in joins:
            joins[key].count += n
        else:
            joins[key] = _Join(a, b, basis, conf, ref, n)

    def see(f: Form, ref: str | None, n: int = 1) -> None:
        seen[f] = seen.get(f, 0) + n
        if first_ref.get(f) is None:
            first_ref[f] = ref

    for rec in recs:
        for g in rec.groups:
            for f in g:
                see(f, rec.ref, rec.weight)
            scoped = [f for f in g if f.kind in _SCOPED]
            for i, a in enumerate(scoped):
                for b in scoped[i + 1 :]:
                    add_join(a, b, "stated together in one record", STRONG, rec.ref, rec.weight)
        for old, new in rec.renames:
            see(old, rec.ref, rec.weight)
            add_join(old, new, f"renamed from {old.value} to {new.value}", STRONG, rec.ref, rec.weight)
        for name, form, spoofable in rec.displays:
            if spoofable:
                spoofed.append((name, form, rec.ref))
            elif _name_tokens(name) != _name_tokens(base_name(form)):
                display_of.setdefault(form, set()).add(name)

    # medium: a NetBIOS form and an address, a DN and an address, by the organisation rules
    by_local: dict[str, list[Form]] = {}
    for f in seen:
        if f.kind == "addr":
            by_local.setdefault(f.value.split("@", 1)[0], []).append(f)
    for f in list(seen):
        if f.kind == "netbios":
            dom, user = f.value.rsplit("\\", 1)
            if dom in _BUILTIN_REALMS:
                continue
            for a in by_local.get(user, []):
                adom = a.value.split("@", 1)[1]
                labels = {adom.split(".")[0]} | {d.split(".")[0] for d in internal if same_org_domain(d, adom, internal)}
                side = any(same_org_domain(adom, d, internal) for d in netbios_map.get(dom, set()))
                foreign = bool(netbios_map.get(dom)) and not side
                if (dom in labels or side) and not foreign:
                    add_join(f, a, "the same account in its organisation (the NetBIOS name of its domain)", MEDIUM, first_ref.get(f))
        elif f.kind == "dn":
            dom = dn_domain(f.value)
            for a in by_local.get(dn_cn(f.value), []):
                if dom and same_org_domain(dom, a.value.split("@", 1)[1], internal):
                    add_join(f, a, "the same account in the directory (its distinguished name)", MEDIUM, first_ref.get(f))

    def org_of(f: Form) -> str | None:
        if f.kind == "addr":
            return f.value.split("@", 1)[1]
        if f.kind == "dn":
            return dn_domain(f.value)
        if f.kind == "netbios":
            dom = f.value.rsplit("\\", 1)[0]
            known = netbios_map.get(dom, set())
            if len(known) == 1:
                return next(iter(known))
            return next((d for d in sorted(internal) if d.split(".")[0] == dom), None)
        return None

    parent: dict[Form, Form] = {f: f for f in seen}
    orgs: dict[Form, set[str]] = {f: ({o} if (o := org_of(f)) else set()) for f in seen}
    machine: dict[Form, bool] = {f: k == "machine" for f in seen if (k := kind_of(f, service_names)) is not None}
    conflicts: list[tuple[_Join, str]] = []

    def find(x: Form) -> Form:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def try_union(j: _Join) -> bool:
        ra, rb = find(j.a), find(j.b)
        if ra == rb:
            return True
        if any(not same_org_domain(x, y, internal) for x in orgs[ra] for y in orgs[rb]):
            conflicts.append((j, "the two forms belong to different organisations"))
            return False
        ma, mb = machine.get(ra), machine.get(rb)
        # a record naming both (a rename, one SID under two names) is believed and noted on the identity
        if ma is not None and mb is not None and ma != mb and j.confidence != STRONG:
            conflicts.append((j, "a machine account and a user account"))
            return False
        parent[rb] = ra
        orgs[ra] |= orgs.pop(rb, set())
        either = mb if ma is None else ma if mb is None else ma or mb
        if either is None:
            machine.pop(ra, None)
        else:
            machine[ra] = either
        return True

    kept: list[_Join] = []
    for j in sorted(joins.values(), key=lambda j: (-CONFIDENCE_RANK[j.confidence], j.a.kind, j.a.value, j.b.kind, j.b.value)):
        if try_union(j):
            kept.append(j)

    # bare names: joined to the one scoped account of that name, else "possibly" each of them
    comps: dict[Form, list[Form]] = {}
    for f in seen:
        comps.setdefault(find(f), []).append(f)
    scoped_by_name: dict[str, set[Form]] = {}
    for root, fs in comps.items():
        for f in fs:
            if f.kind in ("addr", "netbios", "dn"):
                scoped_by_name.setdefault(base_name(f), set()).add(root)
    ambiguous: dict[Form, set[Form]] = {}
    for fs in list(comps.values()):
        if any(f.kind in ("addr", "netbios", "dn", "object") for f in fs):
            continue
        for f in fs:
            if f.kind != "name":
                continue
            roots = {find(r) for r in scoped_by_name.get(f.value, set())}
            if len(roots) == 1:
                target = next(iter(roots))
                anchor = min((x for x in comps[target] if x.kind in ("addr", "netbios", "dn")), key=lambda x: (_RANK[x.kind], x.value))
                j = _Join(f, anchor, "the only account of that name in the case", MEDIUM, first_ref.get(f))
                if try_union(j):
                    kept.append(j)
            elif len(roots) > 1:
                ambiguous[f] = roots

    comps = {}
    for f in seen:
        comps.setdefault(find(f), []).append(f)
    adjacency: dict[Form, list[tuple[Form, str]]] = {}
    for j in kept:
        adjacency.setdefault(j.a, []).append((j.b, j.confidence))
        adjacency.setdefault(j.b, []).append((j.a, j.confidence))
    by_form: dict[Form, str] = {}
    confidence: dict[Form, str] = {}
    identities: list[dict[str, Any]] = []
    for root, fs in comps.items():
        kinds = {k for f in fs if (k := kind_of(f, service_names))}
        kind = next((k for k in ("machine", "builtin", "service") if k in kinds), "person")
        label_form = _label_form(fs)
        iid = "id:" + hashlib.sha1(f"{label_form.kind}:{label_form.value}".encode()).hexdigest()[:12]
        conf = _widest(label_form, adjacency)
        forms = []
        for f in sorted(fs, key=lambda f: (_RANK[f.kind], f.value)):
            by_form[f] = iid
            confidence[f] = conf.get(f, WEAK)
            forms.append({"kind": f.kind, "value": f.value, "seen": seen[f], "ref": first_ref.get(f), "confidence": confidence[f]})
        for f in fs:
            for name in sorted(display_of.get(f, ())):
                forms.append({"kind": "display", "value": name, "seen": 1, "ref": None, "confidence": WEAK})
        identities.append(
            {
                "id": iid,
                "label": label_form.value,
                "kind": kind,
                "org": min(orgs.get(root) or [None], key=lambda o: o or ""),
                "forms": forms,
                "joins": [],
                "possibly": [],
                "namesakes": [],
                "conflicts": [],
                "notes": [],
                "seen": sum(seen[f] for f in fs),
            }
        )
    by_id = {i["id"]: i for i in identities}
    for j in kept:
        by_id[by_form[j.a]]["joins"].append(
            {"a": j.a.value, "b": j.b.value, "kinds": [j.a.kind, j.b.kind], "basis": j.basis, "confidence": j.confidence, "ref": j.ref, "count": j.count}
        )
    for j, why in conflicts:
        for f in (j.a, j.b):
            other = j.b if f == j.a else j.a
            if f in by_form and other in by_form and by_form[f] != by_form[other]:
                by_id[by_form[f]]["conflicts"].append({"id": by_form[other], "a": j.a.value, "b": j.b.value, "basis": j.basis, "why": why, "ref": j.ref})
    for root, fs in comps.items():
        named = [f for f in sorted(fs, key=lambda f: (_RANK[f.kind], f.value)) if f.kind in ("netbios", "addr", "name", "dn")]
        as_machine = [f for f in named if base_name(f).endswith("$")]
        as_user = [f for f in named if not base_name(f).endswith("$") and kind_of(f, service_names) == "person"]
        if as_machine and as_user:
            by_id[by_form[root]]["notes"].append(
                f"written both as a machine account ({as_machine[0].value}) and without the $ ({as_user[0].value}): renaming a machine account "
                "to a name without its $ is how sAMAccountName spoofing (CVE-2021-42278) begins"
            )
    possibly: dict[Form, list[str]] = {}
    for f, roots in ambiguous.items():
        others = sorted({by_form[r] for r in roots})
        possibly[f] = others
        for o in others:
            _relate(by_id, by_form[f], o, f"the bare name {f.value} is written the same by {len(others)} accounts", first_ref.get(f))
    # a display name, or a mail header's, that is another account's name: possibly the same, and
    # in another organisation a namesake (never merged either way)
    by_tokens: dict[tuple[str, ...], set[str]] = {}
    for ident in identities:
        if ident["kind"] != "person":
            continue
        for fv in ident["forms"]:
            if fv["kind"] in ("addr", "netbios", "name", "dn"):
                t = _name_tokens(base_name(Form(fv["kind"], fv["value"])))
                if len(t) > 1:
                    by_tokens.setdefault(t, set()).add(ident["id"])
    for ids in by_tokens.values():
        if 1 < len(ids) <= 10:
            for a in sorted(ids):
                for b in sorted(ids):
                    if a < b:
                        _relate(by_id, a, b, "the same account name", None)
    for form, names in display_of.items():
        for name in sorted(names):
            for other in sorted(by_tokens.get(_name_tokens(name), set())):
                _relate(by_id, by_form.get(form), other, f"the display name “{name}” the directory gives it is that account's name", None)
    for name, form, ref in spoofed:
        for other in sorted(by_tokens.get(_name_tokens(name), set())):
            _relate(by_id, by_form.get(form), other, f"the display name “{name}” in a mail header, which the sender chooses, is that account's name", ref)
    identities.sort(key=lambda i: (_KIND_RANK[i["kind"]], i["label"]))
    return Resolver(identities, by_form, confidence, possibly)


def _relate(by_id: dict[str, dict[str, Any]], owner: str | None, other: str, basis: str, ref: str | None) -> None:
    """Record a weak "possibly the same" between two identities, or a namesake when their organisations differ."""
    if not owner or owner == other:
        return
    a, b = by_id[owner], by_id[other]
    apart = bool(a["org"] and b["org"] and not same_org_domain(a["org"], b["org"]))
    key = "namesakes" if apart else "possibly"
    if any(p["id"] == other for p in a[key]):
        return
    a[key].append(
        {"id": other, "label": b["label"], "basis": basis + (f"; {b['org']} is another organisation, so they are kept apart" if apart else ""), "ref": ref}
    )
    if not any(p["id"] == owner for p in b[key]):
        b[key].append(
            {"id": owner, "label": a["label"], "basis": basis + (f"; {a['org']} is another organisation, so they are kept apart" if apart else ""), "ref": ref}
        )


def _widest(start: Form, adjacency: dict[Form, list[tuple[Form, str]]]) -> dict[Form, str]:
    """Each form's confidence from the label: strong joins first, then medium, so a form takes its surest path."""
    best: dict[Form, str] = {start: STRONG}
    for level in (STRONG, MEDIUM):
        frontier = [f for f, c in best.items() if c == level]
        while frontier:
            nxt = []
            for f in frontier:
                for g, c in adjacency.get(f, []):
                    reach = level if CONFIDENCE_RANK[c] >= CONFIDENCE_RANK[level] else c
                    if CONFIDENCE_RANK[reach] > CONFIDENCE_RANK.get(best.get(g, ""), -1):
                        best[g] = reach
                        if reach == level:
                            nxt.append(g)
            frontier = nxt
    return best


_RANK = {"addr": 0, "netbios": 1, "dn": 2, "object": 3, "sid": 4, "name": 5, "display": 6}
_KIND_RANK = {"person": 0, "service": 1, "machine": 2, "builtin": 3}


def _label_form(fs: list[Form]) -> Form:
    for kind in ("addr", "netbios", "dn", "name", "object", "sid"):
        cands = sorted((f for f in fs if f.kind == kind), key=lambda f: f.value)
        if cands:
            # a machine account is labelled by its machine form, not a renamed user-looking one
            if kind in ("netbios", "addr", "name"):
                machine = [f for f in cands if base_name(f).endswith("$")]
                return (machine or cands)[0]
            return cands[0]
    return fs[0]


def _name_tokens(s: str) -> tuple[str, ...]:
    return tuple(sorted(t for t in re.split(r"[\s._\-,]+", s.lower()) if t))
