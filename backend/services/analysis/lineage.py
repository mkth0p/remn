"""
Host lineage: who was logged on to each host, how they got there, and what ran there.

- **Sessions.** A logon session is a host and a logon id. It opens with its logon (4624), closes
  with its logoff (4634, 4647), and holds every event that names that logon id as its subject on
  that host (4688, 4698, 4720, 4732, 5140, 1102 ...). Activity whose logon is not in the evidence
  still makes a session, marked as such. The SYSTEM, LOCAL SERVICE and NETWORK SERVICE sessions
  are not anyone's and are left out.
- **Hops.** How an account came to a host: an RDP logon (4624 type 10, and 4778, 1149 or the local
  session manager's 21 and 25 when those are what the evidence has), a network session that opened
  an admin share, created a task or a service or ran a program (5140, 5145, 4698, 4697, 4688), a
  service installed right after an admin share was opened (7045: PsExec's pattern), explicit
  credentials used towards another host (4648), and a Sysmon connection to a remote-access port of
  another host of the case. A hop's source is a host when the case shows whose address it is,
  otherwise the address.
- **Process trees.** Sysmon 1 by process GUID; 4688 by process id and creator id on one host, the
  latest creation of that id before the child (ids are reused); a process both logged is one.
  Each process is placed in its logon session.
- **Coverage.** What each host's evidence can show: without Sysmon 1 what ran comes from 4688
  alone, and without command lines when the audit policy left them out; without 4624 who logged
  on is not visible; a cleared log ends what came before in that log.

Everything is computed from the rows given; nothing is inferred beyond what they state, and each
tie says why and how surely: strong when a record states it (a logon id, a process GUID), medium
when it rests on the same account, host and time or on an address the case attributes to a host.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from bisect import bisect_right
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from .identity import MEDIUM, STRONG
from .relationship_identity import numeric_id

LOGON_TYPES = {
    2: "interactive",
    3: "network",
    4: "batch",
    5: "service",
    7: "unlock",
    8: "network (cleartext password)",
    9: "new credentials",
    10: "remote interactive (RDP)",
    11: "cached interactive",
    12: "cached remote interactive",
    13: "cached unlock",
}
# no one's sessions: SYSTEM, LOCAL SERVICE, NETWORK SERVICE and ANONYMOUS LOGON
_SYSTEM_LOGONS = {0, 0x3E4, 0x3E5, 0x3E6, 0x3E7}
_ADMIN_SHARE = re.compile(r"(?i)\\(admin\$|[a-z]\$)$")
# the named pipes remote execution goes through: the service and task managers, and the tools' own
_EXEC_PIPE = re.compile(r"(?i)^\\?(svcctl|atsvc|psexesvc|remcom|paexec|csexec)")
_REMOTE_PORTS = {3389: "rdp", 445: "smb", 139: "smb", 5985: "winrm", 5986: "winrm", 135: "rpc", 22: "ssh"}
_ACTIVITY_SKIP = {4624, 4625, 4634, 4647, 4648, 4672}
_ACCOUNT_CHANGES = {4720, 4722, 4724, 4728, 4732, 4738, 4756}
_SERVICE_AFTER_SHARE = 5 * 60_000
_RDP_MATCH = 2 * 60_000
_PROCESS_REUSE = 7 * 86_400_000
_SAME_PROCESS = 2_000
_LSM = "terminalservices-localsessionmanager"
_RCM = "terminalservices-remoteconnectionmanager"


# --- values ---------------------------------------------------------------------------------------


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def host_key(v: Any) -> str:
    """ws-004 for WS-004.northstar.example, WS-004, \\\\WS-004 and WS-004$; empty for an address or localhost."""
    s = str(v or "").strip().strip("\\").strip().lower()
    if not s or s in ("-", "localhost", "::1", "127.0.0.1") or _is_ip(s):
        return ""
    return s.rstrip("$").split(".", 1)[0]


def ip_of(v: Any) -> str:
    s = str(v or "").strip().lower()
    if s.startswith("::ffff:"):
        s = s[7:]
    if s in ("", "-", "::1", "127.0.0.1", "0.0.0.0", "::", "localhost") or not _is_ip(s):
        return ""
    return s


def is_internal_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # the documentation ranges stand for internet addresses in the samples and labs
    doc = any(a in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
    return (a.is_private or a.is_loopback or a.is_link_local) and not doc


def logon_id(v: Any) -> int | None:
    n = numeric_id(v)
    return int(n) if n else None


def _pid(v: Any) -> int | None:
    n = numeric_id(v)
    return int(n) if n else None


def _ts(ev: dict[str, Any]) -> int:
    try:
        return int(ev.get("ts") or 0)
    except (TypeError, ValueError):
        return 0


def _eid(ev: dict[str, Any]) -> int:
    try:
        return int(ev.get("eventId") or 0)
    except (TypeError, ValueError):
        return 0


def _data(ev: dict[str, Any]) -> dict[str, Any]:
    d = ev.get("data")
    return d if isinstance(d, dict) else {}


def ref_of(ev: dict[str, Any]) -> str:
    """event:<row id>, the reference findings, stories and the interface use; a record key without one."""
    if ev.get("id") is not None:
        return f"event:{ev['id']}"
    return str(ev.get("recordKey") or "event:?")


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts / 1000, UTC).strftime("%Y-%m-%d %H:%M UTC") if ts else "?"


def _hid(prefix: str, *parts: Any) -> str:
    return prefix + ":" + hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


def _base(path: Any) -> str:
    return str(path or "").replace("/", "\\").rsplit("\\", 1)[-1]


def _account(user: Any, domain: Any) -> str:
    u = str(user or "").strip()
    d = str(domain or "").strip()
    if not u or u == "-":
        return ""
    if "\\" in u or "@" in u or not d or d == "-":
        return u
    return f"{d}\\{u}"


def _provider(ev: dict[str, Any]) -> str:
    return (str(ev.get("provider") or "") + " " + str(ev.get("channel") or "")).lower()


# --- lineage --------------------------------------------------------------------------------------


class Lineage:
    """Sessions, hops and process trees of the hosts in a set of events, and what each host's evidence covers."""

    def __init__(self) -> None:
        self.hosts: dict[str, dict[str, Any]] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.hops: dict[str, dict[str, Any]] = {}
        self.processes: dict[str, dict[str, Any]] = {}
        self.ip_hosts: dict[str, dict[str, Any]] = {}
        self._by_key: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
        self._session_of_ref: dict[str, str] = {}
        self._process_of_ref: dict[str, str] = {}
        self._process_of_guid: dict[str, str] = {}
        self._hops_of_ref: dict[str, list[str]] = defaultdict(list)
        self._hop_index: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)

    # lookups the story engine uses
    def session_at(self, host: str, lid: int | None, ts: int) -> dict[str, Any] | None:
        if not host or lid is None or lid in _SYSTEM_LOGONS:
            return None
        cands = self._by_key.get((host, lid))
        if not cands:
            return None
        i = bisect_right([s["start"] for s in cands], ts + 5_000) - 1
        return cands[max(i, 0)]

    def session_of(self, ref: str) -> dict[str, Any] | None:
        sid = self._session_of_ref.get(ref)
        return self.sessions.get(sid) if sid else None

    def process_of(self, ref: str) -> dict[str, Any] | None:
        pid = self._process_of_ref.get(ref)
        return self.processes.get(pid) if pid else None

    def process_of_guid(self, guid: Any) -> dict[str, Any] | None:
        pid = self._process_of_guid.get(_guid(guid))
        return self.processes.get(pid) if pid else None

    def hops_of(self, ref: str) -> list[dict[str, Any]]:
        return [self.hops[h] for h in self._hops_of_ref.get(ref, []) if h in self.hops]

    def host_of_ip(self, ip: str) -> str | None:
        hit = self.ip_hosts.get(ip)
        return hit["host"] if hit else None

    def tree(self, proc_id: str, up: int = 6, down: int = 30) -> dict[str, Any]:
        """A process with its ancestors (nearest first) and its children, as far as the evidence goes."""
        proc = self.processes.get(proc_id)
        if not proc:
            return {}
        ancestors = []
        cur = proc
        while cur.get("parent") and len(ancestors) < up:
            cur = self.processes.get(cur["parent"])
            if not cur:
                break
            ancestors.append(cur)
        children = [self.processes[c] for c in proc.get("children", [])[:down] if c in self.processes]
        return {"process": proc, "ancestors": ancestors, "children": children, "childrenTotal": len(proc.get("children", []))}

    def to_dict(self, refs: Iterable[str] | None = None, hosts: Iterable[str] | None = None) -> dict[str, Any]:
        """The lineage of the given records and hosts (or all of it): their sessions, hops, processes with their ancestors, and host coverage."""
        if refs is None and hosts is None:
            return {
                "hosts": list(self.hosts.values()),
                "sessions": list(self.sessions.values()),
                "hops": list(self.hops.values()),
                "processes": list(self.processes.values()),
            }
        want = set(refs or ())
        host_set = set(hosts or ())
        sessions = {s for r in want if (s := self._session_of_ref.get(r))}
        procs: set[str] = set()
        for r in want:
            p = self._process_of_ref.get(r)
            while p and p not in procs and len(procs) < 5_000:
                procs.add(p)
                p = self.processes.get(p, {}).get("parent")
        hops = {h for r in want for h in self._hops_of_ref.get(r, [])}
        for h in hops:
            if self.hops[h].get("session"):
                sessions.add(self.hops[h]["session"])
        for s in sessions:
            host_set.add(self.sessions[s]["host"])
        for p in procs:
            host_set.add(self.processes[p]["host"])
        for h in hops:
            host_set.add(self.hops[h]["to"])
            if self.hops[h]["from"].get("host"):
                host_set.add(self.hops[h]["from"]["host"])
        return {
            "hosts": [self.hosts[h] for h in sorted(host_set) if h in self.hosts],
            "sessions": [self.sessions[s] for s in sorted(sessions, key=lambda s: self.sessions[s]["start"])],
            "hops": [self.hops[h] for h in sorted(hops, key=lambda h: self.hops[h]["ts"])],
            "processes": [self.processes[p] for p in sorted(procs, key=lambda p: self.processes[p]["ts"])],
        }


def _guid(v: Any) -> str:
    s = str(v or "").strip().strip("{}").lower()
    return s if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", s) and s.strip("0-") else ""


def build_lineage(events: Iterable[dict[str, Any]], settings: dict[str, Any] | None = None) -> Lineage:
    """Sessions, hops, process trees and coverage from the events of a case (or of a story's window)."""
    lin = Lineage()
    rows = sorted((e for e in events if e.get("computer") or e.get("eventId")), key=lambda e: (_ts(e), str(e.get("id") or "")))
    counts: dict[str, Counter] = defaultdict(Counter)
    names: dict[str, Counter] = defaultdict(Counter)
    spans: dict[str, list[int]] = {}
    clears: dict[str, list[tuple[int, str, str]]] = defaultdict(list)
    ip_votes: dict[str, Counter] = defaultdict(Counter)
    ip_basis: dict[tuple[str, str], str] = {}

    logons, logoffs, specials, activity, reconnects, rdp_other, explicit, shares, services, procs4688, sysmon1, conns = ([] for _ in range(12))
    for ev in rows:
        host = host_key(ev.get("computer"))
        eid = _eid(ev)
        prov = _provider(ev)
        ts = _ts(ev)
        if host:
            names[host][str(ev.get("computer"))] += 1
            span = spans.setdefault(host, [ts, ts])
            if ts:
                span[0] = min(span[0], ts) if span[0] else ts
                span[1] = max(span[1], ts)
            c = counts[host]
            c["events"] += 1
        else:
            c = Counter()
        sysmon = "sysmon" in prov
        if sysmon and eid == 1:
            c["sysmon1"] += 1
            sysmon1.append(ev)
        elif sysmon and eid == 3:
            c["sysmon3"] += 1
            conns.append(ev)
            src, dst = ip_of(ev.get("sourceIp")), ip_of(ev.get("destinationIp"))
            initiated = str(ev.get("initiated") or "").lower()
            # a host's own address: the source of what it initiated, the destination of what it
            # accepted; only a private address is taken for a host's own
            own = src if initiated in ("true", "1") else dst if initiated in ("false", "0") else ""
            if host and own and is_internal_ip(own):
                ip_votes[own][host] += 1
                ip_basis[(own, host)] = "the address the host's own connections come from (Sysmon 3)"
        elif sysmon:
            c["sysmon"] += 1
        elif eid == 4688:
            c["process4688"] += 1
            if ev.get("commandLine"):
                c["commandLines"] += 1
            procs4688.append(ev)
        elif eid == 4624:
            c["logons"] += 1
            logons.append(ev)
            ip, ws = ip_of(ev.get("ipAddress")), host_key(ev.get("workstation"))
            if ip and ws and ws != host:
                ip_votes[ip][ws] += 1
                ip_basis.setdefault((ip, ws), "a logon came from this address under that workstation name (4624)")
        elif eid in (4634, 4647):
            c["logoffs"] += 1
            logoffs.append(ev)
        elif eid == 4672:
            specials.append(ev)
        elif eid in (4778, 4779):
            c["rdp"] += 1
            reconnects.append(ev)
        elif (_LSM in prov and eid in (21, 22, 23, 24, 25)) or (_RCM in prov and eid == 1149):
            c["rdp"] += 1
            rdp_other.append(ev)
        elif eid == 4648:
            c["explicit"] += 1
            explicit.append(ev)
        elif eid in (5140, 5145):
            c["shares"] += 1
            shares.append(ev)
        elif eid in (7045, 4697) and "sysmon" not in prov:
            c["services"] += 1
            services.append(ev)
        elif eid == 4104:
            c["powershell"] += 1
        if (eid == 1102 and "security" in prov) or (eid == 104 and "eventlog" in prov):
            clears[host].append((ts, str(ev.get("channel") or "Security"), ref_of(ev)))
        # activity of a session: any event naming its logon id as the subject's, on that host
        lid = logon_id(ev.get("subjectLogonId") or _data(ev).get("SubjectLogonId"))
        if host and lid is not None and lid not in _SYSTEM_LOGONS and eid not in _ACTIVITY_SKIP and eid != 4688:
            activity.append((ev, lid))

    for ip, votes in ip_votes.items():
        host, n = votes.most_common(1)[0]
        lin.ip_hosts[ip] = {"host": host, "basis": ip_basis.get((ip, host), ""), "count": n, "others": sorted(h for h in votes if h != host)[:5]}

    # sessions: a logon, its logoff, 4672 privileges, and its activity
    for ev in logons:
        host, lid = host_key(ev.get("computer")), logon_id(ev.get("targetLogonId"))
        if not host or lid is None or lid in _SYSTEM_LOGONS:
            continue
        lt = _int(ev.get("logonType"))
        ts = _ts(ev)
        ip, ws = ip_of(ev.get("ipAddress")), str(ev.get("workstation") or "").strip()
        s = {
            "id": _hid("ses", host, lid, ts),
            "host": host,
            "logonId": hex(lid),
            "user": ev.get("targetUser"),
            "domain": ev.get("targetDomain"),
            "sid": ev.get("targetSid"),
            "account": _account(ev.get("targetUser"), ev.get("targetDomain")),
            "type": lt,
            "typeName": LOGON_TYPES.get(lt, str(lt) if lt else "unknown"),
            "ip": ip or None,
            "workstation": ws if ws and ws != "-" else None,
            "from": _source(lin, ip, ws, host),
            "authPackage": ev.get("authPackage"),
            "logonProcess": ev.get("logonProcess"),
            "elevated": str(ev.get("elevatedToken") or "").lower() in ("%%1842", "yes", "true"),
            "privileged": False,
            "linked": None,
            "linkedLogonId": hex(x) if (x := logon_id(ev.get("targetLinkedLogonId"))) else None,
            "start": ts,
            "end": None,
            "logonRef": ref_of(ev),
            "logoffRef": None,
            "logonSeen": True,
            "rdp": lt in (10, 12),
            "reconnects": [],
            "activity": 0,
            "activityRefs": [],
            "activityKinds": {},
            "actions": {},
        }
        lin.sessions[s["id"]] = s
        lin._by_key[(host, lid)].append(s)
        lin._session_of_ref[s["logonRef"]] = s["id"]
    for key in lin._by_key:
        lin._by_key[key].sort(key=lambda s: s["start"])
    for ev in logoffs:
        host, lid = host_key(ev.get("computer")), logon_id(ev.get("targetLogonId"))
        s = lin.session_at(host, lid, _ts(ev))
        if s and s["end"] is None and _ts(ev) >= s["start"]:
            s["end"], s["logoffRef"] = _ts(ev), ref_of(ev)
            lin._session_of_ref[s["logoffRef"]] = s["id"]
    for ev in specials:
        host, lid = host_key(ev.get("computer")), logon_id(ev.get("subjectLogonId"))
        s = lin.session_at(host, lid, _ts(ev))
        if s and abs(_ts(ev) - s["start"]) <= 5_000:
            s["privileged"] = True
            lin._session_of_ref[ref_of(ev)] = s["id"]
    for s in lin.sessions.values():
        if s["linkedLogonId"]:
            other = lin.session_at(s["host"], int(s["linkedLogonId"], 16), s["start"])
            if other and other is not s and abs(other["start"] - s["start"]) <= 5_000:
                s["linked"] = other["id"]
    for ev, lid in activity:
        host = host_key(ev.get("computer"))
        s = lin.session_at(host, lid, _ts(ev))
        if s is None:
            # a session known only by its activity is kept for accounts people use, not for a
            # machine account's or Windows' own
            user = str(ev.get("subjectUser") or "").strip().lower()
            if not user or user.endswith("$") or user in ("-", "system", "anonymous logon", "local service", "network service"):
                continue
            s = _unseen_session(lin, host, lid, ev)
        _add_activity(lin, s, ev)

    # RDP evidence outside 4624: reconnects and disconnects (4778, 4779), the session manager and
    # remote connection manager
    for ev in reconnects:
        host = host_key(ev.get("computer"))
        lid = logon_id(_data(ev).get("LogonID") or _data(ev).get("LogonId"))
        s = lin.session_at(host, lid, _ts(ev))
        entry = {
            "ts": _ts(ev),
            "kind": "reconnect" if _eid(ev) == 4778 else "disconnect",
            "ip": ip_of(ev.get("ipAddress")) or None,
            "workstation": ev.get("workstation"),
            "ref": ref_of(ev),
        }
        if s:
            s["reconnects"].append(entry)
            s["rdp"] = True
            lin._session_of_ref[entry["ref"]] = s["id"]
        if entry["kind"] == "reconnect":
            _hop(
                lin,
                "rdp",
                ev,
                host,
                entry["ip"] or "",
                str(ev.get("workstation") or ""),
                ev.get("serviceAccount") or _data(ev).get("AccountName"),
                _data(ev).get("AccountDomain"),
                s,
                "an RDP session was reconnected from it (4778)",
                STRONG,
            )
    for ev in rdp_other:
        host = host_key(ev.get("computer"))
        ip = ip_of(ev.get("ipAddress"))
        eid = _eid(ev)
        if eid in (22, 23, 24) or not ip:
            continue
        s = _nearest_rdp(lin, host, ev)
        what = (
            "an RDP user authenticated from it (1149)"
            if eid == 1149
            else f"the session manager logged an RDP {'logon' if eid == 21 else 'reconnection'} from it ({eid})"
        )
        _hop(lin, "rdp", ev, host, ip, "", ev.get("targetUser"), ev.get("targetDomain"), s, what, STRONG)

    # hops from sessions: RDP, and network sessions that did something
    for s in lin.sessions.values():
        if not s["logonSeen"]:
            continue
        if s["rdp"] and (s["ip"] or s["workstation"]):
            _session_hop(lin, s, "rdp", f"an RDP logon (4624 type {s['type']}) came from it")
        elif s["type"] in (3, 8) and (s["ip"] or s["workstation"]) and s["actions"]:
            acts = s["actions"]
            kind = "remote-service" if "installed a service" in acts else "admin-share" if any(a.startswith("opened") for a in acts) else "remote-action"
            _session_hop(lin, s, kind, f"a network logon from it {', '.join(sorted(acts))}")
    # an admin share opened without its logon in the evidence: the share record names the source
    for ev in shares:
        host = host_key(ev.get("computer"))
        what = remote_action(ev)
        if not what:
            continue
        s = lin.session_of(ref_of(ev))
        if s and s["logonSeen"]:
            continue
        ip = ip_of(ev.get("ipAddress"))
        if ip or s:
            _hop(lin, "admin-share", ev, host, ip, "", ev.get("subjectUser"), ev.get("subjectDomain"), s, f"a connection from it {what} ({_eid(ev)})", STRONG)
    # a service installed right after an admin share was opened on that host: PsExec's pattern
    admin_hops: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for h in lin.hops.values():
        if h["kind"] in ("admin-share", "remote-action"):
            admin_hops[h["to"]].append(h)
    for ev in services:
        host = host_key(ev.get("computer"))
        ts = _ts(ev)
        near = [h for h in admin_hops.get(host, []) if 0 <= ts - h["ts"] <= _SERVICE_AFTER_SHARE or h["ts"] <= ts <= h["tsEnd"] + _SERVICE_AFTER_SHARE]
        if not near:
            continue
        h = max(near, key=lambda h: h["ts"])
        mins = max(0, round((ts - h["tsEnd"]) / 60_000))
        h["kind"] = "remote-service"
        h["evidence"].append(f"service {ev.get('serviceName') or '?'} installed {mins} min after ({_eid(ev)})")
        h["refs"].append(ref_of(ev))
        lin._hops_of_ref[ref_of(ev)].append(h["id"])
    # explicit credentials towards another host (4648): confirmed by a logon there from this host
    for ev in explicit:
        src = host_key(ev.get("computer"))
        dst = host_key(ev.get("targetServer") or _data(ev).get("TargetServerName"))
        if not dst or dst == src:
            continue
        ts = _ts(ev)
        match = _logon_from(lin, dst, src, ev.get("targetUser"), ts)
        h = _hop(
            lin,
            "explicit-credentials",
            ev,
            dst,
            "",
            src,
            ev.get("targetUser"),
            ev.get("targetDomain"),
            match,
            f"{_base(ev.get('processName')) or 'a program'} used explicit credentials towards it (4648)" + (", and the logon there followed" if match else ""),
            STRONG if match else MEDIUM,
            from_host=src,
        )
        if h and match:
            lin._hops_of_ref[match["logonRef"]].append(h["id"])
    # a connection to a remote-access port of another host of the case (Sysmon 3)
    for ev in conns:
        if str(ev.get("initiated") or "").lower() not in ("true", "1"):
            continue
        port = _int(ev.get("destinationPort"))
        kind = _REMOTE_PORTS.get(port)
        src = host_key(ev.get("computer"))
        dst = host_key(ev.get("destinationHostname")) or lin.host_of_ip(ip_of(ev.get("destinationIp"))) or ""
        if not kind or not dst or dst == src or dst not in counts:
            continue
        _hop(
            lin,
            "connection",
            ev,
            dst,
            "",
            src,
            ev.get("user"),
            None,
            None,
            f"{_base(ev.get('image')) or 'a program'} connected to its {kind.upper()} port {port} (Sysmon 3)",
            MEDIUM,
            from_host=src,
        )

    # process trees
    _processes(lin, sysmon1, procs4688)

    # hosts and what their evidence covers
    for host, c in counts.items():
        span = spans.get(host, [0, 0])
        lin.hosts[host] = {
            "key": host,
            "name": names[host].most_common(1)[0][0] if names[host] else host,
            "ips": sorted(ip for ip, v in lin.ip_hosts.items() if v["host"] == host),
            "events": c["events"],
            "first": span[0],
            "last": span[1],
            "coverage": {
                k: c[k] for k in ("sysmon1", "process4688", "commandLines", "logons", "logoffs", "rdp", "shares", "services", "powershell", "sysmon3")
            },
            "cleared": [{"ts": ts, "log": log, "ref": ref} for ts, log, ref in clears.get(host, [])],
            "limits": _limits(host, names[host].most_common(1)[0][0] if names[host] else host, c, clears.get(host, [])),
        }
    return lin


def _int(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _source(lin: Lineage, ip: str, workstation: str, host: str) -> str | None:
    """The host a logon or connection came from, when the case names it or shows whose address it is."""
    ws = host_key(workstation)
    if ws and ws != host:
        return ws
    if ip:
        h = lin.host_of_ip(ip)
        if h and h != host:
            return h
    return None


def _unseen_session(lin: Lineage, host: str, lid: int, ev: dict[str, Any]) -> dict[str, Any]:
    """A session known only by its activity: its logon is not in the evidence."""
    ts = _ts(ev)
    s = {
        "id": _hid("ses", host, lid, "unseen", ts),
        "host": host,
        "logonId": hex(lid),
        "user": ev.get("subjectUser"),
        "domain": ev.get("subjectDomain"),
        "sid": ev.get("subjectSid"),
        "account": _account(ev.get("subjectUser"), ev.get("subjectDomain")),
        "type": 0,
        "typeName": "logon not in the evidence",
        "ip": None,
        "workstation": None,
        "from": None,
        "authPackage": None,
        "logonProcess": None,
        "elevated": False,
        "privileged": False,
        "linked": None,
        "linkedLogonId": None,
        "start": ts,
        "end": None,
        "logonRef": None,
        "logoffRef": None,
        "logonSeen": False,
        "rdp": False,
        "reconnects": [],
        "activity": 0,
        "activityRefs": [],
        "activityKinds": {},
        "actions": {},
    }
    lin.sessions[s["id"]] = s
    cands = lin._by_key[(host, lid)]
    cands.append(s)
    cands.sort(key=lambda x: x["start"])
    return s


def remote_action(ev: dict[str, Any]) -> str | None:
    """What an event done in a network session did that makes the session a way in, in words."""
    eid = _eid(ev)
    share = str(ev.get("shareName") or "")
    if eid in (5140, 5145) and _ADMIN_SHARE.search(share):
        return f"opened the admin share {share.rsplit(chr(92), 1)[-1]}"
    pipe = _EXEC_PIPE.search(str(ev.get("relativeTargetName") or "")) if eid == 5145 and share.upper().endswith("IPC$") else None
    if pipe:
        return f"opened the {pipe.group(1).upper() if pipe.group(1).lower() == 'psexesvc' else pipe.group(1).lower()} pipe"
    if eid in (4698, 4702):
        return "created a scheduled task" if eid == 4698 else "changed a scheduled task"
    if eid in (4697, 7045):
        return "installed a service"
    if eid == 4688:
        return "ran a program"
    if eid in _ACCOUNT_CHANGES:
        return "changed an account or a group"
    return None


def _add_activity(lin: Lineage, s: dict[str, Any], ev: dict[str, Any]) -> None:
    ref = ref_of(ev)
    s["activity"] += 1
    if len(s["activityRefs"]) < 200:
        s["activityRefs"].append(ref)
    k = str(_eid(ev))
    s["activityKinds"][k] = s["activityKinds"].get(k, 0) + 1
    what = remote_action(ev)
    if what:
        s["actions"][what] = s["actions"].get(what, 0) + 1
    lin._session_of_ref[ref] = s["id"]


def _nearest_rdp(lin: Lineage, host: str, ev: dict[str, Any]) -> dict[str, Any] | None:
    """The RDP session of the same account on the host closest in time to a session-manager record."""
    ts = _ts(ev)
    user = str(ev.get("targetUser") or "").lower().rsplit("\\", 1)[-1]
    best = None
    for s in lin.sessions.values():
        if s["host"] != host or not s["rdp"] or str(s.get("user") or "").lower() != user:
            continue
        d = abs(s["start"] - ts)
        if d <= _RDP_MATCH and (best is None or d < abs(best["start"] - ts)):
            best = s
    if best:
        lin._session_of_ref[ref_of(ev)] = best["id"]
    return best


def _logon_from(lin: Lineage, dst: str, src: str, user: Any, ts: int) -> dict[str, Any] | None:
    """A logon on dst of this account, from src (by workstation name or address), within two minutes."""
    u = str(user or "").lower().rsplit("\\", 1)[-1].split("@", 1)[0]
    for s in lin.sessions.values():
        if s["host"] != dst or not s["logonSeen"] or abs(s["start"] - ts) > _RDP_MATCH:
            continue
        if str(s.get("user") or "").lower() == u and s.get("from") == src:
            return s
    return None


def _session_hop(lin: Lineage, s: dict[str, Any], kind: str, basis: str) -> None:
    ev = {
        "computer": s["host"],
        "ts": s["start"],
        "id": s["logonRef"].split(":", 1)[1] if s["logonRef"].startswith("event:") else None,
        "recordKey": s["logonRef"],
    }
    h = _hop(lin, kind, ev, s["host"], s["ip"] or "", s["workstation"] or "", s["user"], s["domain"], s, basis, STRONG)
    if not h:
        return
    h["evidence"].append(f"logon {s['logonId']} ({s['typeName']}) from {s['ip'] or s['workstation']}")
    if kind != "rdp":
        h["evidence"].extend(f"{what}{f' ({n} times)' if n > 1 else ''}" for what, n in sorted(s["actions"].items()))
    for r in s["activityRefs"][:50]:
        if h["id"] not in lin._hops_of_ref[r]:
            lin._hops_of_ref[r].append(h["id"])


def _hop(
    lin: Lineage,
    kind: str,
    ev: dict[str, Any],
    to: str,
    ip: str,
    workstation: str,
    user: Any,
    domain: Any,
    session: dict[str, Any] | None,
    basis: str,
    confidence: str,
    from_host: str | None = None,
) -> dict[str, Any] | None:
    """A way into a host, merged with the same hop (kind, source, target, account) within an hour."""
    if not to:
        return None
    src_host = from_host or _source(lin, ip, workstation, to)
    if not src_host and not ip:
        return None
    ts = _ts(ev)
    account = _account(user, domain)
    key = (kind, src_host or ip, to, account.lower())
    for h in lin._hop_index.get(key, []):
        if ts - h["tsEnd"] <= 3600_000:
            h["tsEnd"] = max(h["tsEnd"], ts)
            h["count"] += 1
            if len(h["refs"]) < 50:
                h["refs"].append(ref_of(ev))
            lin._hops_of_ref[ref_of(ev)].append(h["id"])
            if session and not h.get("session"):
                h["session"] = session["id"]
            return h
    ip_basis = lin.ip_hosts.get(ip, {}).get("basis") if ip and src_host and not host_key(workstation) and not from_host else None
    h = {
        "id": _hid("hop", kind, src_host or ip, to, account.lower(), ts),
        "kind": kind,
        "from": {
            "host": src_host,
            "ip": ip or None,
            "workstation": workstation or None,
            "external": bool(ip) and not is_internal_ip(ip),
            "basis": ip_basis,
        },
        "to": to,
        "account": account or None,
        "user": user,
        "domain": domain,
        "ts": ts,
        "tsEnd": ts,
        "count": 1,
        "session": session["id"] if session else None,
        "refs": [ref_of(ev)],
        "evidence": [],
        "basis": basis,
        # a source host known only from the address it used is as sure as that attribution
        "confidence": MEDIUM if ip_basis and confidence == STRONG else confidence,
    }
    lin._hop_index[key].append(h)
    lin.hops[h["id"]] = h
    lin._hops_of_ref[ref_of(ev)].append(h["id"])
    return h


def _processes(lin: Lineage, sysmon1: list[dict[str, Any]], procs4688: list[dict[str, Any]]) -> None:
    by_pid: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)

    def place(p: dict[str, Any], ev: dict[str, Any], lid: int | None) -> None:
        s = lin.session_at(p["host"], lid, p["ts"])
        if s and not p.get("session"):
            p["session"] = s["id"]
            _add_activity(lin, s, ev)

    for ev in sysmon1:
        host, guid = host_key(ev.get("computer")), _guid(ev.get("processGuid"))
        if not host:
            continue
        pid = _pid(ev.get("callerProcessId") or _data(ev).get("ProcessId"))
        pid_ = _hid("proc", host, guid) if guid else _hid("proc", host, pid, _ts(ev))
        p = {
            "id": pid_,
            "host": host,
            "pid": pid,
            "guid": guid or None,
            "image": ev.get("image"),
            "name": _base(ev.get("image")),
            "commandLine": ev.get("commandLine"),
            "user": ev.get("user"),
            "integrity": ev.get("integrityLevel"),
            "hashes": ev.get("hashes"),
            "parent": None,
            "parentGuid": _guid(ev.get("parentProcessGuid")) or None,
            "parentImage": ev.get("parentImage"),
            "parentPid": _pid(ev.get("parentProcessId")),
            "parentCommandLine": ev.get("parentCommandLine"),
            "ts": _ts(ev),
            "refs": [ref_of(ev)],
            "source": "sysmon",
            "session": None,
            "children": [],
        }
        lin.processes[p["id"]] = p
        lin._process_of_ref[ref_of(ev)] = p["id"]
        if guid:
            lin._process_of_guid[guid] = p["id"]
        if pid is not None:
            by_pid[(host, pid)].append(p)
        place(p, ev, logon_id(_data(ev).get("LogonId")))
    for p in list(lin.processes.values()):
        if p["parentGuid"] and p["parentGuid"] in lin._process_of_guid:
            p["parent"] = lin._process_of_guid[p["parentGuid"]]
    for ev in procs4688:
        host = host_key(ev.get("computer"))
        pid, creator, ts = _pid(ev.get("newProcessId")), _pid(ev.get("callerProcessId")), _ts(ev)
        if not host or pid is None:
            continue
        name = _base(ev.get("processName"))
        # the same process in Sysmon: one process, both records
        same = next((q for q in by_pid.get((host, pid), []) if abs(q["ts"] - ts) <= _SAME_PROCESS and q["name"].lower() == name.lower()), None)
        lid = logon_id(ev.get("targetLogonId"))
        lid = lid if lid else logon_id(ev.get("subjectLogonId"))
        if same:
            same["refs"].append(ref_of(ev))
            same["source"] = "both"
            same["commandLine"] = same["commandLine"] or ev.get("commandLine")
            same["parentImage"] = same["parentImage"] or ev.get("parentProcessName")
            if same["parentPid"] is None:
                same["parentPid"] = creator
            if not same["parent"]:
                same["parent"] = _creator(by_pid, host, creator, same["ts"], same["id"])
            lin._process_of_ref[ref_of(ev)] = same["id"]
            place(same, ev, lid)
            continue
        p = {
            "id": _hid("proc", host, pid, ts),
            "host": host,
            "pid": pid,
            "guid": None,
            "image": ev.get("processName"),
            "name": name,
            "commandLine": ev.get("commandLine"),
            "user": _account(ev.get("targetUser"), ev.get("targetDomain")) or _account(ev.get("subjectUser"), ev.get("subjectDomain")) or None,
            "integrity": ev.get("mandatoryLabel"),
            "hashes": None,
            "parent": None,
            "parentGuid": None,
            "parentImage": ev.get("parentProcessName"),
            "parentPid": creator,
            "parentCommandLine": None,
            "ts": ts,
            "refs": [ref_of(ev)],
            "source": "4688",
            "session": None,
            "children": [],
        }
        p["parent"] = _creator(by_pid, host, creator, ts, p["id"])
        if p["parent"]:
            p["parentImage"] = p["parentImage"] or lin.processes[p["parent"]]["image"]
        lin.processes[p["id"]] = p
        lin._process_of_ref[ref_of(ev)] = p["id"]
        by_pid[(host, pid)].append(p)
        place(p, ev, lid)
    for p in lin.processes.values():
        if p["parent"] and p["parent"] in lin.processes:
            lin.processes[p["parent"]]["children"].append(p["id"])


def _creator(by_pid: dict[tuple[str, int], list[dict[str, Any]]], host: str, creator: int | None, ts: int, own: str) -> str | None:
    """The process that created one: the latest creation of the creator's id on that host before it (ids are reused)."""
    if creator is None:
        return None
    cands = [q for q in by_pid.get((host, creator), []) if 0 <= ts - q["ts"] <= _PROCESS_REUSE and q["id"] != own]
    return max(cands, key=lambda q: q["ts"])["id"] if cands else None


def _limits(host: str, name: str, c: Counter, clears: list[tuple[int, str, str]]) -> list[str]:
    """What this host's evidence cannot show, in words."""
    out = []
    if not c["sysmon1"] and not c["process4688"]:
        out.append(f"What ran on {name} is not in the evidence: it has no Sysmon process creation (1) and no process creation audit (4688).")
    elif not c["sysmon1"]:
        s = f"What ran on {name} comes from 4688 alone: parents are found by process id within the log, and there are no process GUIDs or hashes"
        out.append(s + (", nor command lines: the audit policy did not record them." if not c["commandLines"] else "."))
    if not c["logons"]:
        out.append(f"Who logged on to {name} is not in the evidence: it has no logon events (4624).")
    by_log: dict[str, list[int]] = defaultdict(list)
    for ts, log, _ in clears:
        by_log[log].append(ts)
    for log, times in sorted(by_log.items()):
        if len(times) == 1:
            out.append(f"The {log} log of {name} was cleared at {_iso(times[0])}: what it held before then is not in this log.")
        else:
            out.append(
                f"The {log} log of {name} was cleared {len(times)} times between {_iso(min(times))} and {_iso(max(times))}: "
                "what it held before each clear is not in this log."
            )
    return out
