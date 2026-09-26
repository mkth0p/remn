"""
Host lineage: who was logged on to each host, how they got there, and what ran there.

- **Sessions.** A logon session is a host and a logon id. It opens with its logon (4624), closes
  with its logoff (4634, 4647), and holds every event that names that logon id as its subject on
  that host in between (4688, 4698, 4720, 4732, 5140, 1102 ...). Logon ids are reused after a
  reboot: activity after the session of its id ended, before the first logon of that id, or of
  another account is not that session's. Activity whose logon is not in the evidence still makes
  a session, marked as such. The SYSTEM, LOCAL SERVICE and NETWORK SERVICE sessions are not
  anyone's and are left out.
- **Hops.** How an account came to a host: an RDP logon (4624 type 10, and 4778, 1149 or the local
  session manager's 21 and 25 when those are what the evidence has), a network session that opened
  an admin share, created a task or a service or ran a program (5140, 5145, 4698, 4697, 4688,
  Sysmon 1), through WMI when the program's parent is WmiPrvSE and through WinRM when it is
  wsmprovhost or winrshost or WinRM started a shell then (91), a service installed right after an
  admin share was opened (7045: PsExec's pattern; by time alone medium, strong when the service
  manager's pipe was opened in that connection, the service was installed under its logon id or
  its program written through the share), explicit credentials used towards another host
  (4648), a WMI call from another host that failed (WMI-Activity 5858), remote execution named on
  the source (wmic /node, winrs -r, PowerShell remoting and WMI cmdlets with -ComputerName, WinRM's
  own session record 6), and a Sysmon connection to a remote-access port of another host of the
  case. A hop's source is a host when the case shows whose address it is, otherwise the address.
- **The domain controllers' records.** A logon came with the Kerberos service ticket the domain
  controller issued with its logon GUID (4769; strong), or, without one, with the ticket for the
  host's own account (HOST$: cifs, host ...) the account asked for from the logon's address within
  a minute before it (medium). The ticket's client address, or the host whose explicit credentials
  (4648) carried the ticket's logon GUID, is then the logon's source when the logon does not name
  it; an NTLM validation (4776) names the workstation of a network logon that names none (medium,
  by account and time). A host whose logons consistently follow their tickets by more than a
  minute (or precede them) has its clock skew noted, and the ties by time allow for it.
- **Other credentials.** A NewCredentials logon (4624 type 9: runas /netonly, pass-the-hash
  tooling) names the account its session uses on the network: a network logon of that account from
  this host while the session is open is a way into that host, like explicit credentials (medium).
- **Addresses.** An address belongs to the host whose own Sysmon connections come from it, that a
  logon names as its workstation (4624), that a DNS answer names for it (Sysmon 22, DNS client
  3008), that the DHCP server leased it to (its audit log), that the domain controller gave the
  host's own account a Kerberos ticket at (4768, 4769), or that asked for the ticket of explicit
  credentials used on the host (4648 and 4769 of one logon GUID). When the evidence gives it to
  several hosts, the one whose records put it nearest in time is taken.
- **Devices.** An Entra sign-in's device (its name and how it is joined) is the host of that name
  when the case has its logs.
- **Process trees.** Sysmon 1 by process GUID; 4688 by process id and creator id on one host, the
  latest creation of that id before the child (ids are reused), which must be of the parent's
  program when the 4688 names it (within a week; within a day when only the id ties them); a
  process both logged is one. Each process is placed in its logon session.
- **Coverage.** What each host's evidence can show: without Sysmon 1 what ran comes from 4688
  alone, and without command lines when the audit policy left them out; without 4624 who logged
  on is not visible; a cleared log ends what came before in that log.

Everything is computed from the rows given; nothing is inferred beyond what they state, and each
tie says why and how surely: strong when a record states it (a logon id, a process GUID), medium
when it rests on the same account, host and time or on an address the case attributes to a host.
Each record keeps its own tie to its session and to each hop it is part of: a program, a shell or
a service tied by time is medium even in a hop its logon makes strong.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from functools import lru_cache
from statistics import median
from typing import Any

from .identity import CONFIDENCE_RANK, MEDIUM, STRONG
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
# the pipes a service is created through remotely: the service manager's and the tools' that install one
_SERVICE_PIPES = frozenset({"svcctl", "psexesvc", "remcom", "paexec", "csexec"})
# a service's program: the file an image path runs (quoted or not, with its arguments after it)
_SERVICE_PROGRAM = re.compile(r"(?i)([^\\/\"\s]+\.(?:exe|com|bat|cmd|ps1|dll|sys|scr))(?=$|[\"\s])")
_RDP_MATCH = 2 * 60_000
# a process's creator is the latest creation of its id before it: within a week when the record
# names the parent's program and it matches (explorer or a service runs for days), within a day
# when nothing but the id ties them
_PROCESS_REUSE = 7 * 86_400_000
_PROCESS_REUSE_UNNAMED = 86_400_000
_SAME_PROCESS = 2_000
# records of one moment are not always written in order: an event this close to its session's
# logon or logoff is still in it
_SLACK = 5_000
_LSM = "terminalservices-localsessionmanager"
_RCM = "terminalservices-remoteconnectionmanager"
# the programs remote execution runs its commands under on the target
_WMI_PARENTS = frozenset({"wmiprvse.exe"})
_WINRM_PARENTS = frozenset({"wsmprovhost.exe", "winrshost.exe"})
# remote execution named on the source: wmic /node, winrs -r, PowerShell remoting and WMI cmdlets
_REMOTE_HINT = re.compile(r"(?i)/node:|\bwinrs|-computername\b|-cn\s|\benter-pssession\b|\betsn\b")
_REMOTE_CMDS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"(?i)\bwmic(?:\.exe)?\b[^\n]*?/node:\s*[\"']?([^\s\"',/]+)"), "wmi", "wmic ran against it (/node)"),
    (re.compile(r"(?i)\bwinrs(?:\.exe)?\b[^\n]*?[-/]r(?:emote)?:\s*[\"']?(?:https?://)?([^\s\"':/]+)"), "winrm", "winrs ran a command on it"),
    (
        re.compile(r"(?i)\b(?:invoke-command|icm|enter-pssession|etsn|new-pssession|nsn)\b[^\n|;]*?\s-(?:computername|cn)\s+[\"']?([^\s\"',;)]+)"),
        "winrm",
        "PowerShell remoting to it",
    ),
    (re.compile(r"(?i)\b(?:enter-pssession|etsn)\s+[\"']?([a-z0-9][a-z0-9.\-_]*)"), "winrm", "PowerShell remoting to it"),
    (
        re.compile(
            r"(?i)\b(?:invoke-wmimethod|get-wmiobject|gwmi|set-wmiinstance|swmi|invoke-cimmethod|get-ciminstance|new-cimsession)\b[^\n|;]*?\s-(?:computername|cn)\s+[\"']?([^\s\"',;)]+)"
        ),
        "wmi",
        "a PowerShell WMI call to it",
    ),
)
_WINRM_TARGET = re.compile(r"(?i)^(?:https?://)?\[?([^/\]:?]+)")
# a DNS name that names a domain or a service rather than a host
_NOT_A_HOST = frozenset({"www", "wpad", "isatap", "autodiscover", "localhost", "_msdcs", "_ldap", "_kerberos", "_gc"})
# a program the target runs WMI's or WinRM's command under starts within this long of the caller's logon
_EXEC_AFTER_LOGON = 60_000
# explicit credentials used by a remote-execution client: the way in is that client's
_EXPLICIT_KIND = {"wmic.exe": "wmi", "winrs.exe": "winrm", "mstsc.exe": "rdp"}
# the DHCP server's audit log: a new lease, a renewal (its other records do not give an address to a host)
_DHCP_LEASES = frozenset({"10", "11"})
# the domain controllers' records of an authentication: a ticket-granting ticket (4768), a service
# ticket (4769), an NTLM validation (4776); only a domain controller logs the first two
_KERBEROS = frozenset({4768, 4769})
_NTLM = 4776
# a service ticket is asked for, or NTLM credentials validated, within this long before the logon they are for
_AUTH_BEFORE = 60_000
# a NewCredentials session's network logons are looked for while it is open, or this long when its logoff is not in the evidence
_NEW_CREDENTIALS_REACH = 12 * 3600_000


# --- values ---------------------------------------------------------------------------------------


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def host_key(v: Any) -> str:
    """ws-004 for WS-004.northstar.example, WS-004, \\\\WS-004 and WS-004$; empty for an address or localhost."""
    return _host_key(v if isinstance(v, str) else str(v or ""))


# a case names few hosts and addresses many times over: each is read once
@lru_cache(maxsize=65_536)
def _host_key(v: str) -> str:
    s = v.strip().strip("\\").strip().lower()
    if not s or s in ("-", "localhost", "::1", "127.0.0.1") or _is_ip(s):
        return ""
    return s.rstrip("$").split(".", 1)[0]


def ip_of(v: Any) -> str:
    return _ip_of(v if isinstance(v, str) else str(v or ""))


@lru_cache(maxsize=65_536)
def _ip_of(v: str) -> str:
    s = v.strip().lower()
    if s.startswith("::ffff:"):
        s = s[7:]
    if s in ("", "-", "::1", "127.0.0.1", "0.0.0.0", "::", "localhost") or not _is_ip(s):
        return ""
    return s


_SHARED = ipaddress.ip_network("100.64.0.0/10")
# the documentation ranges stand for internet addresses in the samples and labs
_DOC_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))


@lru_cache(maxsize=65_536)
def is_internal_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # carrier-grade NAT's shared space (a provider's, Tailscale's) is no internet address either
    shared = a.version == 4 and a in _SHARED
    return (a.is_private or a.is_loopback or a.is_link_local or shared) and not any(a in n for n in _DOC_NETS)


def logon_id(v: Any) -> int | None:
    n = numeric_id(v)
    return int(n) if n else None


def _user_key(v: Any) -> str:
    """alice for alice, CONTOSO\\alice and alice@contoso.com: how a session's account and its activity's
    are compared; empty (not compared) when a record does not name it, or names only its SID."""
    s = str(v or "").strip().lower().rsplit("\\", 1)[-1].split("@", 1)[0]
    return "" if s == "-" or s.startswith("s-1-") else s


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


def _granted(ev: dict[str, Any]) -> bool:
    """A Kerberos or NTLM record of a success: the ticket issued, the credentials validated."""
    return str(ev.get("status") or "0x0").strip().lower() in ("0", "0x0", "0x00000000")


def _domain_key(v: Any) -> str:
    """northstar for NORTHSTAR and northstar.example: how two accounts' domains are compared."""
    s = str(v or "").strip().lower()
    return "" if s == "-" else s.split(".", 1)[0]


def other_credentials(ev: dict[str, Any]) -> str | None:
    """The account a logon's session uses on the network when it is not its own: a NewCredentials
    logon (4624 type 9: runas /netonly, pass-the-hash tooling) names it as its network account."""
    if _eid(ev) != 4624 or _int(ev.get("logonType")) != 9:
        return None
    user = str(ev.get("targetOutboundUser") or "").strip()
    if not _user_key(user):
        return None
    domain = ev.get("targetOutboundDomain")
    mine, theirs = _domain_key(ev.get("targetDomain")), _domain_key(domain)
    if _user_key(user) == _user_key(ev.get("targetUser")) and (not mine or not theirs or mine == theirs):
        return None
    return _account(user, domain)


# --- lineage --------------------------------------------------------------------------------------


class Lineage:
    """Sessions, hops and process trees of the hosts in a set of events, and what each host's evidence covers."""

    def __init__(self) -> None:
        self.hosts: dict[str, dict[str, Any]] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.hops: dict[str, dict[str, Any]] = {}
        self.processes: dict[str, dict[str, Any]] = {}
        self.ip_hosts: dict[str, dict[str, Any]] = {}
        # Entra devices by host key: the name, ids and join types sign-ins give, the accounts that used them
        self.devices: dict[str, dict[str, Any]] = {}
        self._by_key: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
        self._session_of_ref: dict[str, str] = {}
        self._process_of_ref: dict[str, str] = {}
        self._process_of_guid: dict[str, str] = {}
        self._hops_of_ref: dict[str, list[str]] = defaultdict(list)
        self._hop_index: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
        # how surely each record is part of each hop it is in, and the records placed in a session
        # by time rather than by their logon id
        self._hop_ties: dict[tuple[str, str], str] = {}
        self._timed: set[tuple[str, str]] = set()
        # the pipes opened and the files written through admin shares, by session and by hop
        self._marks: dict[str, set[str]] = defaultdict(set)
        # the sessions of each host, and of each account on a host, in the order they began
        self._by_host: dict[str, tuple[list[int], list[dict[str, Any]]]] = {}
        self._by_host_user: dict[tuple[str, str], tuple[list[int], list[dict[str, Any]]]] = {}
        # how surely the host a session's source was named by beyond its logon (a ticket, a 4648, a 4776) is
        self._from_conf: dict[str, str] = {}
        # the sessions each service ticket was tied to, and how surely; each host's clock against the domain controllers'
        self._ticket_ties: dict[str, list[tuple[dict[str, Any], str]]] = defaultdict(list)
        self._clock: dict[str, dict[str, Any]] = {}

    # lookups the story engine uses
    def session_at(self, host: str, lid: int | None, ts: int, user: Any = None) -> dict[str, Any] | None:
        """The session of a logon id on a host at a time. Logon ids are reused after a reboot: it is
        the latest session of that id to begin by then, unless it had ended; before any logon of
        that id, or after its session ended, an event is in no session known yet, except one whose
        logon is not in the evidence (it began before its first record). A session of another
        account is not the event's either."""
        if not host or lid is None or lid in _SYSTEM_LOGONS:
            return None
        cands = self._by_key.get((host, lid))
        if not cands:
            return None
        i = bisect_right([s["start"] for s in cands], ts + _SLACK) - 1
        s = cands[i] if i >= 0 else None
        if s is not None and s["end"] is not None and ts > s["end"] + _SLACK:
            s = None
        if s is None and i + 1 < len(cands) and not cands[i + 1]["logonSeen"]:
            s = cands[i + 1]
        if s is not None and _user_key(user) and _user_key(s.get("user")) and _user_key(user) != _user_key(s.get("user")):
            return None
        return s

    def session_of(self, ref: str) -> dict[str, Any] | None:
        sid = self._session_of_ref.get(ref)
        return self.sessions.get(sid) if sid else None

    def session_tie(self, ref: str) -> str:
        """How surely a record is in its session: strong by its logon id, medium when only time put it there."""
        return MEDIUM if (self._session_of_ref.get(ref), ref) in self._timed else STRONG

    def hop_tie(self, hop: dict[str, Any], ref: str) -> str:
        """How surely a record is part of a hop: as sure as what joined it to the hop (the record that
        made the hop is as sure as the hop; a WMI program or a service tied to it by time is medium)."""
        return self._hop_ties.get((hop["id"], ref), hop["confidence"])

    def sessions_near(self, host: str, lo: int, hi: int, user: str | None = None) -> Iterator[dict[str, Any]]:
        """The sessions of a host (of an account on it, given its name) that began between two times, in order."""
        starts, ss = (self._by_host.get(host) if user is None else self._by_host_user.get((host, user))) or ([], [])
        i = bisect_left(starts, lo)
        while i < len(ss) and starts[i] <= hi:
            yield ss[i]
            i += 1

    def process_of(self, ref: str) -> dict[str, Any] | None:
        pid = self._process_of_ref.get(ref)
        return self.processes.get(pid) if pid else None

    def process_of_guid(self, guid: Any) -> dict[str, Any] | None:
        pid = self._process_of_guid.get(_guid(guid))
        return self.processes.get(pid) if pid else None

    def hops_of(self, ref: str) -> list[dict[str, Any]]:
        return [self.hops[h] for h in self._hops_of_ref.get(ref, []) if h in self.hops]

    def host_of_ip(self, ip: str, ts: int | None = None) -> str | None:
        """The host an address belongs to; at a time, when the evidence gives it to several hosts, the one
        whose records put it nearest to that time."""
        hit = self.ip_hosts.get(ip)
        if not hit:
            return None
        spans = hit.get("spans") or []
        if ts and len(spans) > 1:

            def distance(sp: dict[str, Any]) -> int:
                return 0 if sp["first"] <= ts <= sp["last"] else min(abs(ts - sp["first"]), abs(ts - sp["last"]))

            return min(spans, key=lambda sp: (distance(sp), -sp["count"]))["host"]
        return hit["host"]

    def device_of(self, row: dict[str, Any]) -> dict[str, Any] | None:
        """The Entra device a sign-in names, with the host of that name when the case has its logs."""
        key = host_key(_data(row).get("deviceName"))
        return self.devices.get(key) if key else None

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
                "devices": list(self.devices.values()),
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
            "devices": [d for d in self.devices.values() if want.intersection(d["refs"])][:20],
        }


def _guid(v: Any) -> str:
    s = str(v or "").strip().strip("{}").lower()
    return s if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", s) and s.strip("0-") else ""


def build_lineage(events: Iterable[dict[str, Any]], settings: dict[str, Any] | None = None) -> Lineage:
    """Sessions, hops, process trees and coverage from the events of a case (or of a story's window)."""
    lin = Lineage()
    rows = sorted(
        (e for e in events if e.get("computer") or e.get("eventId") or e.get("artifactType") == "dhcp" or _data(e).get("deviceName")),
        key=lambda e: (_ts(e), str(e.get("id") or "")),
    )
    counts: dict[str, Counter] = defaultdict(Counter)
    names: dict[str, Counter] = defaultdict(Counter)
    spans: dict[str, list[int]] = {}
    clears: dict[str, list[tuple[int, str, str]]] = defaultdict(list)
    ip_votes: dict[str, Counter] = defaultdict(Counter)
    ip_basis: dict[tuple[str, str], str] = {}
    ip_spans: dict[tuple[str, str], list[int]] = {}

    def vote(ip: str, host: str, basis: str, ts: int) -> None:
        ip_votes[ip][host] += 1
        ip_basis.setdefault((ip, host), basis)
        if ts:
            sp = ip_spans.setdefault((ip, host), [ts, ts])
            sp[0], sp[1] = min(sp[0], ts), max(sp[1], ts)

    logons, logoffs, specials, activity, reconnects, rdp_other, explicit, shares, services, procs4688, sysmon1, conns = ([] for _ in range(12))
    dns_answers: list[tuple[dict[str, Any], str]] = []
    dhcp: list[dict[str, Any]] = []
    winrm: list[dict[str, Any]] = []
    wmi_failed: list[dict[str, Any]] = []
    remote_cmds: list[dict[str, Any]] = []
    signins: list[dict[str, Any]] = []
    tickets: list[dict[str, Any]] = []
    ntlm: list[dict[str, Any]] = []
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
                vote(own, host, "the address the host's own connections come from (Sysmon 3)", ts)
        elif sysmon and eid == 22:
            c["sysmon"] += 1
            dns_answers.append((ev, host))
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
                vote(ip, ws, "a logon came from this address under that workstation name (4624)", ts)
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
        elif eid in _KERBEROS:
            c["kerberos"] += 1
            tickets.append(ev)
        elif eid == _NTLM:
            c["ntlm"] += 1
            ntlm.append(ev)
        if (eid == 1102 and "security" in prov) or (eid == 104 and "eventlog" in prov):
            clears[host].append((ts, str(ev.get("channel") or "Security"), ref_of(ev)))
        # remote execution named on the source, WinRM's and WMI's own records, DNS answers, DHCP
        # leases and the devices sign-ins come from
        if eid in (1, 4688, 4104) and _REMOTE_HINT.search(str(ev.get("commandLine") or ev.get("scriptBlockText") or "")):
            remote_cmds.append(ev)
        if "winrm" in prov and eid in (6, 91):
            winrm.append(ev)
        elif "wmi-activity" in prov and eid == 5858:
            wmi_failed.append(ev)
        elif "dns-client" in prov and eid == 3008:
            dns_answers.append((ev, host))
        elif ev.get("artifactType") == "dhcp":
            dhcp.append(ev)
        elif "entra" in prov and _data(ev).get("deviceName"):
            signins.append(ev)
        # activity of a session: any event naming its logon id as the subject's, on that host
        lid = logon_id(ev.get("subjectLogonId") or _data(ev).get("SubjectLogonId"))
        if host and lid is not None and lid not in _SYSTEM_LOGONS and eid not in _ACTIVITY_SKIP and eid != 4688:
            activity.append((ev, lid))

    # a DNS answer names a host for a private address: only a plain answer (no alias), for a name
    # that is a host of the case or reads as one (three labels or more, not a service record)
    for ev, host in dns_answers:
        name = str(ev.get("query") or _data(ev).get("QueryName") or "").strip().rstrip(".").lower()
        results = str(ev.get("queryResults") or _data(ev).get("QueryResults") or "")
        if not name or "type:" in results.lower() or name.startswith("_") or _is_ip(name):
            continue
        target = host_key(name)
        if not target or target in _NOT_A_HOST or (target not in counts and name.count(".") < 2):
            continue
        for entry in results.split(";"):
            ip = ip_of(entry)
            if ip and is_internal_ip(ip):
                vote(ip, target, f"a DNS answer on {host or 'a host'} gave it for {name}", _ts(ev))
    for ev in dhcp:
        d = _data(ev)
        if str(d.get("ID") or "").strip() not in _DHCP_LEASES:
            continue
        ip, target = ip_of(ev.get("ipAddress") or d.get("IP Address")), host_key(ev.get("workstation") or d.get("Host Name"))
        if ip and target:
            vote(ip, target, "the DHCP server leased it to that host (its audit log)", _ts(ev))
    # the domain controller's tickets: a host's own account asks for its tickets from the host's
    # address, and explicit credentials used on a host (4648) ask for theirs from that host's, the
    # ticket carrying the logon GUID the 4648 names as its target's
    asked = {g: host_key(ev.get("computer")) for ev in explicit if (g := _guid(_data(ev).get("TargetLogonGuid")))}
    for ev in tickets:
        ip = ip_of(ev.get("ipAddress"))
        if not ip or not is_internal_ip(ip) or not _granted(ev):
            continue
        name = str(ev.get("targetUser") or "").split("@", 1)[0].strip()
        if name.endswith("$") and (own := host_key(name)):
            vote(ip, own, "the domain controller gave the host's own account a Kerberos ticket there (4768, 4769)", _ts(ev))
        elif _eid(ev) == 4769 and (src := asked.get(_guid(ev.get("logonGuid")))):
            vote(ip, src, "explicit credentials used on the host asked for their Kerberos ticket from it (4648, 4769)", _ts(ev))
    for ip, votes in ip_votes.items():
        host, n = votes.most_common(1)[0]
        lin.ip_hosts[ip] = {"host": host, "basis": ip_basis.get((ip, host), ""), "count": n, "others": sorted(h for h in votes if h != host)[:5]}
        timed = [{"host": h, "first": ip_spans[(ip, h)][0], "last": ip_spans[(ip, h)][1], "count": votes[h]} for h in votes if (ip, h) in ip_spans]
        if len(votes) > 1 and len(timed) > 1:
            lin.ip_hosts[ip]["spans"] = sorted(timed, key=lambda sp: sp["first"])

    # sessions: a logon, its logoff, 4672 privileges, and its activity
    for ev in logons:
        host, lid = host_key(ev.get("computer")), logon_id(ev.get("targetLogonId"))
        if not host or lid is None or lid in _SYSTEM_LOGONS:
            continue
        lt = _int(ev.get("logonType"))
        ts = _ts(ev)
        ip, ws = ip_of(ev.get("ipAddress")), str(ev.get("workstation") or "").strip()
        network = other_credentials(ev)
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
            "from": _source(lin, ip, ws, host, ts),
            # how the source host was named when the logon does not name it (a ticket, explicit credentials, NTLM)
            "fromBasis": None,
            "logonGuid": _guid(ev.get("logonGuid")) or None,
            # the account a NewCredentials logon uses on the network, and the records that say how the logon authenticated
            "network": network,
            "auth": [],
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
            "actions": {f"used other credentials ({network}) for the network": 1} if network else {},
        }
        lin.sessions[s["id"]] = s
        lin._by_key[(host, lid)].append(s)
        lin._session_of_ref[s["logonRef"]] = s["id"]
    for key in lin._by_key:
        lin._by_key[key].sort(key=lambda s: s["start"])
    for ev in logoffs:
        host, lid = host_key(ev.get("computer")), logon_id(ev.get("targetLogonId"))
        s = lin.session_at(host, lid, _ts(ev), ev.get("targetUser"))
        if s and s["end"] is None and _ts(ev) >= s["start"]:
            s["end"], s["logoffRef"] = _ts(ev), ref_of(ev)
            lin._session_of_ref[s["logoffRef"]] = s["id"]
    for ev in specials:
        host, lid = host_key(ev.get("computer")), logon_id(ev.get("subjectLogonId"))
        s = lin.session_at(host, lid, _ts(ev), ev.get("subjectUser"))
        if s and abs(_ts(ev) - s["start"]) <= _SLACK:
            s["privileged"] = True
            lin._session_of_ref[ref_of(ev)] = s["id"]
    for s in lin.sessions.values():
        if s["linkedLogonId"]:
            other = lin.session_at(s["host"], int(s["linkedLogonId"], 16), s["start"], s["user"])
            if other and other is not s and abs(other["start"] - s["start"]) <= _SLACK:
                s["linked"] = other["id"]
    for ev, lid in activity:
        host = host_key(ev.get("computer"))
        s = lin.session_at(host, lid, _ts(ev), ev.get("subjectUser"))
        if s is None:
            # a session known only by its activity is kept for accounts people use, not for a
            # machine account's or Windows' own; activity after a session of its logon id ended
            # (the id reused after a reboot) or before it began is such a session too
            user = str(ev.get("subjectUser") or "").strip().lower()
            if not user or user.endswith("$") or user in ("-", "system", "anonymous logon", "local service", "network service"):
                continue
            s = _unseen_session(lin, host, lid, ev)
        _add_activity(lin, s, ev)
    # no session is made after this point: index them by host and by account for the lookups below
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_host_user: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for s in sorted(lin.sessions.values(), key=lambda s: s["start"]):
        by_host[s["host"]].append(s)
        by_host_user[(s["host"], str(s.get("user") or "").lower())].append(s)
    lin._by_host = {k: ([s["start"] for s in v], v) for k, v in by_host.items()}
    lin._by_host_user = {k: ([s["start"] for s in v], v) for k, v in by_host_user.items()}
    # what the domain controllers' records and explicit credentials say of each logon: its ticket, its
    # source when the logon does not name it, each host's clock against the domain controllers'
    by_guid, ticket_of_guid = _authentications(lin, tickets, ntlm, explicit)

    # RDP evidence outside 4624: reconnects and disconnects (4778, 4779), the session manager and
    # remote connection manager
    for ev in reconnects:
        host = host_key(ev.get("computer"))
        lid = logon_id(_data(ev).get("LogonID") or _data(ev).get("LogonId"))
        s = lin.session_at(host, lid, _ts(ev), ev.get("serviceAccount") or _data(ev).get("AccountName"))
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

    # process trees, placed in their sessions: what a network session ran is part of what it did
    _processes(lin, sysmon1, procs4688)
    # A program WmiPrvSE or the WinRM host started under its own service account (4688 without the
    # caller's logon) belongs to the network logon of a person on that host just before it: WMI
    # and WinRM authenticate the caller, then start the program. A tie by time, so medium.
    for p in lin.processes.values():
        via = "WMI" if _base(p.get("parentImage")).lower() in _WMI_PARENTS else "WinRM" if _base(p.get("parentImage")).lower() in _WINRM_PARENTS else ""
        if not via:
            continue
        own = lin.sessions.get(p.get("session") or "")
        if own and own["type"] in (3, 8):
            continue
        near = [
            x
            for x in lin.sessions_near(p["host"], p["ts"] - _EXEC_AFTER_LOGON, p["ts"])
            if x["logonSeen"] and x["type"] in (3, 8) and _has_source(x) and not str(x.get("user") or "").endswith("$")
        ]
        if not near:
            continue
        x = max(near, key=lambda x: x["start"])
        what = f"ran a program through {via} (by time)"
        x["actions"][what] = x["actions"].get(what, 0) + 1
        x.setdefault("timed", True)
        for r in p["refs"]:
            lin._timed.add((x["id"], r))
            if len(x["activityRefs"]) < 200:
                x["activityRefs"].append(r)
    # WinRM started a shell (91) on a host: the network logon of that moment is its session, by time
    for ev in winrm:
        if _eid(ev) != 91:
            continue
        host, ts = host_key(ev.get("computer")), _ts(ev)
        near = [x for x in lin.sessions_near(host, ts - _RDP_MATCH, ts + _RDP_MATCH) if x["logonSeen"] and x["type"] in (3, 8)]
        if near:
            best = min(near, key=lambda x: abs(x["start"] - ts))
            best["actions"]["started a WinRM shell (91)"] = best["actions"].get("started a WinRM shell (91)", 0) + 1
            lin._session_of_ref[ref_of(ev)] = best["id"]
            lin._timed.add((best["id"], ref_of(ev)))
            if len(best["activityRefs"]) < 200:
                best["activityRefs"].append(ref_of(ev))

    # hops from sessions: RDP, and network sessions that did something
    for s in lin.sessions.values():
        if not s["logonSeen"]:
            continue
        if s["rdp"] and _has_source(s):
            _session_hop(lin, s, "rdp", f"an RDP logon (4624 type {s['type']}) came from it")
        elif s["type"] in (3, 8) and _has_source(s) and s["actions"]:
            acts = s["actions"]
            kind = (
                "remote-service"
                if "installed a service" in acts
                else "wmi"
                if any(a.startswith("ran a program through WMI") for a in acts)
                else "winrm"
                if any(a.startswith("ran a program through WinRM") for a in acts) or "started a WinRM shell (91)" in acts
                else "admin-share"
                if any(a.startswith("opened") for a in acts)
                else "remote-action"
            )
            # the program tied to the logon by time only is as sure as that tie
            timed = s.get("timed") and not any(a in acts for a in ("installed a service", "ran a program through WMI", "ran a program through WinRM"))
            _session_hop(lin, s, kind, f"a network logon from it {', '.join(sorted(acts))}", MEDIUM if timed else STRONG)
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
            h = _hop(
                lin, "admin-share", ev, host, ip, "", ev.get("subjectUser"), ev.get("subjectDomain"), s, f"a connection from it {what} ({_eid(ev)})", STRONG
            )
            if h and (marks := _share_marks(ev)):
                lin._marks[h["id"]] |= marks
    # a service installed right after an admin share was opened on that host: PsExec's pattern. By
    # time alone that is medium; the service manager's pipe opened in that connection, the logon id
    # the service was installed under (4697) or its program written through the share make it strong.
    admin_hops: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for h in lin.hops.values():
        if h["kind"] in ("admin-share", "remote-action"):
            admin_hops[h["to"]].append(h)
    # a hop's confidence before a service was tied to it, and whether one was tied beyond time
    as_share: dict[str, str] = {}
    linked: set[str] = set()
    for ev in services:
        ref = ref_of(ev)
        if lin._hops_of_ref.get(ref):
            # installed in a session that is already a way in (4697 names its logon id)
            continue
        host = host_key(ev.get("computer"))
        ts = _ts(ev)
        near = [h for h in admin_hops.get(host, []) if 0 <= ts - h["ts"] <= _SERVICE_AFTER_SHARE or h["ts"] <= ts <= h["tsEnd"] + _SERVICE_AFTER_SHARE]
        if not near:
            continue
        h = max(near, key=lambda h: h["ts"])
        mins = max(0, round((ts - h["tsEnd"]) / 60_000))
        link = _service_link(lin, h, ev)
        # a way in read as a remote service by time alone is as sure as that tie
        as_share.setdefault(h["id"], h["confidence"])
        if link:
            linked.add(h["id"])
        h["confidence"] = as_share[h["id"]] if h["id"] in linked else MEDIUM
        h["kind"] = "remote-service"
        h["evidence"].append(f"service {ev.get('serviceName') or '?'} installed {mins} min after ({_eid(ev)}), {link or 'by time only'}")
        h["refs"].append(ref)
        lin._hops_of_ref[ref].append(h["id"])
        _tie(lin, h, ref, STRONG if link else MEDIUM)
    # explicit credentials towards another host (4648): confirmed by the logon that carries their
    # target logon GUID, or that the ticket of that GUID led to (4769), else by a logon there from this host
    for ev in explicit:
        src = host_key(ev.get("computer"))
        dst = host_key(ev.get("targetServer") or _data(ev).get("TargetServerName"))
        ts = _ts(ev)
        match, conf, ticket, how = _guid_logon(lin, _guid(_data(ev).get("TargetLogonGuid")), src, by_guid, ticket_of_guid)
        if match:
            # the logon of their GUID is where they went; as surely as the ticket led there, unless the 4648 names that host too
            conf = STRONG if match["host"] == dst else conf
            dst = match["host"]
        elif not dst or dst == src:
            continue
        else:
            match = _logon_from(lin, dst, src, ev.get("targetUser"), ts)
            conf, how = STRONG, ", and the logon there followed"
        h = _hop(
            lin,
            _EXPLICIT_KIND.get(_base(ev.get("processName")).lower(), "explicit-credentials"),
            ev,
            dst,
            "",
            src,
            ev.get("targetUser"),
            ev.get("targetDomain"),
            match,
            f"{_base(ev.get('processName')) or 'a program'} used explicit credentials towards it (4648)" + (how if match else ""),
            conf if match else MEDIUM,
            from_host=src,
        )
        if h and match:
            if h["id"] not in lin._hops_of_ref[match["logonRef"]]:
                lin._hops_of_ref[match["logonRef"]].append(h["id"])
            _tie(lin, h, match["logonRef"], conf)
            if ticket is not None:
                _add_ref(lin, h, ref_of(ticket), conf)
    # a connection to a remote-access port of another host of the case (Sysmon 3)
    for ev in conns:
        if str(ev.get("initiated") or "").lower() not in ("true", "1"):
            continue
        port = _int(ev.get("destinationPort"))
        kind = _REMOTE_PORTS.get(port)
        src = host_key(ev.get("computer"))
        dst = host_key(ev.get("destinationHostname")) or lin.host_of_ip(ip_of(ev.get("destinationIp")), _ts(ev)) or ""
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

    # remote execution named on the source: a command line, a script block or WinRM's own record
    # of the session it opened (6); strong when the logon on the target from this host follows
    for ev in remote_cmds + [e for e in winrm if _eid(e) == 6]:
        src, ts = host_key(ev.get("computer")), _ts(ev)
        if not src:
            continue
        user = ev.get("user") or _account(ev.get("subjectUser"), ev.get("subjectDomain")) or None
        if _eid(ev) == 6:
            m = _WINRM_TARGET.match(str(_data(ev).get("connection") or _data(ev).get("Connection") or "").strip())
            targets = [(m.group(1), "winrm", "WinRM opened a session to it (6)")] if m else []
        else:
            text = str(ev.get("commandLine") or ev.get("scriptBlockText") or "")
            targets = [(mm.group(1), kind, what) for rx, kind, what in _REMOTE_CMDS for mm in rx.finditer(text)]
        seen: set[tuple[str, str]] = set()
        for raw, kind, what in targets:
            value = raw.strip().strip("\"'").rstrip(",;")
            if not value or value.startswith("$") or value in (".", "*"):
                continue
            ip = ip_of(value)
            dst = (lin.host_of_ip(ip, ts) or ip) if ip else host_key(value)
            if not dst or dst == src or (dst, kind) in seen:
                continue
            seen.add((dst, kind))
            match = _logon_from(lin, dst, src, user, ts)
            h = _hop(
                lin,
                kind,
                ev,
                dst,
                "",
                src,
                user,
                None,
                match,
                f"{what} from {src} ({_eid(ev)})" + (", and the logon there followed" if match else ""),
                STRONG if match else MEDIUM,
                from_host=src,
            )
            if h and match and match.get("logonRef"):
                lin._hops_of_ref[match["logonRef"]].append(h["id"])
                _tie(lin, h, match["logonRef"], STRONG)
    # a WMI call from another host that failed on this one (WMI-Activity 5858 names its client)
    for ev in wmi_failed:
        d = _data(ev)
        dst, src = host_key(ev.get("computer")), host_key(d.get("ClientMachine"))
        if dst and src and src != dst:
            _hop(
                lin,
                "wmi",
                ev,
                dst,
                "",
                src,
                d.get("User"),
                None,
                None,
                f"a WMI call from it failed ({d.get('Operation') or '5858'})"[:200],
                MEDIUM,
                from_host=src,
            )
    # other credentials set for the network (4624 type 9): where that account then logged on from this host
    _new_credentials(lin)

    # hosts and what their evidence covers
    for host, c in counts.items():
        span = spans.get(host, [0, 0])
        name = names[host].most_common(1)[0][0] if names[host] else host
        lin.hosts[host] = {
            "key": host,
            "name": name,
            "ips": sorted(ip for ip, v in lin.ip_hosts.items() if v["host"] == host),
            "events": c["events"],
            "first": span[0],
            "last": span[1],
            "coverage": {
                k: c[k]
                for k in (
                    "sysmon1",
                    "process4688",
                    "commandLines",
                    "logons",
                    "logoffs",
                    "rdp",
                    "shares",
                    "services",
                    "powershell",
                    "sysmon3",
                    "kerberos",
                    "ntlm",
                )
            },
            "cleared": [{"ts": ts, "log": log, "ref": ref} for ts, log, ref in clears.get(host, [])],
            "limits": _limits(host, name, c, clears.get(host, [])),
        }
        if host in lin._clock:
            clock = lin._clock[host]
            lin.hosts[host]["clock"] = clock
            lin.hosts[host]["limits"].append(
                f"{name}'s clock reads {_duration(clock['offsetMs'])} {'ahead of' if clock['offsetMs'] > 0 else 'behind'} the domain controller's: "
                f"the median of its {clock['matches']} logons matched to their Kerberos tickets by logon GUID. The ties by time between "
                "its logons and the domain controller's records allow for it."
            )
    # the devices sign-ins come from: a device named like a host of the case is that host
    for ev in signins:
        d = _data(ev)
        key = host_key(d.get("deviceName"))
        if not key:
            continue
        dev = lin.devices.setdefault(
            key,
            {
                "key": key,
                "name": str(d.get("deviceName")),
                "host": None,
                "deviceIds": [],
                "trustTypes": [],
                "accounts": [],
                "signIns": 0,
                "first": 0,
                "last": 0,
                "refs": [],
            },
        )
        dev["signIns"] += 1
        ts = _ts(ev)
        dev["first"] = min(dev["first"], ts) if dev["first"] else ts
        dev["last"] = max(dev["last"], ts)
        for field, value in (("deviceIds", d.get("deviceId")), ("trustTypes", d.get("trustType")), ("accounts", ev.get("upn") or ev.get("user"))):
            if value and str(value) not in dev[field] and len(dev[field]) < 10:
                dev[field].append(str(value))
        if len(dev["refs"]) < 200:
            dev["refs"].append(ref_of(ev))
    for key, dev in lin.devices.items():
        if key in lin.hosts:
            dev["host"] = key
            lin.hosts[key]["devices"] = sorted(set(lin.hosts[key].get("devices", [])) | set(dev["deviceIds"]))
    return lin


def _int(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _source(lin: Lineage, ip: str, workstation: str, host: str, ts: int | None = None) -> str | None:
    """The host a logon or connection came from, when the case names it or shows whose address it is."""
    ws = host_key(workstation)
    if ws and ws != host:
        return ws
    if ip:
        h = lin.host_of_ip(ip, ts)
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
        "fromBasis": None,
        "logonGuid": None,
        "network": None,
        "auth": [],
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


def remote_action(ev: dict[str, Any], parent: Any = None) -> str | None:
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
    if eid == 4688 or (eid == 1 and "sysmon" in _provider(ev)):
        by = _base(ev.get("parentProcessName") or ev.get("parentImage") or parent).lower()
        if by in _WMI_PARENTS:
            return "ran a program through WMI"
        if by in _WINRM_PARENTS:
            return "ran a program through WinRM"
        return "ran a program"
    if eid in _ACCOUNT_CHANGES:
        return "changed an account or a group"
    return None


def _add_activity(lin: Lineage, s: dict[str, Any], ev: dict[str, Any], parent: Any = None) -> None:
    ref = ref_of(ev)
    s["activity"] += 1
    if len(s["activityRefs"]) < 200:
        s["activityRefs"].append(ref)
    k = str(_eid(ev))
    s["activityKinds"][k] = s["activityKinds"].get(k, 0) + 1
    what = remote_action(ev, parent)
    if what:
        s["actions"][what] = s["actions"].get(what, 0) + 1
    marks = _share_marks(ev)
    if marks:
        lin._marks[s["id"]] |= marks
    lin._session_of_ref[ref] = s["id"]


def _share_marks(ev: dict[str, Any]) -> set[str]:
    """What a share access (5145) reached: an execution pipe on IPC$, or a file through an admin share."""
    target = str(ev.get("relativeTargetName") or "").strip()
    if _eid(ev) != 5145 or not target:
        return set()
    share = str(ev.get("shareName") or "")
    if share.upper().endswith("IPC$"):
        pipe = _EXEC_PIPE.search(target)
        return {f"pipe:{pipe.group(1).lower()}"} if pipe else set()
    return {f"file:{_base(target).lower()}"} if _ADMIN_SHARE.search(share) else set()


def _service_link(lin: Lineage, h: dict[str, Any], ev: dict[str, Any]) -> str | None:
    """What ties a service to the admin-share connection before it beyond time, in words: the logon id
    it was installed under (4697), the service manager's or the tool's pipe opened in that
    connection, or the service's program written through the share."""
    s = lin.sessions.get(h.get("session") or "")
    marks = lin._marks.get(h["id"], set()) | (lin._marks.get(s["id"], set()) if s else set())
    lid = logon_id(ev.get("subjectLogonId"))
    if s and lid is not None and _eid(ev) == 4697 and lid == int(s["logonId"], 16):
        return "under the logon id of that connection"
    pipe = next((m[5:] for m in sorted(marks) if m.startswith("pipe:") and m[5:] in _SERVICE_PIPES), None)
    if pipe:
        return f"the {'PSEXESVC' if pipe == 'psexesvc' else pipe} pipe opened in that connection"
    prog = _SERVICE_PROGRAM.search(str(ev.get("serviceFile") or ""))
    if prog and f"file:{prog.group(1).lower()}" in marks:
        return f"its program {prog.group(1)} written through the admin share"
    return None


def _nearest_rdp(lin: Lineage, host: str, ev: dict[str, Any]) -> dict[str, Any] | None:
    """The RDP session of the same account on the host closest in time to a session-manager record (by time: medium)."""
    ts = _ts(ev)
    user = str(ev.get("targetUser") or "").lower().rsplit("\\", 1)[-1]
    best = None
    for s in lin.sessions_near(host, ts - _RDP_MATCH, ts + _RDP_MATCH, user):
        if s["rdp"] and (best is None or abs(s["start"] - ts) < abs(best["start"] - ts)):
            best = s
    if best:
        lin._session_of_ref[ref_of(ev)] = best["id"]
        lin._timed.add((best["id"], ref_of(ev)))
    return best


def _logon_from(lin: Lineage, dst: str, src: str, user: Any, ts: int) -> dict[str, Any] | None:
    """A logon on dst of this account, from src (by workstation name or address), within two minutes."""
    u = str(user or "").lower().rsplit("\\", 1)[-1].split("@", 1)[0]
    return next((s for s in lin.sessions_near(dst, ts - _RDP_MATCH, ts + _RDP_MATCH, u) if s["logonSeen"] and s.get("from") == src), None)


def _session_hop(lin: Lineage, s: dict[str, Any], kind: str, basis: str, confidence: str = STRONG) -> None:
    """A session's way in: its logon and its activity are part of it by their logon id (strong), a
    program or a shell tied to the session by time is part of it by time (medium)."""
    ev = _logon_ev(s)
    # a source the logon does not name comes from the domain controller's records or explicit
    # credentials, as surely as they tie it; the ticket's client address stands in for a missing one
    from_host = s["from"] if s.get("fromBasis") else None
    if from_host and lin._from_conf.get(s["id"]) == MEDIUM:
        confidence = MEDIUM
    ticket = max((a for a in s["auth"] if a["kind"] == "kerberos" and a.get("service")), key=lambda a: CONFIDENCE_RANK[a["confidence"]], default=None)
    if ticket:
        basis += f", with a Kerberos ticket for {ticket['service']} from {ticket['host']} (4769)"
    ip = s["ip"] or _auth_ip(s) or ""
    h = _hop(lin, kind, ev, s["host"], ip, s["workstation"] or "", s["user"], s["domain"], s, basis, confidence, from_host=from_host, tie=STRONG)
    if not h:
        return
    if from_host and not h["from"]["basis"]:
        h["from"]["basis"] = s["fromBasis"]
    h["evidence"].append(f"logon {s['logonId']} ({s['typeName']}) from {s['ip'] or s['workstation'] or ip or s['from']}")
    if kind != "rdp":
        h["evidence"].extend(f"{what}{f' ({n} times)' if n > 1 else ''}" for what, n in sorted(s["actions"].items()))
    for r in s["activityRefs"][:50]:
        if h["id"] not in lin._hops_of_ref[r]:
            lin._hops_of_ref[r].append(h["id"])
        _tie(lin, h, r, MEDIUM if (s["id"], r) in lin._timed else STRONG)
    # the domain controller's records of the logon are part of the way in, as surely as they tie to it
    for a in s["auth"]:
        if a["kind"] in ("kerberos", "ntlm"):
            _add_ref(lin, h, a["ref"], a["confidence"])
            line = _auth_line(a)
            if line not in h["evidence"]:
                h["evidence"].append(line)


def _logon_ev(s: dict[str, Any]) -> dict[str, Any]:
    """The logon of a session as the record a hop is made from."""
    return {
        "computer": s["host"],
        "ts": s["start"],
        "id": s["logonRef"].split(":", 1)[1] if s["logonRef"].startswith("event:") else None,
        "recordKey": s["logonRef"],
    }


def _add_ref(lin: Lineage, h: dict[str, Any], ref: str, confidence: str) -> None:
    """A record that is part of a hop beyond the one that made it (a ticket, an NTLM validation)."""
    if ref not in h["refs"] and len(h["refs"]) < 50:
        h["refs"].append(ref)
    if h["id"] not in lin._hops_of_ref[ref]:
        lin._hops_of_ref[ref].append(h["id"])
    _tie(lin, h, ref, confidence)


# --- the domain controllers' records and other credentials ------------------------------------------


def _has_source(s: dict[str, Any]) -> bool:
    """A logon whose source the evidence names: its address or workstation, or a host or an address the domain controller's records give."""
    return bool(s["ip"] or s["workstation"] or s["from"] or _auth_ip(s))


def _auth_ip(s: dict[str, Any]) -> str | None:
    """The client address a session's ticket or NTLM validation names, the surest first."""
    got = sorted((a for a in s["auth"] if a.get("ip")), key=lambda a: -CONFIDENCE_RANK[a["confidence"]])
    return got[0]["ip"] if got else None


def _auth_line(a: dict[str, Any]) -> str:
    """A ticket or an NTLM validation as a hop's evidence."""
    if a["kind"] == "kerberos":
        return f"{a['host']} issued a Kerberos ticket for {a['service'] or '?'} to {a['ip'] or 'the client'} ({a['basis']}, 4769)"
    return f"{a['host']} validated the account's NTLM credentials from {a['workstation'] or a['ip'] or '?'} ({a['basis']}, 4776)"


def _auth(lin: Lineage, s: dict[str, Any], ev: dict[str, Any], kind: str, confidence: str, basis: str) -> dict[str, Any] | None:
    """A record that says how a logon authenticated: its ticket (4769), its NTLM validation (4776), the
    explicit credentials it came from (4648). A record joins a session once, at its surest."""
    ref = ref_of(ev)
    cur = next((a for a in s["auth"] if a["ref"] == ref), None)
    if cur:
        if CONFIDENCE_RANK[confidence] > CONFIDENCE_RANK[cur["confidence"]]:
            cur["confidence"], cur["basis"] = confidence, basis
        return cur
    if len(s["auth"]) >= 10:
        return None
    ws = str(ev.get("workstation") or "").strip()
    a = {
        "kind": kind,
        "ref": ref,
        "host": host_key(ev.get("computer")) or None,
        "ts": _ts(ev),
        "ip": ip_of(ev.get("ipAddress")) or (ip_of(ws) if kind == "ntlm" else "") or None,
        "workstation": ws if kind == "ntlm" and host_key(ws) else None,
        "service": str(ev.get("serviceName") or "").strip() or None if kind == "kerberos" else None,
        "confidence": confidence,
        "basis": basis,
    }
    s["auth"].append(a)
    return a


def _name_source(lin: Lineage, s: dict[str, Any], host: str | None, basis: str, confidence: str) -> None:
    """Name the host a logon came from when the logon itself does not: the first, surest, record that does."""
    if s["from"] or not host or host == s["host"]:
        return
    s["from"], s["fromBasis"] = host, basis
    lin._from_conf[s["id"]] = confidence


def _ticket(lin: Lineage, s: dict[str, Any], ev: dict[str, Any], confidence: str, basis: str, asker: dict[str, Any] | None) -> None:
    """A service ticket (4769) tied to the logon it was for: the host whose explicit credentials asked
    for it (4648), else the host of its client address, is the logon's source when the logon names none."""
    if not _auth(lin, s, ev, "kerberos", confidence, basis):
        return
    lin._ticket_ties[ref_of(ev)].append((s, confidence))
    dc = host_key(ev.get("computer")) or "the domain controller"
    if asker is not None:
        src = host_key(asker.get("computer"))
        _auth(lin, s, asker, "explicit-credentials", confidence, f"their logon GUID is the ticket's, which {dc} issued for this logon")
        _name_source(lin, s, src, f"explicit credentials used on {src} asked for the Kerberos ticket of this logon (4648, 4769)", confidence)
        return
    ip = ip_of(ev.get("ipAddress"))
    src = lin.host_of_ip(ip, _ts(ev)) if ip else None
    if src and ip != s["ip"]:
        attributed = lin.ip_hosts.get(ip, {}).get("basis") or "the case's records"
        _name_source(lin, s, src, f"the address {ip} {dc} issued its Kerberos ticket to (4769), known as {src}'s from {attributed}", MEDIUM)


def _authentications(
    lin: Lineage, tickets: list[dict[str, Any]], ntlm: list[dict[str, Any]], explicit: list[dict[str, Any]]
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]]]:
    """What the domain controllers' records and explicit credentials on the source say of each logon.

    A service ticket (4769) carries the logon GUID of the logon it was for (4624), and so does the
    target of explicit credentials (4648): a strong tie. Without it, a ticket for the host's own
    account (HOST$: cifs, host ...) the account asked for within a minute before its network logon
    there, from the logon's address when it names one, is its ticket by time (medium); an NTLM
    validation (4776) of the account within a minute before names the workstation of a network logon
    that names none (medium). Logons that consistently follow their GUID's ticket by more than those
    ties allow give the host's clock against the domain controller's, and the ties by time allow for
    it. Returns the logons by logon GUID and the tickets by theirs, for explicit credentials."""
    by_guid: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in lin.sessions.values():
        if s["logonSeen"] and s.get("logonGuid"):
            by_guid[s["logonGuid"]].append(s)
    asked: dict[str, dict[str, Any]] = {}
    for ev in explicit:
        g = _guid(_data(ev).get("TargetLogonGuid"))
        if g:
            asked.setdefault(g, ev)
    # explicit credentials whose target logon GUID is a logon's: they were used on its source
    for g, ev in asked.items():
        src = host_key(ev.get("computer"))
        for s in by_guid.get(g, []):
            if src and s["host"] != src:
                _auth(lin, s, ev, "explicit-credentials", STRONG, "the same logon GUID")
                _name_source(lin, s, src, f"explicit credentials used on {src} carried its logon GUID (4648)", STRONG)
    granted = [ev for ev in tickets if _eid(ev) == 4769 and _granted(ev)]
    ticket_of_guid = {g: ev for ev in granted if (g := _guid(ev.get("logonGuid")))}
    # the tickets of a logon GUID; the first logon of each gives its host's clock against the domain controller's
    offsets: dict[str, list[int]] = defaultdict(list)
    tied: set[str] = set()
    for ev in granted:
        g = _guid(ev.get("logonGuid"))
        matched = by_guid.get(g, []) if g else []
        for s in matched:
            _ticket(lin, s, ev, STRONG, "the same logon GUID", asked.get(g))
        if matched:
            tied.add(ref_of(ev))
            first = min(matched, key=lambda s: s["start"])
            offsets[first["host"]].append(first["start"] - _ts(ev))
    skew: dict[str, int] = {}
    for host, offs in offsets.items():
        m = int(median(offs))
        if len(offs) >= 2 and not -_SLACK <= m <= _AUTH_BEFORE:
            skew[host] = m
            lin._clock[host] = {"offsetMs": m, "matches": len(offs)}
    # a ticket for the host's own account, asked for just before a network logon of that account there
    for ev in granted:
        if ref_of(ev) in tied:
            continue
        svc = str(ev.get("serviceName") or "").strip()
        host, user, ip = host_key(svc) if svc.endswith("$") else "", _user_key(ev.get("targetUser")), ip_of(ev.get("ipAddress"))
        if not host or not user:
            continue
        t = _ts(ev) + skew.get(host, 0)
        near = [
            s
            for s in lin.sessions_near(host, t - _SLACK, t + _AUTH_BEFORE)
            if s["logonSeen"]
            and s["type"] in (3, 8)
            and _user_key(s["user"]) == user
            and (not s["ip"] or not ip or s["ip"] == ip)
            and "ntlm" not in str(s.get("authPackage") or "").lower()
            and not any(a["kind"] == "kerberos" and a["confidence"] == STRONG for a in s["auth"])
        ]
        if not near:
            continue
        s = min(near, key=lambda s: (abs(s["start"] - t), s["start"]))
        how = "by account, service, address and time" if ip and s["ip"] else "by account, service and time"
        # the logons that carry the same logon GUID came with the same ticket
        for x in by_guid.get(s.get("logonGuid") or "", []) or [s]:
            _ticket(lin, x, ev, MEDIUM, how, asked.get(_guid(ev.get("logonGuid"))))
    # NTLM: the domain controller (a host that issues tickets) or the logon's own host validated the account from a workstation
    dcs = {host_key(ev.get("computer")) for ev in tickets}
    by_user: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    for ev in ntlm:
        u, ws = _user_key(ev.get("targetUser")), str(ev.get("workstation") or "").strip()
        if u and ws and ws != "-" and _granted(ev):
            by_user[u].append((_ts(ev), ev))
    for lst in by_user.values():
        lst.sort(key=lambda x: x[0])
    for s in lin.sessions.values():
        if not s["logonSeen"] or s["type"] not in (3, 8) or s["from"] or host_key(s["workstation"]) or "kerberos" in str(s.get("authPackage") or "").lower():
            continue
        lst = by_user.get(_user_key(s["user"]))
        if not lst:
            continue
        t = s["start"] - skew.get(s["host"], 0)
        i = bisect_left(lst, t - _AUTH_BEFORE, key=lambda x: x[0])
        near = []
        while i < len(lst) and lst[i][0] <= t + _SLACK:
            ev = lst[i][1]
            if host_key(ev.get("computer")) in dcs or host_key(ev.get("computer")) == s["host"]:
                near.append(ev)
            i += 1
        # the workstation a validation names, as a host when the case knows it (a name, or an address it attributes)
        client = {
            id(ev): host_key(ev.get("workstation")) or lin.host_of_ip(ip_of(ev.get("workstation")), _ts(ev)) or ip_of(ev.get("workstation")) for ev in near
        }
        clients = set(client.values()) - {"", s["host"]}
        # validations from two workstations in that minute: which was this logon's is not known
        if len(clients) != 1:
            continue
        ev = max((ev for ev in near if client[id(ev)] in clients), key=_ts)
        _auth(lin, s, ev, "ntlm", MEDIUM, "by account and time")
        src = next(iter(clients))
        if not _is_ip(src):
            dc = host_key(ev.get("computer")) or "the domain controller"
            _name_source(lin, s, src, f"{dc}'s NTLM validation of the account from {ev.get('workstation')} a moment before (4776), by account and time", MEDIUM)
    return by_guid, ticket_of_guid


def _guid_logon(
    lin: Lineage, g: str, src: str, by_guid: dict[str, list[dict[str, Any]]], ticket_of_guid: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any] | None, str, dict[str, Any] | None, str]:
    """The logon on another host that explicit credentials' target logon GUID leads to: the logon of
    that GUID (strong), else the one the ticket of that GUID was tied to (as surely as it was);
    with how surely, the ticket and the words for the hop."""
    if not g:
        return None, MEDIUM, None, ""
    s = next((s for s in by_guid.get(g, []) if s["host"] != src), None)
    if s:
        return s, STRONG, None, ", and the logon there carried their logon GUID"
    ticket = ticket_of_guid.get(g)
    if ticket is None:
        return None, MEDIUM, None, ""
    for s, conf in lin._ticket_ties.get(ref_of(ticket), []):
        if s["host"] != src:
            dc = host_key(ticket.get("computer")) or "the domain controller"
            return s, conf, ticket, f", and the Kerberos ticket {dc} issued for them ({ticket.get('serviceName') or '?'}, 4769) led to the logon there"
    return None, MEDIUM, None, ""


def _new_credentials(lin: Lineage) -> None:
    """A NewCredentials logon (4624 type 9: runas /netonly, pass-the-hash tooling) sets another
    account for what its session does on the network. A network logon of that account on another
    host, from this one, while the session is open (or within twelve hours when its logoff is not in
    the evidence) is a way into that host with those credentials: tied by account, source and time, medium."""
    net: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in lin.sessions.values():
        if s["logonSeen"] and s["type"] in (3, 8) and s["from"]:
            net[_user_key(s["user"])].append(s)
    for lst in net.values():
        lst.sort(key=lambda s: s["start"])
    for s in sorted(lin.sessions.values(), key=lambda s: s["start"]):
        acct = s.get("network")
        if not acct or not s["logonRef"]:
            continue
        end = (s["end"] if s["end"] is not None else s["start"] + _NEW_CREDENTIALS_REACH) + _SLACK
        reached: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for m in net.get(_user_key(acct), []):
            if s["start"] - _SLACK <= m["start"] <= end and m["from"] == s["host"] and m["host"] != s["host"]:
                reached[m["host"]].append(m)
        for dst, logons in sorted(reached.items()):
            h = _hop(
                lin,
                "explicit-credentials",
                _logon_ev(s),
                dst,
                "",
                s["host"],
                acct,
                None,
                logons[0],
                f"{s['account'] or 'an account'} set other credentials ({acct}) for the network on {s['host']} (4624 type 9), "
                f"and a logon there as {acct} came from {s['host']}",
                MEDIUM,
                from_host=s["host"],
            )
            if not h:
                continue
            for m in logons:
                _add_ref(lin, h, m["logonRef"], MEDIUM)
                h["evidence"].append(f"logon {m['logonId']} ({m['typeName']}) as {acct}, {max(0, round((m['start'] - s['start']) / 60_000))} min after")


def _duration(ms: int) -> str:
    """7 min for 420,000 ms; hours past two, seconds under one minute."""
    a = abs(ms)
    if a >= 2 * 3600_000:
        return f"{round(a / 3600_000)} h"
    return f"{round(a / 60_000)} min" if a >= 60_000 else f"{round(a / 1000)} s"


def _tie(lin: Lineage, h: dict[str, Any], ref: str, confidence: str) -> None:
    """How surely a record is part of a hop; of two ways it joined, the surer."""
    cur = lin._hop_ties.get((h["id"], ref))
    if cur is None or CONFIDENCE_RANK[confidence] > CONFIDENCE_RANK[cur]:
        lin._hop_ties[(h["id"], ref)] = confidence


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
    tie: str | None = None,
) -> dict[str, Any] | None:
    """A way into a host, merged with the same hop (kind, source, target, account) within an hour.
    The record is part of it as surely as the confidence given says, or its tie when given."""
    if not to:
        return None
    ts = _ts(ev)
    src_host = from_host or _source(lin, ip, workstation, to, ts)
    if not src_host and not ip:
        return None
    account = _account(user, domain)
    key = (kind, src_host or ip, to, account.lower())
    for h in lin._hop_index.get(key, []):
        if ts - h["tsEnd"] <= 3600_000:
            h["tsEnd"] = max(h["tsEnd"], ts)
            h["count"] += 1
            if len(h["refs"]) < 50:
                h["refs"].append(ref_of(ev))
            lin._hops_of_ref[ref_of(ev)].append(h["id"])
            _tie(lin, h, ref_of(ev), tie or confidence)
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
    _tie(lin, h, ref_of(ev), tie or confidence)
    return h


def _processes(lin: Lineage, sysmon1: list[dict[str, Any]], procs4688: list[dict[str, Any]]) -> None:
    by_pid: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)

    def place(p: dict[str, Any], ev: dict[str, Any], lid: int | None, user: Any) -> None:
        s = lin.session_at(p["host"], lid, p["ts"], user)
        if s and not p.get("session"):
            p["session"] = s["id"]
            _add_activity(lin, s, ev, p.get("parentImage"))

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
        place(p, ev, logon_id(_data(ev).get("LogonId")), ev.get("user"))
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
        # the new process's logon when the record gives it, else its creator's
        lid, user = logon_id(ev.get("targetLogonId")), ev.get("targetUser")
        if not lid:
            lid, user = logon_id(ev.get("subjectLogonId")), ev.get("subjectUser")
        # the parent's program as the record states it: not as the parser filled it in from an
        # earlier 4688 of the creator's id, which is the same guess _creator makes
        named = "" if "parentProcessName from" in str(ev.get("enriched") or "") else ev.get("parentProcessName")
        if same:
            same["refs"].append(ref_of(ev))
            same["source"] = "both"
            same["commandLine"] = same["commandLine"] or ev.get("commandLine")
            named = same["parentImage"] or named
            same["parentImage"] = same["parentImage"] or ev.get("parentProcessName")
            if same["parentPid"] is None:
                same["parentPid"] = creator
            if not same["parent"]:
                same["parent"] = _creator(by_pid, host, creator, same["ts"], same["id"], named)
            lin._process_of_ref[ref_of(ev)] = same["id"]
            place(same, ev, lid, user)
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
        p["parent"] = _creator(by_pid, host, creator, ts, p["id"], named)
        if p["parent"]:
            p["parentImage"] = p["parentImage"] or lin.processes[p["parent"]]["image"]
        lin.processes[p["id"]] = p
        lin._process_of_ref[ref_of(ev)] = p["id"]
        by_pid[(host, pid)].append(p)
        place(p, ev, lid, user)
    for p in lin.processes.values():
        if p["parent"] and p["parent"] in lin.processes:
            lin.processes[p["parent"]]["children"].append(p["id"])


def _creator(by_pid: dict[tuple[str, int], list[dict[str, Any]]], host: str, creator: int | None, ts: int, own: str, parent: Any = None) -> str | None:
    """The process that created one: the latest creation of the creator's id on that host before it
    (ids are reused). When the record names the parent's program, that creation must be of it: if
    it is another program, the parent started before the evidence and its id was reused since."""
    if creator is None:
        return None
    want = _base(parent).lower()
    window = _PROCESS_REUSE if want else _PROCESS_REUSE_UNNAMED
    cands = [q for q in by_pid.get((host, creator), []) if 0 <= ts - q["ts"] <= window and q["id"] != own]
    if not cands:
        return None
    q = max(cands, key=lambda q: q["ts"])
    return q["id"] if not want or not q["name"] or q["name"].lower() == want else None


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
