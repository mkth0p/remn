#!/usr/bin/env python
"""
Read MITRE's APT29 evaluation into stories, the way a server case reads it, and check the stories
against what the evaluation did.

OTRF's Security-Datasets recorded the two days of the evaluation's emulated APT29 intrusion on a lab
domain, dmevals.local, as NXLog JSON: the Sysmon, Security, PowerShell and a few other channels of
four hosts, one record a line. The datasets are MIT-licensed and fetched on demand, never committed:

    mkdir -p apt29 && cd apt29
    curl -sSfLO https://raw.githubusercontent.com/OTRF/Security-Datasets/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip
    curl -sSfLO https://raw.githubusercontent.com/OTRF/Security-Datasets/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/compound/apt29/day2/apt29_evals_day2_manual.zip
    unzip apt29_evals_day1_manual.zip && unzip apt29_evals_day2_manual.zip && cd ..
    .venv/bin/python tools/apt29_stories.py --data apt29                      # day 1, REMN's own rules
    .venv/bin/python tools/apt29_stories.py --data apt29 --day 2 --packs      # day 2, with the default SigmaHQ packs

or --fetch to download the zips into --data first. A zip's SHA-256 is checked before it is unzipped
and the JSON's as it is read. tests/backend/test_apt29_stories.py runs the same checks when
REMN_APT29 names the folder (pytest -m heavy).

Day 1 (196,081 records, 02:55 to 03:28 UTC on 2 May 2020): the attacker starts as pbeesly on
SCRANTON (a payload disguised by a right-to-left override, a UAC bypass, discovery, credential
access, persistence), then moves to NASHUA; NEWYORK is the domain controller and UTICA is not
attacked. Day 2 (587,286 records) is the evaluation's second scenario; its stories are printed
and checked only for what holds on any case.

The records are converted to the rows an .evtx of the same records gives (nxlog_event, then the
parser's own flatten and the lineage it fills in on upload):
- NXLog writes its own fields beside the event's data: the record's System values under names of
  its own (Hostname, SourceName, RecordNumber, Keywords as a signed number...), the account it
  resolved the header's UserID to (AccountName, Domain), the rendered Message, and what Logstash
  added (host, port, tags). They go back into System, or are dropped: an .evtx has the SID only.
- EventTime is the record's time as the collector's local time, to the second: US Eastern, which
  was EDT (UTC-4) on 1 and 2 May 2020. A Sysmon record keeps its own UtcTime instead, when the
  event happened, to the millisecond (Sysmon wrote some records half a minute after it on a busy
  host). @timestamp is when the collector received the record, up to a minute later after a
  reboot, and is not used. The summary says on how many Sysmon records the two times agree.
- What NXLog kept only in the rendered message is read back from it into the names the event's
  XML gives it: Sysmon's EventType and the service account of a 7045 (NXLog's own EventType and
  AccountName took their names), the UserData of the Terminal Services session events (21 to 25,
  1149) and of WMI-Activity 5858 and 5861 (NXLog reads EventData only), and the unnamed data of
  the classic Windows PowerShell log. A ProcessId the collector added to Sysmon records whose
  schema has none (8, 10) is dropped. The other UserData events keep no fields; REMN reads none.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.request
import uuid
import zipfile
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "tools"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "forensic.settings")

from evtx_attack_samples import DEFAULT_PACKS, SETTINGS, event_rules

from services.parsers.evtx_parser import Lineage, flatten

REPO = "OTRF/Security-Datasets"
SHA = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
DAYS: dict[int, dict[str, str]] = {
    1: {
        "zip": "datasets/compound/apt29/day1/apt29_evals_day1_manual.zip",
        "zipSha256": "98a073140860560d70080ace9142961be4f64b4862bae892d62d0f254d0fdbe5",
        "json": "apt29_evals_day1_manual_2020-05-01225525.json",
        "jsonSha256": "dce651806007a20f6f4bac806dd6054e3361e0dd57a74ddd2f7cb5665d98c954",
    },
    2: {
        "zip": "datasets/compound/apt29/day2/apt29_evals_day2_manual.zip",
        "zipSha256": "377f8cba5db95a453a3ee8bd19f493efafc23724541482a4da99da28ee4665f9",
        "json": "apt29_evals_day2_manual_2020-05-02035409.json",
        "jsonSha256": "fd4043c9ad2382f57da882476acb541332d2d19b60ad538572a8d4a070d59a89",
    },
}
RAW = "https://raw.githubusercontent.com/{repo}/{sha}/{path}"
# the case settings an analyst gives the lab: a new case's, with the lab's domain as internal
LAB_SETTINGS = {**SETTINGS, "internal_domains": ["dmevals.local"]}
# day 1: who the attacker was, the hosts they worked on, and the hosts they left alone
VICTIM = "pbeesly"
ATTACKED = ("scranton", "nashua")
UNTOUCHED = ("newyork", "utica")

# ---------------------------------------------------------------------------
# NXLog JSON to event rows
# ---------------------------------------------------------------------------
EDT = dt.timezone(dt.timedelta(hours=-4), "EDT")
# NXLog's (im_msvistalog) and Logstash's fields beside the event's data
NXLOG_FIELDS = frozenset(
    {
        "EventTime", "EventReceivedTime", "@timestamp", "@version", "port", "host", "tags", "Message",
        "SourceModuleName", "SourceModuleType", "SourceName", "ProviderGuid", "EventID", "Channel", "Hostname",
        "RecordNumber", "Task", "Category", "Opcode", "OpcodeValue", "Keywords", "Version", "Severity", "SeverityValue",
        "EventType", "ExecutionProcessID", "ThreadID", "ActivityID", "RelatedActivityID", "UserID", "AccountName",
        "AccountType", "Domain",
    }
)  # fmt: skip
SYSMON = "Microsoft-Windows-Sysmon"
# the Windows level of NXLog's severity (5 critical ... 1 debug); audit records are level 0
_LEVEL = {5: 1, 4: 2, 3: 3, 2: 4, 1: 5}
_CHANNEL = {"security": "Security"}
_LINE = re.compile(r"^([A-Za-z]+): ?(.*?)\r?$", re.M)
_SESSION = re.compile(r"^User: (?P<User>.*?)\r?\nSession ID: (?P<SessionID>\d+)(?:\r?\nSource Network Address: (?P<Address>[^\r\n]*))?", re.M)
# what NXLog kept only in the rendered message, by provider and event id: the section and element
# the event's XML holds it in, and the message's pattern with the XML's names
_FROM_MESSAGE: dict[tuple[str, int], tuple[str, str | None, re.Pattern[str]]] = {
    **{("Microsoft-Windows-TerminalServices-LocalSessionManager", eid): ("UserData", "EventXML", _SESSION) for eid in (21, 22, 23, 24, 25)},
    ("Microsoft-Windows-TerminalServices-RemoteConnectionManager", 1149): (
        "UserData",
        "EventXML",
        re.compile(r"^User: (?P<Param1>.*?)\r?\nDomain: (?P<Param2>.*?)\r?\nSource Network Address: (?P<Param3>[^\r\n]*)", re.M),
    ),
    ("Microsoft-Windows-WMI-Activity", 5858): (
        "UserData",
        "Operation_ClientFailure",
        re.compile(
            r"^Id = (?P<Id>.*?); ClientMachine = (?P<ClientMachine>.*?); User = (?P<User>.*?); ClientProcessId = (?P<ClientProcessId>.*?); "
            r"Component = (?P<Component>.*?); Operation = (?P<Operation>.*); ResultCode = (?P<ResultCode>.*?); PossibleCause = (?P<PossibleCause>.*)$",
            re.S,
        ),
    ),
    ("Microsoft-Windows-WMI-Activity", 5861): (
        "UserData",
        "Operation_ESStoConsumerBinding",
        re.compile(
            r"^Namespace = (?P<Namespace>.*?); Eventfilter = (?P<ESS>.*?) \(refer to its activate eventid:5859\); "
            r"Consumer = (?P<CONSUMER>.*?); PossibleCause = (?P<PossibleCause>.*)$",
            re.S,
        ),
    ),
    ("Service Control Manager", 7045): ("EventData", None, re.compile(r"^Service Account:\s*(?P<AccountName>[^\r\n]*?)\s*$", re.M)),
}
# event data only a message gives: NXLog's own fields of these names are dropped
_READ_BACK = frozenset({"EventType", "AccountName", "Data"})


def _utc(record: dict[str, Any]) -> tuple[dt.datetime | None, dt.datetime | None]:
    """The record's time from EventTime (EDT) and, on a Sysmon record, from its own UtcTime."""
    local = sysmon = None
    try:
        local = dt.datetime.fromisoformat(str(record.get("EventTime"))).replace(tzinfo=EDT).astimezone(dt.UTC)
    except ValueError:
        pass
    if record.get("SourceName") == SYSMON and record.get("UtcTime"):
        try:
            sysmon = dt.datetime.fromisoformat(str(record["UtcTime"])).replace(tzinfo=dt.UTC)
        except ValueError:
            pass
    return local, sysmon


def nxlog_event(record: dict[str, Any], when: dt.datetime | None = None) -> dict[str, Any]:
    """One NXLog record as the event an .evtx gives for it (pyevtx-rs's JSON: System, EventData, UserData)."""
    if when is None:
        local, sysmon = _utc(record)
        when = sysmon or local
    provider, eid = str(record.get("SourceName") or ""), int(record.get("EventID") or 0)
    channel = str(record.get("Channel") or "")
    system: dict[str, Any] = {
        "Provider": {"#attributes": {"Name": provider, "Guid": record.get("ProviderGuid")}},
        "EventID": eid,
        "Version": record.get("Version"),
        "Level": 0 if str(record.get("EventType") or "").startswith("AUDIT") else _LEVEL.get(record.get("SeverityValue")),
        "Task": record.get("Task"),
        "Opcode": record.get("OpcodeValue"),
        "Keywords": f"0x{int(record['Keywords']) & 0xFFFFFFFFFFFFFFFF:x}" if record.get("Keywords") is not None else None,
        "TimeCreated": {"#attributes": {"SystemTime": when.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if when else None}},
        "EventRecordID": record.get("RecordNumber"),
        "Execution": {"#attributes": {"ProcessID": record.get("ExecutionProcessID"), "ThreadID": record.get("ThreadID")}},
        "Channel": _CHANNEL.get(channel.lower(), channel),
        "Computer": record.get("Hostname"),
    }
    if record.get("ActivityID") or record.get("RelatedActivityID"):
        system["Correlation"] = {"#attributes": {k: record[k] for k in ("ActivityID", "RelatedActivityID") if record.get(k)}}
    if record.get("UserID"):
        system["Security"] = {"#attributes": {"UserID": record["UserID"]}}
    data = {k: v if isinstance(v, str) else json.dumps(v) for k, v in record.items() if k not in NXLOG_FIELDS}
    message = str(record.get("Message") or "")
    event: dict[str, Any] = {"System": system}
    if provider == SYSMON and message:
        # the message lists the record's own fields in its schema's order
        lines: dict[str, str] = {}
        for k, v in _LINE.findall(message):
            lines.setdefault(k, v)
        data = {k: (v if k == "EventType" else data[k]) for k, v in lines.items() if k in data or k == "EventType"}
    elif channel == "Windows PowerShell" and not data and message:
        data = {"Data": [message]}
    found = _FROM_MESSAGE.get((provider, eid))
    if found and message and (m := found[2].search(message)):
        values = {k: v.strip() for k, v in m.groupdict().items() if v is not None}
        if found[0] == "UserData":
            event["UserData"] = {found[1]: values}
        else:
            data.update(values)
    event["EventData"] = data
    return {"Event": event}


@dataclass
class Conversion:
    """What reading one NXLog file gave."""

    file: str
    sha256: str = ""
    records: int = 0
    hosts: dict[str, int] = field(default_factory=dict)
    channels: dict[str, int] = field(default_factory=dict)
    first: int | None = None
    last: int | None = None
    # Sysmon records whose EventTime read as EDT is within a minute of their own UtcTime (Sysmon
    # writes a record up to half a minute after the event): a wrong zone would put it hours off
    sysmon: int = 0
    sysmon_agree: int = 0
    # records given fields read back from their message, records out of their log's order
    from_message: int = 0
    out_of_order: int = 0
    seconds: float = 0.0


def nxlog_rows(path: Path, conv: Conversion | None = None, include_raw: bool = True) -> Iterator[dict[str, Any]]:
    """The rows of one NXLog file, as an upload of the same records' .evtx files gives them."""
    conv = conv if conv is not None else Conversion(path.name)
    digest = hashlib.sha256()
    lineage = Lineage()
    # the order the lineage reads records in is each log's own, which the collector keeps
    last_record: dict[tuple[str, str], int] = {}
    t0 = time.time()
    with open(path, "rb") as fh:
        for line in fh:
            digest.update(line)
            if not line.strip():
                continue
            record = json.loads(line)
            local, sysmon = _utc(record)
            event = nxlog_event(record, sysmon or local)
            row = flatten(event, include_raw=include_raw)
            row["sourceFile"] = path.name
            lineage.apply(row)
            conv.records += 1
            host, channel = str(row.get("computer") or ""), str(row.get("channel") or "")
            conv.hosts[host] = conv.hosts.get(host, 0) + 1
            conv.channels[channel] = conv.channels.get(channel, 0) + 1
            ts = row.get("ts")
            if ts is not None:
                conv.first = ts if conv.first is None else min(conv.first, ts)
                conv.last = ts if conv.last is None else max(conv.last, ts)
            if sysmon and local:
                conv.sysmon += 1
                conv.sysmon_agree += abs((local - sysmon.replace(microsecond=0)).total_seconds()) <= 60
            ev = event["Event"]
            conv.from_message += "UserData" in ev or not _READ_BACK.isdisjoint(ev["EventData"])
            key = (host, channel)
            rid = int(row.get("recordId") or 0)
            conv.out_of_order += rid < last_record.get(key, 0)
            last_record[key] = max(rid, last_record.get(key, 0))
            yield row
    conv.sha256 = digest.hexdigest()
    conv.seconds = time.time() - t0


# ---------------------------------------------------------------------------
# The datasets
# ---------------------------------------------------------------------------
def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def locate(data: Path, day: int, fetch: bool = False) -> Path:
    """The day's JSON under data: unzipped from its zip (downloaded first with fetch) when only the zip is there."""
    pin = DAYS[day]
    target = data / pin["json"]
    if target.is_file():
        return target
    zpath = data / Path(pin["zip"]).name
    if not zpath.is_file():
        if not fetch:
            raise FileNotFoundError(f"{target} is missing: fetch {RAW.format(repo=REPO, sha=SHA, path=pin['zip'])} into {data} and unzip it, or pass --fetch")
        data.mkdir(parents=True, exist_ok=True)
        url = RAW.format(repo=REPO, sha=SHA, path=pin["zip"])
        print(f"fetching {url}", flush=True)
        with urllib.request.urlopen(url, timeout=600) as resp, open(zpath, "wb") as out:  # noqa: S310 - a fixed https host
            shutil.copyfileobj(resp, out)
    got = _sha256(zpath)
    if got != pin["zipSha256"]:
        raise ValueError(f"{zpath}: SHA-256 {got}, not the pinned {pin['zipSha256']}")
    with zipfile.ZipFile(zpath) as zf:
        zf.extract(pin["json"], data)
    return target


# ---------------------------------------------------------------------------
# Rules and stories on a server store
# ---------------------------------------------------------------------------
def rules_for(packs: bool) -> list[dict[str, Any]]:
    """REMN's own event rules, with the default SigmaHQ packs when packs is set."""
    sets = event_rules()
    return sets["core"] + ([r for p in DEFAULT_PACKS for r in sets[p]] if packs else [])


def run(path: Path, packs: bool = False, settings: dict[str, Any] | None = None, include_raw: bool = True, work: Path | None = None) -> dict[str, Any]:
    """Load one NXLog file into a new server store, run the rules, build the stories, and read what the checks need."""
    from services.analysis.stories import stories_for_store
    from services.store.casestore import StoreRegistry, rows_to_dicts
    from services.store.rules import run_rules
    from services.store.writers import EventWriter

    settings = settings or LAB_SETTINGS
    rules = rules_for(packs)
    own = work is None
    work = work or Path(tempfile.mkdtemp(prefix="remn-apt29-"))
    reg = StoreRegistry()
    reg.configure(work / "stores")
    key = str(uuid.uuid4())
    store = reg.get(key)
    try:
        conv = Conversion(path.name)
        writer = EventWriter(store, 1, include_raw=include_raw)
        t0 = time.time()
        for row in nxlog_rows(path, conv, include_raw=include_raw):
            writer.add(row)
        writer.flush()
        loaded = time.time() - t0
        t0 = time.time()
        res = run_rules(store, rules, settings)
        rules_s = time.time() - t0
        t0 = time.time()
        stories = stories_for_store(store, settings, res["findings"])
        stories_s = time.time() - t0
        # the accounts the records name with their SIDs, and the flagged script blocks with the
        # SID of the account that ran them
        flagged = sorted({int(r) for f in res["findings"] if f.get("source", "events") == "events" for r in f.get("refs") or [] if str(r).isdigit()})
        cur = store.cursor()
        cur.execute(
            'SELECT DISTINCT "subjectSid" AS sid, "subjectUser" AS name, "subjectDomain" AS domain FROM events WHERE "subjectSid" LIKE \'S-1-5-21-%\' '
            'UNION SELECT DISTINCT "targetSid", "targetUser", "targetDomain" FROM events WHERE "targetSid" LIKE \'S-1-5-21-%\''
        )
        accounts = rows_to_dicts(cur)
        blocks: list[dict[str, Any]] = []
        for i in range(0, len(flagged), 5_000):
            chunk = flagged[i : i + 5_000]
            cur.execute(f'SELECT id, computer, "userSid" FROM events WHERE "eventId" = 4104 AND id IN ({", ".join("?" for _ in chunk)})', chunk)
            blocks += rows_to_dicts(cur)
    finally:
        reg.close_all()
        shutil.rmtree(work if own else work / "stores", ignore_errors=True)
    return {
        "conversion": conv,
        "rules": len(rules),
        "packs": packs,
        "findings": res["findings"],
        "ruleErrors": res["errors"],
        "result": stories,
        "accounts": accounts,
        "scriptBlocks": blocks,
        "seconds": {"load": loaded, "rules": rules_s, "stories": stories_s},
    }


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    # the later work a failure waits for, when it is expected to fail until then
    later: str = ""


SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SID = re.compile(r"(?:^|\\)s-1-\d+(?:-\d+)+$", re.I)
# the domains Windows' own service, virtual and built-in accounts go by
_SYSTEM_DOMAINS = {"nt authority", "nt service", "window manager", "font driver host", "iis apppool", "nt virtual machine", "autorité nt"}


def refs_of(story: dict[str, Any]) -> set[str]:
    return {r for st in story["steps"] for r in st["refs"]}


def _local(label: str) -> str:
    """alice for alice@contoso.com, CONTOSO\\alice and alice."""
    return label.lower().split("\\")[-1].split("@")[0]


def person_story(result: dict[str, Any], name: str) -> list[dict[str, Any]]:
    return [s for s in result["stories"] if s["kind"] == "person" and _local(s["subject"]["label"]) == name.lower()]


def system_subjects(result: dict[str, Any]) -> Check:
    """No story is about a SID, a service or virtual account, or a machine account."""
    bad = []
    for s in result["stories"]:
        label = str(s["subject"].get("label") or "")
        low = label.lower()
        if s["kind"] == "person" and (_SID.search(low) or low.endswith("$") or ("\\" in low and low.split("\\")[0] in _SYSTEM_DOMAINS)):
            bad.append(label)
    return Check("no story is about a SID, a service account or a machine", not bad, ", ".join(bad) or "none")


def script_blocks_with_their_person(out: dict[str, Any], name: str = VICTIM, hosts: Iterable[str] = ATTACKED) -> Check:
    """The flagged 4104 script blocks the person ran on those hosts (their SID in the record's header) are in the person's story."""
    from services.analysis.lineage import host_key

    sids = {a["sid"] for a in out["accounts"] if str(a.get("name") or "").lower() == name.lower()}
    hosts = set(hosts)
    mine = {f"event:{b['id']}" for b in out["scriptBlocks"] if b.get("userSid") in sids and host_key(b.get("computer")) in hosts}
    stories = person_story(out["result"], name)
    held = set().union(*(refs_of(s) for s in stories)) & mine if stories else set()
    theirs = {s["id"] for s in stories}
    elsewhere = collections.Counter(
        f"{s['subject']['label']} ({s['kind']})" for s in out["result"]["stories"] if s["id"] not in theirs for _ in refs_of(s) & (mine - held)
    )
    nowhere = len(mine - held) - sum(elsewhere.values())
    others = [f"{k} {v}" for k, v in elsewhere.items()] + ([f"no story {nowhere}"] if nowhere > 0 else [])
    detail = f"{len(held)} of {len(mine)} in {name}'s story" + (f"; the others in {', '.join(others)}" if others else "")
    return Check(
        f"{name}'s flagged script blocks on {' and '.join(h.upper() for h in sorted(hosts))} are in {name}'s story", bool(mine) and held == mine, detail
    )


def reaches_through_hop(result: dict[str, Any], name: str = VICTIM, host: str = "nashua") -> Check:
    """The person's story reaches the host by a hop (a logon from another host of the story)."""
    stories = person_story(result, name)
    hops = [h for s in stories for h in (s.get("lineage") or {}).get("hops", []) if h.get("to") == host and (h.get("from") or {}).get("host") != host]
    kinds = sorted({str(h.get("kind")) for h in hops})
    return Check(
        f"{name}'s story reaches {host.upper()} through a hop", bool(hops), ", ".join(kinds) or f"no hop to {host} in {len(stories)} stories of {name}"
    )


def quiet_hosts(result: dict[str, Any], hosts: Iterable[str] = UNTOUCHED) -> Check:
    """No high or critical story holds only those hosts."""
    hosts = set(hosts)
    bad = [
        f"{s['subject']['label']} ({s['severity']})"
        for s in result["stories"]
        if SEVERITY.get(s["severity"], 0) >= 3 and s["hosts"] and set(s["hosts"]) <= hosts
    ]
    return Check(
        f"{' and '.join(h.upper() for h in sorted(hosts))} raise no high story",
        not bad,
        ", ".join(bad) or "none",
    )


def one_intrusion(result: dict[str, Any], hosts: Iterable[str] = ATTACKED) -> Check:
    """The flagged steps on the attacked hosts are in one story, or in stories one incident or one campaign links."""
    hosts = set(hosts)
    holding = [s for s in result["stories"] if any(st["host"] in hosts and st["tie"]["kind"] in ("flag", "chain") for st in s["steps"])]
    incident = bool(holding) and len({s.get("incident") for s in holding}) == 1 and holding[0].get("incident") is not None
    linked = bool(holding) and bool(set.intersection(*(set(s.get("campaigns") or []) for s in holding)))
    labels = ", ".join(f"{s['subject']['label']} ({s['kind']})" for s in holding)
    how = " in one incident" if incident else " in one campaign" if linked else ", not linked" if len(holding) > 1 else ""
    return Check(
        f"the intrusion on {' and '.join(h.upper() for h in sorted(hosts))} reads as one story or linked stories",
        len(holding) == 1 or incident or linked,
        f"{len(holding)} {'story' if len(holding) == 1 else 'stories'}{how}: {labels}",
    )


def checks(day: int, out: dict[str, Any]) -> list[Check]:
    result = out["result"]
    found = [
        Check("every rule ran", not out["ruleErrors"], "; ".join(f"{e['ruleId']}: {e['error']}" for e in out["ruleErrors"][:5]) or "no errors"),
        Check("the file is the pinned one", out["conversion"].sha256 == DAYS[day]["jsonSha256"], out["conversion"].sha256),
        system_subjects(result),
    ]
    if day == 1:
        found += [script_blocks_with_their_person(out), reaches_through_hop(result), quiet_hosts(result), one_intrusion(result)]
    return found


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def _when(ms: int | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    return dt.datetime.fromtimestamp(ms / 1000, dt.UTC).strftime(fmt) if ms else "?"


def summary(day: int, out: dict[str, Any], found: list[Check]) -> str:
    conv: Conversion = out["conversion"]
    result = out["result"]
    sev = collections.Counter(f.get("severity") for f in out["findings"])
    lines = [
        f"APT29 day {day}: {conv.records:,} records from {conv.file}, {_when(conv.first)} to {_when(conv.last, '%H:%M')} UTC",
        "  hosts: " + ", ".join(f"{h.split('.')[0]} {n:,}" for h, n in sorted(conv.hosts.items(), key=lambda x: -x[1])),
        f"  EventTime read as EDT is within a minute of Sysmon's own UtcTime on {conv.sysmon_agree:,} of {conv.sysmon:,} Sysmon records; "
        f"{conv.from_message:,} records given fields from their message; {conv.out_of_order:,} out of their log's order",
        f"  read and loaded in {out['seconds']['load']:.1f} s",
        f"rules: {out['rules']:,} ({'REMN and the default SigmaHQ packs' if out['packs'] else 'REMN'}), {len(out['findings']):,} findings "
        f"({', '.join(f'{k} {sev[k]}' for k in ('critical', 'high', 'medium', 'low', 'info') if sev[k])}), {len(out['ruleErrors'])} errors, {out['seconds']['rules']:.1f} s",
        f"stories: {len(result['stories'])} and {len(result['campaigns'])} campaigns from {result['stats']['events']:,} events in {out['seconds']['stories']:.1f} s"
        + (f"; selection cut: {', '.join(result['stats']['truncated'])}" if result["stats"].get("truncated") else ""),
        "",
    ]
    for s in result["stories"]:
        flagged = sum(1 for st in s["steps"] if st["tie"]["kind"] in ("flag", "chain"))
        lines.append(
            f"  {s['severity']:<8} {s['score']:>3}  {s['kind']:<6} {s['subject']['label']}  ({s['confidence']}; {_when(s['start'], '%H:%M')}-{_when(s['end'], '%H:%M')} UTC)"
        )
        lines.append(f"      hosts {', '.join(s['hosts']) or '-'}; {len(s['steps'])} steps, {flagged} flagged, {s['records']:,} records")
        lines.append("      phases " + ", ".join(f"{p['phase']} {p['steps']}" for p in s["phases"]))
        hops = (s.get("lineage") or {}).get("hops") or []
        if hops:
            lines.append("      hops " + ", ".join(sorted({f"{(h.get('from') or {}).get('host') or '?'}->{h.get('to')} ({h.get('kind')})" for h in hops})))
        if s.get("campaigns"):
            lines.append("      campaigns " + ", ".join(s["campaigns"]))
    for c in result["campaigns"]:
        lines.append(f"  campaign {c['id']} ({c['labelKind']} {c['label']}): {len(c['stories'])} stories, {len(c['targets'])} targets")
    lines += ["", "checks:"]
    for c in found:
        state = "ok" if c.ok else f"FAIL (later work: {c.later})" if c.later else "FAIL"
        lines.append(f"  {state:<8} {c.name}: {c.detail}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, required=True, help="the folder holding the unzipped JSON (or the zips)")
    ap.add_argument("--day", type=int, choices=sorted(DAYS), default=1)
    ap.add_argument("--fetch", action="store_true", help=f"download the day's zip from {REPO} at {SHA[:7]} when --data does not hold it")
    ap.add_argument("--packs", action="store_true", help="also run the default SigmaHQ packs (" + ", ".join(DEFAULT_PACKS) + ")")
    ap.add_argument("--no-raw", action="store_true", help="keep no raw record on the rows (faster; the few rules that read raw then miss)")
    ap.add_argument("--json", type=Path, help="write the stories, the findings and the checks to this file")
    a = ap.parse_args(argv)
    path = locate(a.data, a.day, a.fetch)
    out = run(path, packs=a.packs, include_raw=not a.no_raw)
    found = checks(a.day, out)
    print(summary(a.day, out, found))
    if a.json:
        payload = {
            "day": a.day,
            "source": {"repo": REPO, "sha": SHA, **DAYS[a.day]},
            "conversion": asdict(out["conversion"]),
            "seconds": out["seconds"],
            "checks": [asdict(c) for c in found],
            "stories": out["result"],
            "findings": out["findings"],
        }
        a.json.write_text(json.dumps(payload, default=str), encoding="utf-8")
    return 0 if all(c.ok or c.later for c in found) else 1


if __name__ == "__main__":
    raise SystemExit(main())
