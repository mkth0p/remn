#!/usr/bin/env python
"""
Score REMN, Hayabusa and Chainsaw on one EVTX library by the ATT&CK technique each file records.

    .venv/bin/python tools/evtx_attack_samples.py --library LIB --out /tmp/remn        # REMN, SQL engine
    hayabusa json-timeline -d LIB -L -p verbose -w -q -C -U -o /tmp/hayabusa.jsonl      # every Hayabusa rule
    chainsaw hunt LIB -s SIGMA/rules/windows -s SIGMA/rules-emerging-threats/windows \\
        -s SIGMA/rules-threat-hunting/windows --mapping mappings/sigma-event-logs-all.yml \\
        -r rules/evtx --json -q -o /tmp/chainsaw.json
    .venv/bin/python tools/head_to_head.py --library LIB --remn /tmp/remn \\
        --hayabusa /tmp/hayabusa.jsonl --chainsaw /tmp/chainsaw.json --labels folders

A file counts as detected when an alert fires on it from a rule tagged with the file's technique,
its parent or one of its sub-techniques (tools/measure_rules.py related(), with ATT&CK v19's
revoked ids mapped to their successors on both sides). Labels come from the library:

- folders: the technique folder each file sits in (mdecrevoisier/EVTX-to-MITRE-Attack,
  TA0006-Credential Access/T1558-Steal or Forge Kerberos Tickets/...); files outside a
  technique folder are counted apart;
- credits: the techniques of the rules REMN's reviewers credited with each sample
  (tests/fixtures/evtx-attack-samples/expected.json, EVTX-ATTACK-SAMPLES), which favours REMN.

Each tool runs every rule it has; levels are cut when scoring, the same for all three.

With --clean DIR it counts false alarms instead: the alerts of medium level and above that each tool
raises on the seven clean machines of evtx-baseline, without threat-hunting rules (Hayabusa run with
-m medium, Chainsaw with --level medium --level high --level critical, one output per machine in DIR;
REMN's counts come from rules/measures.json).
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from measure_rules import related, techniques  # noqa: E402

LEVELS = {"critical": 4, "crit": 4, "high": 3, "medium": 2, "med": 2, "low": 1, "informational": 0, "info": 0}
FOLDER = re.compile(r"^(T\d{4})(?:\.(\d{3}))?", re.I)
TAG = re.compile(r"T\d{4}(?:\.\d{3})?", re.I)


# Rules that carry no ATT&CK technique are tagged here by title, the same way for every tool, where
# the title names one technique or tool: SigmaHQ rules its authors left without one (all three
# tools carry them), Hayabusa's own and Chainsaw's own rules (Chainsaw's carry no ATT&CK tags at
# all; some name their technique in the title, read from there). Rules about a generic event stay
# untagged: Hayabusa's "(Sysmon Alert)" rules, a password change or reset, a logon type, VPN and RDS
# events, antivirus alerts, AppLocker. --as-tagged scores every tool without these maps.
UNTAGGED = {
    # SigmaHQ
    "MSSQL Disable Audit Settings": ["T1562.002"],
    "MSSQL XPCmdshell Option Change": ["T1505.001"],
    "MSSQL XPCmdshell Suspicious Execution": ["T1505.001"],
    "MSSQL Add Account To Sysadmin Role": ["T1098"],
    "PsExec Service Execution": ["T1569.002"],
    "PsExec Service Child Process Execution as LOCAL SYSTEM": ["T1569.002"],
    "Certificate Use With No Strong Mapping": ["T1649"],
    "Potential AS-REP Roasting via Kerberos TGT Requests": ["T1558.004"],
    "Base64 MZ Header In CommandLine": ["T1027"],
    "Potential CVE-2023-36874 Exploitation - Fake Wermgr.Exe Creation": ["T1068"],
    "Firewall Rule Update Via Netsh.EXE": ["T1562.004"],
    "Mshtml.DLL RunHTMLApplication Suspicious Usage": ["T1218"],
    "Suspicious PowerShell Invocations - Specific - ProcessCreation": ["T1059.001"],
    "Suspicious Execution of InstallUtil Without Log": ["T1218.004"],
    "Sysmon Configuration Change": ["T1562.001"],
    "Dump Ntds.dit To Suspicious Location": ["T1003.003"],
    "Rundll32 Spawned Via Explorer.EXE": ["T1218.011"],
    "Pikabot Fake DLL Extension Execution Via Rundll32.EXE": ["T1218.011"],
    "Qakbot Rundll32 Fake DLL Extension Execution": ["T1218.011"],
    # Hayabusa's own
    "Hidden User Account Created": ["T1136"],
    "Potential RDP Session Hijacking Activity": ["T1563.002"],
    "Possible Token Impersonation": ["T1134.001"],
    "Explicit Logon Attempt (Susp Proc) - Possible Mimikatz PrivEsc": ["T1134"],
    "Potentially Malicious PwSh": ["T1059.001"],
    "Proc Injection": ["T1055"],
    "LOLBAS Renamed": ["T1036.003"],
    "WMI Event Consumer (Sysmon Alert)": ["T1546.003"],
    "WMI Event Filter (Sysmon Alert)": ["T1546.003"],
}
# Chainsaw's own (rules/evtx at v2.16.5)
CHAINSAW_OWN = {
    "New User Created": ["T1136"],
    "User Added to Global Group": ["T1098"],
    "User Added to Local Group": ["T1098"],
    "User Added to Universal Group": ["T1098"],
    "Kerberos service ticket requested for Administrator": ["T1558.003"],
    "Weak Kerberos ticket encryption algorithm": ["T1558"],
    "Security Audit Logs Cleared": ["T1070.001"],
    "System Logs Cleared": ["T1070.001"],
    "Account Brute Force": ["T1110"],
    "Credential Dumping Tools Service Installation": ["T1003", "T1543.003"],
    "CSExec Service Installation": ["T1569.002", "T1021.002"],
    "KrbRelayUp Service Installation": ["T1558", "T1543.003"],
    "Meterpreter or Cobalt Strike Getsystem Service Installation": ["T1134.001", "T1543.003"],
    "PowerShell Script Service Installation": ["T1059.001", "T1543.003"],
    "ProcessHacker Service Installation": ["T1543.003"],
    "Remote Access Tool Service Installation": ["T1219", "T1543.003"],
    "Impacket smbexec.py Service Installation": ["T1569.002", "T1021.002"],
    "Suspicious Commands Service Installation": ["T1543.003"],
    "Suspicious Paths Service Installation": ["T1543.003"],
    "Sysinternals PsExec Service Installation": ["T1569.002", "T1021.002"],
    "OpenVPN TAP Driver Service Installation": ["T1543.003"],
    "Windows Event Log Stopped": ["T1562.002"],
    "MSSQL XP_CMDSHELL Enabled": ["T1505.001"],
}
BY_TITLE = {**UNTAGGED, **CHAINSAW_OWN}


def level(v: str | None) -> int:
    return LEVELS.get(str(v or "").strip().lower(), 0)


# an alert: (rule id, level, techniques, title)
Alerts = dict[str, list[tuple[str, int, frozenset[str], str]]]


def _tagged(tech: frozenset[str], title: str, by_title: dict[str, list[str]]) -> frozenset[str]:
    return tech or techniques(by_title.get(title.strip(), []) + (TAG.findall(title) if by_title else []))


def remn(out: Path, sets: tuple[str, ...], by_title: dict[str, list[str]] | None = None) -> Alerts:
    meta = {
        r["id"]: (level(r.get("severity")), techniques(r.get("attack")), r.get("title", r["id"]))
        for s in json.loads((out / "rules.json").read_text()).values()
        for r in s
    }
    alerts: Alerts = collections.defaultdict(list)
    for rel, got in json.loads((out / "sql.json").read_text()).items():
        for s in sets:
            for rid, keys in got.get(s, {}).items():
                lv, tech, title = meta[rid]
                alerts[rel] += [(rid, lv, _tagged(tech, title, by_title or {}), title)] * len(keys)
    return alerts


def _rel(path: str, lib: Path) -> str:
    p = Path(path)
    try:
        return p.resolve().relative_to(lib.resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def hayabusa_hunting(rules_dir: Path) -> set[str]:
    """The ids of the Hayabusa rules converted from SigmaHQ's threat-hunting set."""
    import yaml

    out = set()
    for p in rules_dir.rglob("*.yml"):
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError):
            continue
        if isinstance(doc, dict) and "detection.threat-hunting" in (doc.get("tags") or []):
            out.add(str(doc.get("id")))
    return out


def hayabusa(path: Path, lib: Path, skip: set[str] = frozenset(), by_title: dict[str, list[str]] | None = None) -> Alerts:
    alerts: Alerts = collections.defaultdict(list)
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            a = json.loads(line)
            if str(a.get("RuleID")) in skip:
                continue
            tags = a.get("MitreTags") or []
            tags = TAG.findall(" ".join(tags) if isinstance(tags, list) else str(tags))
            title = str(a.get("RuleTitle"))
            alerts[_rel(a["EvtxFile"], lib)].append((str(a.get("RuleID")), level(a.get("Level")), _tagged(techniques(tags), title, by_title or {}), title))
    return alerts


def chainsaw(path: Path, lib: Path, by_title: dict[str, list[str]] | None = None) -> Alerts:
    alerts: Alerts = collections.defaultdict(list)
    for d in json.loads(path.read_text(encoding="utf-8")):
        name = str(d.get("name", "")).strip()
        tech = _tagged(techniques(TAG.findall(" ".join(str(t) for t in d.get("tags") or []))), name, by_title or {})
        rid, lv = str(d.get("id") or d.get("name")), level(d.get("level"))
        # an aggregate fires once, on every file among its events
        paths = [d["document"]["path"]] if "document" in d else sorted({doc["path"] for doc in d.get("documents", [])})
        for p in paths:
            alerts[_rel(p, lib)].append((rid, lv, tech, name))
    return alerts


def labels(lib: Path, how: str, rule_tech: dict[str, frozenset[str]]) -> tuple[dict[str, frozenset[str]], list[str]]:
    files = sorted(p.relative_to(lib).as_posix() for p in lib.rglob("*.evtx") if ".git" not in p.parts)
    expected = json.loads((ROOT / "tests/fixtures/evtx-attack-samples/expected.json").read_text()) if how == "credits" else {}
    out, apart = {}, []
    for rel in files:
        if how == "folders":
            parts = rel.split("/")
            m = FOLDER.match(parts[1]) if len(parts) == 3 else None
            tech = techniques([m.group(1) + (f".{m.group(2)}" if m.group(2) else "")]) if m else frozenset()
        else:
            tech = frozenset().union(*(rule_tech.get(r, frozenset()) for r in expected.get(rel, [])))
        if tech:
            out[rel] = tech
        else:
            apart.append(rel)
    return out, apart


def score(name: str, alerts: Alerts, truth: dict[str, frozenset[str]], apart: list[str], floor: int) -> dict:
    why = {f: sorted({title for _, lv, tech, title in alerts.get(f, []) if lv >= floor and related(tech, t)}) for f, t in truth.items()}
    hit = {f for f, titles in why.items() if titles}
    fired = {f for f in truth if any(x[1] >= floor for x in alerts.get(f, []))}
    per = [sum(1 for x in alerts.get(f, []) if x[1] >= floor) for f in truth]
    return {
        "tool": name,
        "floor": floor,
        "files": len(truth),
        "detected": len(hit),
        "anyAlert": len(fired),
        "alerts": sum(per),
        "medianAlerts": statistics.median(per) if per else 0,
        "apartAnyAlert": sum(1 for f in apart if any(x[1] >= floor for x in alerts.get(f, []))),
        "hit": {f: why[f][:4] for f in sorted(hit)},
    }


def noise(clean: Path, remn_rules: dict, measures: dict, hunting: set[str]) -> list[dict]:
    """
    Alerts of medium level and above on the clean machines, each tool without its threat-hunting rules:
    REMN's from rules/measures.json (the events each rule matched on evtx-baseline), Hayabusa's and
    Chainsaw's from their runs on the same machines in --clean (hayabusa-*.jsonl, chainsaw-*.json).
    """
    tools: dict[str, dict[str, list]] = {}  # tool -> rule -> [level, events]
    remn_level = {r["id"]: level(r.get("severity")) for r in remn_rules["default"]}
    tools["REMN (default rules)"] = {
        rid: [remn_level[rid], m["clean"]["events"]] for rid, m in measures["rules"].items() if rid in remn_level and m.get("clean", {}).get("events")
    }
    tools["Hayabusa (without threat-hunting rules)"] = h = {}
    for f in sorted(clean.glob("hayabusa-*.jsonl")):
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                if line.strip() and (a := json.loads(line)) and str(a.get("RuleID")) not in hunting:
                    h.setdefault(str(a.get("RuleID")), [level(a.get("Level")), 0])[1] += 1
    tools["Chainsaw (SigmaHQ without hunting, and its own rules)"] = c = {}
    for f in sorted(clean.glob("chainsaw-*.json")):
        for d in json.loads(f.read_text(encoding="utf-8")):
            n = 1 if "document" in d else len(d.get("documents", []))
            c.setdefault(str(d.get("id") or d.get("name")), [level(d.get("level")), 0])[1] += n
    out = []
    for name, per in tools.items():
        row = {"tool": name}
        for floor, word in ((2, "medium"), (3, "high"), (4, "critical")):
            fired = {r: n for r, (lv, n) in per.items() if lv >= floor and n}
            row[word] = {"rules": len(fired), "events": sum(fired.values())}
        row["top"] = sorted(((n, r) for r, (lv, n) in per.items() if lv >= 3), reverse=True)[:5]
        out.append(row)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--library", type=Path)
    ap.add_argument("--remn", type=Path, required=True)
    ap.add_argument("--hayabusa", type=Path)
    ap.add_argument("--chainsaw", type=Path)
    ap.add_argument("--chainsaw-default", type=Path, help="a Chainsaw run without the threat-hunting rules")
    ap.add_argument("--hayabusa-rules", type=Path, help="the hayabusa-rules checkout, to score Hayabusa without its threat-hunting rules too")
    ap.add_argument("--labels", choices=("folders", "credits"), default="folders")
    ap.add_argument("--as-tagged", action="store_true", help="score each rule by the techniques its authors gave it, without the title maps")
    ap.add_argument("--clean", type=Path, help="count the alerts each tool raises on the clean machines' runs in this directory instead")
    ap.add_argument("--json", type=Path, help="write every score, with the files each tool detected, here")
    a = ap.parse_args(argv)
    rules = json.loads((a.remn / "rules.json").read_text())
    if a.clean:
        measures = json.loads((ROOT / "rules" / "measures.json").read_text())
        rows = noise(a.clean, rules, measures, hayabusa_hunting(a.hayabusa_rules) if a.hayabusa_rules else set())
        for r in rows:
            print(f"{r['tool']:55s} " + "  ".join(f"{w}+: {r[w]['rules']:3d} rules, {r[w]['events']:7d} events" for w in ("medium", "high", "critical")))
            print("    noisiest high+: " + ", ".join(f"{rid} ({n})" for n, rid in r["top"]))
        if a.json:
            a.json.write_text(json.dumps(rows, indent=1))
        return 0
    truth, apart = labels(a.library, a.labels, {r["id"]: techniques(r.get("attack")) for s in rules.values() for r in s})
    bt = {} if a.as_tagged else BY_TITLE
    tools = {
        "REMN (default rules)": remn(a.remn, ("default",), bt),
        "REMN (with the hunting pack)": remn(a.remn, ("default", "hunting"), bt),
        "Hayabusa (every rule)": hayabusa(a.hayabusa, a.library, by_title=bt),
        "Chainsaw (SigmaHQ with hunting, and its own rules)": chainsaw(a.chainsaw, a.library, bt),
    }
    if a.hayabusa_rules:
        tools["Hayabusa (without threat-hunting rules)"] = hayabusa(a.hayabusa, a.library, hayabusa_hunting(a.hayabusa_rules), bt)
    if a.chainsaw_default:
        tools["Chainsaw (SigmaHQ without hunting, and its own rules)"] = chainsaw(a.chainsaw_default, a.library, bt)
    results = [score(n, al, truth, apart, floor) for floor in (0, 2, 3) for n, al in tools.items()]
    floor_word = {0: "any level", 2: "medium and above", 3: "high and above"}
    print(f"{len(truth)} files labelled with a technique, {len(apart)} apart")
    for r in results:
        print(
            f"{floor_word[r['floor']]:17s} {r['tool']:52s} detected {r['detected']:3d} of {r['files']} ({r['detected'] / r['files']:.0%})"
            f"  any alert {r['anyAlert']:3d}  alerts {r['alerts']:6d} (median {r['medianAlerts']:g})  apart with an alert {r['apartAnyAlert']}/{len(apart)}"
        )
    if a.json:
        a.json.write_text(json.dumps({"labels": {k: sorted(v) for k, v in truth.items()}, "apart": apart, "results": results}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
