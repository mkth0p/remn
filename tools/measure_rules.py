#!/usr/bin/env python
"""
Measure every event rule on recorded attacks and on the logs of clean machines, and write
rules/measures.json. The server attaches each measure to the rule it was taken on (a rule whose
logic has changed since is served as changed), and the Rules page, the finding panel and the
report say from it how far a rule's finding can be taken as a detection.

The datasets, at the versions measured:

    git clone https://github.com/SigmaHQ/sigma && git -C sigma checkout 272daf82bf77fb0bb97f1f0c4d82bc61154772e1
    git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES && git -C EVTX-ATTACK-SAMPLES checkout 4ceed2f4706daf601c212a8f91c113dd85349a2c
    GIT_LFS_SKIP_SMUDGE=1 git clone https://github.com/splunk/attack_data && git -C attack_data checkout 7a5e9d5bedf2c18450599777e870f7bfa42a4025
    for h in win10-client win11-client win11-client-2023 win2022-ad win2022-0-20348-azure win2022-evtx win7-x86; do
      mkdir -p baseline/$h && curl -sSfL https://github.com/NextronSystems/evtx-baseline/releases/download/v0.8.4/$h.tgz | tar xz -C baseline/$h
    done
    .venv/bin/python tools/measure_rules.py --sigma sigma --attack-samples EVTX-ATTACK-SAMPLES \\
        --attack-data attack_data --baseline baseline --out rules/measures.json

The attack_data datasets are Git LFS files: the Office 365 and Entra ID ones (13 MB) are fetched
from GitHub's media host at the pinned commit into --cache, unless the checkout has them.

Recorded attacks:
- the SigmaHQ regression samples: one recording per rule, made by the rule's author;
- EVTX-ATTACK-SAMPLES, with the rules reviewed as identifying each file
  (tests/fixtures/evtx-attack-samples/expected.json);
- Splunk attack_data's Office 365 and Entra ID (azure:monitor:aad) datasets, each labelled with
  its ATT&CK technique; the Entra audit logs among them are a format REMN does not read.
Clean machines: the seven Windows installations of NextronSystems/evtx-baseline, which SigmaHQ
runs its rules against for false positives.

Each rule's measure:
  own     a SigmaHQ rule with a regression sample: whether it fires on it
  of      recordings of what it looks for: its own sample, a file reviewed as identifying it, or
          a recording it can read (the event ids, channels and fields it needs are in it)
          labelled with one of its techniques (the same id, its parent or a sub-technique;
          ATT&CK v19 ids)
  hits    of those, the ones it fires on
  fires   recordings it fires on at all
  clean   on the clean machines: its findings, the events they cover, the machines it fired
          on, and the events of the log sources it reads (its channels and event ids) and the
          machines that have them; absent when none of them logs what it reads
  settings  the case settings it cannot run without (internal domains, VIPs...): such a rule
          is not measured
"""

from __future__ import annotations

import argparse
import collections
import datetime
import json
import os
import re
import sys
import tempfile
import urllib.request
import uuid
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "tools"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "forensic.settings")

import yaml  # noqa: E402
from evtx_attack_samples import EXPECTED, SETTINGS, event_rules  # noqa: E402

PINS = {
    "sigma": {"repo": "SigmaHQ/sigma", "sha": "272daf82bf77fb0bb97f1f0c4d82bc61154772e1"},
    "attackSamples": {"repo": "sbousseaden/EVTX-ATTACK-SAMPLES", "sha": "4ceed2f4706daf601c212a8f91c113dd85349a2c"},
    "attackData": {"repo": "splunk/attack_data", "sha": "7a5e9d5bedf2c18450599777e870f7bfa42a4025"},
    "baseline": {"repo": "NextronSystems/evtx-baseline", "tag": "v0.8.4"},
}
M365_SOURCETYPES = ("o365:management:activity", "azure:monitor:aad")
MEDIA = "https://media.githubusercontent.com/media/{repo}/{sha}/{path}"
# ATT&CK v19 revoked these ids (MITRE's de-split crosswalk; tests/backend/test_rules_yaml.py): the
# rules carry the new ones, older labels are read as them
REVOKED = {
    "T1672": "T1684.002", "T1562": "T1685", "T1562.001": "T1685", "T1562.002": "T1685.001", "T1562.003": "T1690",
    "T1562.004": "T1686", "T1562.006": "T1685", "T1562.007": "T1686.001", "T1562.008": "T1685.002", "T1562.009": "T1688",
    "T1562.010": "T1689", "T1562.011": "T1685.003", "T1562.012": "T1685.004", "T1562.013": "T1686.002", "T1656": "T1684.001",
    "T1070.001": "T1685.005", "T1070.002": "T1685.006",
}  # fmt: skip
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


def techniques(values: Any) -> frozenset[str]:
    out = set()
    for v in values or []:
        t = str(v).strip().upper().removeprefix("ATTACK.")
        if TECHNIQUE.match(t):
            out.add(REVOKED.get(t, t))
    return frozenset(out)


def related(a: frozenset[str], b: frozenset[str]) -> bool:
    """The same technique, or one the parent of the other."""
    return any(x == y or x.startswith(y + ".") or y.startswith(x + ".") for x in a for y in b)


@dataclass
class Recording:
    dataset: str
    name: str
    files: list[Path]
    techniques: frozenset[str]
    # the rules it is a recording of: its own rule, or the rules reviewed as identifying it
    credit: frozenset[str] = frozenset()
    owner: str | None = None
    rows: int = 0
    unread: int = 0
    fired: set[str] = field(default_factory=set)
    # the rules that can read it: its event ids, channels and fields are the ones they need
    readable: set[str] = field(default_factory=set)


# --- recordings ---------------------------------------------------------------------------------


def sigma_recordings(root: Path, rule_tech: dict[str, frozenset[str]]) -> list[Recording]:
    """One recording per SigmaHQ regression sample, of the rule its info.yml names."""
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    upstream: dict[str, frozenset[str]] = {}
    for d in ("rules", "rules-emerging-threats", "rules-threat-hunting"):
        for p in (root / d).rglob("*.yml"):
            try:
                doc = yaml.load(p.read_text(encoding="utf-8"), Loader=loader)
            except yaml.YAMLError:
                continue
            if isinstance(doc, dict) and doc.get("id"):
                upstream[str(doc["id"])] = techniques(doc.get("tags"))
    out = []
    for info in sorted((root / "regression_data").rglob("info.yml")):
        doc = yaml.safe_load(info.read_text(encoding="utf-8")) or {}
        ids = [str(m["id"]) for m in doc.get("rule_metadata") or [] if isinstance(m, dict) and m.get("id")]
        tests = [t for t in doc.get("regression_tests_info") or [] if isinstance(t, dict) and t.get("type") == "evtx" and t.get("path")]
        if len(ids) != 1 or not tests:
            continue
        owner = f"sigma-{ids[0]}"
        files = [root / t["path"] for t in tests if (root / t["path"]).is_file()]
        if files:
            tech = rule_tech.get(owner) or upstream.get(ids[0], frozenset())
            out.append(Recording("sigma", info.parent.relative_to(root).as_posix(), files, tech, frozenset({owner}), owner))
    return out


def attack_sample_recordings(root: Path, rule_tech: dict[str, frozenset[str]]) -> list[Recording]:
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    out = []
    for p in sorted(p for p in root.rglob("*.evtx") if ".git" not in p.parts):
        rel = p.relative_to(root).as_posix()
        credit = frozenset(expected.get(rel, []))
        tech = frozenset().union(*(rule_tech.get(r, frozenset()) for r in credit)) if credit else frozenset()
        out.append(Recording("attackSamples", rel, [p], tech, credit))
    return out


def attack_data_recordings(root: Path, cache: Path) -> list[Recording]:
    """The Office 365 and Entra ID datasets, one recording per dataset descriptor."""
    pin = PINS["attackData"]
    out = []
    for desc in sorted((root / "datasets" / "attack_techniques").rglob("*.yml")):
        doc = yaml.safe_load(desc.read_text(encoding="utf-8")) or {}
        paths = [
            str(d["path"]).lstrip("/") for d in doc.get("datasets") or [] if isinstance(d, dict) and d.get("sourcetype") in M365_SOURCETYPES and d.get("path")
        ]
        if not paths:
            continue
        files = []
        for rel in paths:
            local = root / rel
            if local.is_file() and not local.read_bytes()[:40].startswith(b"version https://git-lfs"):
                files.append(local)
                continue
            cached = cache / pin["sha"] / rel
            if not cached.is_file():
                cached.parent.mkdir(parents=True, exist_ok=True)
                url = MEDIA.format(repo=pin["repo"], sha=pin["sha"], path=rel)
                with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 - a fixed https host
                    cached.write_bytes(resp.read())
            files.append(cached)
        folder = desc.relative_to(root / "datasets" / "attack_techniques").parts[0]
        out.append(Recording("attackData", desc.parent.relative_to(root).as_posix(), files, techniques(doc.get("mitre_technique") or [folder])))
    return out


# --- running the rules (in worker processes) ------------------------------------------------------

_W: dict[str, Any] = {}


def _worker_init(tmp: str) -> None:
    sets = event_rules()
    from services.store import rules as R
    from services.store.casestore import StoreRegistry

    rules, seen = [], set()
    for rs in sets.values():
        for r in rs:
            if r.get("id") and r["id"] not in seen:
                seen.add(r["id"])
                rules.append({**r, "enabled": True})
    reg = StoreRegistry()
    work = Path(tempfile.mkdtemp(prefix="remn-measure-", dir=tmp))
    reg.configure(work / "cases")
    _W.update(rules=rules, reg=reg, R=R, tmp=str(work))


def _load(files: list[Path]):
    """A store holding the rows of the files, and the count of rows and unread records."""
    from services.ingest.pipeline import EvtxSource
    from services.store.writers import EventWriter

    key = str(uuid.uuid4())
    store = _W["reg"].get(key)
    writer = EventWriter(store, 1)
    n = unread = 0
    for f in files:
        src = EvtxSource(f.name, str(f), None, _W["tmp"], include_raw=True)
        for row in src:
            n += 1
            row = json.loads(json.dumps(row, default=str))
            row.update(id=n, caseId=1, evidenceId=1)
            writer.add(row)
        unread += src.stats.errors
    writer.flush()
    return key, store, n, unread


def run_recording(files: list[str]) -> dict[str, Any]:
    key, store, n, unread = _load([Path(f) for f in files])
    try:
        if not n:
            return {"rows": 0, "unread": unread, "fired": [], "readable": [], "errors": []}
        R = _W["R"]
        res = R.run_rules(store, _W["rules"], SETTINGS)
        return {
            "rows": n,
            "unread": unread,
            "fired": sorted({f["ruleId"] for f in res["findings"]}),
            "readable": readable_rules(R, store),
            "errors": res["errors"],
        }
    finally:
        _W["reg"].delete(key)


def readable_rules(R, store) -> list[str]:
    """
    The rules a recording can be of: the event ids and channels it holds are not ones a rule rules
    out, it has a value in every column the rule's conditions need, and a Microsoft 365 or Entra
    rule needs cloud records. A collection rule is not of an event log recorded for its technique.
    """
    from services.store.casestore import q
    from services.store.sqlfilter import EVENT_COLS

    ids, chans = R.present_selectors(store)
    cols = sorted(c for c in EVENT_COLS if c != "id")
    with store.lock:
        counts = store._con.execute("SELECT " + ", ".join(f"count({q(c)})" for c in cols) + " FROM events").fetchone()
    present = {c for c, n in zip(cols, counts, strict=True) if n}
    out = []
    for rule in _W["rules"]:
        if R.rule_not_applicable(rule, ids, chans) or not presence_columns(rule.get("where"), EVENT_COLS) <= present:
            continue
        if cloud_rule(rule) and "recordKey" not in present:
            continue
        out.append(rule["id"])
    return out


def run_machine(files: list[str]) -> dict[str, Any]:
    """A clean machine: each rule's findings, the events they cover, and the events it reads."""
    R = _W["R"]
    key, store, n, unread = _load([Path(f) for f in files])
    try:
        res = R.run_rules(store, _W["rules"], SETTINGS)
        found: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
        for f in res["findings"]:
            found[f["ruleId"]][0] += 1
            found[f["ruleId"]][1] += int(f.get("count") or 1)
        scope_cache: dict[str, int] = {}
        scopes = {}
        with store.lock:
            con = store._con
            for rule in _W["rules"]:
                if cloud_rule(rule):
                    continue
                sql, params = scope_sql(R, rule)
                k = sql + "\0" + "\0".join(params)
                if k not in scope_cache:
                    scope_cache[k] = int(con.execute(f"SELECT count(*) FROM events WHERE {sql}", params).fetchone()[0])
                if scope_cache[k]:
                    scopes[rule["id"]] = scope_cache[k]
        return {"rows": n, "unread": unread, "found": dict(found), "scopes": scopes, "errors": res["errors"]}
    finally:
        _W["reg"].delete(key)


def cloud_rule(rule: dict[str, Any]) -> bool:
    """A Microsoft 365 or Entra rule: the clean machines are Windows logs, which hold none of its records."""
    return bool({"m365", "entra"} & set(rule.get("tags") or []))


# operators that match no event whose field has no value
POSITIVE_OPS = {
    "",
    "eq",
    "in",
    "contains",
    "contains_any",
    "contains_all",
    "startswith",
    "endswith",
    "re",
    "gt",
    "gte",
    "lt",
    "lte",
    "exists",
    "in_setting",
    "levenshtein",
    "contains_cs",
    "startswith_cs",
    "endswith_cs",
}


def presence_columns(cond: Any, columns: set[str], acc: set[str] | None = None) -> set[str]:
    """The columns a rule's conditions need a value in, from its AND positions (an any_of or a not needs none)."""
    acc = set() if acc is None else acc
    if not isinstance(cond, dict):
        return acc
    for k, v in cond.items():
        if re.match(r"^all_of(_\d+)?$", k):
            for m in v if isinstance(v, list) else [v]:
                presence_columns(m, columns, acc)
            continue
        if re.match(r"^any_of(_\d+)?$", k) or k == "not":
            continue
        field, _, op = k.partition("|")
        if op not in POSITIVE_OPS or field not in columns or (op == "exists" and v is not True):
            continue
        # an equality with nothing matches an empty field
        if op in ("", "eq", "in") and any(x is None or x == "" for x in (v if isinstance(v, list) else [v])):
            continue
        acc.add(field)
    return acc


def scope_sql(R, rule: dict[str, Any]) -> tuple[str, list[str]]:
    """
    The events a rule reads: those of the channels and event ids its where clause pins, with a value
    in every column its conditions need one in. A Microsoft 365 rule, which needs an operation,
    reads no Windows event; a keyword rule reads every event with raw XML.
    """
    from services.store.casestore import q
    from services.store.sqlfilter import EVENT_COLS

    parts, params = [], []
    ids = R._rule_event_ids(rule.get("where"))
    if ids:
        parts.append(f'"eventId" IN ({", ".join(str(int(i)) for i in ids)})')
    chans = R._rule_channels(rule.get("where"))
    if chans:
        alts = []
        for value, contains in chans:
            alts.append("strpos(lower(channel), ?) > 0" if contains else "lower(channel) = ?")
            params.append(value)
        parts.append("(" + " OR ".join(alts) + ")")
    parts += [f"{q(c)} IS NOT NULL" for c in sorted(presence_columns(rule.get("where"), EVENT_COLS))]
    return (" AND ".join(parts) or "TRUE"), params


def needs_settings(R, rule: dict[str, Any]) -> list[str]:
    """The case settings without which the rule cannot fire, empty in a new case."""
    req = rule.get("require_setting")
    names = [req] if req and R._setting_empty(SETTINGS, req) else []
    return names + [n for n in R._empty_positive_settings(rule.get("where"), SETTINGS) if n not in names]


# --- the measures -------------------------------------------------------------------------------


def dump(payload: dict[str, Any]) -> str:
    """One line per rule, in id order: a re-measurement's diff names the rules whose measure changed."""
    lines = ["{"]
    for k in sorted(k for k in payload if k != "rules"):
        lines.append(f"  {json.dumps(k)}: {json.dumps(payload[k], sort_keys=True)},")
    lines.append('  "rules": {')
    items = sorted(payload["rules"].items())
    for i, (rid, m) in enumerate(items):
        lines.append(f"    {json.dumps(rid)}: {json.dumps(m, sort_keys=True)}{',' if i < len(items) - 1 else ''}")
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sigma", type=Path, required=True, help="SigmaHQ/sigma checkout")
    ap.add_argument("--attack-samples", type=Path, required=True, help="EVTX-ATTACK-SAMPLES checkout")
    ap.add_argument("--attack-data", type=Path, required=True, help="splunk/attack_data checkout (LFS files may be pointers)")
    ap.add_argument("--baseline", type=Path, required=True, help="evtx-baseline: one directory per machine")
    ap.add_argument("--out", type=Path, default=ROOT / "rules" / "measures.json")
    ap.add_argument("--cache", type=Path, default=Path(tempfile.gettempdir()) / "remn-measure-cache")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    ap.add_argument("--limit", type=int, default=0, help="a trial run: the first N recordings of each dataset (no file is written unless --out is given)")
    a = ap.parse_args(argv)

    sets = event_rules()
    from services.rules.measures import logic_hash
    from services.store import rules as R

    rules: dict[str, dict[str, Any]] = {}
    for rs in sets.values():
        for r in rs:
            rules.setdefault(r["id"], r)
    rule_tech = {rid: techniques(r.get("attack")) for rid, r in rules.items()}
    settings_needed = {rid: s for rid, r in rules.items() if (s := needs_settings(R, r))}

    recordings = sigma_recordings(a.sigma, rule_tech) + attack_sample_recordings(a.attack_samples, rule_tech) + attack_data_recordings(a.attack_data, a.cache)
    if a.limit:
        by_set = collections.defaultdict(list)
        for rec in recordings:
            by_set[rec.dataset].append(rec)
        recordings = [rec for recs in by_set.values() for rec in recs[: a.limit]]
    machines = sorted(p for p in a.baseline.iterdir() if p.is_dir() and any(p.rglob("*.evtx")))
    print(f"{len(rules)} event rules; {len(recordings)} recordings; {len(machines)} clean machines", flush=True)

    tmp = tempfile.mkdtemp(prefix="remn-measure-")
    problems: list[str] = []
    clean: dict[str, dict[str, Any]] = {}
    with ProcessPoolExecutor(max_workers=a.jobs, initializer=_worker_init, initargs=(tmp,)) as pool:
        # the machines first: they take longest
        jobs = {pool.submit(run_machine, [str(p) for p in sorted(m.rglob("*.evtx"))]): ("machine", m.name) for m in machines}
        jobs.update({pool.submit(run_recording, [str(f) for f in rec.files]): ("recording", i) for i, rec in enumerate(recordings)})
        done = 0
        for fut in as_completed(jobs):
            kind, ref = jobs[fut]
            out = fut.result()
            problems += [f"{ref}: rule {e['ruleId']} failed: {e['error']}" for e in out["errors"]]
            if kind == "machine":
                clean[ref] = out
                print(f"  clean machine {ref}: {out['rows']:,} events, {sum(v[0] for v in out['found'].values()):,} findings", flush=True)
            else:
                rec = recordings[ref]
                rec.rows, rec.unread, rec.fired, rec.readable = out["rows"], out["unread"], set(out["fired"]), set(out["readable"])
            done += 1
            if done % 100 == 0:
                print(f"  {done} of {len(jobs)}", flush=True)

    read = [r for r in recordings if r.rows]
    measures: dict[str, dict[str, Any]] = {}
    for rid, rule in sorted(rules.items()):
        m: dict[str, Any] = {"h": logic_hash(rule)}
        if rid in settings_needed:
            m["settings"] = settings_needed[rid]
            measures[rid] = m
            continue
        tech = rule_tech[rid]
        of = hits = fires = 0
        for rec in read:
            on = rid in rec.credit or (bool(tech) and rid in rec.readable and related(tech, rec.techniques))
            fired = rid in rec.fired
            of += on
            hits += on and fired
            fires += fired
            if rec.owner == rid:
                m["own"] = fired
        m.update({k: v for k, v in (("of", of), ("hits", hits), ("fires", fires)) if v})
        findings = events = machines_fired = scope = machines_scoped = 0
        for out in clean.values():
            f, e = out["found"].get(rid, (0, 0))
            findings, events, machines_fired = findings + f, events + e, machines_fired + (1 if f else 0)
            if out["scopes"].get(rid):
                scope, machines_scoped = scope + out["scopes"][rid], machines_scoped + 1
        if scope:
            m["clean"] = {"findings": findings, "events": events, "machines": machines_fired, "scope": scope, "of": machines_scoped}
        measures[rid] = m

    counted = collections.Counter(r.dataset for r in read)
    unreadable = [r.name for r in recordings if not r.rows]
    payload = {
        "version": 1,
        "measured": datetime.datetime.now(datetime.UTC).date().isoformat(),
        "sources": {
            "sigma": {**PINS["sigma"], "recordings": counted["sigma"]},
            "attackSamples": {**PINS["attackSamples"], "recordings": counted["attackSamples"]},
            "attackData": {
                **PINS["attackData"],
                "recordings": counted["attackData"],
                "unreadable": sum(1 for r in recordings if r.dataset == "attackData" and not r.rows),
            },
            "baseline": {**PINS["baseline"], "machines": len(clean), "events": sum(o["rows"] for o in clean.values())},
        },
        "rules": measures,
    }
    a.out.write_text(dump(payload), encoding="utf-8")

    measured = [m for m in measures.values() if "settings" not in m]
    print(f"wrote {a.out}: {len(measures)} rules")
    print(f"  recordings read: {dict(counted)}; not readable: {len(unreadable)}")
    print(f"  fire on a recording of what they look for: {sum(1 for m in measured if m.get('hits'))}")
    print(f"  own SigmaHQ sample: {sum(1 for m in measured if m.get('own') is True)} fire on it, {sum(1 for m in measured if m.get('own') is False)} do not")
    print(
        f"  fire on a clean machine: {sum(1 for m in measured if m.get('clean', {}).get('findings'))} of {sum(1 for m in measured if 'clean' in m)} whose log sources the machines have"
    )
    print(f"  need a case setting: {len(settings_needed)}")
    for p in problems[:50]:
        print("FAIL", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
