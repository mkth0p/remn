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
    git clone https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack && git -C EVTX-to-MITRE-Attack checkout 474856008f037ccd42753f02a631b42690195829
    for h in win10-client win11-client win11-client-2023 win2022-ad win2022-0-20348-azure win2022-evtx win7-x86; do
      mkdir -p baseline/$h && curl -sSfL https://github.com/NextronSystems/evtx-baseline/releases/download/v0.8.4/$h.tgz | tar xz -C baseline/$h
    done
    .venv/bin/python tools/measure_rules.py --sigma sigma --attack-samples EVTX-ATTACK-SAMPLES \\
        --attack-data attack_data --evtx-to-mitre EVTX-to-MITRE-Attack --baseline baseline \\
        --out rules/measures.json --detail rules/measures-detail.json

or, with the checkouts under one directory and whichever are missing fetched first:

    .venv/bin/python tools/measure_rules.py --datasets DIR --fetch --out rules/measures.json --detail rules/measures-detail.json

The attack_data datasets are Git LFS files: the ones measured (the Office 365 and Entra ID ones,
13 MB, and the Windows ones of up to --max-dataset-mb a dataset, about 1.3 GB) are fetched from GitHub's
media host at the pinned commit into --cache, unless the checkout has them.

The gate (--gate rules/measures-detail.json, run weekly and on a change to the rules, the rule
engine or the parsers by .github/workflows/measure-rules.yml) fails when a rule no longer detects
a recording it detected when the committed detail was measured, a SigmaHQ rule no longer fires on
its own sample, a recording is no longer read, or a high or critical rule raises more findings on
a clean machine. A change that means to do one of those commits the measures it takes.

The measure can be shared out over machines: --shard I/N --raw FILE measures the I-th of N shares
of the recordings and clean machines (a clean machine larger than a share is split by rules), and
--merge FILE... makes the measure of the N files, as one run would, with --out, --detail and
--gate. The workflow runs eight shares.

Recorded attacks:
- the SigmaHQ regression samples: one recording per rule, made by the rule's author;
- EVTX-ATTACK-SAMPLES, with the rules reviewed as identifying each file
  (tests/fixtures/evtx-attack-samples/expected.json);
- Splunk attack_data's Office 365 and Entra ID (azure:monitor:aad) datasets, each labelled with
  its ATT&CK technique; the Entra audit logs among them are a format REMN does not read;
- Splunk attack_data's Windows datasets (attackDataWindows): the event logs of its attack range,
  kept as XmlWinEventLog, one recording per dataset labelled with its techniques. No rule was
  written against them before they were first measured (2026-09-25);
- EVTX-to-MITRE-Attack, each file labelled with the technique of the folder it is filed in. No
  rule was written against it before it was first measured (docs/reviews/2026-09-25-head-to-head.md);
  a rule written since, after studying some of its files, is not measured on it (WRITTEN_AGAINST).
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
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
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
    "evtxToMitre": {"repo": "mdecrevoisier/EVTX-to-MITRE-Attack", "sha": "474856008f037ccd42753f02a631b42690195829"},
    "baseline": {"repo": "NextronSystems/evtx-baseline", "tag": "v0.8.4"},
}
M365_SOURCETYPES = ("o365:management:activity", "azure:monitor:aad")
WINDOWS_SOURCETYPES = ("XmlWinEventLog",)
# a Windows dataset of attack_data larger than this is not measured: the largest are days of a
# lab's Sysmon (up to 380 MB) around one technique
ATTACK_DATA_MAX_BYTES = 20 * 1024 * 1024
MEDIA = "https://media.githubusercontent.com/media/{repo}/{sha}/{path}"
# ATT&CK v19 revoked these ids (MITRE's de-split crosswalk; tests/backend/test_rules_yaml.py): the
# rules carry the new ones, older labels are read as them
REVOKED = {
    "T1672": "T1684.002", "T1562": "T1685", "T1562.001": "T1685", "T1562.002": "T1685.001", "T1562.003": "T1690",
    "T1562.004": "T1686", "T1562.006": "T1685", "T1562.007": "T1686.001", "T1562.008": "T1685.002", "T1562.009": "T1688",
    "T1562.010": "T1689", "T1562.011": "T1685.003", "T1562.012": "T1685.004", "T1562.013": "T1686.002", "T1656": "T1684.001",
    "T1070.001": "T1685.005", "T1070.002": "T1685.006",
}  # fmt: skip
# --datasets: each dataset under the name of its checkout, and the option naming it on its own
LAYOUT = {"sigma": "sigma", "attackSamples": "EVTX-ATTACK-SAMPLES", "attackData": "attack_data", "evtxToMitre": "EVTX-to-MITRE-Attack", "baseline": "baseline"}
DEST = {"sigma": "sigma", "attackSamples": "attack_samples", "attackData": "attack_data", "evtxToMitre": "evtx_to_mitre", "baseline": "baseline"}
BASELINE_MACHINES = ("win10-client", "win11-client", "win11-client-2023", "win2022-ad", "win2022-0-20348-azure", "win2022-evtx", "win7-x86")
DETAIL = ROOT / "rules" / "measures-detail.json"
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
# EVTX-to-MITRE-Attack files a recording under its tactic and technique: TA0006-.../T1558-.../file.evtx
TECHNIQUE_FOLDER = re.compile(r"^(T\d{4})(?:\.(\d{3}))?", re.I)
# rules written after studying a dataset's files: that dataset is not evidence for them
WRITTEN_AGAINST: dict[str, frozenset[str]] = {
    # written for the gaps the head-to-head of 2026-09-25 found on EVTX-to-MITRE-Attack
    "win-user-added-security-group": frozenset({"evtxToMitre"}),
    "win-explicit-credentials-unusual-process": frozenset({"evtxToMitre"}),
    # rules/windows/directory.yaml, written for the directory changes the 2026-09-26 research found missed there
    "win-account-security-weakened": frozenset({"evtxToMitre"}),
    "win-account-delegation-enabled": frozenset({"evtxToMitre"}),
    "win-password-never-expires-set": frozenset({"evtxToMitre"}),
    "win-ad-acl-changed-domain-root-or-adminsdholder": frozenset({"evtxToMitre"}),
    "win-ad-acl-changed": frozenset({"evtxToMitre"}),
    "win-ad-extended-right-modified": frozenset({"evtxToMitre"}),
    "win-ad-server-object-created": frozenset({"evtxToMitre"}),
    "win-domain-policy-changed-by-user": frozenset({"evtxToMitre"}),
    "win-special-groups-table-changed": frozenset({"evtxToMitre"}),
    "win-sensitive-user-right-assigned": frozenset({"evtxToMitre"}),
    "win-guest-account-enabled": frozenset({"evtxToMitre"}),
}


def techniques(values: Any) -> frozenset[str]:
    out = set()
    for v in values or []:
        t = str(v).strip().upper().removeprefix("ATTACK.")
        if TECHNIQUE.match(t):
            out.add(REVOKED.get(t, t))
    return frozenset(out)


def folder_technique(rel: str) -> frozenset[str]:
    """The technique of an EVTX-to-MITRE-Attack file from its folder, or none for a file outside a technique folder."""
    parts = rel.split("/")
    m = TECHNIQUE_FOLDER.match(parts[1]) if len(parts) == 3 else None
    return techniques([m.group(1) + (f".{m.group(2)}" if m.group(2) else "")]) if m else frozenset()


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
    # attack_data files still to fetch into files (Git LFS pointers), and the bytes of its files
    lfs: list[str] = field(default_factory=list)
    size: int = 0

    def meta(self) -> dict[str, Any]:
        """What the measures need of a recording besides what the rules did on it (--raw, --merge)."""
        return {
            "dataset": self.dataset,
            "name": self.name,
            "techniques": sorted(self.techniques),
            "credit": sorted(self.credit),
            "owner": self.owner,
        }

    @classmethod
    def from_meta(cls, m: dict[str, Any]) -> Recording:
        return cls(m["dataset"], m["name"], [], frozenset(m["techniques"]), frozenset(m["credit"]), m["owner"])


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


def evtx_to_mitre_recordings(root: Path) -> list[Recording]:
    """One recording per file filed under a technique; the full attack chains and Defender events outside one are left out."""
    out = []
    for p in sorted(p for p in root.rglob("*.evtx") if ".git" not in p.parts):
        rel = p.relative_to(root).as_posix()
        if tech := folder_technique(rel):
            out.append(Recording("evtxToMitre", rel, [p], tech))
    return out


def _lfs_size(path: Path) -> int | None:
    """The size of a Git LFS file from its pointer, or of the file itself; None when the checkout has neither."""
    if not path.is_file():
        return None
    head = path.read_bytes()[:200]
    if head.startswith(b"version https://git-lfs"):
        m = re.search(rb"\nsize (\d+)", head)
        return int(m.group(1)) if m else None
    return path.stat().st_size


def _fetch_lfs(root: Path, cache: Path, rel: str) -> Path:
    """A Git LFS file of the attack_data checkout: the file itself when it was checked out, else
    fetched from GitHub's media host at the pinned commit into the cache."""
    pin = PINS["attackData"]
    local = root / rel
    if local.is_file() and not local.read_bytes()[:40].startswith(b"version https://git-lfs"):
        return local
    cached = cache / pin["sha"] / rel
    if not cached.is_file():
        cached.parent.mkdir(parents=True, exist_ok=True)
        url = MEDIA.format(repo=pin["repo"], sha=pin["sha"], path=rel)
        partial = cached.with_name(cached.name + ".part")
        with urllib.request.urlopen(url, timeout=300) as resp, open(partial, "wb") as fh:  # noqa: S310 - a fixed https host
            while chunk := resp.read(1 << 20):
                fh.write(chunk)
        partial.replace(cached)
    return cached


def attack_data_recordings(root: Path, cache: Path, max_bytes: int = ATTACK_DATA_MAX_BYTES) -> tuple[list[Recording], dict[str, dict[str, int]]]:
    """
    One recording per dataset descriptor: its Office 365 and Entra ID logs (dataset attackData),
    and its Windows event logs, which Splunk keeps as XmlWinEventLog (attackDataWindows). A
    descriptor whose Windows logs are larger than max_bytes together is not measured, nor one
    whose files are not at the pinned commit; both are counted.
    """
    base = root / "datasets" / "attack_techniques"
    wanted: list[tuple[str, Path, list[str], frozenset[str]]] = []
    left_out: dict[str, dict[str, int]] = {"attackData": {}, "attackDataWindows": {}}
    for desc in sorted(base.rglob("*.yml")):
        doc = yaml.safe_load(desc.read_text(encoding="utf-8")) or {}
        folder = desc.relative_to(base).parts[0]
        tech = techniques(doc.get("mitre_technique") or [folder])
        for dataset, types in (("attackData", M365_SOURCETYPES), ("attackDataWindows", WINDOWS_SOURCETYPES)):
            paths = [str(d["path"]).lstrip("/") for d in doc.get("datasets") or [] if isinstance(d, dict) and d.get("sourcetype") in types and d.get("path")]
            if not paths:
                continue
            sizes = [_lfs_size(root / rel) for rel in paths]
            if any(size is None for size in sizes):
                left_out[dataset]["missing"] = left_out[dataset].get("missing", 0) + 1
                continue
            if dataset == "attackDataWindows" and sum(s or 0 for s in sizes) > max_bytes:
                left_out[dataset]["overSize"] = left_out[dataset].get("overSize", 0) + 1
                continue
            wanted.append((dataset, desc, paths, tech, sum(s or 0 for s in sizes)))
    # the files are fetched by fetch_recordings, for the recordings a run measures
    out = [
        Recording(dataset, desc.parent.relative_to(root).as_posix(), [root / rel for rel in paths], tech, lfs=paths, size=size)
        for dataset, desc, paths, tech, size in wanted
    ]
    return out, left_out


def fetch_recordings(recordings: list[Recording], root: Path, cache: Path) -> None:
    """The attack_data files of the recordings, from the checkout or GitHub's media host (_fetch_lfs)."""
    todo = [rec for rec in recordings if rec.lfs]
    with ThreadPoolExecutor(max_workers=8) as pool:
        fetched = list(pool.map(lambda rec: [_fetch_lfs(root, cache, rel) for rel in rec.lfs], todo))
    for rec, files in zip(todo, fetched, strict=True):
        rec.files, rec.lfs = files, []


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
        res = R.run_rules(store, _W["rules"], SETTINGS, diagnose=False)
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


def run_machine(files: list[str], part: int = 0, parts: int = 1) -> dict[str, Any]:
    """
    A clean machine: each rule's findings, the events they cover, and the events it reads. With
    parts, the rules of one part of them (every parts-th rule from the part-th): a large machine is
    measured in parts on several runners, each loading it.
    """
    R = _W["R"]
    rules = _W["rules"][part::parts]
    key, store, n, unread = _load([Path(f) for f in files])
    try:
        res = R.run_rules(store, rules, SETTINGS, diagnose=False)
        found: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
        for f in res["findings"]:
            found[f["ruleId"]][0] += 1
            found[f["ruleId"]][1] += int(f.get("count") or 1)
        scope_cache: dict[str, int] = {}
        scopes = {}
        with store.lock:
            con = store._con
            for rule in rules:
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


# --- sharing the work out ------------------------------------------------------------------------


@dataclass
class Unit:
    """A recording, or a clean machine with one part of the rules, and the share of the work it falls to."""

    kind: str
    ref: Any  # the recording's index, the machine's directory
    files: list[Path]
    weight: int
    part: int = 0
    parts: int = 1
    share: int = 1


def plan(recordings: list[Recording], machines: list[Path], shares: int) -> list[Unit]:
    """
    The recordings and clean machines dealt out to the shares, largest first to the least loaded, by
    the bytes of their files. A machine larger than a share is split into parts of the rules, each
    loading the whole machine; the rules then take about half its time. Every share computes the
    same plan from the same datasets.
    """
    units: list[Unit] = []
    for m in machines:
        files = sorted(m.rglob("*.evtx"))
        units.append(Unit("machine", m.name, files, sum(f.stat().st_size for f in files)))
    for i, rec in enumerate(recordings):
        size = rec.size or sum(f.stat().st_size for f in rec.files if f.is_file())
        units.append(Unit("recording", i, rec.files, size))
    if shares > 1:
        target = sum(u.weight for u in units) / shares
        split = []
        for u in units:
            parts = min(shares, -(-u.weight // max(1, int(target)))) if u.kind == "machine" else 1
            split += [Unit(u.kind, u.ref, u.files, int(u.weight * (0.5 + 0.5 / parts)), p, parts) for p in range(parts)] if parts > 1 else [u]
        units = split
    load = [0] * shares
    for u in sorted(units, key=lambda u: (-u.weight, u.kind, str(u.ref), u.part)):
        u.share = min(range(shares), key=lambda i: (load[i], i)) + 1
        load[u.share - 1] += u.weight
    return units


def measure(units: list[Unit], recordings: list[Recording], jobs: int) -> tuple[dict[str, Any], list[str]]:
    """The rules run on each unit: what they did on each recording, and on each part of each machine."""
    results: dict[str, Any] = {"recordings": {}, "machines": {}}
    problems: list[str] = []
    tmp = tempfile.mkdtemp(prefix="remn-measure-")
    with ProcessPoolExecutor(max_workers=jobs, initializer=_worker_init, initargs=(tmp,)) as pool:
        # the largest first: the machines take longest
        futures = {}
        for u in sorted(units, key=lambda u: -u.weight):
            files = [str(f) for f in (u.files if u.kind == "machine" else recordings[u.ref].files)]
            fut = pool.submit(run_machine, files, u.part, u.parts) if u.kind == "machine" else pool.submit(run_recording, files)
            futures[fut] = u
        done = 0
        for fut in as_completed(futures):
            u = futures[fut]
            out = fut.result()
            problems += [f"{u.ref}: rule {e['ruleId']} failed: {e['error']}" for e in out["errors"]]
            if u.kind == "machine":
                results["machines"].setdefault(u.ref, {})[str(u.part)] = out
                of = f" (rules part {u.part + 1} of {u.parts})" if u.parts > 1 else ""
                print(f"  clean machine {u.ref}{of}: {out['rows']:,} events, {sum(v[0] for v in out['found'].values()):,} findings", flush=True)
            else:
                results["recordings"][str(u.ref)] = out
            done += 1
            if done % 100 == 0:
                print(f"  {done} of {len(futures)}", flush=True)
    return results, problems


def apply_results(results: dict[str, Any], recordings: list[Recording]) -> dict[str, dict[str, Any]]:
    """The results onto the recordings, and each clean machine's parts as one."""
    for i, out in results["recordings"].items():
        rec = recordings[int(i)]
        rec.rows, rec.unread, rec.fired, rec.readable = out["rows"], out["unread"], set(out["fired"]), set(out["readable"])
    clean: dict[str, dict[str, Any]] = {}
    for name, parts in sorted(results["machines"].items()):
        outs = [parts[k] for k in sorted(parts, key=int)]
        clean[name] = {
            "rows": outs[0]["rows"],
            "unread": outs[0]["unread"],
            "found": {rid: v for o in outs for rid, v in o["found"].items()},
            "scopes": {rid: v for o in outs for rid, v in o["scopes"].items()},
            "errors": [e for o in outs for e in o["errors"]],
        }
    return clean


def merge(paths: list[Path]) -> tuple[list[Recording], dict[str, dict[str, Any]], dict[str, dict[str, int]], int, list[str]]:
    """
    The shares --shard wrote, as one measure. It fails unless every share of one plan is there once
    and every recording and every part of every clean machine was measured: a share missing is
    never a measure with less in it.
    """
    raws = [json.loads(p.read_text(encoding="utf-8")) for p in paths]
    first = raws[0]
    shares = sorted(r["share"] for r in raws)
    if shares != list(range(1, first["shares"] + 1)) or any(r["shares"] != first["shares"] for r in raws):
        sys.exit(f"--merge needs each of the {first['shares']} shares once, got shares {shares}")
    for r in raws:
        for k in ("units", "recordings", "leftOut", "maxMb"):
            if r[k] != first[k]:
                sys.exit(f"share {r['share']} was planned on other datasets than share {first['share']} ({k} differ)")
    results: dict[str, Any] = {"recordings": {}, "machines": {}}
    for r in raws:
        results["recordings"].update(r["results"]["recordings"])
        for name, parts in r["results"]["machines"].items():
            results["machines"].setdefault(name, {}).update(parts)
    missing = [
        f"{kind} {ref}" + (f" part {part + 1}" if parts > 1 else "")
        for kind, ref, part, parts in first["units"]
        if (str(ref) not in results["recordings"] if kind == "recording" else str(part) not in results["machines"].get(ref, {}))
    ]
    if missing:
        sys.exit(f"--merge: {len(missing)} unit(s) measured by no share: {', '.join(missing[:5])}")
    recordings = [Recording.from_meta(m) for m in first["recordings"]]
    clean = apply_results(results, recordings)
    return recordings, clean, first["leftOut"], first["maxMb"], [p for r in raws for p in r["problems"]]


# --- the measures -------------------------------------------------------------------------------


def gate(before: dict[str, Any], after: dict[str, Any], rules: dict[str, dict[str, Any]]) -> tuple[list[str], list[str], list[str]]:
    """
    The measure against a committed one (rules/measures-detail.json): a recording a rule detected
    that it no longer detects, a SigmaHQ sample its rule no longer fires on, a recording no longer
    read, and a high or critical rule raising more findings on a clean machine than it did (all of
    them, when it was not high or critical then). What was gained is noted, not failed.
    """
    lost: list[str] = []
    noisier: list[str] = []
    notes: list[str] = []
    if before.get("sources") != after.get("sources"):
        lost.append("the datasets are not the versions the committed measure was taken on: re-run with --detail and commit it")
        return lost, noisier, notes
    for name in sorted(set(after.get("unread", [])) - set(before.get("unread", []))):
        lost.append(f"{name} is no longer read")
    gained = 0
    for rid, b in sorted(before.get("rules", {}).items()):
        now = after.get("rules", {}).get(rid, {})
        gone = sorted(set(b.get("hits", [])) - set(now.get("hits", [])))
        if gone:
            more = f" and {len(gone) - 5} more" if len(gone) > 5 else ""
            lost.append(f"{rid} no longer detects {', '.join(gone[:5])}{more}")
        if b.get("own") is True and now.get("own") is not True:
            lost.append(f"{rid} no longer fires on its own SigmaHQ sample")
    for rid, now in sorted(after.get("rules", {}).items()):
        b = before.get("rules", {}).get(rid, {})
        gained += len(set(now.get("hits", [])) - set(b.get("hits", [])))
        severity = str(rules.get(rid, {}).get("severity") or now.get("severity") or "")
        high = severity in ("high", "critical")
        then = b.get("severity")
        # findings it raised at a lower level when measured are new at this one
        lower_then = high and bool(b.get("clean")) and then is not None and then not in ("high", "critical")
        was = {} if lower_then else b.get("clean", {})
        more = {m: n for m, n in now.get("clean", {}).items() if n > was.get(m, 0)}
        raised = f", {then} when measured" if lower_then else ""
        if more and high:
            noisier.append(f"{rid} ({severity}{raised}) raises more findings on {', '.join(f'{m} ({was.get(m, 0)} to {n})' for m, n in sorted(more.items()))}")
        elif more:
            notes.append(f"{rid} ({severity or 'no severity'}) raises more findings on {', '.join(sorted(more))}")
    if gained:
        notes.append(f"{gained} detection(s) gained")
    return lost, noisier, notes


def fetch(root: Path) -> None:
    """Every dataset at its pinned version under root, as --datasets reads them; one already there is kept."""
    import subprocess
    import tarfile

    root.mkdir(parents=True, exist_ok=True)
    for key, name in LAYOUT.items():
        dest = root / name
        pin = PINS[key]
        if key == "baseline":
            for machine in BASELINE_MACHINES:
                target = dest / machine
                if target.is_dir() and any(target.rglob("*.evtx")):
                    continue
                target.mkdir(parents=True, exist_ok=True)
                url = f"https://github.com/{pin['repo']}/releases/download/{pin['tag']}/{machine}.tgz"
                print(f"fetching {url}", flush=True)
                with urllib.request.urlopen(url, timeout=600) as resp, tarfile.open(fileobj=resp, mode="r|gz") as tar:  # noqa: S310 - a fixed https host
                    tar.extractall(target, filter="data")
            continue
        if dest.is_dir() and any(dest.iterdir()):
            continue
        print(f"fetching {pin['repo']} at {pin['sha']}", flush=True)
        # attack_data's datasets are Git LFS files: only the pointers are checked out, and the
        # datasets measured are fetched one by one into --cache
        env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1"}
        for cmd in (
            ["git", "init", "-q", str(dest)],
            ["git", "-C", str(dest), "fetch", "-q", "--depth", "1", f"https://github.com/{pin['repo']}", pin["sha"]],
            ["git", "-C", str(dest), "checkout", "-q", "FETCH_HEAD"],
        ):
            subprocess.run(cmd, check=True, env=env)  # noqa: S603 - fixed arguments


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
    ap.add_argument("--datasets", type=Path, help="a directory holding every dataset under the name of its checkout (" + ", ".join(LAYOUT.values()) + ")")
    ap.add_argument("--fetch", action="store_true", help="first fetch the datasets --datasets does not hold yet, at the pinned versions")
    ap.add_argument("--sigma", type=Path, help="SigmaHQ/sigma checkout")
    ap.add_argument("--attack-samples", type=Path, help="EVTX-ATTACK-SAMPLES checkout")
    ap.add_argument("--attack-data", type=Path, help="splunk/attack_data checkout (LFS files may be pointers)")
    ap.add_argument("--evtx-to-mitre", type=Path, help="EVTX-to-MITRE-Attack checkout")
    ap.add_argument("--baseline", type=Path, help="evtx-baseline: one directory per machine")
    ap.add_argument("--out", type=Path, default=ROOT / "rules" / "measures.json")
    ap.add_argument(
        "--detail", type=Path, help=f"also write what each rule detects and raises on the clean machines, recording by recording ({DETAIL.relative_to(ROOT)})"
    )
    ap.add_argument(
        "--gate",
        type=Path,
        help="fail when a rule no longer detects a recording it detected in this detail file, or a high or critical rule raises more findings on a clean machine",
    )
    ap.add_argument("--cache", type=Path, default=Path(tempfile.gettempdir()) / "remn-measure-cache")
    ap.add_argument("--max-dataset-mb", type=int, default=ATTACK_DATA_MAX_BYTES >> 20, help="the largest attack_data Windows dataset measured")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    ap.add_argument("--limit", type=int, default=0, help="a trial run: the first N recordings of each dataset (no file is written unless --out is given)")
    ap.add_argument("--shard", help="I/N: measure the I-th of N shares of the recordings and clean machines (1 <= I <= N) and write them to --raw")
    ap.add_argument("--raw", type=Path, help="with --shard: where the share measured is written, for --merge")
    ap.add_argument("--merge", type=Path, nargs="+", help="take the measures from the --raw files of every share instead of measuring")
    a = ap.parse_args(argv)
    shard = None
    if a.shard:
        m = re.fullmatch(r"(\d+)/(\d+)", a.shard)
        if not m or not 1 <= int(m.group(1)) <= int(m.group(2)):
            ap.error("--shard is I/N, 1 <= I <= N")
        if not a.raw:
            ap.error("--shard needs --raw")
        shard = (int(m.group(1)), int(m.group(2)))
    if a.merge and (a.shard or a.fetch):
        ap.error("--merge measures nothing: it takes no --shard or --fetch")
    if a.datasets and a.fetch:
        fetch(a.datasets)
    for key, name in LAYOUT.items():
        attr = DEST[key]
        if getattr(a, attr) is None and not a.merge:
            if not a.datasets:
                ap.error(f"--{attr.replace('_', '-')} or --datasets is required")
            setattr(a, attr, a.datasets / name)

    sets = event_rules()
    from services.rules.measures import logic_hash
    from services.store import rules as R

    rules: dict[str, dict[str, Any]] = {}
    for rs in sets.values():
        for r in rs:
            rules.setdefault(r["id"], r)
    rule_tech = {rid: techniques(r.get("attack")) for rid, r in rules.items()}
    settings_needed = {rid: s for rid, r in rules.items() if (s := needs_settings(R, r))}

    if a.merge:
        recordings, clean, left_out, max_mb, problems = merge(a.merge)
        a.max_dataset_mb = max_mb
        print(f"{len(rules)} event rules; {len(recordings)} recordings; {len(clean)} clean machines, from {len(a.merge)} shares", flush=True)
    else:
        attack_data, left_out = attack_data_recordings(a.attack_data, a.cache, a.max_dataset_mb << 20)
        recordings = (
            sigma_recordings(a.sigma, rule_tech)
            + attack_sample_recordings(a.attack_samples, rule_tech)
            + attack_data
            + evtx_to_mitre_recordings(a.evtx_to_mitre)
        )
        if a.limit:
            by_set = collections.defaultdict(list)
            for rec in recordings:
                by_set[rec.dataset].append(rec)
            recordings = [rec for recs in by_set.values() for rec in recs[: a.limit]]
        machines = sorted(p for p in a.baseline.iterdir() if p.is_dir() and any(p.rglob("*.evtx")))
        print(f"{len(rules)} event rules; {len(recordings)} recordings; {len(machines)} clean machines", flush=True)
        units = plan(recordings, machines, shard[1] if shard else 1)
        mine = [u for u in units if u.share == (shard[0] if shard else 1)]
        fetch_recordings([recordings[u.ref] for u in mine if u.kind == "recording"], a.attack_data, a.cache)
        if shard:
            print(
                f"share {shard[0]} of {shard[1]}: {len(mine)} of {len(units)} units, {sum(u.weight for u in mine) / 1e9:.2f} of {sum(u.weight for u in units) / 1e9:.2f} GB",
                flush=True,
            )
        results, problems = measure(mine, recordings, a.jobs)
        if shard:
            a.raw.write_text(
                json.dumps(
                    {
                        "share": shard[0],
                        "shares": shard[1],
                        "units": [[u.kind, u.ref, u.part, u.parts] for u in units],
                        "recordings": [rec.meta() for rec in recordings],
                        "leftOut": left_out,
                        "maxMb": a.max_dataset_mb,
                        "results": results,
                        "problems": problems,
                    }
                ),
                encoding="utf-8",
            )
            print(f"wrote {a.raw}: share {shard[0]} of {shard[1]}; merge the shares with --merge")
            return 0
        clean = apply_results(results, recordings)

    read = [r for r in recordings if r.rows]
    measures: dict[str, dict[str, Any]] = {}
    detail_rules: dict[str, dict[str, Any]] = {}
    for rid, rule in sorted(rules.items()):
        m: dict[str, Any] = {"h": logic_hash(rule)}
        if rid in settings_needed:
            m["settings"] = settings_needed[rid]
            measures[rid] = m
            continue
        tech = rule_tech[rid]
        of = hits = fires = 0
        detected: list[str] = []
        for rec in read:
            if rec.dataset in WRITTEN_AGAINST.get(rid, ()):
                continue
            on = rid in rec.credit or (bool(tech) and rid in rec.readable and related(tech, rec.techniques))
            fired = rid in rec.fired
            of += on
            hits += on and fired
            fires += fired
            if on and fired:
                detected.append(f"{rec.dataset}:{rec.name}")
            if rec.owner == rid:
                m["own"] = fired
        m.update({k: v for k, v in (("of", of), ("hits", hits), ("fires", fires)) if v})
        findings = events = machines_fired = scope = machines_scoped = 0
        noise: dict[str, int] = {}
        for machine, out in sorted(clean.items()):
            f, e = out["found"].get(rid, (0, 0))
            findings, events, machines_fired = findings + f, events + e, machines_fired + (1 if f else 0)
            if f:
                noise[machine] = f
            if out["scopes"].get(rid):
                scope, machines_scoped = scope + out["scopes"][rid], machines_scoped + 1
        if scope:
            m["clean"] = {"findings": findings, "events": events, "machines": machines_fired, "scope": scope, "of": machines_scoped}
        measures[rid] = m
        entry = {k: v for k, v in (("hits", sorted(detected)), ("own", m.get("own")), ("clean", noise)) if v not in (None, [], {})}
        if noise:
            # the level its clean-machine findings were raised at, for the gate
            entry["severity"] = rule.get("severity")
        if entry:
            detail_rules[rid] = entry

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
                **left_out["attackData"],
            },
            "attackDataWindows": {
                **PINS["attackData"],
                "recordings": counted["attackDataWindows"],
                "maxMb": a.max_dataset_mb,
                **left_out["attackDataWindows"],
            },
            "evtxToMitre": {**PINS["evtxToMitre"], "recordings": counted["evtxToMitre"]},
            "baseline": {**PINS["baseline"], "machines": len(clean), "events": sum(o["rows"] for o in clean.values())},
        },
        "rules": measures,
    }
    a.out.write_text(dump(payload), encoding="utf-8")
    detail = {
        "version": 1,
        "measured": payload["measured"],
        "sources": {k: {x: y for x, y in v.items() if x in ("sha", "tag")} for k, v in payload["sources"].items()},
        # recordings no row could be read from: a parser that stops reading one loses what it holds
        "unread": sorted(f"{r.dataset}:{r.name}" for r in recordings if not r.rows),
        "rules": detail_rules,
    }
    if a.detail:
        a.detail.write_text(dump(detail), encoding="utf-8")

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
    failed = bool(problems)
    if a.gate:
        before = json.loads(a.gate.read_text(encoding="utf-8"))
        lost, noisier, notes = gate(before, detail, rules)
        for line in notes:
            print("  " + line)
        for line in lost + noisier:
            print("GATE", line)
        if lost or noisier:
            print(
                f"the gate against {a.gate} failed: {len(lost)} detection(s) lost, {len(noisier)} high or critical rule(s) noisier on the "
                "clean machines. When that is intended, re-run with --out rules/measures.json --detail rules/measures-detail.json and commit both."
            )
            failed = True
        else:
            print(f"the gate against {a.gate} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
