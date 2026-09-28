#!/usr/bin/env python
"""
Every event rule on every public library REMN is measured on, every finding kept, and the figures the
home page and docs/reviews/2026-09-28-measures-across-libraries.md quote, made from them.

    .venv/bin/python tools/library_measures.py fetch --datasets DS [--max-dataset-mb 20]
    .venv/bin/python tools/library_measures.py harvest --datasets DS --out OUT [--jobs N] [--max-dataset-mb 20] [--no-clean]
    .venv/bin/python tools/library_measures.py figures --harvest OUT [--json frontend/src/data/libraryMeasures.json]

fetch gets what tools/measure_rules.py measures (its pinned checkouts, attack_data's datasets and
the clean machines of evtx-baseline) and two more OTRF Security-Datasets sources, at a pinned commit:
its atomic Windows datasets (tools/security_datasets.py) and the two days of MITRE's APT29
evaluation (tools/apt29_stories.py). About 11 GB with the clean machines.

harvest runs every rule of REMN's own set and of the three SigmaHQ packs, at every level, on each
recording and clean machine, with a new case's settings, on the SQL engine, and keeps every finding
with its host, time and count (OUT/findings.jsonl, one line a recording, a clean machine or an APT29
day), the recordings' labels (OUT/recordings.json) and the rules' levels and techniques
(OUT/rules.json). It resumes where it stopped. A clean machine is loaded once and its rules run in
parts on copies of its store.

figures scores the harvest: a recording is detected when an enabled rule tagged with its technique
(the same id, its parent or a sub-technique, ATT&CK v19) raises a finding on it, at or above the
level cut. The default rule set is REMN's own rules and SigmaHQ's windows and emerging-threats
packs. A rule written after studying a library (tools/measure_rules.py WRITTEN_AGAINST) is not
counted on it. Tactics are the tactic each technique plays in an intrusion (the story engine's
map, backend/services/analysis/stories.py).
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "tools"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "forensic.settings")

import measure_rules as M  # noqa: E402
import security_datasets as SD  # noqa: E402

try:  # macOS allows 256 open files by default; each worker opens DuckDB stores
    import resource

    _soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    for _want in (65536, 10240, 4096, 2048):
        if _want <= _soft:
            break
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (_want if _hard == resource.RLIM_INFINITY else min(_want, _hard), _hard))
            break
        except (ValueError, OSError):
            continue
except ImportError:
    pass

SECURITY_DATASETS = "Security-Datasets"
APT29 = "apt29"
DEFAULT_PACKS = ("core", "sigma-windows", "sigma-emerging-threats")
LV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}
# the libraries scored, in the order the page lists them; practice: REMN's rules were reviewed or
# written against it as a whole
LIBRARIES = [
    ("evtxToMitre", "EVTX-to-MITRE-Attack", False),
    ("attackDataWindows", "Splunk attack_data, Windows", False),
    ("securityDatasets", "OTRF Security-Datasets, atomic Windows", False),
    ("attackSamples", "EVTX-ATTACK-SAMPLES", True),
    ("sigma", "SigmaHQ regression samples", True),
]


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------
def fetch(ds: Path, max_mb: int) -> None:
    M.fetch(ds)
    sd = ds / SECURITY_DATASETS
    if not (sd / SD.METADATA).is_dir():
        print(f"fetching {SD.PIN['repo']} at {SD.PIN['sha']} (atomic Windows datasets)", flush=True)
        # a partial clone with only the atomic Windows datasets checked out (about 130 MB of 4 GB)
        for cmd in (
            ["git", "clone", "-q", "--filter=blob:none", "--no-checkout", f"https://github.com/{SD.PIN['repo']}", str(sd)],
            ["git", "-C", str(sd), "sparse-checkout", "set", "--no-cone", f"{SD.METADATA}/*", "datasets/atomic/windows/*"],
            ["git", "-C", str(sd), "checkout", "-q", SD.PIN["sha"]],
        ):
            subprocess.run(cmd, check=True)  # noqa: S603 - fixed arguments
    from apt29_stories import locate

    for day in (1, 2):
        locate(ds / APT29, day, fetch=True)
    recs, _ = M.attack_data_recordings(ds / "attack_data", ds / "cache", max_mb * 1024 * 1024)
    print(f"fetching attack_data files for {len(recs)} recordings", flush=True)
    M.fetch_recordings(recs, ds / "attack_data", ds / "cache")


# ---------------------------------------------------------------------------
# harvest (worker processes)
# ---------------------------------------------------------------------------
_W: dict[str, Any] = {}


def _init(stores: str) -> None:
    from services.store import rules as R
    from services.store.casestore import StoreRegistry

    rules, seen = [], set()
    for rs in M.event_rules().values():
        for r in rs:
            if r.get("id") and r["id"] not in seen:
                seen.add(r["id"])
                rules.append({**r, "enabled": True})
    reg = StoreRegistry()
    reg.configure(Path(stores))
    _W.update(rules=rules, reg=reg, R=R, stores=Path(stores))


def key_of(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, name))


def _rows(reader: str, files: list[str]):
    """The rows of a unit's files: .evtx and event XML through the upload's own reader, OTRF's JSON through its converters."""
    if reader == "securityDatasets":
        yield from SD.rows([Path(f) for f in files])
        return
    if reader == "nxlog":
        from apt29_stories import nxlog_rows

        for f in files:
            yield from nxlog_rows(Path(f))
        return
    from services.ingest.pipeline import EvtxSource

    for f in files:
        src = EvtxSource(Path(f).name, f, None, str(_W["stores"] / "tmp"), include_raw=True)
        yield from src
        _W["unread"] += src.stats.errors


def _load(key: str, reader: str, files: list[str]):
    from services.store.writers import EventWriter

    reg = _W["reg"]
    done = _W["stores"] / key / "DONE"
    if done.exists():
        n, unread, seconds = json.loads(done.read_text())
        return reg.get(key), n, unread, seconds
    reg.delete(key)
    store = reg.get(key)
    writer = EventWriter(store, 1)
    n = 0
    _W["unread"] = 0
    t0 = time.perf_counter()
    for row in _rows(reader, files):
        n += 1
        row = json.loads(json.dumps(row, default=str))
        row.update(id=n, caseId=1, evidenceId=1)
        writer.add(row)
    writer.flush()
    seconds = time.perf_counter() - t0
    done.write_text(json.dumps([n, _W["unread"], seconds]))
    return store, n, _W["unread"], seconds


def run_unit(name: str, key: str, reader: str, files: list[str], part: int = 0, parts: int = 1, keep: bool = False) -> dict[str, Any]:
    try:
        store, n, unread, load_s = _load(key, reader, files)
        out: dict[str, Any] = {
            "name": name,
            "key": key,
            "rows": n,
            "unread": unread,
            "seconds": {"load": load_s, "rules": 0.0},
            "findings": [],
            "sel": {},
            "errors": [],
        }
        if not n:
            return out
        t0 = time.perf_counter()
        res = _W["R"].run_rules(store, _W["rules"][part::parts], M.SETTINGS, diagnose=False)
        out["seconds"]["rules"] = time.perf_counter() - t0
        out["errors"] = res["errors"]
        firsts = sorted({f["refs"][0] for f in res["findings"] if f.get("refs") and str(f["refs"][0]).isdigit()})
        host: dict[int, str] = {}
        with store.lock:
            con = store._con
            for i in range(0, len(firsts), 5000):
                chunk = firsts[i : i + 5000]
                for rid, comp in con.execute(f"SELECT id, computer FROM events WHERE id IN ({','.join(map(str, chunk))})").fetchall():
                    host[rid] = comp
            for ch, eid, c in con.execute("SELECT channel, eventId, count(*) FROM events GROUP BY 1, 2").fetchall():
                out["sel"][f"{ch}|{eid}"] = c
        for f in res["findings"]:
            ref = (f.get("refs") or [None])[0]
            out["findings"].append(
                [
                    f["ruleId"],
                    f.get("severity"),
                    int(f.get("count") or 1),
                    str(f.get("ts") or ""),
                    str(f.get("tsEnd") or f.get("ts") or ""),
                    host.get(ref),
                    f.get("entities"),
                ]
            )
        return out
    finally:
        st = _W["reg"]._stores.pop(key, None)
        if st is not None:
            st.close()
        if not keep:
            shutil.rmtree(_W["stores"] / key, ignore_errors=True)


def load_only(name: str, key: str, reader: str, files: list[str]) -> tuple[str, int]:
    try:
        _, n, _, _ = _load(key, reader, files)
    finally:
        st = _W["reg"]._stores.pop(key, None)
        if st is not None:
            st.close()
    return name, n


def rule_table() -> dict[str, dict[str, Any]]:
    """Each rule's pack, level, follow-up level, techniques and tactic tags, as the harvest ran them."""
    out: dict[str, dict[str, Any]] = {}
    for pack, rs in M.event_rules().items():
        for r in rs:
            if r.get("id") and r["id"] not in out:
                out[r["id"]] = {
                    "pack": pack,
                    "severity": str(r.get("severity") or "medium").lower(),
                    "then": str((r.get("then") or {}).get("severity") or "").lower() or None,
                    "techniques": sorted(M.techniques(r.get("attack"))),
                    "title": r.get("title") or r["id"],
                }
    return out


def units(ds: Path, max_mb: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """The recordings and APT29 days, with their labels, and what was left out."""
    rules = {rid: frozenset(r["techniques"]) for rid, r in rule_table().items()}
    ad, left = M.attack_data_recordings(ds / "attack_data", ds / "cache", max_mb * 1024 * 1024)
    M.fetch_recordings(ad, ds / "attack_data", ds / "cache")
    recs = (
        M.sigma_recordings(ds / "sigma", rules)
        + M.attack_sample_recordings(ds / "EVTX-ATTACK-SAMPLES", rules)
        + ad
        + M.evtx_to_mitre_recordings(ds / "EVTX-to-MITRE-Attack")
    )
    out = [{**r.meta(), "files": [str(f) for f in r.files], "reader": "evtx", "size": sum(f.stat().st_size for f in r.files)} for r in recs]
    sd = ds / SECURITY_DATASETS
    left["securityDatasets"] = {}
    if (sd / SD.METADATA).is_dir():
        for d in SD.datasets(sd):
            if not d.files:
                left["securityDatasets"]["missing"] = left["securityDatasets"].get("missing", 0) + 1
                continue
            out.append(
                {
                    "dataset": "securityDatasets",
                    "name": d.id,
                    "title": d.title,
                    "techniques": sorted(M.techniques(sorted(d.techniques))),
                    "tactics": list(d.tactics),
                    "credit": [],
                    "owner": None,
                    "files": [str(f) for f in d.files],
                    "reader": "securityDatasets",
                    "size": sum(f.stat().st_size for f in d.files),
                }
            )
    from apt29_stories import DAYS

    for day, pin in DAYS.items():
        f = ds / APT29 / pin["json"]
        if f.is_file():
            out.append(
                {
                    "dataset": "apt29",
                    "name": f"day{day}",
                    "techniques": [],
                    "credit": [],
                    "owner": None,
                    "files": [str(f)],
                    "reader": "nxlog",
                    "size": f.stat().st_size,
                }
            )
    return out, left


def harvest(ds: Path, out_dir: Path, jobs: int, max_mb: int, clean: bool, keep: bool) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    stores = out_dir / "stores"
    (stores / "tmp").mkdir(parents=True, exist_ok=True)
    recs, left = units(ds, max_mb)
    head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()  # noqa: S603, S607
    (out_dir / "recordings.json").write_text(json.dumps({"commit": head, "maxMb": max_mb, "recordings": recs, "leftOut": left}))
    (out_dir / "rules.json").write_text(json.dumps({"commit": head, "rules": rule_table()}))
    path = out_dir / "findings.jsonl"
    have = {json.loads(line)["name"] for line in path.open()} if path.exists() else set()
    todo = [(f"{r['dataset']}:{r['name']}", r["reader"], r["files"], r["size"]) for r in recs if f"{r['dataset']}:{r['name']}" not in have]
    machines = []
    if clean:
        base = ds / "baseline"
        machines = [(f"clean:{m}", sorted(str(f) for f in (base / m).rglob("*.evtx"))) for m in M.BASELINE_MACHINES if (base / m).is_dir()]
        machines = [m for m in machines if m[0] not in have and m[1]]
    print(f"{len(todo)} recordings and {len(machines)} clean machines to do on {jobs} processes (commit {head[:7]})", flush=True)
    t_all = time.perf_counter()
    with ProcessPoolExecutor(max_workers=jobs, initializer=_init, initargs=(str(stores),)) as pool:
        loads = [pool.submit(load_only, n, key_of(n), "evtx", fs) for n, fs in machines]
        futs = {pool.submit(run_unit, n, key_of(n), reader, fs): n for n, reader, fs, _ in sorted(todo, key=lambda u: -u[3])}
        with path.open("a") as fh:
            for i, fut in enumerate(as_completed(futs), 1):
                try:
                    res = fut.result()
                except Exception as e:  # noqa: BLE001 - one failed unit is reported, the rest go on
                    print(f"FAILED {futs[fut]}: {e}", flush=True)
                    continue
                fh.write(json.dumps(res, default=str) + "\n")
                fh.flush()
                if i % 100 == 0 or i == len(futs):
                    print(f"  recordings {i}/{len(futs)} ({time.perf_counter() - t_all:.0f} s)", flush=True)
        for fut in loads:
            name, n = fut.result()
            print(f"loaded {name}: {n:,} events", flush=True)
    if not machines:
        print("ALL DONE", flush=True)
        return 0
    sizes = {n: sum(Path(f).stat().st_size for f in fs) for n, fs in machines}
    total = sum(sizes.values()) or 1
    parts_of = []
    for n, fs in machines:
        parts = max(1, min(jobs, round(jobs * 2 * sizes[n] / total)))
        for p in range(parts):
            k = key_of(n) if p == 0 else key_of(f"{n}#{p}")
            if p and not (stores / k / "DONE").exists():
                shutil.rmtree(stores / k, ignore_errors=True)
                shutil.copytree(stores / key_of(n), stores / k)
            parts_of.append((n, k, fs, p, parts))
    print(f"{len(parts_of)} rule parts over {len(machines)} clean machines", flush=True)
    merged: dict[str, dict[str, Any]] = {}
    with ProcessPoolExecutor(max_workers=jobs, initializer=_init, initargs=(str(stores),)) as pool:
        futs2 = {pool.submit(run_unit, n, k, "evtx", fs, p, parts, keep): (n, p, parts) for n, k, fs, p, parts in parts_of}
        for fut in as_completed(futs2):
            n, p, parts = futs2[fut]
            res = fut.result()
            m = merged.setdefault(
                n,
                {
                    "name": n,
                    "key": key_of(n),
                    "rows": res["rows"],
                    "unread": res["unread"],
                    "seconds": {"load": res["seconds"]["load"], "rules": 0.0},
                    "findings": [],
                    "sel": res["sel"],
                    "errors": [],
                    "_done": 0,
                },
            )
            m["findings"] += res["findings"]
            m["errors"] += res["errors"]
            m["seconds"]["rules"] += res["seconds"]["rules"]
            m["_done"] += 1
            if m["_done"] == parts:
                m.pop("_done")
                with path.open("a") as fh:
                    fh.write(json.dumps(m, default=str) + "\n")
                print(f"DONE {n}: {m['rows']:,} events, {len(m['findings']):,} findings ({time.perf_counter() - t_all:.0f} s)", flush=True)
    print("ALL DONE", flush=True)
    return 0


# ---------------------------------------------------------------------------
# figures
# ---------------------------------------------------------------------------
def phase_of(techniques: list[str]) -> str | None:
    from services.analysis.stories import _TECHNIQUE_PHASE

    for t in techniques:
        p = _TECHNIQUE_PHASE.get(t.split(".")[0])
        if p:
            return p
    return None


def load_harvest(h: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    recs = json.loads((h / "recordings.json").read_text())
    rules = json.loads((h / "rules.json").read_text())
    units: dict[str, dict[str, Any]] = {}
    for line in (h / "findings.jsonl").open():
        u = json.loads(line)
        units[u["name"]] = u
    return recs, rules["rules"], units


def figures(h: Path) -> dict[str, Any]:
    recs, rules, units = load_harvest(h)
    tech = {rid: frozenset(r["techniques"]) for rid, r in rules.items()}
    # a finding's level: its own when it carries one (a follow-up raises it), else its rule's
    by_lib: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for r in recs["recordings"]:
        by_lib[r["dataset"]].append(r)

    def alerts(name: str, dataset: str, packs=DEFAULT_PACKS) -> list[tuple[str, int]]:
        u = units.get(name)
        if not u:
            return []
        skip = {rid for rid, dss in M.WRITTEN_AGAINST.items() if dataset in dss}
        return [
            (f[0], LV.get(str(f[1]).lower(), LV.get(rules[f[0]]["severity"], 2)))
            for f in u["findings"]
            if f[0] in rules and rules[f[0]]["pack"] in packs and f[0] not in skip
        ]

    libs = []
    tactic_rows: dict[str, dict[str, list[int]]] = collections.defaultdict(dict)
    techniques_seen: dict[str, set[str]] = collections.defaultdict(set)
    techniques_hit: dict[str, set[str]] = collections.defaultdict(set)
    for key, label, practice in LIBRARIES:
        rows = by_lib.get(key, [])
        read = [r for r in rows if units.get(f"{key}:{r['name']}", {}).get("rows")]
        cut = {"any": 0, "medium": 0, "high": 0}
        fired_medium = 0
        for r in read:
            name = f"{key}:{r['name']}"
            want = frozenset(r["techniques"])
            al = alerts(name, key)
            good = [lv for rid, lv in al if M.related(tech[rid], want)]
            best = max(good, default=-1)
            cut["any"] += best >= 0
            cut["medium"] += best >= 2
            cut["high"] += best >= 3
            fired_medium += any(lv >= 2 for _, lv in al)
            if not practice and want:
                phase = phase_of(sorted(want)) or "other"
                row = tactic_rows[phase].setdefault(key, [0, 0, 0])
                row[0] += 1
                row[1] += best >= 0
                row[2] += best >= 2
                parents = {t.split(".")[0] for t in want}
                techniques_seen[key] |= parents
                if best >= 2:
                    techniques_hit[key] |= parents
        libs.append(
            {
                "key": key,
                "name": label,
                "practice": practice,
                "recordings": len(rows),
                "read": len(read),
                "detected": cut,
                "anyAlertMedium": fired_medium,
                "events": sum(units.get(f"{key}:{r['name']}", {}).get("rows", 0) for r in read),
            }
        )
    held = [lib["key"] for lib in libs if not lib["practice"]]
    seen_all = set().union(*(techniques_seen[k] for k in held))
    hit_all = set().union(*(techniques_hit[k] for k in held))

    # the clean machines: findings by level per machine, default packs, and per million events
    clean = []
    for m in M.BASELINE_MACHINES:
        u = units.get(f"clean:{m}")
        if not u:
            continue
        levels = collections.Counter()
        for f in u["findings"]:
            r = rules.get(f[0])
            if r and r["pack"] in DEFAULT_PACKS:
                levels[LV.get(str(f[1]).lower(), LV.get(r["severity"], 2))] += 1
        clean.append(
            {
                "machine": m,
                "events": u["rows"],
                "medium": sum(v for k, v in levels.items() if k >= 2),
                "high": sum(v for k, v in levels.items() if k >= 3),
                "critical": levels[4],
                "all": sum(levels.values()),
            }
        )

    # MITRE's APT29 evaluation: the findings of each host, medium and above, by level
    apt29 = {}
    for day in (1, 2):
        u = units.get(f"apt29:day{day}")
        if not u:
            continue
        hosts: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
        for f in u["findings"]:
            r = rules.get(f[0])
            if not r or r["pack"] not in DEFAULT_PACKS:
                continue
            lv = LV.get(str(f[1]).lower(), LV.get(r["severity"], 2))
            host = str(f[5] or "?").split(".")[0].lower()
            hosts[host][lv] += 1
        apt29[f"day{day}"] = {
            "events": u["rows"],
            "hosts": {
                h: {"medium": sum(v for k, v in c.items() if k >= 2), "high": sum(v for k, v in c.items() if k >= 3), "all": sum(c.values())}
                for h, c in sorted(hosts.items())
            },
        }

    # throughput: events read and rules run per second, per process, over every unit
    load_s = sum(u.get("seconds", {}).get("load", 0) for u in units.values())
    rules_s = sum(u.get("seconds", {}).get("rules", 0) for u in units.values())
    events = sum(u.get("rows", 0) for u in units.values())
    return {
        "commit": recs.get("commit"),
        "measured": dt.date.today().isoformat(),
        "rules": {"all": len(rules), "default": sum(1 for r in rules.values() if r["pack"] in DEFAULT_PACKS)},
        "libraries": libs,
        "tactics": {p: v for p, v in sorted(tactic_rows.items())},
        "techniques": {"seen": len(seen_all), "detected": len(hit_all), "byLibrary": {k: [len(techniques_seen[k]), len(techniques_hit[k])] for k in held}},
        "clean": clean,
        "apt29": apt29,
        "throughput": {"events": events, "loadSeconds": round(load_s, 1), "rulesSeconds": round(rules_s, 1)},
        "leftOut": recs.get("leftOut"),
        "maxMb": recs.get("maxMb"),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    f.add_argument("--datasets", type=Path, required=True)
    f.add_argument("--max-dataset-mb", type=int, default=20)
    hv = sub.add_parser("harvest")
    hv.add_argument("--datasets", type=Path, required=True)
    hv.add_argument("--out", type=Path, required=True)
    hv.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    hv.add_argument("--max-dataset-mb", type=int, default=20)
    hv.add_argument("--no-clean", action="store_true", help="leave the clean machines out")
    hv.add_argument("--keep", action="store_true", help="keep the clean machines' stores once measured")
    fg = sub.add_parser("figures")
    fg.add_argument("--harvest", type=Path, required=True)
    fg.add_argument("--json", type=Path)
    args = ap.parse_args(argv)
    if args.cmd == "fetch":
        fetch(args.datasets.resolve(), args.max_dataset_mb)
        return 0
    if args.cmd == "harvest":
        return harvest(args.datasets.resolve(), args.out.resolve(), args.jobs, args.max_dataset_mb, not args.no_clean, args.keep)
    fig = figures(args.harvest.resolve())
    text = json.dumps(fig, indent=1)
    if args.json:
        args.json.write_text(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
