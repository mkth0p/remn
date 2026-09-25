#!/usr/bin/env python
"""
Run EVTX-ATTACK-SAMPLES through REMN: parse every file, run the Windows rules, and check what fires.

    git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES && git -C EVTX-ATTACK-SAMPLES checkout 4ceed2f4706daf601c212a8f91c113dd85349a2c
    .venv/bin/python tools/evtx_attack_samples.py --library EVTX-ATTACK-SAMPLES --out /tmp/attack
    (cd frontend && EVTX_ATTACK_OUT=/tmp/attack npx vitest run src/rules/attackSamples.test.ts)

Each file is a one-file case with a new case's settings. The script parses it (no parse error may
occur), runs the core rules and the SigmaHQ packs on the SQL engine, and fails when a rule listed in
tests/fixtures/evtx-attack-samples/expected.json for a sample no longer fires on it: those are the
rules that identify the attack each sample records (docs/reviews/2026-09-23-evtx-attack-samples.md).
It also writes the rows, the rules and every finding key to --out, where the browser-engine test
compares its own findings with them key for key. CI runs both; endpoint protection tends to
quarantine the library on a workstation.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "forensic.settings")

EXPECTED = ROOT / "tests" / "fixtures" / "evtx-attack-samples" / "expected.json"
PACKS = ("sigma-windows", "sigma-emerging-threats", "sigma-threat-hunting")
DEFAULT_PACKS = ("sigma-windows", "sigma-emerging-threats")
# a new case's settings (frontend/src/db/schema.ts defaultSettings), with UTC business hours
SETTINGS = {
    "internal_domains": [],
    "expected_countries": [],
    "vip_names": [],
    "admin_accounts": [],
    "service_accounts": [],
    "internal_ips": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1", "fe80::/10", "fc00::/7"],
    "brands": [],
    "trusted_senders": [],
    "businessHours": {"start": 8, "end": 19, "tz": "UTC"},
    "weekendDays": [0, 6],
}


def event_rules() -> dict[str, list[dict]]:
    import django

    django.setup()
    from django.conf import settings

    from api.views.meta import load_rules
    from services.rules import packs

    core = [e["rule"] for e in load_rules(Path(settings.RULES_DIR)) if e.get("rule") and e["rule"].get("source", "events") == "events"]
    out = {"core": core}
    for pid in PACKS:
        out[pid] = [x["rule"] for x in packs.load_pack(pid)["rules"] if x.get("rule") and x["rule"].get("source", "events") == "events"]
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--library", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    sets = event_rules()
    from services.ingest.pipeline import EvtxSource
    from services.store import rules as R
    from services.store.casestore import StoreRegistry
    from services.store.writers import EventWriter

    default = sets["core"] + [r for p in DEFAULT_PACKS for r in sets[p]]
    hunting = sets["sigma-threat-hunting"]
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "rows").mkdir(exist_ok=True)
    (a.out / "rules.json").write_text(json.dumps({"default": default, "hunting": hunting}, default=str))
    expected = json.loads(EXPECTED.read_text(encoding="utf-8")) if EXPECTED.is_file() else {}
    files = sorted(p for p in a.library.rglob("*.evtx") if ".git" not in p.parts)
    reg = StoreRegistry()
    tmp = Path(tempfile.mkdtemp(prefix="remn-attack-"))
    reg.configure(tmp / "cases")
    index, keys, problems = [], {}, []
    fired_by_tactic: collections.Counter[str] = collections.Counter()
    total_by_tactic: collections.Counter[str] = collections.Counter()
    for i, path in enumerate(files):
        rel = path.relative_to(a.library).as_posix()
        src = EvtxSource(path.name, str(path), None, str(tmp), include_raw=True)
        rows = [json.loads(json.dumps(r, default=str)) for r in src]
        if src.stats.errors:
            problems.append(f"{rel}: {src.stats.errors} parse error(s)")
        for n, r in enumerate(rows, 1):
            r.update(id=n, caseId=1, evidenceId=1)
        with open(a.out / "rows" / f"{i}.ndjson", "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        index.append({"i": i, "file": rel, "rows": len(rows)})
        key = str(uuid.uuid4())
        store = reg.get(key)
        w = EventWriter(store, 1)
        for r in rows:
            w.add(dict(r))
        w.flush()
        got: dict[str, dict[str, list[str]]] = {}
        for name, rules in (("default", default), ("hunting", hunting)):
            res = R.run_rules(store, rules, SETTINGS)
            problems += [f"{rel}: rule {e['ruleId']} failed: {e['error']}" for e in res["errors"]]
            per: dict[str, list[str]] = collections.defaultdict(list)
            for f in res["findings"]:
                per[f["ruleId"]].append(f["key"])
            got[name] = {rid: sorted(ks) for rid, ks in per.items()}
        keys[rel] = got
        reg.delete(key)
        tactic = rel.split("/")[0] if "/" in rel else "(root)"
        total_by_tactic[tactic] += 1
        want = expected.get(rel, [])
        missing = [rid for rid in want if rid not in got["default"]]
        if missing:
            problems.append(f"{rel}: expected rule(s) no longer fire: {', '.join(missing)}")
        if want and not missing:
            fired_by_tactic[tactic] += 1
    reg.close_all()
    (a.out / "index.json").write_text(json.dumps(index))
    (a.out / "sql.json").write_text(json.dumps(keys))
    for t in sorted(total_by_tactic):
        print(f"  {t:24s} {fired_by_tactic[t]:3d} of {total_by_tactic[t]:3d} samples detected by the rules that identify them")
    print(f"{len(files)} files, {sum(x['rows'] for x in index)} rows; {sum(fired_by_tactic.values())} detected as expected")
    for p in problems:
        print("FAIL", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
