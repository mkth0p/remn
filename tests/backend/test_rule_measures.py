"""Rule measures (rules/measures.json, tools/measure_rules.py): each measure reaches the rule it was taken on, and only that rule."""

from __future__ import annotations

import json
import re
import shutil
import warnings
from pathlib import Path

import pytest
import yaml
from django.test import Client

from services.rules import measures, packs

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
ROOT = Path(__file__).resolve().parents[2]

RULE = {
    "id": "win-test-rule",
    "title": "A test rule",
    "severity": "medium",
    "source": "events",
    "attack": ["T1059.001"],
    "where": {"eventId": 4104, "scriptBlockText|contains": "Invoke-Mimikatz"},
}


@pytest.fixture
def rules_dir(tmp_path, settings):
    """A rules directory with one core rule and a copy of one community pack."""
    (tmp_path / "windows").mkdir()
    (tmp_path / "windows" / "test.yaml").write_text(yaml.safe_dump(RULE, sort_keys=False), encoding="utf-8")
    shutil.copytree(ROOT / "rules" / "community" / "sigma-emerging-threats", tmp_path / "community" / "sigma-emerging-threats")
    settings.RULES_DIR = tmp_path
    packs._cache.clear()
    yield tmp_path
    packs._cache.clear()


def write_measures(root: Path, rules: dict) -> None:
    body = {"version": 1, "measured": "2026-09-24", "sources": {"baseline": {"machines": 7, "events": 6611184}}, "rules": rules}
    (root / "measures.json").write_text(json.dumps(body), encoding="utf-8")


def test_the_hash_is_of_what_the_rule_matches_not_how_it_is_described():
    h = measures.logic_hash(RULE)
    assert measures.logic_hash({**RULE, "title": "Renamed", "severity": "high", "attack": ["T1059"], "sigma": {"status": "stable"}}) == h
    assert measures.logic_hash({**RULE, "where": {"eventId": 4104, "scriptBlockText|contains": "Invoke-Kerberoast"}}) != h
    assert measures.logic_hash({**RULE, "threshold": ">= 2"}) != h


def test_a_measure_reaches_its_rule_and_a_changed_rule_is_said_to_have_changed(rules_dir):
    assert measures.for_rule(RULE) is None  # never measured
    write_measures(rules_dir, {RULE["id"]: {"h": measures.logic_hash(RULE), "hits": 2, "of": 3, "fires": 4}})
    assert measures.for_rule(RULE) == {"hits": 2, "of": 3, "fires": 4}
    changed = {**RULE, "where": {"eventId": 4104}}
    assert measures.for_rule(changed) == {"changed": True}
    assert measures.for_rule({"id": "another-rule"}) is None


def test_meta_and_packs_carry_the_measures(rules_dir):
    pack = packs.load_pack("sigma-emerging-threats")
    first = pack["rules"][0]["rule"]
    assert "measured" not in pack["rules"][0]
    write_measures(
        rules_dir,
        {
            RULE["id"]: {"h": measures.logic_hash(RULE), "own": True, "hits": 1, "of": 1, "fires": 1},
            first["id"]: {"h": measures.logic_hash(first), "of": 2, "clean": {"findings": 0, "events": 0, "machines": 0, "scope": 5000, "of": 7}},
        },
    )
    c = Client()
    meta = c.get("/api/meta", **HDR).json()
    core = next(r for r in meta["rules"] if r.get("rule", {}).get("id") == RULE["id"])
    assert core["measured"] == {"own": True, "hits": 1, "of": 1, "fires": 1}
    assert meta["measures"] == {"version": 1, "measured": "2026-09-24", "sources": {"baseline": {"machines": 7, "events": 6611184}}}
    # the pack's cached payload is rebuilt with the new measures, its manifest hash unchanged
    served = c.get("/api/rules/packs/sigma-emerging-threats", **HDR).json()
    assert served["rules"][0]["measured"] == {"of": 2, "clean": {"findings": 0, "events": 0, "machines": 0, "scope": 5000, "of": 7}}
    assert served["pack"]["hash"] == pack["pack"]["hash"]
    assert all("measured" not in r for r in served["rules"][1:])


def test_the_shipped_measures_are_well_formed_and_say_which_rules_changed_since():
    """rules/measures.json, when present: every measure is of a known shape. A rule changed since it
    was measured is served as changed; the warning lists them until tools/measure_rules.py is re-run."""
    path = ROOT / "rules" / "measures.json"
    if not path.is_file():
        pytest.skip("the rules have not been measured")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["version"] == 1 and set(data["sources"]) == {"sigma", "attackSamples", "attackData", "evtxToMitre", "baseline"}
    known = {"h", "own", "of", "hits", "fires", "clean", "settings"}
    for rid, m in data["rules"].items():
        assert re.fullmatch(r"[0-9a-f]{12}", m["h"]) and set(m) <= known, rid
        assert m.get("hits", 0) <= m.get("of", 0) and m.get("hits", 0) <= m.get("fires", 0), rid
        if "clean" in m:
            c = m["clean"]
            assert c["scope"] > 0 and c["machines"] <= c["of"] <= data["sources"]["baseline"]["machines"] and c["events"] >= c["findings"], rid
    from api.views.meta import load_rules

    current = {e["rule"]["id"]: e["rule"] for e in load_rules(ROOT / "rules") if e.get("rule")}
    for pid in ("sigma-windows", "sigma-emerging-threats", "sigma-threat-hunting"):
        current.update({x["rule"]["id"]: x["rule"] for x in packs.load_pack(pid)["rules"] if x.get("rule")})
    stale = sorted(rid for rid, m in data["rules"].items() if rid in current and m["h"] != measures.logic_hash(current[rid]))
    unmeasured = sorted(rid for rid, r in current.items() if r.get("source", "events") == "events" and rid not in data["rules"])
    if stale or unmeasured:
        warnings.warn(
            f"re-run tools/measure_rules.py: {len(stale)} rules changed since measured {stale[:3]}, {len(unmeasured)} never measured {unmeasured[:3]}",
            stacklevel=1,
        )
