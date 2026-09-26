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


def test_the_summary_counts_the_rules_measured_and_those_seen_to_detect(rules_dir):
    write_measures(rules_dir, {"a": {"h": "x", "hits": 2, "of": 3}, "b": {"h": "y", "of": 4}, "c": {"h": "z", "fires": 1}})
    s = measures.summary()
    assert s["totals"] == {"rules": 3, "detect": 1}
    assert s["measured"] == "2026-09-24" and "rules" not in s


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
    assert meta["measures"] == {
        "version": 1,
        "measured": "2026-09-24",
        "sources": {"baseline": {"machines": 7, "events": 6611184}},
        "totals": {"rules": 2, "detect": 1},
    }
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
    assert data["version"] == 1 and set(data["sources"]) == {"sigma", "attackSamples", "attackData", "attackDataWindows", "evtxToMitre", "baseline"}
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


def _measure_tool():
    import sys

    sys.path.insert(0, str(ROOT / "tools"))
    import measure_rules

    return measure_rules


def test_the_gate_fails_on_a_lost_detection_and_on_new_noise_from_a_high_rule():
    M = _measure_tool()
    sources = {"sigma": {"sha": "a"}, "baseline": {"tag": "v1"}}
    before = {
        "sources": sources,
        "unread": ["attackData:entra-audit"],
        "rules": {
            "lsass": {"hits": ["attackSamples:dump.evtx", "evtxToMitre:T1003/a.evtx"], "clean": {"win10": 1}},
            "sigma-x": {"own": True, "hits": ["sigma:x"]},
            "loud": {"clean": {"win10": 2}, "severity": "high"},
            "raised": {"clean": {"win2022": 3}, "severity": "medium"},
        },
    }
    after = {
        "sources": sources,
        "unread": ["attackData:entra-audit", "attackDataWindows:T1003/new"],
        "rules": {
            "lsass": {"hits": ["attackSamples:dump.evtx", "attackDataWindows:T1003/b"], "clean": {"win10": 1}},
            "sigma-x": {"own": False},
            "loud": {"clean": {"win10": 5, "win11": 1}, "severity": "high"},
            "low": {"clean": {"win7": 40}, "severity": "low"},
            "raised": {"clean": {"win2022": 3}, "severity": "high"},
        },
    }
    rules = {
        "lsass": {"severity": "critical"},
        "sigma-x": {"severity": "medium"},
        "loud": {"severity": "high"},
        "low": {"severity": "low"},
        "raised": {"severity": "high"},
    }
    lost, noisier, notes = M.gate(before, after, rules)
    assert lost == [
        "attackDataWindows:T1003/new is no longer read",
        "lsass no longer detects evtxToMitre:T1003/a.evtx",
        "sigma-x no longer detects sigma:x",
        "sigma-x no longer fires on its own SigmaHQ sample",
    ]
    # a rule raised to high brings all its clean-machine findings to that level
    assert noisier == [
        "loud (high) raises more findings on win10 (2 to 5), win11 (0 to 1)",
        "raised (high, medium when measured) raises more findings on win2022 (0 to 3)",
    ]
    # a low rule's noise and what was gained are said, not failed
    assert notes == ["low (low) raises more findings on win7", "1 detection(s) gained"]
    assert M.gate(before, before, {**rules, "raised": {"severity": "medium"}}) == ([], [], [])
    # a snapshot of other dataset versions cannot be compared rule by rule
    lost, _, _ = M.gate(before, {**after, "sources": {**sources, "sigma": {"sha": "b"}}}, rules)
    assert len(lost) == 1 and "not the versions" in lost[0]


def test_attack_data_windows_datasets_are_recordings_up_to_the_size_cap(tmp_path):
    """Splunk's attack range keeps Windows event logs as XmlWinEventLog, which REMN reads. Each
    descriptor is a recording of its techniques; one over the cap or not at the pinned commit is counted, not measured."""
    M = _measure_tool()
    base = tmp_path / "attack_data" / "datasets" / "attack_techniques"

    def descriptor(folder: str, datasets: list[dict], tech=None) -> None:
        d = base / folder
        d.mkdir(parents=True)
        doc = {"mitre_technique": tech or [folder.split("/")[0]], "datasets": datasets}
        (d / "data.yml").write_text(yaml.safe_dump(doc), encoding="utf-8")

    def lfs(rel: str, size: int) -> None:
        (tmp_path / "attack_data" / rel).write_text(f"version https://git-lfs.github.com/spec/v1\noid sha256:{'0' * 64}\nsize {size}\n", encoding="utf-8")

    descriptor("T1003.001/dump", [{"sourcetype": "XmlWinEventLog", "path": "/datasets/attack_techniques/T1003.001/dump/sysmon.log"}])
    (base / "T1003.001/dump/sysmon.log").write_text("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'></Event>\n", encoding="utf-8")
    descriptor("T1059.001/big", [{"sourcetype": "XmlWinEventLog", "path": "/datasets/attack_techniques/T1059.001/big/a.log"}])
    lfs("datasets/attack_techniques/T1059.001/big/a.log", 30 << 20)
    descriptor("T1021.001/gone", [{"sourcetype": "XmlWinEventLog", "path": "/datasets/attack_techniques/T1021.001/gone/a.log"}])
    descriptor("T1078.004/signin", [{"sourcetype": "azure:monitor:aad", "path": "/datasets/attack_techniques/T1078.004/signin/s.json"}])
    (base / "T1078.004/signin/s.json").write_text("{}\n", encoding="utf-8")
    descriptor("T1190/linux", [{"sourcetype": "sysmon:linux", "path": "/datasets/attack_techniques/T1190/linux/l.log"}])

    recs, left = M.attack_data_recordings(tmp_path / "attack_data", tmp_path / "cache", max_bytes=20 << 20)
    assert [(r.dataset, r.name, sorted(r.techniques)) for r in recs] == [
        ("attackDataWindows", "datasets/attack_techniques/T1003.001/dump", ["T1003.001"]),
        ("attackData", "datasets/attack_techniques/T1078.004/signin", ["T1078.004"]),
    ]
    assert left == {"attackData": {}, "attackDataWindows": {"overSize": 1, "missing": 1}}


def test_the_committed_detail_is_the_detail_of_the_committed_measures():
    """rules/measures-detail.json lists, recording by recording, what rules/measures.json counts: the
    gate compares a new measure against it, so the two are taken and committed together."""
    detail_path, measures_path = ROOT / "rules" / "measures-detail.json", ROOT / "rules" / "measures.json"
    if not detail_path.is_file():
        pytest.skip("no detail committed")
    detail, data = json.loads(detail_path.read_text(encoding="utf-8")), json.loads(measures_path.read_text(encoding="utf-8"))
    assert detail["measured"] == data["measured"]
    assert detail["sources"] == {k: {x: y for x, y in v.items() if x in ("sha", "tag")} for k, v in data["sources"].items()}
    for rid, m in data["rules"].items():
        d = detail["rules"].get(rid, {})
        assert len(d.get("hits", [])) == m.get("hits", 0), rid
        assert d.get("own") == m.get("own"), rid
        assert sum(d.get("clean", {}).values()) == m.get("clean", {}).get("findings", 0), rid
    assert set(detail["rules"]) <= set(data["rules"])


def test_the_shares_deal_out_every_recording_and_every_part_of_a_large_machine_once(tmp_path):
    """--shard: the plan every share computes gives each recording to one share, and a clean machine
    larger than a share to several, each running its part of the rules."""
    M = _measure_tool()
    recs = []
    for i, size in enumerate([5, 40, 3, 12, 7]):
        f = tmp_path / f"r{i}.evtx"
        f.write_bytes(b"x" * size)
        recs.append(M.Recording("sigma", f"r{i}", [f], frozenset()))
    machines = []
    for name, size in (("big", 200), ("small", 20)):
        (tmp_path / name).mkdir()
        (tmp_path / name / "a.evtx").write_bytes(b"x" * size)
        machines.append(tmp_path / name)

    units = M.plan(recs, machines, 3)
    assert [(u.kind, u.ref, u.part, u.share) for u in units] == [(u.kind, u.ref, u.part, u.share) for u in M.plan(recs, machines, 3)]
    assert sorted(u.ref for u in units if u.kind == "recording") == list(range(5))
    big = [u for u in units if u.ref == "big"]
    assert len(big) > 1 and sorted(u.part for u in big) == list(range(big[0].parts)) and len({u.share for u in big}) == len(big)
    assert [u.parts for u in units if u.ref == "small"] == [1]
    assert {u.share for u in M.plan(recs, machines, 1)} == {1}


def test_the_merge_fails_unless_every_share_measured_all_it_was_dealt(tmp_path):
    M = _measure_tool()
    out = {"rows": 1, "unread": 0, "fired": [], "readable": [], "errors": []}
    machine = {"rows": 9, "unread": 0, "found": {"a": [1, 2]}, "scopes": {"a": 9}, "errors": []}

    def share(i: int, results: dict) -> Path:
        raw = {
            "share": i,
            "shares": 2,
            "units": [["recording", 0, 0, 1], ["machine", "m", 0, 2], ["machine", "m", 1, 2]],
            "recordings": [{"dataset": "sigma", "name": "r0", "techniques": [], "credit": ["x"], "owner": "x"}],
            "leftOut": {},
            "maxMb": 20,
            "results": results,
            "problems": [],
        }
        p = tmp_path / f"share-{i}.json"
        p.write_text(json.dumps(raw), encoding="utf-8")
        return p

    one = share(1, {"recordings": {"0": out}, "machines": {"m": {"0": machine}}})
    with pytest.raises(SystemExit, match="each of the 2 shares"):
        M.merge([one])
    two = share(2, {"recordings": {}, "machines": {}})
    with pytest.raises(SystemExit, match="machine m part 2"):
        M.merge([one, two])
    two = share(2, {"recordings": {}, "machines": {"m": {"1": {**machine, "found": {"b": [3, 3]}, "scopes": {"b": 4}}}}})
    recs, clean, _, _, problems = M.merge([one, two])
    assert recs[0].owner == "x" and recs[0].rows == 1 and not problems
    assert clean["m"]["found"] == {"a": [1, 2], "b": [3, 3]} and clean["m"]["scopes"] == {"a": 9, "b": 4}
