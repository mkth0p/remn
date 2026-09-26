"""The synthetic linked lab read as stories: one per victim, holding its scenario's records, and none of the planted controls."""

from __future__ import annotations

import json
import sys
import uuid
from collections import defaultdict
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import golden_corpus as G  # noqa: E402

from services.analysis import baseline  # noqa: E402
from services.analysis.mail_calibration import calibrate_mail  # noqa: E402
from services.analysis.stories import build_stories  # noqa: E402
from services.ingest.pipeline import EvtxSource, MailSource  # noqa: E402
from services.parsers.mail.common import ParseContext  # noqa: E402
from services.store.casestore import StoreRegistry  # noqa: E402
from services.store.rules import run_rules  # noqa: E402
from services.store.writers import EventWriter, MailWriter  # noqa: E402

ATTACKS = ("S01", "S02", "S03", "S04", "S06")


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    """The quick lab parsed, its mails calibrated, REMN's own rules run on it, and its ground truth by record."""
    tmp = tmp_path_factory.mktemp("lab")
    pack = G.generate_lab(tmp)
    manifest = json.loads((pack / "manifest.json").read_text())
    settings = {
        "internal_domains": manifest["settings"]["internalDomains"],
        "expected_countries": ["FR"],
        "internal_ips": ["10.0.0.0/8"],
        "service_accounts": manifest["settings"].get("serviceAccounts", []),
        "vip_names": ["marie lefevre"],
    }
    ctx = ParseContext(internal_domains=settings["internal_domains"], analyze_attachments=True)
    events: list[dict] = []
    mails: list[dict] = []
    for entry in manifest["files"]:
        path = pack / entry["path"]
        is_mail = entry["kind"] == "mail"
        src = MailSource(path.name, str(path), None, ctx, str(tmp)) if is_mail else EvtxSource(path.name, str(path), None, str(tmp))
        for n, row in enumerate(src, 1):
            row["_file"], row["_ordinal"] = path.name, n
            (mails if is_mail else events).append(row)
    for i, r in enumerate(events, 1):
        r["id"] = i
    for i, m in enumerate(mails, 1):
        m["id"] = i
    history = baseline.enrich(mails, settings)
    mails = [calibrate_mail({**m, **history.get(m["id"], {})}, settings) for m in mails]
    reg = StoreRegistry()
    reg.configure(tmp / "stores")
    store = reg.get(str(uuid.uuid4()))
    try:
        mw, ew = MailWriter(store, 1), EventWriter(store, 2)
        for m in mails:
            mw.add(dict(m))
        mw.flush()
        for e in events:
            ew.add(dict(e))
        ew.flush()
        rules = [
            r
            for folder in ("rules/mail", "rules/m365", "rules/windows")
            for f in (ROOT / folder).rglob("*.yaml")
            for r in yaml.safe_load_all(f.read_text(encoding="utf-8"))
            if isinstance(r, dict)
        ]
        result = run_rules(store, rules, settings)
        assert not result["errors"]
    finally:
        reg.close_all()
    where = {(r["_file"], r["_ordinal"]): f"event:{r['id']}" for r in events} | {(m["_file"], m["_ordinal"]): f"mail:{m['id']}" for m in mails}
    truth: dict[str, set[str]] = defaultdict(set)
    for line in (pack / "ground-truth.jsonl").read_text().splitlines():
        g = json.loads(line)
        truth[g["scenario"]].add(where[(g["file"], g["ordinal"])])
    victims = {s["id"]: s["victim"] for s in manifest["scenarios"]}
    return {"events": events, "mails": mails, "findings": result["findings"], "settings": settings, "truth": truth, "victims": victims}


def _refs(story: dict) -> set[str]:
    return {r for st in story["steps"] for r in st["refs"]}


def test_each_attack_is_one_story_of_its_victim_holding_its_records(lab):
    res = build_stories(lab["events"], lab["mails"], lab["findings"], lab["settings"])
    truth = lab["truth"]
    planted = set().union(*truth.values())
    for scen in ATTACKS:
        mine = [s for s in res["stories"] if s["kind"] == "person" and s["subject"]["label"] == lab["victims"][scen]]
        assert len(mine) == 1, (scen, [s["subject"]["label"] for s in res["stories"]])
        got = _refs(mine[0])
        recall = len(got & truth[scen]) / len(truth[scen])
        precision = len(got & truth[scen]) / len(got)
        assert recall >= 0.95 and precision >= 0.85, (scen, recall, precision)
        # nothing of another scenario, and little background
        assert not any(got & truth[other] for other in ATTACKS if other != scen), scen
        assert len(got - planted) <= 10, (scen, len(got - planted))
        assert mine[0]["severity"] == "critical"


def test_the_planted_controls_stay_out(lab):
    res = build_stories(lab["events"], lab["mails"], lab["findings"], lab["settings"])
    truth = lab["truth"]
    northstar = [s for s in res["stories"] if s["subject"].get("org") == "northstar.example"]
    # the other tenant's alice.martin is a story of her own, never part of a Northstar one
    assert not any(_refs(s) & truth["NEG-TENANT"] for s in northstar)
    [other] = [s for s in res["stories"] if _refs(s) & truth["NEG-TENANT"]]
    assert other["subject"]["label"] == "alice.martin@other-tenant.example"
    # the domain seen on Alice's host two weeks before is no part of any story
    assert not any(_refs(s) & truth["NEG-TIME"] for s in res["stories"])
    # the benign controls and the lure raise no story
    for scen in ("S05", "S07"):
        assert not any(_refs(s) & truth[scen] for s in res["stories"] if s["subject"]["label"] == lab["victims"][scen])


def test_s04_shows_the_session_the_hop_and_what_the_hosts_cannot_show(lab):
    res = build_stories(lab["events"], lab["mails"], lab["findings"], lab["settings"])
    [s04] = [s for s in res["stories"] if s["subject"]["label"] == lab["victims"]["S04"]]
    phases = [p["phase"] for p in s04["phases"]]
    assert {"initial-access", "credential-access", "execution", "persistence", "lateral-movement", "collection", "defense-impairment"} <= set(phases)
    [session] = [x for x in s04["lineage"]["sessions"] if x["rdp"]]
    assert session["host"] == "ws-004" and session["logonId"] == "0x9a01" and session["ip"] == "203.0.113.69"
    cleared = next(st for st in s04["steps"] if st["phase"] == "defense-impairment")
    assert cleared["session"] == session["id"]
    hops = {(h["kind"], h["to"]) for h in s04["lineage"]["hops"]}
    assert hops == {("rdp", "ws-004"), ("remote-service", "fs-001")}
    assert any(g.startswith("What ran on FS-001") for g in s04["gaps"])
    # without Sysmon, what ran on the victim's host is said to be out of reach
    no_sysmon = [e for e in lab["events"] if e["_file"] != "Sysmon.evtx"]
    [again] = [s for s in build_stories(no_sysmon, lab["mails"], lab["findings"], lab["settings"])["stories"] if s["subject"]["label"] == lab["victims"]["S04"]]
    assert any(g.startswith("What ran on WS-004") for g in again["gaps"])


def test_s04s_spine_runs_from_the_rdp_logon_through_its_session_to_the_service_on_fs_001(lab):
    res = build_stories(lab["events"], lab["mails"], lab["findings"], lab["settings"])
    [s04] = [s for s in res["stories"] if s["subject"]["label"] == lab["victims"]["S04"]]
    [session] = [x for x in s04["lineage"]["sessions"] if x["rdp"]]
    spine = [st for st in s04["steps"] if st["id"] in s04["spine"]]
    assert [st["id"] for st in spine] == s04["spine"] and len(spine) <= 15
    at = {st["id"]: i for i, st in enumerate(spine)}
    # anchored on the log cleared in the RDP session, whose ties lead back to the phishing mail
    cleared = next(st for st in spine if st["phase"] == "defense-impairment")
    basis = s04["spineBasis"]
    assert cleared["session"] == session["id"] and basis["anchor"] == cleared["id"] and basis["tied"] and basis["wayIn"][0].startswith("mail:")
    # the RDP logon, then the log cleared and the credential access, the admin share and the service on FS-001
    rdp = at[session["logonRef"]]
    share = next(i for i, st in enumerate(spine) if st["host"] == "fs-001" and st["phase"] == "lateral-movement")
    service = next(i for i, st in enumerate(spine) if st["host"] == "fs-001" and st["phase"] == "persistence")
    access = [i for i, st in enumerate(spine) if st["phase"] == "credential-access"]
    assert rdp < at[cleared["id"]] and rdp < share < service and access and min(access) > rdp
    # not the password spray before the way in, nor Daniel's own sign-ins from his usual address
    assert not any(st["ip"] == "198.51.100.10" for st in spine)
    assert len(s04["steps"]) - len(spine) >= 10
