"""tools/head_to_head.py: a file counts for a tool when a rule of the file's technique fires on it, at the same level cut for every tool."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("head_to_head", ROOT / "tools" / "head_to_head.py")
h2h = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h2h)

SPRAY = "TA0006-Credential Access/T1110.xxx-Brut force/ID4771-Kerberos spraying.evtx"
CLEARED = "TA0005-Defense Evasion/T1070.001-Clear Windows event logs/ID1102-Security log cleared.evtx"
CHAIN = "EVTX_full_APT_attack_steps/ID4688-a whole attack.evtx"


def _library(tmp_path: Path) -> Path:
    lib = tmp_path / "lib"
    for rel in (SPRAY, CLEARED, CHAIN):
        (lib / rel).parent.mkdir(parents=True, exist_ok=True)
        (lib / rel).write_bytes(b"")
    return lib


def test_each_file_takes_the_technique_of_its_folder(tmp_path):
    truth, apart = h2h.labels(_library(tmp_path), "folders", {})
    assert truth[SPRAY] == {"T1110"}
    # a revoked ATT&CK v19 id is read as its successor, on the label as on the rules
    assert truth[CLEARED] == h2h.techniques(["T1070.001"]) != {"T1070.001"}
    assert apart == [CHAIN]


def test_a_rule_of_the_technique_counts_at_or_above_the_level_cut(tmp_path):
    lib = _library(tmp_path)
    truth, apart = h2h.labels(lib, "folders", {})
    out = tmp_path / "remn"
    out.mkdir()
    rules = [
        {"id": "spray", "title": "Kerberos spraying", "severity": "low", "attack": ["T1110.003"]},
        {"id": "logon", "title": "Logon", "severity": "high", "attack": ["T1078"]},
    ]
    (out / "rules.json").write_text(json.dumps({"default": rules, "hunting": []}))
    (out / "sql.json").write_text(json.dumps({SPRAY: {"default": {"spray": ["k1", "k2"], "logon": ["k3"]}}}))
    alerts = h2h.remn(out, ("default",))
    # a sub-technique of the label counts; a rule of another technique does not
    anylevel = h2h.score("REMN", alerts, truth, apart, 0)
    assert anylevel["detected"] == 1 and anylevel["hit"] == {SPRAY: ["Kerberos spraying"]} and anylevel["alerts"] == 3
    medium = h2h.score("REMN", alerts, truth, apart, 2)
    assert medium["detected"] == 0 and medium["anyAlert"] == 1
    # a rule written after studying the library is left out of its score
    skipped = h2h.score("REMN", h2h.remn(out, ("default",), skip=frozenset({"spray"})), truth, apart, 0)
    assert skipped["detected"] == 0 and skipped["alerts"] == 1


def test_rules_written_against_a_dataset_exist_and_name_a_measured_source():
    import yaml

    ids = {d["id"] for p in (ROOT / "rules").rglob("*.yaml") for d in yaml.safe_load_all(p.read_text(encoding="utf-8")) if isinstance(d, dict) and d.get("id")}
    assert h2h.WRITTEN_AGAINST
    for rid, datasets in h2h.WRITTEN_AGAINST.items():
        assert rid in ids, rid
        assert datasets and datasets <= {"sigma", "attackSamples", "attackData", "evtxToMitre"}, rid


def test_hayabusa_hunting_rules_and_chainsaw_aggregates_and_own_rules(tmp_path):
    lib = _library(tmp_path)
    truth, apart = h2h.labels(lib, "folders", {})
    hay = tmp_path / "hayabusa.jsonl"
    hay.write_text(
        "\n".join(
            json.dumps({"EvtxFile": str(lib / SPRAY), "RuleID": rid, "RuleTitle": rid, "Level": "med", "MitreTags": ["T1110.003"]}) for rid in ("spray", "hunt")
        )
    )
    assert h2h.score("H", h2h.hayabusa(hay, lib), truth, apart, 2)["alerts"] == 2
    assert h2h.score("H", h2h.hayabusa(hay, lib, {"hunt"}), truth, apart, 2)["alerts"] == 1
    cs = tmp_path / "chainsaw.json"
    cs.write_text(
        json.dumps(
            [
                # Chainsaw's own rule: no tags, a technique only through the title map
                {
                    "kind": "individual",
                    "group": "Log Tampering",
                    "name": "Security Audit Logs Cleared",
                    "level": "critical",
                    "document": {"path": str(lib / CLEARED)},
                },
                # an aggregate over two files counts once on each
                {
                    "kind": "aggregate",
                    "group": "Sigma",
                    "name": "Burst",
                    "level": "high",
                    "tags": ["attack.t1110"],
                    "documents": [{"path": str(lib / SPRAY)}, {"path": str(lib / SPRAY)}, {"path": str(lib / CLEARED)}],
                },
            ]
        )
    )
    tagged = h2h.score("C", h2h.chainsaw(cs, lib, h2h.CHAINSAW_OWN), truth, apart, 2)
    assert tagged["detected"] == 2 and tagged["alerts"] == 3
    assert h2h.score("C", h2h.chainsaw(cs, lib, {}), truth, apart, 2)["detected"] == 1
