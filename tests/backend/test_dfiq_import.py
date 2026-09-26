"""The Questions page's catalog: DFIQ scenarios with REMN's hints, and REMN's own scenarios."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("dfiq_import", ROOT / "tools" / "dfiq_import.py")
X = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(X)


def _write(folder: Path, doc: dict) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{doc['id']}.yaml").write_text("# licence header\n---\n" + yaml.safe_dump(doc), encoding="utf-8")


@pytest.fixture
def release(tmp_path: Path) -> Path:
    data = tmp_path / "dfiq" / "data"
    _write(
        data / "scenarios",
        {"id": "S1008", "type": "scenario", "display_name": "Lateral Movement", "description": "Moving >\n  between hosts.", "tags": ["TA0008", "Windows"]},
    )
    _write(data / "scenarios", {"id": "S1009", "type": "scenario", "display_name": "Not wanted"})
    _write(data / "facets", {"id": "F1027", "type": "facet", "display_name": "Moving FROM this host?", "parent_ids": ["S1008"], "tags": ["TA0008"]})
    _write(data / "facets", {"id": "F1099", "type": "facet", "display_name": "Only macOS here", "parent_ids": ["S1008"]})
    _write(
        data / "questions",
        {
            "id": "Q1036",
            "type": "question",
            "display_name": "Have there been any executions of PsExec?",
            "parent_ids": ["F1027"],
            "tags": ["Windows", "T1569.002"],
        },
    )
    _write(
        data / "questions",
        {"id": "Q1053", "type": "question", "display_name": "What Launch Agents are configured?", "parent_ids": ["F1099"], "tags": ["macOS"]},
    )
    _write(
        data / "approaches",
        {
            "id": "Q1036.10",
            "type": "approach",
            "display_name": "Prefetch",
            "description": {"summary": "Look at Prefetch."},
            "view": {"notes": {"covered": ["Windows clients"], "not_covered": ["Servers, where Prefetch is off"]}},
        },
    )
    meta = tmp_path / "dfiq-1.0.1.dist-info"
    meta.mkdir()
    (meta / "METADATA").write_text("Name: dfiq\nVersion: 1.0.1\n", encoding="utf-8")
    return tmp_path


OVERLAY = {
    "include": {"scenarios": ["S1008"]},
    "evidence": {
        "security": {"label": "Security log", "channels": ["Security"]},
        "sysmon": {"label": "Sysmon log", "channels": ["Microsoft-Windows-Sysmon/Operational"]},
    },
    "questions": {
        "Q1036": {
            "evidence": ["sysmon", "security"],
            "attack": ["T1021.002"],
            "search": {"source": "events", "label": "PsExec run", "filter": {"conditions": [{"field": "image", "op": "contains", "value": "psexec"}]}},
        }
    },
    "scenarios": [
        {
            "id": "S0001",
            "name": "Dwell time",
            "facets": [
                {
                    "id": "F0001",
                    "name": "First activity?",
                    "questions": [{"id": "Q0001", "name": "Earliest activity?", "evidence": ["security"], "derived": "first-activity"}],
                }
            ],
        }
    ],
}


def test_imports_the_chosen_scenarios_with_remn_hints_and_leaves_out_the_rest(release: Path):
    data = X.find_data(release)
    assert X.dfiq_version(release) == "1.0.1"
    c = X.build(X.load_dfiq(data), OVERLAY, "1.0.1")
    assert [s["id"] for s in c["scenarios"]] == ["S1008", "S0001"]
    lateral = c["scenarios"][0]
    assert lateral == {
        "id": "S1008",
        "origin": "dfiq",
        "name": "Lateral Movement",
        "description": "Moving > between hosts.",
        "tags": ["Windows"],
        "attack": ["TA0008"],
        "facets": ["F1027"],
    }
    q = next(q for q in c["questions"] if q["id"] == "Q1036")
    assert q["attack"] == ["T1569.002", "T1021.002"]
    assert q["evidence"] == ["sysmon", "security"]
    assert q["searches"][0]["label"] == "PsExec run"
    assert q["approaches"] == [
        {"id": "Q1036.10", "name": "Prefetch", "summary": "Look at Prefetch.", "covered": ["Windows clients"], "notCovered": ["Servers, where Prefetch is off"]}
    ]
    # a question without hints goes, and the facet left empty with it
    assert c["skipped"] == [{"id": "Q1053", "name": "What Launch Agents are configured?"}]
    assert "F1099" not in [f["id"] for f in c["facets"]]
    own = next(q for q in c["questions"] if q["id"] == "Q0001")
    assert own["origin"] == "remn" and own["derived"] == "first-activity"
    assert json.loads(X.render(c)) == c


def test_refuses_hints_that_name_unknown_evidence_or_ids_outside_the_private_range(release: Path):
    dfiq = X.load_dfiq(X.find_data(release))
    bad = json.loads(json.dumps(OVERLAY))
    bad["questions"]["Q1036"]["evidence"] = ["browser"]
    with pytest.raises(SystemExit, match="evidence"):
        X.build(dfiq, bad, "1.0.1")
    bad = json.loads(json.dumps(OVERLAY))
    bad["scenarios"][0]["id"] = "S2001"
    with pytest.raises(SystemExit, match="starting with S0"):
        X.build(dfiq, bad, "1.0.1")
    bad = json.loads(json.dumps(OVERLAY))
    bad["questions"]["Q1036"]["search"]["source"] = "files"
    with pytest.raises(SystemExit, match="search"):
        X.build(dfiq, bad, "1.0.1")


def test_the_bundled_catalog_follows_the_remn_layer():
    """The generated file is committed (the DFIQ release is not): it must carry what tools/dfiq_remn.yaml says now."""
    overlay = X.load_overlay()
    catalog = json.loads(X.OUT.read_text(encoding="utf-8"))
    assert catalog["evidence"] == overlay["evidence"]
    questions = {q["id"]: q for q in catalog["questions"]}
    for qid, hint in overlay["questions"].items():
        assert qid in questions, f"{qid}: run tools/dfiq_import.py"
        expected = X._hints(hint, overlay["evidence"], qid)
        got = questions[qid]
        assert {k: got.get(k) for k in ("evidence", "ruleTags", "searches", "note", "derived")} == {
            k: expected.get(k) for k in ("evidence", "ruleTags", "searches", "note", "derived")
        }, qid
        assert set(expected["attack"]) <= set(got["attack"]), qid
    own = [s for s in catalog["scenarios"] if s["origin"] == "remn"]
    assert [s["id"] for s in own] == [s["id"] for s in overlay["scenarios"]]
    for s in overlay["scenarios"]:
        for f in s["facets"]:
            for q in f["questions"]:
                assert questions[q["id"]]["name"] == X._text(q["name"])
                assert questions[q["id"]]["evidence"] == q["evidence"]
