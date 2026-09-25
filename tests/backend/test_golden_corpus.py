"""The golden corpus: what the parsers make of the synthetic lab changes only when someone meant it to.

tools/golden_corpus.py regenerates the lab (byte for byte the same on every run), parses it as an
upload is parsed and compares every row with the frozen one. A parser change that alters rows fails
here with the file, the number of rows that differ and the first of them; if the change is intended,
review it and freeze the new rows with tools/golden_corpus.py --write.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("golden_corpus", ROOT / "tools" / "golden_corpus.py")
G = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(G)


def test_the_parsers_make_of_the_lab_what_the_golden_corpus_froze(tmp_path):
    lab = G.generate_lab(tmp_path)
    diff = G.differences(G.load(), G.build(lab), lab)
    assert not diff, "\n".join(diff) + "\nIf the change is intended, review it and run tools/golden_corpus.py --write"


def test_a_changed_row_is_named_and_a_changed_lab_is_not_blamed_on_a_parser():
    golden = G.load()
    assert {n: f["rows"] for n, f in golden["files"].items()} == {
        "Mailboxes.mbox": 1000,
        "Security.evtx": 6000,
        "Sysmon.evtx": 3000,
        "PowerShell.evtx": 800,
        "System.evtx": 190,
        "Defender.evtx": 10,
        "M365-UnifiedAuditLog.csv": 2000,
        "M365-EntraSignIns.jsonl": 2000,
    }
    now = json.loads(json.dumps(golden))
    security = now["files"]["Security.evtx"]
    security["rowDigests"][3] = "0" * 16
    security["sha256"] = "changed"
    now["files"]["System.evtx"]["input"] = "another lab"
    assert G.differences(golden, now) == [
        "Security.evtx: 6000 rows frozen, 6000 now; 1 row(s) differ, first at row 3",
        "System.evtx: the lab file itself changed (the generator, not a parser)",
    ]
