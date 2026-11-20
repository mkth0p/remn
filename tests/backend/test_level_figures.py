"""The detection level figures the app shows are the ones tools/detection_levels.py computes from the committed
rule measure: tools/level_figures.py writes them to frontend/src/data/detectionLevels.gen.json, and the level
picker and the home page read that file. A measure taken, a rule's severity changed or a budget moved without
running the script fails here; so does a figure typed into the app by hand.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import level_figures


def test_the_app_level_figures_are_the_ones_the_committed_measure_gives():
    committed = json.loads(level_figures.OUT.read_text(encoding="utf-8"))
    assert committed == level_figures.figures(), "run tools/level_figures.py"


def test_the_app_reads_its_level_figures_from_the_generated_file():
    text = (ROOT / "frontend" / "src" / "data" / "detectionLevel.ts").read_text(encoding="utf-8")
    assert "from './detectionLevels.gen.json'" in text
    # a figure typed into a level would stand beside the file's and go stale with the next measure
    assert not re.search(r"(alone|perCleanMachine): \d", text)


def test_the_figures_name_the_measure_and_every_level():
    f = level_figures.figures()
    measures = json.loads((ROOT / "rules" / "measures.json").read_text(encoding="utf-8"))
    assert f["measured"] == measures["measured"]
    assert f["machines"] == measures["sources"]["baseline"]["machines"]
    assert [row["level"] for row in f["levels"]] == [1, 2, 3, 4, 5]
    assert all(row["lines"] >= row["alone"] for row in f["levels"])


def test_the_level_table_of_the_detection_page_quotes_the_same_figures():
    text = (ROOT / "docs" / "detection.md").read_text(encoding="utf-8")
    f = level_figures.figures()
    rows = {
        int(m.group(1)): (int(m.group(2)), int(m.group(3))) for m in re.finditer(r"^\| \**(\d), [^|]*\| [^|]*\| \**(\d+)\** \| \**(\d+)\** \|$", text, re.M)
    }
    assert rows == {row["level"]: (row["alone"], row["lines"]) for row in f["levels"]}
    assert f"| medium and up, nothing else | | {f['mediumUp']} | {f['mediumUp']} |" in text
    assert f"The default level has {f['fewerLines']}% fewer lines" in re.sub(r"\s+", " ", text)
