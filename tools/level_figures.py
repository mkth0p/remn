#!/usr/bin/env python
"""
The detection level figures the app shows, from the committed rule measure.

    .venv/bin/python tools/level_figures.py

Writes frontend/src/data/detectionLevels.gen.json: for each level of frontend/src/data/detectionLevel.ts,
the findings on their own and the lines per clean machine that tools/detection_levels.py computes (the
table of docs/detection.md), the same for every medium and higher finding on its own, and the measure and
machines they were counted on. The level picker and the home page read the file, so run this script after
a measure is taken, a rule's severity changes or a level's budget moves; tests/backend/test_level_figures.py
fails until it is run.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import detection_levels

OUT = ROOT / "frontend" / "src" / "data" / "detectionLevels.gen.json"


def _whole(x: float) -> int:
    # rounded half up, as the table of docs/detection.md rounds them
    return int(math.floor(x + 0.5))


def figures() -> dict[str, Any]:
    t, _ = detection_levels.compute()
    measures = json.loads((ROOT / "rules" / "measures.json").read_text(encoding="utf-8"))
    return {
        "measured": measures["measured"],
        "machines": t["machines"],
        "levels": [{"level": r["level"], "alone": _whole(r["alone"]), "lines": _whole(r["lines"])} for r in t["rows"]],
        "mediumUp": _whole(t["mediumUp"]),
        "fewerLines": t["fewerLines"],
    }


def main() -> None:
    OUT.write_text(json.dumps(figures(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
