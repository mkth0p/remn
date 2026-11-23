#!/usr/bin/env python
"""
The detection level table of docs/detection.md, from the committed rule measures.

    .venv/bin/python tools/detection_levels.py

For each level of frontend/src/data/detectionLevel.ts, the findings that stand on their own and the
lines an analyst reads (those findings, plus one per rule folded on a host) per clean machine of the
rule measure, averaged over its machines. It reads rules/measures.json and rules/measures-detail.json
(each rule's findings on each clean machine), the rules a new case enables (REMN's own event rules
and the SigmaHQ packs on by default) at their current severities, and the budgets of the levels.

A rule's noise is taken as the app takes it ((findings + 0.5) per clean machine that logs what it
reads), but from the six other machines when the lines of one are counted, so no machine's lines
are judged by its own findings. A rule changed since it was measured, or one that needs a case
setting, counts as unmeasured, as in the app. A finding is counted at its rule's severity; a
follow-up that escalates one on a clean machine is not seen here.
"""

from __future__ import annotations

import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
# the rule loaders read the rules folder from the settings; the apps are not started, so nothing runs
# beside the script
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "forensic.settings")

from api.views.meta import load_rules  # noqa: E402
from services.rules import measures as measures_mod  # noqa: E402
from services.rules import packs  # noqa: E402

LEVELS_TS = ROOT / "frontend" / "src" / "data" / "detectionLevel.ts"
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def levels(text: str | None = None) -> dict[str, Any]:
    """The levels, the default level and the unmeasured floor, read from detectionLevel.ts so the
    table is computed with the budgets the app uses."""
    text = LEVELS_TS.read_text(encoding="utf-8") if text is None else text
    block = text[text.index("export const DETECTION_LEVELS") :]
    block = block[: block.index("\n]\n")]
    out = []
    for entry in re.split(r"\n  \{", block)[1:]:
        level = int(re.search(r"\blevel: (\d)", entry).group(1))
        label = re.search(r"\blabel: '([^']*)'", entry).group(1)
        budget_text = re.search(r"\bbudget: ([\d.]+|Infinity)", entry).group(1)
        always = re.search(r"\balways: (\d)", entry)
        out.append(
            {
                "level": level,
                "label": label,
                "budget": math.inf if budget_text == "Infinity" else float(budget_text),
                "always": int(always.group(1)) if always else None,
            }
        )
    return {
        "levels": out,
        "default": int(re.search(r"DEFAULT_DETECTION_LEVEL: DetectionLevel = (\d)", text).group(1)),
        "unmeasured": int(re.search(r"UNMEASURED_FLOOR = (\d)", text).group(1)),
        "never": int(re.search(r"export const NEVER = (\d)", text).group(1)),
    }


def severity_floor(level: dict[str, Any], noise: float | None, unmeasured: int, never: int) -> int:
    """severityFloor of detectionLevel.ts, for a bundled or pack rule."""
    always = never if level["always"] is None else level["always"]
    if level["budget"] == math.inf:
        return 0
    if noise is None:
        return min(unmeasured, always)
    s = max(0, math.ceil(2 + math.log2(noise / level["budget"]) - 1e-9))
    return min(never if s > 4 else s, always)


def default_rules() -> dict[str, dict[str, Any]]:
    """The event rules a new case enables, by id: REMN's own and those of the packs on by default."""
    out = {}
    for entry in load_rules(ROOT / "rules"):
        rule = entry.get("rule")
        if rule and rule.get("source", "events") == "events" and rule.get("enabled") is not False:
            out[rule["id"]] = rule
    for manifest in packs.list_packs():
        if not manifest.get("defaultEnabled") or manifest.get("source") != "events":
            continue
        for item in packs.load_pack(manifest["id"])["rules"]:
            rule = item.get("rule")
            if rule and rule.get("enabled") is not False:
                out[rule["id"]] = rule
    return out


def table(measures: dict[str, Any], detail: dict[str, Any], rules: dict[str, dict[str, Any]], lv: dict[str, Any]) -> dict[str, Any]:
    machines = measures["sources"]["baseline"]["machines"]
    rows = []
    for level in lv["levels"]:
        alone = lines = 0
        for rid, rule in rules.items():
            m = measures["rules"].get(rid)
            per_machine = (detail["rules"].get(rid) or {}).get("clean") or {}
            measured = m is not None and "settings" not in m and m["h"] == measures_mod.logic_hash(rule) and (m.get("clean") or {}).get("of")
            rank = RANK.get(str(rule.get("severity")), RANK["medium"])
            for count in per_machine.values():
                if not count:
                    continue
                noise = None
                if measured and m["clean"]["of"] > 1:
                    noise = (m["clean"]["findings"] - count + 0.5) / (m["clean"]["of"] - 1)
                if rank >= severity_floor(level, noise, lv["unmeasured"], lv["never"]):
                    alone += count
                    lines += count
                else:
                    lines += 1
        rows.append({**level, "alone": alone / machines, "lines": lines / machines})
    medium_up = 0
    for rid, rule in rules.items():
        if RANK.get(str(rule.get("severity")), RANK["medium"]) >= RANK["medium"]:
            medium_up += sum(((detail["rules"].get(rid) or {}).get("clean") or {}).values())
    default = next(r for r in rows if r["level"] == lv["default"])
    return {
        "rows": rows,
        "mediumUp": medium_up / machines,
        "machines": machines,
        "fewerLines": round(100 * (1 - default["lines"] / (medium_up / machines))),
    }


def _whole(x: float) -> int:
    return int(math.floor(x + 0.5))


def _budget(level: dict[str, Any]) -> str:
    if level["budget"] == math.inf:
        return "none"
    text = f"{level['budget']:g}"
    return text + (", and medium and up" if level["always"] == RANK["medium"] else "")


def markdown(t: dict[str, Any], default: int) -> str:
    lines = [
        "| level | medium budget | findings on their own per clean machine | lines per clean machine |",
        "|---|---|---|---|",
    ]
    for r in t["rows"]:
        name, alone, read = f"{r['level']}, {r['label']}", str(_whole(r["alone"])), str(_whole(r["lines"]))
        if r["level"] == default:
            name, alone, read = f"**{name} (a new case)**", f"**{alone}**", f"**{read}**"
        lines.append(f"| {name} | {_budget(r)} | {alone} | {read} |")
    lines.append(f"| medium and up, nothing else | | {_whole(t['mediumUp'])} | {_whole(t['mediumUp'])} |")
    return "\n".join(lines)


def compute() -> tuple[dict[str, Any], str]:
    measures = json.loads((ROOT / "rules" / "measures.json").read_text(encoding="utf-8"))
    detail = json.loads((ROOT / "rules" / "measures-detail.json").read_text(encoding="utf-8"))
    lv = levels()
    t = table(measures, detail, default_rules(), lv)
    return t, markdown(t, lv["default"])


def main() -> None:
    t, text = compute()
    print(text)
    print()
    print(f"The default level has {t['fewerLines']}% fewer lines on a clean machine than raising every medium and higher finding on its own.")


if __name__ == "__main__":
    main()
