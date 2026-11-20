"""The figures the pages quote from what the repository holds, beyond the sentences test_quoted_measures.py
reads in README.md and docs/detection.md: the measure's figures wherever another page quotes them, the size
of each community pack and of its level changes, the number of rules a file ships, the detection level
table of docs/detection.md, which tools/detection_levels.py computes from the committed measure, and the
rules and limits of the browser's regex timing test that docs/rules.md names. A pack refreshed, a rule
added or a measure taken without the pages fails here; so does a figure edited by hand.
"""

from __future__ import annotations

import collections
import json
import math
import re
import sys
from pathlib import Path

import pytest
import test_quoted_measures as quoted
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMMUNITY = ROOT / "rules" / "community"

# (page, sentence with one group per figure, the figure each group is) - other pages quoting the measure
QUOTED: list[tuple[str, str, tuple[str, ...]]] = [
    ("docs/faq.md", r"on (\w+) public sets of recorded attacks and on the logs of (\w+) clean Windows machines", ("libraries", "machines")),
    ("docs/faq.md", r"([\d,]+) of the ([\d,]+) event rules measured fire on a recording of what they look for", ("detect", "rules")),
    ("docs/validation.md", r"EVTX-ATTACK-SAMPLES, ([\d,]+) public logs of one attack technique each", ("recordings attackSamples",)),
    ("docs/validation.md", r"\| EVTX-ATTACK-SAMPLES \| ([\d,]+) small \.evtx files at the commit measured", ("recordings attackSamples",)),
    ("docs/validation.md", r"\| EVTX-to-MITRE-Attack \| ([\d,]+) \.evtx files at the commit measured", ("recordings evtxToMitre",)),
    (
        "docs/validation.md",
        r"the rule measure reads ([\d,]+) of them at the commit measured \(`7a5e9d5`\), leaving out ([\d,]+) larger than ([\d,]+) MB and ([\d,]+) whose",
        ("recordings attackDataWindows", "overSize attackDataWindows", "maxMb attackDataWindows", "missing attackDataWindows"),
    ),
]


def _page(name: str) -> str:
    # one line, so a sentence wrapped anywhere in the source still reads as one
    return re.sub(r"\s+", " ", (ROOT / name).read_text(encoding="utf-8"))


def _pages() -> dict[str, str]:
    # the dated reviews under docs/reviews/ quote the measures of their day and are left as written
    names = ["README.md", "SECURITY.md", "CONTRIBUTING.md", *(p.relative_to(ROOT).as_posix() for p in sorted((ROOT / "docs").glob("*.md")))]
    return {name: _page(name) for name in names}


def _quote_mismatches(pages: dict[str, str], fig: dict, quotes: list[tuple[str, str, tuple[str, ...]]]) -> list[str]:
    out = []
    for page, pattern, keys in quotes:
        m = re.search(pattern, pages[page])
        if not m:
            out.append(f"{page}: no longer says {pattern!r}; update the page or this test's list")
            continue
        for group, key in zip(m.groups(), keys, strict=True):
            if quoted._value(group) != fig[key]:
                out.append(f"{page}: says {group} where the repository gives {key} = {fig[key]}")
    return out


@pytest.fixture(scope="module")
def committed() -> dict:
    fig = quoted.figures(quoted._load("measures.json"), quoted._load("measures-detail.json"), quoted.off_by_default())
    fig["libraries"] = sum(1 for key in fig if key.startswith("recordings "))
    return fig


def pack_figures() -> dict[str, int | bool]:
    out: dict[str, int | bool] = {}
    for manifest in sorted(COMMUNITY.glob("*/pack.json")):
        pack = json.loads(manifest.read_text(encoding="utf-8"))
        out[f"converted {pack['id']}"] = pack["counts"]["converted"]
        out[f"upstream {pack['id']}"] = pack["counts"]["upstream"]
        out[f"on {pack['id']}"] = bool(pack.get("defaultEnabled"))
    sigma = [p.parent.name for p in COMMUNITY.glob("sigma-*/pack.json")]
    out["converted sigma"] = sum(int(out[f"converted {p}"]) for p in sigma)
    out["upstream sigma"] = sum(int(out[f"upstream {p}"]) for p in sigma)
    levels = json.loads((COMMUNITY / "levels.json").read_text(encoding="utf-8"))["levels"].values()
    moves = collections.Counter((e["upstream"], e["severity"]) for e in levels)
    out["level changes"] = sum(moves.values())
    out["low to medium"] = moves[("low", "medium")]
    out["medium to low"] = moves[("medium", "low")]
    out["high to low"] = moves[("high", "low")]
    return out


PACK_QUOTES: list[tuple[str, str, tuple[str, ...]]] = [
    ("README.md", r"from ([\d,]+) of Sublime Security's ([\d,]+) mail rules", ("converted sublime", "upstream sublime")),
    ("THIRD_PARTY_NOTICES.md", r"\| ([\d,]+) of ([\d,]+) rules converted\. When a pack loads", ("converted sigma", "upstream sigma")),
    (
        "THIRD_PARTY_NOTICES.md",
        r"the level of ([\d,]+) rules is changed \(([\d,]+) raised from low to medium, ([\d,]+) lowered from medium and ([\d,]+) from high to low\)",
        ("level changes", "low to medium", "medium to low", "high to low"),
    ),
    ("THIRD_PARTY_NOTICES.md", r"\| MIT \| ([\d,]+) of ([\d,]+) rules converted \|", ("converted sublime", "upstream sublime")),
]
# a row of the community pack table of docs/detection.md: | `sigma-windows` | ... | 2,387 of 2,410 | on |
PACK_ROW = re.compile(r"^\| `([a-z0-9-]+)` \| [^|]+ \| ([\d,]+) of ([\d,]+) \| (on|off)\b", re.M)


def pack_table_mismatches(text: str, fig: dict[str, int | bool]) -> list[str]:
    out = []
    rows = {m.group(1): m for m in PACK_ROW.finditer(text)}
    packs = {key.split(" ", 1)[1] for key in fig if key.startswith("on ")}
    out += [f"docs/detection.md: the pack {p} has no row in the table of community packs" for p in sorted(packs - rows.keys())]
    out += [f"docs/detection.md: the table of community packs has a row for {p}, which is no pack" for p in sorted(rows.keys() - packs)]
    for pid in sorted(packs & rows.keys()):
        m = rows[pid]
        said = (quoted._value(m.group(2)), quoted._value(m.group(3)), m.group(4) == "on")
        real = (fig[f"converted {pid}"], fig[f"upstream {pid}"], fig[f"on {pid}"])
        if said != real:
            out.append(f"docs/detection.md: {pid} is given as {said} (converted, upstream, on), its pack.json says {real}")
    return out


def rule_count(path: str) -> int:
    return sum(1 for doc in yaml.safe_load_all((ROOT / path).read_text(encoding="utf-8")) if isinstance(doc, dict) and doc.get("id"))


RULE_COUNT_QUOTES = [
    ("docs/detection.md", r"the ([\d,]+) business email compromise rules over Microsoft 365", "rules/m365/bec.yaml"),
    ("docs/sources.md", r"`rules/m365/bec\.yaml` ships ([\d,]+) rules", "rules/m365/bec.yaml"),
]


def _detection_levels():
    sys.path.insert(0, str(ROOT / "tools"))
    import detection_levels

    return detection_levels


def level_table_mismatches(text: str, table: str, fewer: int) -> list[str]:
    """The table of docs/detection.md under "Detection level", and the share of fewer lines it gives."""
    out = []
    start = text.find("| level | medium budget |")
    said = text[start : text.find("\n\n", start)].strip() if start >= 0 else ""
    if said != table:
        out.append("docs/detection.md: the detection level table is not the one tools/detection_levels.py prints:\n" + table)
    m = re.search(r"The default level has (\d+)% fewer lines", re.sub(r"\s+", " ", text))
    if not m or int(m.group(1)) != fewer:
        out.append(f"docs/detection.md: the default level has {fewer}% fewer lines than every medium and higher finding on its own")
    return out


def test_the_pages_quote_the_figures_of_the_committed_measure(committed):
    pages = _pages()
    # the sentences of README.md and docs/detection.md, then any "N of M" of a library or rule count on every page
    assert quoted.mismatches(pages, committed) == []
    assert _quote_mismatches(pages, committed, QUOTED) == []


def test_a_figure_of_the_measure_on_another_page_is_caught(committed):
    pages = _pages()
    stale = dict(pages)
    stale["docs/faq.md"] = pages["docs/faq.md"].replace(f"{committed['detect']:,} of the", "1,019 of the")
    assert any("1,019" in line for line in _quote_mismatches(stale, committed, QUOTED))
    stale["docs/validation.md"] = pages["docs/validation.md"] + " The rules detect 109 of 279 files."
    assert any("'109 of 279'" in line for line in quoted.mismatches(stale, committed))


def test_the_pack_sizes_the_pages_quote_are_those_of_the_packs():
    fig = pack_figures()
    pages = {name: _page(name) for name in ("README.md", "THIRD_PARTY_NOTICES.md")}
    assert _quote_mismatches(pages, fig, PACK_QUOTES) == []
    assert pack_table_mismatches((ROOT / "docs" / "detection.md").read_text(encoding="utf-8"), fig) == []


def test_a_pack_refreshed_without_the_pages_is_caught():
    fig = dict(pack_figures())
    text = (ROOT / "docs" / "detection.md").read_text(encoding="utf-8")
    fig["converted sigma-windows"] = int(fig["converted sigma-windows"]) + 1
    fig["on sublime"] = False
    found = pack_table_mismatches(text, fig)
    assert any(line.startswith("docs/detection.md: sigma-windows is given as") for line in found)
    assert any(line.startswith("docs/detection.md: sublime is given as") for line in found)
    fig["on sigma-new-pack"] = True
    assert "docs/detection.md: the pack sigma-new-pack has no row in the table of community packs" in pack_table_mismatches(text, fig)


def test_the_rule_counts_the_pages_quote_are_those_of_the_rule_files():
    wrong = []
    for page, pattern, path in RULE_COUNT_QUOTES:
        m = re.search(pattern, _page(page))
        assert m, f"{page} no longer says {pattern!r}; update the page or this test's list"
        if quoted._value(m.group(1)) != rule_count(path):
            wrong.append(f"{page}: says {m.group(1)} rules in {path}, which holds {rule_count(path)}")
    assert wrong == []


def test_the_detection_level_table_is_the_one_the_script_computes():
    t, table = _detection_levels().compute()
    assert level_table_mismatches((ROOT / "docs" / "detection.md").read_text(encoding="utf-8"), table, t["fewerLines"]) == []


def test_a_level_table_edited_by_hand_is_caught():
    t, table = _detection_levels().compute()
    text = (ROOT / "docs" / "detection.md").read_text(encoding="utf-8")
    edited = text.replace(table, table + "\n| 6, more | none | 1 | 1 |")
    assert any("is not the one tools/detection_levels.py prints" in line for line in level_table_mismatches(edited, table, t["fewerLines"]))
    assert any("fewer lines" in line for line in level_table_mismatches(text, table, t["fewerLines"] + 1))


def test_the_level_budgets_are_read_from_the_app():
    lv = _detection_levels().levels()
    budgets = [level["budget"] for level in lv["levels"]]
    assert [level["level"] for level in lv["levels"]] == [1, 2, 3, 4, 5]
    # the levels nest only when each budget is at least the one below it
    assert budgets == sorted(budgets) and budgets[-1] == math.inf
    assert lv["default"] in {level["level"] for level in lv["levels"]}
    assert any(level["always"] is not None for level in lv["levels"])


TIMING_TEST = ROOT / "frontend" / "src" / "test" / "regexTiming.test.ts"


def timing_mismatches(page: str, timing: str) -> list[str]:
    """docs/rules.md against the browser's timing test: the rules it leaves as they are, the length of
    the value it tries and the time it allows."""
    out = []
    block = timing[timing.index("const RULE_EXEMPT") :]
    # the object ends at its first closing brace, which may sit on the same line when it is empty
    exempt = set(re.findall(r"^\s+'([a-z0-9-]+)':", block[: block.index("}")], re.M))
    m = re.search(r"so (\w+) own rules? keeps? it(?: and (?:is|are) listed with that reason in the timing test: (.*?))?\. ", page)
    if not m:
        return ["docs/rules.md no longer names the own rules the timing test leaves as they are"]
    named = set(re.findall(r"`([a-z0-9-]+)`", m.group(2) or ""))
    count = 0 if m.group(1) == "no" else quoted._value(m.group(1))
    if named != exempt or count != len(exempt):
        out.append(f"docs/rules.md: names {m.group(1)} rules {sorted(named)}, the timing test leaves {sorted(exempt)}")
    length = int(re.search(r"const LENGTH = ([\d_]+)", timing).group(1).replace("_", ""))
    budget = int(re.search(r"const BUDGET_MS = ([\d_]+)", timing).group(1).replace("_", ""))
    if f"a hostile value of {length:,} characters within {budget} ms" not in page:
        out.append(f"docs/rules.md: the timing test tries {length:,} characters within {budget} ms")
    return out


def test_the_rules_page_names_what_the_timing_test_leaves_and_allows():
    assert timing_mismatches(_page("docs/rules.md"), TIMING_TEST.read_text(encoding="utf-8")) == []


def test_a_rule_left_out_of_the_timing_test_is_caught():
    timing = TIMING_TEST.read_text(encoding="utf-8")
    added = timing.replace("const RULE_EXEMPT: Record<string, string> = {", "const RULE_EXEMPT: Record<string, string> = {\n  'win-a-new-rule': 'a reason',")
    assert any("win-a-new-rule" in line for line in timing_mismatches(_page("docs/rules.md"), added))
    assert any(
        "characters within" in line for line in timing_mismatches(_page("docs/rules.md"), re.sub(r"const BUDGET_MS = \d+", "const BUDGET_MS = 1", timing))
    )
