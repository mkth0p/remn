"""The figures README.md and docs/detection.md quote from the rule measures are the ones in the committed
rules/measures.json and rules/measures-detail.json. A new measure committed without the pages, or a figure
edited by hand, fails here; so does a sentence that quotes a library or the rule count with any other figure.
"""

from __future__ import annotations

import collections
import json
import re
from pathlib import Path

import pytest

from services.rules import packs

ROOT = Path(__file__).resolve().parents[2]
PAGES = ("README.md", "docs/detection.md")
OWN_PREFIXES = ("win-", "m365-", "collection-", "mail-")
# the sources measured before a library was added: a rule that detects on that library and on none of
# them had its first recorded attack there
EARLIER = {"evtxToMitre": {"sigma", "attackSamples", "attackData"}, "attackDataWindows": {"sigma", "attackSamples", "attackData", "evtxToMitre"}}


def _load(name: str) -> dict:
    return json.loads((ROOT / "rules" / name).read_text(encoding="utf-8"))


def off_by_default() -> set[str]:
    """Rule ids of the packs a new case does not enable, and of rules switched off in their pack."""
    off: set[str] = set()
    for pid in ("sigma-windows", "sigma-emerging-threats", "sigma-threat-hunting"):
        pack = packs.load_pack(pid)
        rules = [x["rule"] for x in pack["rules"] if x.get("rule")]
        off |= {r["id"] for r in rules if not pack["pack"].get("defaultEnabled") or r.get("enabled") is False}
    return off


def figures(measures: dict, detail: dict, off: set[str]) -> dict[str, int | str]:
    rules = measures["rules"]
    measured = [m for m in rules.values() if "settings" not in m]
    detect = sum(1 for m in measured if m.get("hits"))
    out: dict[str, int | str] = {
        "measured": measures["measured"],
        "rules": len(rules),
        "detect": detect,
        "leads": len(measured) - detect,
        "settings": len(rules) - len(measured),
        "own sample": sum(1 for m in measured if m.get("own") is True),
        "with a sample": sum(1 for m in measured if "own" in m),
        "clean fired": sum(1 for m in measured if m.get("clean", {}).get("findings")),
        "clean scoped": sum(1 for m in measured if "clean" in m),
        "machines": measures["sources"]["baseline"]["machines"],
        "baseline events, millions": round(measures["sources"]["baseline"]["events"] / 1e6, 1),
    }
    for source, s in measures["sources"].items():
        if "recordings" in s:
            out[f"recordings {source}"] = s["recordings"]
        for k in ("unreadable", "overSize", "missing", "maxMb"):
            if k in s:
                out[f"{k} {source}"] = s[k]
    detected: dict[str, set[str]] = collections.defaultdict(set)
    first: collections.Counter[tuple[str, bool]] = collections.Counter()
    high = 0
    for rid, d in detail["rules"].items():
        libraries = {h.split(":", 1)[0] for h in d.get("hits", [])}
        if rid not in off:
            for h in d.get("hits", []):
                source, name = h.split(":", 1)
                detected[source].add(name)
        for source, before in EARLIER.items():
            if source in libraries and not libraries & before:
                first[(source, rid.startswith(OWN_PREFIXES))] += 1
        if rid.startswith(OWN_PREFIXES) and d.get("severity") in ("high", "critical"):
            high += sum(d.get("clean", {}).values())
    for source, names in detected.items():
        out[f"detected {source}"] = len(names)
    for source in EARLIER:
        out[f"first {source}"] = first[(source, False)] + first[(source, True)]
        out[f"first own {source}"] = first[(source, True)]
    out["own high clean"] = high
    return out


def _n(text: str) -> int | float:
    return float(text) if "." in text else int(text.replace(",", ""))


# (page, sentence with one group per figure, the figure each group is) - the sentences that quote the measure
QUOTED: list[tuple[str, str, tuple[str, ...]]] = [
    ("README.md", r"The committed measure, `rules/measures.json`, was taken on (\d{4}-\d\d-\d\d)", ("measured",)),
    ("README.md", r"of the ([\d,]+) event rules measured then, ([\d,]+) fire on a recording of what they look for", ("rules", "detect")),
    ("README.md", r"detect ([\d,]+) of the ([\d,]+) Windows datasets of Splunk attack_data", ("detected attackDataWindows", "recordings attackDataWindows")),
    ("README.md", r"and ([\d,]+) of the ([\d,]+) files of EVTX-to-MITRE-Attack", ("detected evtxToMitre", "recordings evtxToMitre")),
    ("README.md", r"and ([\d,]+) of the ([\d,]+) files of EVTX-ATTACK-SAMPLES", ("detected attackSamples", "recordings attackSamples")),
    ("README.md", r"logs of (\w+) clean Windows lab machines", ("machines",)),
    ("README.md", r"REMN's own rules raised ([\d,]+) findings at high or critical", ("own high clean",)),
    ("docs/detection.md", r"SigmaHQ regression samples .{0,120}?: ([\d,]+) recordings", ("recordings sigma",)),
    ("docs/detection.md", r"EVTX-ATTACK-SAMPLES \(`4ceed2f`\): ([\d,]+) recordings", ("recordings attackSamples",)),
    ("docs/detection.md", r"Office 365 and Entra ID datasets of Splunk attack_data \(`7a5e9d5`\): ([\d,]+) recordings", ("recordings attackData",)),
    ("docs/detection.md", r"([\d,]+) more are Entra directory audit logs", ("unreadable attackData",)),
    ("docs/detection.md", r"EVTX-to-MITRE-Attack \(`4748560`\): ([\d,]+) recordings", ("recordings evtxToMitre",)),
    ("docs/detection.md", r"Windows datasets of Splunk attack_data \(`7a5e9d5`\): ([\d,]+) recordings", ("recordings attackDataWindows",)),
    (
        "docs/detection.md",
        r"the ([\d,]+) datasets larger than ([\d,]+) MB, and the ([\d,]+) whose files",
        ("overSize attackDataWindows", "maxMb attackDataWindows", "missing attackDataWindows"),
    ),
    (
        "docs/detection.md",
        r"the (\w+) Windows installations of NextronSystems/evtx-baseline `v0\.8\.4` \(([\d.]+) million events",
        ("machines", "baseline events, millions"),
    ),
    ("docs/detection.md", r"The committed measure was taken on (\d{4}-\d\d-\d\d)", ("measured",)),
    (
        "docs/detection.md",
        r"([\d,]+) of the ([\d,]+) event rules measured fire on a recording of what they look for, ([\d,]+) are leads and ([\d,]+) cannot run",
        ("detect", "rules", "leads", "settings"),
    ),
    ("docs/detection.md", r"([\d,]+) of the ([\d,]+) SigmaHQ rules with a sample fire on it", ("own sample", "with a sample")),
    ("docs/detection.md", r"on the clean machines ([\d,]+) of the ([\d,]+) rules whose log sources they have fired", ("clean fired", "clean scoped")),
    ("docs/detection.md", r"detect ([\d,]+) of the ([\d,]+) attack_data Windows datasets", ("detected attackDataWindows", "recordings attackDataWindows")),
    ("docs/detection.md", r"([\d,]+) of the ([\d,]+) EVTX-to-MITRE-Attack files and", ("detected evtxToMitre", "recordings evtxToMitre")),
    ("docs/detection.md", r"([\d,]+) of the ([\d,]+) EVTX-ATTACK-SAMPLES files\. On the clean", ("detected attackSamples", "recordings attackSamples")),
    ("docs/detection.md", r"REMN's own rules raised ([\d,]+) findings at high or critical", ("own high clean",)),
    ("docs/detection.md", r"gave ([\d,]+) leads their first recorded attack, (\w+) of them REMN's own", ("first evtxToMitre", "first own evtxToMitre")),
    ("docs/detection.md", r"added the same day, gave ([\d,]+), (\w+) of them REMN's own", ("first attackDataWindows", "first own attackDataWindows")),
]
WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10}


def _page(name: str) -> str:
    # one line, so a sentence wrapped anywhere in the source still reads as one
    return re.sub(r"\s+", " ", (ROOT / name).read_text(encoding="utf-8"))


def _value(text: str) -> int | float | str:
    if re.fullmatch(r"\d{4}-\d\d-\d\d", text):
        return text
    return WORDS[text.lower()] if text.lower() in WORDS else _n(text)


def mismatches(pages: dict[str, str], fig: dict[str, int | str]) -> list[str]:
    out = []
    for page, pattern, keys in QUOTED:
        m = re.search(pattern, pages[page])
        if not m:
            out.append(f"{page}: no longer says {pattern!r}; update the page or this test's QUOTED")
            continue
        for group, key in zip(m.groups(), keys, strict=True):
            if _value(group) != fig[key]:
                out.append(f"{page}: says {group} where the committed measure gives {key} = {fig[key]}")
    # any "N of [the] M" whose M is the size of a library or of the measure: N has to be a figure of it
    sizes: dict[int, set[int]] = collections.defaultdict(set)
    for key, value in fig.items():
        if key.startswith("recordings ") and isinstance(value, int):
            sizes[value].add(int(fig.get("detected " + key.split(" ", 1)[1], -1)))
    sizes[int(fig["rules"])].add(int(fig["detect"]))
    sizes[int(fig["clean scoped"])].add(int(fig["clean fired"]))
    for page, text in pages.items():
        for m in re.finditer(r"\b(\d[\d,]*) of (?:the |its )?(\d[\d,]*)\b", text):
            whole, part = _n(m.group(2)), _n(m.group(1))
            if whole in sizes and part not in sizes[whole]:
                out.append(f"{page}: {m.group(0)!r} is not a figure of the committed measure (it gives {sorted(sizes[whole])} of {whole})")
    return out


@pytest.fixture(scope="module")
def committed() -> dict[str, int | str]:
    return figures(_load("measures.json"), _load("measures-detail.json"), off_by_default())


def test_the_pages_quote_the_committed_measure(committed):
    assert mismatches({p: _page(p) for p in PAGES}, committed) == []


def test_a_figure_from_an_older_measure_is_caught(committed):
    pages = {p: _page(p) for p in PAGES}
    stale = dict(pages)
    stale["README.md"] = pages["README.md"].replace(f"of the {committed['rules']:,} event rules", "of the 2,999 event rules")
    assert any("2,999" in line for line in mismatches(stale, committed))
    # the superseded figures of earlier versions of the README, in a sentence the list above does not know
    stale["README.md"] = pages["README.md"] + " REMN detected 109 of 279 at medium and above, and 227 of 535 (42%)."
    found = mismatches(stale, committed)
    assert any("'109 of 279'" in line for line in found) and any("'227 of 535'" in line for line in found)


def test_a_new_measure_changes_the_figures_the_pages_must_quote(committed):
    measures, detail = _load("measures.json"), _load("measures-detail.json")
    measures["rules"]["win-a-new-rule"] = {"h": "0" * 12, "of": 3, "hits": 1, "fires": 1}
    detail["rules"]["win-a-new-rule"] = {"hits": ["evtxToMitre:T1003/a-file-no-rule-detected.evtx"]}
    after = figures(measures, detail, off_by_default())
    assert after["rules"] == committed["rules"] + 1 and after["detect"] == committed["detect"] + 1
    assert after["detected evtxToMitre"] == committed["detected evtxToMitre"] + 1
    assert mismatches({p: _page(p) for p in PAGES}, after)
