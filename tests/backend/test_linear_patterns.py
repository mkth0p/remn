"""Three community patterns that grew with the cube of the value are written in a linear form.

Each upstream pattern is a token, any text, another token and so on; a backtracking engine (the
browser's, and Python's) tries it again from each occurrence of each token. The converters write a
pattern that reads the value line by line from its start and takes the first occurrence of each
token. It is compared with the pattern it replaces on random text built from the pieces that pattern
reads, in the store's engine (RE2) and in Python's, and timed on hostile values as long as a rule's
regular expression reads. frontend/src/test/regexRewrites.test.ts does the same in the browser's
engine. All text here is invented.
"""

from __future__ import annotations

import pathlib
import random
import re
import time

import duckdb
import pytest
import yaml

from services.rules import mql, sigma
from services.rules.linear import LINEAR, linear

PACKS = pathlib.Path(__file__).resolve().parents[2] / "rules" / "community"
RE_VALUE_MAX = 65_536  # the characters of a value a rule's regular expression reads (services/store/sqlfilter.py)

# the pattern before | the pieces of the text it reads | values a backtracking engine took minutes on
CASES = [
    (
        r"\ \\\\.*\\.*\$",
        [" ", "\\", "\\\\", " \\\\", "$", "a", "\n", "\r", " ", "net use", "C$"],
        [" \\\\" * (RE_VALUE_MAX // 3), " \\" * (RE_VALUE_MAX // 2), " \\\\a\\" * (RE_VALUE_MAX // 5), " " * RE_VALUE_MAX],
    ),
    (
        r"\\\\.*\\.*\$",
        ["\\", "\\\\", "$", "a", "\n", "\r", "C$", " ", "Sysvol"],
        ["\\\\" * (RE_VALUE_MAX // 2), "\\\\a\\" * (RE_VALUE_MAX // 4), "\\" * RE_VALUE_MAX],
    ),
    (
        r".*\|.*(Manager|Careers|Recruitment|Specialist|Global)",
        ["|", "manager", "Careers", "GLOBAL", "Recruit", "ment", "Glob", "a", " ", "\n", "\r"],
        ["|" * RE_VALUE_MAX, "|Manage" * (RE_VALUE_MAX // 7), "a|" * (RE_VALUE_MAX // 2)],
    ),
]


def test_every_pattern_made_linear_is_covered_here():
    assert sorted(LINEAR) == sorted(c[0] for c in CASES)


@pytest.mark.parametrize("before, pieces, hostile", CASES, ids=["admin share mount", "admin share copy", "sender name"])
def test_a_linear_pattern_matches_the_values_its_pattern_matched_in_the_store(before, pieces, hostile):
    now = linear(before)
    assert now != before
    rng = random.Random(before)
    values = ["".join(rng.choice(pieces) for _ in range(rng.randint(0, 16))) for _ in range(20_000)]
    # as the store runs a rule's re operator: RE2, without regard to case
    rows = duckdb.connect().execute("SELECT v, regexp_matches(v, ?, 'i'), regexp_matches(v, ?, 'i') FROM unnest(?) AS t(v)", [before, now, values]).fetchall()
    assert [v for v, old, new in rows if old != new] == []
    assert sum(old for _, old, _ in rows) > 1000
    # Python's engine reads `.` as RE2 does: any character but a newline
    assert [v for v in values if bool(re.search(before, v, re.I)) != bool(re.search(now, v, re.I))] == []


@pytest.mark.parametrize("before, pieces, hostile", CASES, ids=["admin share mount", "admin share copy", "sender name"])
def test_a_linear_pattern_reads_a_hostile_value_as_long_as_a_rule_reads_in_under_a_second(before, pieces, hostile):
    # the pattern it replaces took more than a second on 3,000 of these characters, eight times as
    # long at twice the length
    now = re.compile(linear(before), re.I)
    for value in hostile:
        assert len(value) <= RE_VALUE_MAX
        t0 = time.process_time()
        now.search(value)
        assert time.process_time() - t0 < 1.0, value[:20]


def _sigma(detection: str) -> list:
    """The command-line conditions an invented Sigma rule converts to, without its log source's."""
    rule = sigma.convert_text(
        f"""title: Admin share (invented)
id: 00000000-0000-4000-8000-000000000001
logsource: {{category: process_creation, product: windows}}
detection:
{detection}
    condition: selection
level: medium
""",
        "invented.yml",
    )[0]
    assert rule["ok"], rule
    where = rule["rule"]["where"]
    return [{k: v} for c in where.get("all_of", [where]) for k, v in c.items() if k.startswith("commandLine")]


def test_the_converters_write_the_linear_pattern():
    # as SigmaHQ writes them: wildcards in a contains value, beside a value without one
    assert _sigma("""    selection:
        CommandLine|contains|all:
            - ' use '
            - ' \\\\\\\\*\\\\*$'
""") == [{"commandLine|re": r"\ use\ "}, {"commandLine|re": LINEAR[r"\ \\\\.*\\.*\$"]}]
    assert _sigma("""    selection:
        CommandLine|contains:
            - '\\\\\\\\*\\\\*$'
            - '\\Sysvol\\'
""") == [{"commandLine|re": [LINEAR[r"\\\\.*\\.*\$"], r"\\Sysvol\\"]}]
    # and as a rule may write the pattern itself
    assert _sigma("""    selection:
        CommandLine|re|i: '\\ \\\\\\\\.*\\\\.*\\$'
""") == [{"commandLine|re": LINEAR[r"\ \\\\.*\\.*\$"]}]
    sub = mql.convert_rule(
        {
            "name": "Sender name (invented)",
            "id": "00000000-0000-4000-8000-000000000002",
            "type": "rule",
            "severity": "low",
            "source": "type.inbound and regex.icontains(sender.display_name, '.*\\|.*(Manager|Careers|Recruitment|Specialist|Global)')",
        }
    )
    assert sub["ok"], sub
    assert sub["rule"]["where"]["fromName|re"] == LINEAR[r".*\|.*(Manager|Careers|Recruitment|Specialist|Global)"]


def test_no_community_pack_keeps_a_pattern_that_grows_with_the_cube_of_the_value():
    patterns: dict[str, list[str]] = {}

    def walk(cond, rule: str) -> None:
        if isinstance(cond, list):
            for c in cond:
                walk(c, rule)
        elif isinstance(cond, dict):
            for k, v in cond.items():
                if "|re" in k or "|not_re" in k:
                    for p in v if isinstance(v, list) else [v]:
                        patterns.setdefault(str(p), []).append(rule)
                else:
                    walk(v, rule)

    for path in sorted(PACKS.glob("*/*.yaml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if isinstance(doc, dict):
                walk(doc.get("where"), str(doc.get("id")))
    assert [(p, patterns[p]) for p in LINEAR if p in patterns] == []
    assert patterns[LINEAR[r"\ \\\\.*\\.*\$"]] == ["sigma-3abd6094-7027-475f-9630-8ab9be7b9725"]
    assert patterns[LINEAR[r"\\\\.*\\.*\$"]] == ["sigma-855bc8b5-2ae8-402e-a9ed-b889e6df1900"]
    assert patterns[LINEAR[r".*\|.*(Manager|Careers|Recruitment|Specialist|Global)"]] == ["sublime-6154f197-9543-50d8-af3d-f8a7e1d79cf8"]
