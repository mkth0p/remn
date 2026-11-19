"""Every regular expression that reads mail header text runs in linear time.

A pattern that backtracks over a long run of the characters it repeats on takes quadratic time, and
Python's `re` holds the interpreter lock for the whole match: one From display name of a few hundred
kilobytes with no `@` in it stopped every request thread of the server for minutes. This harness
feeds each pattern of the modules below (compiled at module level or written inline in a `re.` call)
long runs of such characters. A linear pattern answers each input in a few milliseconds; the
quadratic one took about ten seconds at this length. The bound is a full second of processor time,
so a busy machine does not make the test fail.
"""

from __future__ import annotations

import ast
import inspect
import itertools
import random
import re
import time
from types import ModuleType

import pytest

from services.analysis import lookalike
from services.analysis.lookalike import display_name_looks_like_email
from services.parsers import m365
from services.parsers.mail.common import ParseContext, build_row

# lookalike reads the From and Reply-To display names and domains; m365 reads inbox rule fields of an
# export, which whoever made the rule wrote.
MODULES: list[ModuleType] = [lookalike, m365]
LENGTH = 50_000
BOUND_S = 1.0
# word characters (ASCII, digit, underscore, accented), the punctuation of addresses and domains, space
PALETTE = ["a", "Z", "0", "_", "é", ".", "-", "+", "'", "@", " ", ":", "/", "["]


def _patterns(module: ModuleType) -> list[re.Pattern[str]]:
    """The module's compiled patterns and the literal patterns of its inline `re.` calls."""
    found = {p.pattern: p for p in vars(module).values() if isinstance(p, re.Pattern)}
    for node in ast.walk(ast.parse(inspect.getsource(module))):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "re"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            found.setdefault(node.args[0].value, re.compile(node.args[0].value))
    return list(found.values())


def _adversarial() -> list[str]:
    """Long runs of one character, with and without a character that ends them, and of every pair."""
    out: list[str] = []
    for c in PALETTE:
        out += [c * LENGTH, c * LENGTH + "!", "a@" + c * LENGTH]
    for a, b in itertools.product(PALETTE, repeat=2):
        if a != b:
            out.append((a + b) * (LENGTH // 2))
    return out


PATTERNS = [(m.__name__.rsplit(".", 1)[-1], p) for m in MODULES for p in _patterns(m)]
INPUTS = _adversarial()


def test_the_harness_sees_the_patterns_that_read_a_display_name_and_a_rule_field():
    seen = {p.pattern for _, p in PATTERNS}
    assert any("@" in p for p in seen if p in {q.pattern for q in _patterns(lookalike)})
    assert m365._EMAIL_RE.pattern in seen
    assert len(INPUTS) > 200


@pytest.mark.parametrize("pattern", [p for _, p in PATTERNS], ids=[f"{m}:{p.pattern}" for m, p in PATTERNS])
def test_a_pattern_on_mail_header_text_answers_a_long_run_in_linear_time(pattern: re.Pattern[str]):
    for text in INPUTS:
        t0 = time.process_time()
        pattern.findall(text)
        spent = time.process_time() - t0
        assert spent < BOUND_S, f"{pattern.pattern!r} took {spent:.2f} s on {len(text):,} characters starting {text[:8]!r}"


def test_a_display_name_finds_the_address_it_found_before():
    # the pattern before it was made linear, kept to show both answer the same on short names
    before = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
    rng = random.Random(7)
    alphabet = "ab0_é.-+@ ()<>'\""
    for _ in range(20_000):
        name = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24)))
        m = before.search(name)
        assert display_name_looks_like_email(name) == (m.group(0).lower() if m else None), name
    assert display_name_looks_like_email("Marie Lefevre (Marie.Lefevre@interne.fr)") == "marie.lefevre@interne.fr"
    assert display_name_looks_like_email("IT Support") is None


def test_an_inbox_rule_still_names_every_recipient():
    rule = {
        "RuleName": "invented rule",
        "RuleActions": '[{"ActionType": "Forward", "Recipients": ["drop.box@mail.example", "Second <second+tag@relay.example.org>"]}]',
    }
    assert m365.outlook_rule_fields(rule)["ForwardTo"] == "drop.box@mail.example;second+tag@relay.example.org"


def test_a_message_with_a_huge_display_name_is_parsed_in_seconds():
    # an invented message whose From display name is 300,000 word characters with no address in it
    headers = [
        ("From", f"{'a' * 300_000} <sender@mail.example>"),
        ("To", "Analyst <analyst@interne.example>"),
        ("Subject", "invented"),
        ("Date", "Tue, 1 Sep 2026 09:05:00 +0000"),
    ]
    t0 = time.process_time()
    row = build_row(headers, "body", None, [], ParseContext(internal_domains=["interne.example"]))
    assert time.process_time() - t0 < 10.0
    assert row["fromAddr"] == "sender@mail.example"
