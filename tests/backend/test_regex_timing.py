"""Every regular expression of the backend runs in linear time on hostile text.

A pattern that backtracks over a long run of the characters it repeats takes quadratic time or
worse, and Python's `re` holds the interpreter lock for the whole match: one From display name of a
few hundred kilobytes stopped every request thread of the server for minutes. Mail headers and
bodies, attachments, URLs, event fields, collection files and API values all reach a pattern here,
so this harness times every pattern of the backend: the ones compiled at module level (found by
importing every module) and the literal patterns of each inline `re.` call (found in the source).

The inputs come from the pattern itself. For each repeated part the harness builds a long run of
what that part matches, alone, after the text that leads to it and with that text repeated, ending
at the end of the string or on a character that fails what follows; and long runs of pairs of the
repeated characters and of common separators. A linear pattern answers each in well under a
millisecond at the first length. One that takes longer is tried at twice the length: when its time
grows more than about linearly it is tried at the full length, where a quadratic pattern takes
seconds and a linear one some milliseconds. The budget sits between them, in processor time, so a
busy machine does not make the test fail. Both lengths grow with the square root of the repeated
unit: a pattern that rescans the text once per occurrence of a long unit is quadratic in the number
of occurrences, which a longer unit makes fewer.
"""

from __future__ import annotations

import ast
import importlib
import pathlib
import random
import re
import time

import pytest
from regex_harness import BUDGET_S, RUNAWAY, UP_TO_LAST, full_length, in_child, suspects

from services.analysis.lookalike import display_name_looks_like_email
from services.parsers import m365
from services.parsers.mail.common import ParseContext, build_row

BACKEND = pathlib.Path(__file__).resolve().parents[2] / "backend"
PACKAGES = ("api", "forensic", "services")
CHILD_S = 30.0  # how long a harness self-test may run in its child before it counts as endless
SCANNING = {"search", "findall", "finditer", "sub", "subn", "split"}
ANCHORED = {"match", "fullmatch"}
FLAGS_AT = {"compile": 1, "search": 2, "match": 2, "fullmatch": 2, "findall": 2, "finditer": 2, "split": 3, "sub": 4, "subn": 4}
# patterns that are not literals in the source, so there is nothing to time: each is built from data
NOT_LITERAL = {
    "services/analysis/attachments/pdf.py": "a fixed PDF keyword, escaped",
    "services/analysis/body.py": "a fixed lure phrase, escaped",
    "services/parsers/collection.py": "a fixed hexadecimal length",
    "services/rules/mql.py": "a rule author's pattern, compiled only to validate it; DuckDB runs it with RE2",
}


def _flags(node: ast.expr | None) -> int:
    if node is None:
        return 0
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "re":
        return int(getattr(re, node.attr))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _flags(node.left) | _flags(node.right)
    raise ValueError(f"flags the harness cannot read: {ast.unparse(node)}")


def _name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_re_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "re"


def _how(methods: set[str]) -> str:
    """How a pattern is applied: from the start of the text only, or searched for anywhere."""
    if methods and methods <= ANCHORED:
        return "fullmatch" if methods == {"fullmatch"} else "match"
    return "search"


def _sites() -> dict[tuple[str | bytes, int, str], str]:
    """Every pattern of the backend as (pattern, flags, how it is applied) -> where it is written."""
    # how each name is used anywhere in the backend: the pattern methods called on it, and "passed"
    # when it is read any other way (handed to a function, returned, stored)
    uses: dict[str, set[str]] = {}
    calls: list[tuple[str, ast.Call]] = []
    target: dict[int, str] = {}  # a compile call -> the name it is assigned to, or the method called on it
    rels = []
    for package in PACKAGES:
        for path in sorted((BACKEND / package).rglob("*.py")):
            rel = path.relative_to(BACKEND).as_posix()
            rels.append(rel)
            loads: list[ast.Name | ast.Attribute] = []
            receivers = set()
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Call):
                    if _is_re_call(node):
                        calls.append((rel, node))
                    if isinstance(node.func, ast.Attribute) and node.func.attr in SCANNING | ANCHORED:
                        name = _name(node.func.value)
                        if name and name != "re":
                            uses.setdefault(name, set()).add(node.func.attr)
                            receivers.add(id(node.func.value))
                        if isinstance(node.func.value, ast.Call):
                            target[id(node.func.value)] = "." + node.func.attr
                elif isinstance(node, ast.Assign) and len(node.targets) == 1 and _name(node.targets[0]):
                    target[id(node.value)] = _name(node.targets[0]) or ""
                elif isinstance(node, ast.Name | ast.Attribute) and isinstance(node.ctx, ast.Load):
                    loads.append(node)
            for node in loads:
                if id(node) not in receivers and _name(node):
                    uses.setdefault(_name(node) or "", set()).add("passed")
    out: dict[tuple[str | bytes, int, str], str] = {}
    for rel, node in calls:
        method = node.func.attr
        if method not in SCANNING | ANCHORED | {"compile"}:
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant):
            assert rel in NOT_LITERAL, f"backend/{rel}:{node.lineno} builds a pattern the harness cannot time"
            continue
        flag_node = next((k.value for k in node.keywords if k.arg == "flags"), None)
        if flag_node is None and len(node.args) > FLAGS_AT[method]:
            flag_node = node.args[FLAGS_AT[method]]
        if method == "compile":
            assigned = target.get(id(node), "")
            methods = {assigned[1:]} if assigned.startswith(".") else uses.get(assigned, {"passed"})
            method = "search" if "passed" in methods else _how(methods)
        out.setdefault((node.args[0].value, _flags(flag_node), _how({method})), f"backend/{rel}:{node.lineno}")
    # what importing the modules adds: a pattern compiled at module level from anything but a literal
    seen = {(source, re.compile(source, flags).flags) for source, flags, _ in out}
    for rel in rels:
        module = importlib.import_module(rel.removesuffix(".py").removesuffix("/__init__").replace("/", "."))
        for name, value in vars(module).items():
            if isinstance(value, re.Pattern) and (value.pattern, value.flags) not in seen:
                seen.add((value.pattern, value.flags))
                out[(value.pattern, value.flags, "search")] = f"{module.__name__}.{name}"
    return out


SITES = _sites()


@pytest.mark.parametrize("key", list(SITES), ids=[SITES[k] for k in SITES])
def test_a_pattern_of_the_backend_answers_hostile_text_in_linear_time(key: tuple[str | bytes, int, str]):
    source, flags, how = key
    pattern = re.compile(source, flags)
    for shape in suspects(pattern, how):
        length, spent = full_length(pattern, how, shape)
        assert spent < BUDGET_S, (
            f"{SITES[key]}: {pattern.pattern!r} ({how}) took {'over ' if spent == float('inf') else ''}"
            f"{min(spent, 2 * BUDGET_S):.2f} s on {length:,} characters built from {shape!r}"
        )


def test_the_harness_reads_every_module_and_both_kinds_of_pattern():
    where = set(SITES.values())
    assert {source for source, _, _ in SITES} >= set(UP_TO_LAST)
    assert any(w.startswith("backend/services/analysis/lookalike.py:") for w in where)
    assert any(w.startswith("backend/services/parsers/mail/common.py:") for w in where)
    assert any(w.startswith("backend/services/analysis/attachments/") for w in where)
    assert any(w.startswith("backend/api/") for w in where) and any(w.startswith("backend/forensic/") for w in where)
    assert (m365._EMAIL_RE.pattern, m365._EMAIL_RE.flags & ~re.UNICODE, "search") in SITES
    assert len(SITES) > 200


@pytest.mark.parametrize(
    "source, how",
    [
        # the From display name pattern before it was made linear: a run of address characters
        (r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", "search"),
        # a tag with no closing bracket, rescanned from every opening
        (r"(?i)<input[^>]*type\s*=\s*[\"']?password", "search"),
        (rb"(?i)(?:<w:instrText[^>]*>\s*)?DDE(?:AUTO)?[\s\"'\\][^<]{0,200}", "search"),
        # two runs of the same characters side by side, split every way when what follows fails
        (r"^\s*(>=|<=|=)?\s*(\d+)\s*$", "match"),
        # a lazy run whose end is rescanned from every position of a run of spaces
        (r"(?s)\bfrom\s+(.+?)(?=\s+\b(?:by|with)\b|;|$)", "search"),
        # nested repetition: exponential
        (r"^(?:\s|<!--.*?-->)*<Events?[\s>]", "match"),
        # a trim whose second branch is tried from every position of a run inside the text
        (r"^\s+|\s+$", "search"),
    ],
)
def test_the_harness_finds_a_pattern_that_backtracks(source: str | bytes, how: str):
    # in a child: where no interval timer can interrupt the exponential one, the child is stopped
    found = in_child(f"next(h.suspects(re.compile({source!r}), {how!r}), None) is not None", CHILD_S)
    assert found in (True, RUNAWAY), source


def test_a_pattern_that_backtracks_runs_past_the_budget_at_the_full_length():
    # the threshold of a rule before it was made linear, on a value of spaces
    pattern = re.compile(r"^\s*(>=|<=|==|=|>|<|!=)?\s*(\d+)\s*$")
    assert next(suspects(pattern, "match")) == ("", " ", "")
    # in a child: without an interval timer the quadratic try at the full length would take hours
    spent = in_child(f"h.full_length(re.compile({pattern.pattern!r}), 'match', ('', ' ', ''))[1]", CHILD_S)
    assert spent == RUNAWAY or spent >= BUDGET_S


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
