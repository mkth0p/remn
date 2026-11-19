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
import itertools
import math
import pathlib
import random
import re
import signal
import threading
import time
from collections.abc import Callable, Iterator
from re import _compiler, _parser  # the standard library's own parser: what each pattern repeats
from re import _constants as sre

import pytest

from services.analysis.lookalike import display_name_looks_like_email
from services.parsers import m365
from services.parsers.mail.common import ParseContext, build_row

BACKEND = pathlib.Path(__file__).resolve().parents[2] / "backend"
PACKAGES = ("api", "forensic", "services")
SCREEN = 4_000  # characters of the first, quick try of each input
SCREEN_S = 0.002  # wall time past which an input is tried again at twice the length
GROWTH = 3.0  # growth at twice the length past which it is tried at the full length (linear: 2)
SCREEN_LIMIT_S = 0.1  # a try at the first lengths that runs this long is interrupted and suspect
LENGTH = 100_000  # characters of the decisive try
BUDGET_S = 0.5  # processor time the decisive try may take
SCANNING = {"search", "findall", "finditer", "sub", "subn", "split"}
ANCHORED = {"match", "fullmatch"}
FLAGS_AT = {"compile": 1, "search": 2, "match": 2, "fullmatch": 2, "findall": 2, "finditer": 2, "split": 3, "sub": 4, "subn": 4}
# the characters a run is built from: printable ASCII, the controls and separators text carries, a
# few letters and spaces outside ASCII
UNIVERSE = [chr(i) for i in range(0x20, 0x7F)] + ["\t", "\n", "\r", "\x0b", "\x0c", "\x00", "\xa0"] + [chr(c) for c in (0xE9, 0x436, 0x200B, 0x2028)]
PREFERRED = "a0_ .-/@%\\:=\n\t\"'<>;,&?#+(é"
GENERIC = [" ", ".", "@", "/", "%41", "a", "<a", "\t\n"]
TAILS = ("", "\x00")
SINGLE = {sre.LITERAL, sre.NOT_LITERAL, sre.ANY, sre.IN}
REPEATS = {sre.MAX_REPEAT, sre.MIN_REPEAT, sre.POSSESSIVE_REPEAT}

# patterns the code applies only up to the end of the last closing tag, because nothing after it can
# match: a "<" after the last ">" opens no tag, a script opened after the last </script> is never
# closed. Timed the same way.
UP_TO_LAST = {
    r"<[^>]*>": ">",  # services/parsers/mail/common.py normalize_name
    r"<[^>]+>": ">",  # services/analysis/urls.py extract_urls
    r"(?is)<script\b(?:(?!<script\b)[^>])*>(.*?)</script>": "(?i)</script>",  # attachments/html.py analyze_html
    r"(<Data(?:\s(?:(?!<Data)[^>])*)?(?<!/)>)(.*?)(</Data>)": "</Data>",  # parsers/evtx_parser.py _xml_repaired
}

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


def _own_characters(seq: list, acc: list[str]) -> list[str]:
    """The characters a pattern names: its literals and the ends of its ranges."""
    for op, av in seq:
        if op is sre.LITERAL:
            acc.append(chr(av))
        elif op is sre.IN:
            for o, a in av:
                if o is sre.LITERAL:
                    acc.append(chr(a))
                elif o is sre.RANGE:
                    acc += [chr(a[0]), chr(a[1])]
        elif op in REPEATS:
            _own_characters(av[2], acc)
        elif op is sre.SUBPATTERN:
            _own_characters(av[3], acc)
        elif op is sre.ATOMIC_GROUP:
            _own_characters(av, acc)
        elif op is sre.BRANCH:
            for alt in av[1]:
                _own_characters(alt, acc)
        elif op in (sre.ASSERT, sre.ASSERT_NOT):
            _own_characters(av[1], acc)
    return acc


class _Pumps:
    """Reads a parsed pattern: for each repeated part, the text that leads to it and a few strings
    the part matches once."""

    def __init__(self, parsed: _parser.SubPattern, universe: list[str]):
        self.state = parsed.state
        self.universe = universe
        own = list(dict.fromkeys(c for c in _own_characters(list(parsed), []) if c in universe))
        self.order = own + [c for c in PREFERRED if c not in own]
        self.groups: dict[int, str] = {}
        self.found: list[tuple[str, list[str]]] = []
        self._chars: dict[str, list[str]] = {}
        self.walk(list(parsed), "")

    def chars(self, node: tuple) -> list[str]:
        """Up to four characters one position of the pattern accepts, the pattern's own first."""
        key = repr(node)
        if key not in self._chars:
            one = _compiler.compile(_parser.SubPattern(self.state, [node]), self.state.flags)
            accepted = [c for c in self.universe if one.fullmatch(c)]
            self._chars[key] = [c for c in self.order if c in accepted][:4] or accepted[:1]
        return self._chars[key]

    def one(self, seq: list) -> str:
        """A short string the sequence matches: each repeat at its minimum, each branch its shortest."""
        s = ""
        for op, av in seq:
            if op in SINGLE:
                s += (self.chars((op, av)) or [""])[0]
            elif op in REPEATS:
                s += self.one(av[2]) * min(av[0], 64)
            elif op is sre.SUBPATTERN:
                g = self.one(av[3])
                if av[0]:
                    self.groups[av[0]] = g
                s += g
            elif op is sre.ATOMIC_GROUP:
                s += self.one(av)
            elif op is sre.BRANCH:
                s += min((self.one(alt) for alt in av[1]), key=len)
            elif op is sre.GROUPREF:
                s += self.groups.get(av, "")
            elif op is sre.GROUPREF_EXISTS:
                s += self.one(av[1])
        return s

    def many(self, seq: list) -> list[str]:
        """A few strings the sequence matches, varying one position at a time."""
        choices: list[list[str]] = []
        for op, av in seq:
            if op in SINGLE:
                choices.append(self.chars((op, av)))
            elif op is sre.BRANCH:
                choices.append([self.one(alt) for alt in av[1]])
            elif op is sre.SUBPATTERN:
                choices.append(self.many(av[3]))
            else:
                choices.append([self.one([(op, av)])])
        base = [c[0] if c else "" for c in choices]
        out = ["".join(base)] + ["".join(base[:i] + [alt] + base[i + 1 :]) for i, c in enumerate(choices) for alt in c[1:]]
        return [s for s in dict.fromkeys(out) if s][:6]

    def walk(self, seq: list, before: str) -> None:
        for i, (op, av) in enumerate(seq):
            lead = before + self.one(seq[:i])
            if op in REPEATS:
                if av[1] is sre.MAXREPEAT or av[1] > 32:
                    self.found.append((lead, self.many(av[2])))
                self.walk(av[2], lead)
            elif op is sre.SUBPATTERN:
                self.walk(av[3], lead)
            elif op is sre.ATOMIC_GROUP:
                self.walk(av, lead)
            elif op is sre.BRANCH:
                for alt in av[1]:
                    self.walk(alt, lead)
            elif op in (sre.ASSERT, sre.ASSERT_NOT):
                self.walk(av[1], lead)
            elif op is sre.GROUPREF_EXISTS:
                self.walk(av[1], lead)
                if av[2]:
                    self.walk(av[2], lead)


def shapes(pattern: re.Pattern) -> list[tuple[str, str, str]]:
    """The hostile inputs of one pattern, each as (head, unit, tail): the text is the head, the unit
    repeated to the length, then the tail."""
    universe = [chr(i) for i in range(256)] if isinstance(pattern.pattern, bytes) else UNIVERSE
    pumps = _Pumps(_parser.parse(pattern.pattern, pattern.flags), universe)
    units: list[tuple[str, str]] = []
    singles: list[str] = []
    for lead, strings in pumps.found:
        for s in strings:
            units.append(("", s))
            if lead:
                units += [(lead, s), ("", lead + s)]
            if len(s) == 1:
                singles.append(s)
    singles = list(dict.fromkeys(singles))[:3]
    units += [("", a + b) for a, b in itertools.combinations(singles, 2)]
    units += [("", g) for g in GENERIC]
    found = [(head, unit, tail) for head, unit in units for tail in TAILS]
    # a run after other text: "^\s+|\s+$" takes a leading run whole, and only a run that does not
    # start the text makes it try the second branch from every position of the run
    found += [("\x00", unit, "\x00") for head, unit in units if not head]
    return list(dict.fromkeys(found))


def text(shape: tuple[str, str, str], length: int, as_bytes: bool) -> str | bytes:
    head, unit, tail = shape
    t = head + unit * max(1, length // len(unit)) + tail
    return t.encode("utf-8" if any(ord(c) > 255 for c in t) else "latin-1") if as_bytes else t


class _Runaway(Exception):
    pass


def _stop(signum: int, frame: object) -> None:
    raise _Runaway


def timed(run: Callable[[], object], limit_s: float) -> float:
    """Processor time of one call. Where the platform has interval timers (not Windows), a call that
    runs past the limit is interrupted instead of holding the test for hours."""
    guard = hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread()
    previous = signal.signal(signal.SIGALRM, _stop) if guard else None
    if guard:
        signal.setitimer(signal.ITIMER_REAL, limit_s)
    t0 = time.process_time()
    try:
        run()
    except _Runaway:
        return float("inf")
    finally:
        if guard:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
    return time.process_time() - t0


def applier(pattern: re.Pattern, how: str) -> Callable[[str | bytes], object]:
    """The pattern applied as the code applies it, to the part of a text the code gives it."""
    apply = {"search": pattern.findall, "match": pattern.match, "fullmatch": pattern.fullmatch}[how]
    closing = UP_TO_LAST.get(pattern.pattern) if isinstance(pattern.pattern, str) else None
    if closing is None:
        return apply
    last = re.compile(r"(?s).*" + closing.removeprefix("(?i)"), re.I if closing.startswith("(?i)") else 0)

    def up_to_last(t: str | bytes) -> object:
        m = last.match(t)
        return apply(t[: m.end() if m else 0])

    return up_to_last


def scaled(length: int, shape: tuple[str, str, str]) -> int:
    return int(length * math.sqrt(len(shape[1])))


def suspects(pattern: re.Pattern, how: str) -> Iterator[tuple[str, str, str]]:
    """Each input that takes longer than the screen and grows more than linearly at twice the length
    (or that runs past the screen limit and is interrupted)."""
    as_bytes = isinstance(pattern.pattern, bytes)
    apply = applier(pattern, how)

    def wall(t: str | bytes) -> float:
        t0 = time.perf_counter()
        spent = timed(lambda: apply(t), SCREEN_LIMIT_S)
        return spent if spent == float("inf") else time.perf_counter() - t0

    for shape in shapes(pattern):
        short = wall(text(shape, scaled(SCREEN, shape), as_bytes))
        if short >= SCREEN_S and (short == float("inf") or wall(text(shape, 2 * scaled(SCREEN, shape), as_bytes)) >= GROWTH * short):
            yield shape


def full_length(pattern: re.Pattern, how: str, shape: tuple[str, str, str]) -> tuple[int, float]:
    """The length of the decisive try of one input, and the processor time it took."""
    length = scaled(LENGTH, shape)
    full = text(shape, length, isinstance(pattern.pattern, bytes))
    apply = applier(pattern, how)
    return length, timed(lambda: apply(full), 2 * BUDGET_S)


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
    assert next(suspects(re.compile(source), how), None), source


def test_a_pattern_that_backtracks_runs_past_the_budget_at_the_full_length():
    # the threshold of a rule before it was made linear, on a value of spaces
    pattern = re.compile(r"^\s*(>=|<=|==|=|>|<|!=)?\s*(\d+)\s*$")
    assert next(suspects(pattern, "match")) == ("", " ", "")
    assert full_length(pattern, "match", ("", " ", ""))[1] >= BUDGET_S


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
