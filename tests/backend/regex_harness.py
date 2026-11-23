"""The timing harness of test_regex_timing.py: the inputs it builds from a pattern and how it times
them. It imports nothing of the backend, so a test can run it in a fresh interpreter where the
platform cannot interrupt a call that runs away (Windows has no interval timer)."""

from __future__ import annotations

import faulthandler
import itertools
import json
import math
import pathlib
import re
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from re import _compiler, _parser  # the standard library's own parser: what each pattern repeats
from re import _constants as sre

SCREEN = 4_000  # characters of the first, quick try of each input
SCREEN_S = 0.002  # wall time past which an input is tried again at twice the length
GROWTH = 3.0  # growth at twice the length past which it is tried at the full length (linear: 2)
SCREEN_LIMIT_S = 0.1  # a try at the first lengths that runs this long is interrupted and suspect
LENGTH = 100_000  # characters of the decisive try
BUDGET_S = 0.5  # processor time the decisive try may take
RUNAWAY_S = 120.0  # without interval timers: a call this long ends the run (see timed)
RUNAWAY = "runaway"  # what in_child gives back for a child stopped at its limit
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


def interruptible() -> bool:
    """Whether a call can be interrupted at its limit: there is an interval timer (Windows has none)
    and this is the main thread, the only one its signal reaches. `re` holds the interpreter lock
    for a whole match, so no other thread can stop one."""
    return hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread()


def timed(run: Callable[[], object], limit_s: float) -> float:
    """Processor time of one call. Where the platform has interval timers (not Windows), a call that
    runs past the limit is interrupted and counts as endless. Where it has none, a call that runs
    past RUNAWAY_S ends the whole interpreter with the stack of every thread, so a pattern that
    backtracks fails the run where it is instead of holding it until the job's own time limit; a
    test times a pattern in a child there (in_child), which is stopped long before."""
    guard = interruptible()
    previous = signal.signal(signal.SIGALRM, _stop) if guard else None
    if guard:
        signal.setitimer(signal.ITIMER_REAL, limit_s)
    else:
        faulthandler.dump_traceback_later(RUNAWAY_S, exit=True)
    t0 = time.process_time()
    try:
        run()
    except _Runaway:
        return float("inf")
    finally:
        if guard:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        else:
            faulthandler.cancel_dump_traceback_later()
    return time.process_time() - t0


def in_child(call: str, limit_s: float) -> object:
    """`call`, an expression over this module (as `h`) and `re`, evaluated in a fresh interpreter
    and given back through JSON; RUNAWAY when it has not answered within limit_s. A test that runs
    a pattern known to backtrack calls the harness this way, so that where the platform cannot
    interrupt a call the child is what is stopped."""
    code = "import json, re, sys; sys.path.insert(0, sys.argv[1]); import regex_harness as h; print(json.dumps(eval(sys.argv[2])))"
    try:
        done = subprocess.run(
            [sys.executable, "-I", "-c", code, str(pathlib.Path(__file__).resolve().parent), call],
            capture_output=True,
            text=True,
            timeout=limit_s,
            check=True,
        )
    except subprocess.TimeoutExpired:
        return RUNAWAY
    return json.loads(done.stdout)


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


def first_failure(pattern: re.Pattern, how: str) -> tuple[tuple[str, str, str], int, float] | None:
    """The first input on which the pattern runs past the budget at the full length, with that length
    and the processor time it took; None when it answers every input in time."""
    for shape in suspects(pattern, how):
        length, spent = full_length(pattern, how, shape)
        if spent >= BUDGET_S:
            return shape, length, spent
    return None
