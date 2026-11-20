"""Parsers that misbehave on purpose, for the tests of the parse process.

A test points services.ingest.isolation.ENTRY at one of the functions at the bottom; the child it
starts then runs that parser for every kind of evidence, under the real limits and speaking the real
protocol. Every parser here stops on its own after a bounded time or amount of memory, so a limit
that does not work fails its test instead of taking the machine. Nothing here is evidence: the rows
are invented.
"""

from __future__ import annotations

import os
import signal
import socket
import sys
import time
from collections.abc import Iterator
from typing import Any

from django.conf import settings

from services.ingest.isolation import _Work, child_main

# the most any parser here allocates or runs when nothing stops it
ALLOCATE_AT_MOST = 3 * 1024**3
RUN_AT_MOST_S = 60.0


def row(n: int, **data: Any) -> dict[str, Any]:
    """An invented event row, shaped so the server store takes it; what a test reads is in data."""
    return {
        "ts": 1_700_000_000_000 + n,
        "eventId": 4624,
        "computer": "WS01",
        "channel": "Test",
        "recordId": n,
        "message": "invented row",
        "data": {"pid": os.getpid(), **data},
    }


class _Hostile(_Work):
    format = "test"

    def __init__(self, spec: dict[str, Any], deadline: float | None, run_engine: Any) -> None:
        super().__init__(spec, deadline, run_engine)
        self.count = 0
        self.files: list[dict[str, Any]] = []

    def rows(self) -> Iterator[dict[str, Any]]:
        raise NotImplementedError

    def __iter__(self) -> Iterator[dict[str, Any]]:
        for item in self.rows():
            self.count += 1
            yield item

    def entries(self) -> int:
        return len(self.files)

    def state(self) -> dict[str, Any]:
        return {"format": self.format, "stats": {"count": self.count, "errors": 0, "files": self.files}, "members": [], "engineSummaries": []}


class Environ(_Hostile):
    """Reports what a parser can see: its process, its environment, its settings, its network."""

    def rows(self) -> Iterator[dict[str, Any]]:
        try:
            secret = settings.SECRET_KEY
        except Exception:  # noqa: BLE001
            secret = ""
        reached = None
        port = self.options.get("port")
        if port:
            try:
                with socket.create_connection(("127.0.0.1", int(port)), timeout=2):
                    reached = True
            except OSError as exc:
                reached = f"{type(exc).__name__}: {exc}"
        yield row(
            1,
            uid=os.getuid() if hasattr(os, "getuid") else None,
            environ=sorted(os.environ),
            token=os.environ.get("FORENSIC_AUTH_TOKEN"),
            settingsToken=getattr(settings, "FORENSIC_AUTH_TOKEN", None),
            reputationKeys=getattr(settings, "REPUTATION_KEYS", None),
            secretKey=secret,
            reached=reached,
            cwd=os.getcwd(),
        )


class Allocate(_Hostile):
    """Sends two rows, then holds more and more memory until something stops it."""

    def rows(self) -> Iterator[dict[str, Any]]:
        yield row(1)
        yield row(2)
        self.files.append({"name": "big.bin", "status": "pending"})
        held = []
        total = 0
        while total < ALLOCATE_AT_MOST:
            # filled, so every page is really used on every system
            held.append(b"x" * (16 * 1024**2))
            total += 16 * 1024**2
            time.sleep(0.02)
        yield row(3, notStopped=total)


class Share(_Hostile):
    """Holds ever more memory in shared mappings, which a limit on private memory does not count."""

    def rows(self) -> Iterator[dict[str, Any]]:
        import mmap

        yield row(1)
        held = []
        total = 0
        while total < ALLOCATE_AT_MOST:
            block = mmap.mmap(-1, 16 * 1024**2)
            block.write(b"x" * (16 * 1024**2))
            held.append(block)
            total += 16 * 1024**2
            time.sleep(0.02)
        yield row(2, notStopped=total)


class Silent(_Hostile):
    """Sends one row, then never another: stuck inside one record."""

    def rows(self) -> Iterator[dict[str, Any]]:
        yield row(1)
        until = time.monotonic() + RUN_AT_MOST_S
        while time.monotonic() < until:
            time.sleep(0.05)
        yield row(2, notStopped=True)


class Spin(_Hostile):
    """Sends one row, then burns processor time without sending another."""

    def rows(self) -> Iterator[dict[str, Any]]:
        yield row(1)
        until = time.monotonic() + RUN_AT_MOST_S
        x = 0
        while time.monotonic() < until:
            x = (x * 31 + 7) % 1_000_003
        yield row(2, notStopped=True)


class Crash(_Hostile):
    """Sends one row, then dies the way a memory-safety bug in a decoder ends a process."""

    def rows(self) -> Iterator[dict[str, Any]]:
        yield row(1)
        # let the row reach the server before the process goes
        time.sleep(0.3)
        sys.stderr.flush()
        if os.name == "nt":
            # the status of an access violation, 0xC0000005, as the signed number _exit takes
            os._exit(-1073741819)
        os.kill(os.getpid(), signal.SIGSEGV)
        time.sleep(5)


class Odd(_Hostile):
    """Rows with values that must cross unchanged: text the decoders could not pair, large
    numbers, nesting, nothing at all."""

    def rows(self) -> Iterator[dict[str, Any]]:
        yield {"text": "a\ud800b", "emoji": "\U0001f600", "big": 2**62, "neg": -1, "float": 1.5, "nested": {"list": [1, "two", None]}, "none": None}
        yield {"n": 2, "empty": "", "line": "one\ntwo\r\n", "quote": '"{"t":"end"}"'}


def _run(cls: type[_Hostile]) -> None:
    child_main(kinds={"evtx": cls, "mail": cls, "package": cls, "attachment": cls})


def environ() -> None:
    _run(Environ)


def allocate() -> None:
    _run(Allocate)


def share() -> None:
    _run(Share)


def silent() -> None:
    _run(Silent)


def spin() -> None:
    _run(Spin)


def crash() -> None:
    _run(Crash)


def odd() -> None:
    _run(Odd)


def start_fails() -> None:
    """Fails in the parse process's own start, before any parser runs, with a message that quotes
    (invented) evidence, as an exception's text often does."""
    from services.analysis.attachments import yara_scan

    def configure(rules_dir: Any) -> None:
        raise ValueError("invented evidence text from Fabrikam-payroll.evtx")

    yara_scan.configure = configure
    _run(Environ)
