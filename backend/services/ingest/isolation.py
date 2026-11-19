"""Each parse of uploaded evidence in a process of its own.

The server exists to run hostile files through libpff, the EVTX reader, oletools, pypdf, YARA and
the archive readers, and a memory-safety bug in any of them gives its process to whoever wrote the
file. That process used to be the web server, which holds the access token, the provider keys and
every case store. A parse now runs in a child process that starts with none of the server's
environment and only the settings a parser reads, under a memory and a processor-time limit where
the system enforces one, without a network where that takes no privilege, and as another account
when one is configured. The server keeps everything else: the stream to the browser, the case
store, the statistics, the external detection engine, the deadline and the cancel of a job, and it
stops the child at the deadline, at its memory limit or when the job is cancelled.

What crosses between the two is JSON, one message a line. A child that has been taken over can
lie about the rows, which came from hostile evidence anyway, but it cannot make the server run
anything (nothing it sends is unpickled or executed) and nothing it sends is longer than a line
the server is prepared to hold.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import logging
import logging.config
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import psutil
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from services.common import json_default
from services.ingest.pipeline import DeadlineExceeded

log = logging.getLogger(__name__)

# the folder one parse works in, in the staging area: the suffix puts it in the staging budget, the
# sweep and the clean-up at startup like the other folders a parse creates
WORK_SUFFIX = ".parse"
# how long past the deadline a child that did not stop itself is given before it is killed: it
# stops at the next record or archive member, which is quick unless it is stuck inside one
GRACE_S = 5.0
# rows go to the server in batches, and a batch waits no longer than this for more rows, so a slow
# parse streams as it goes and a stopped one loses nothing it had read
BATCH_ROWS = 500
BATCH_BYTES = 1024**2
BATCH_S = 0.05
# what the server holds of a child's output before the child has to wait for it to be consumed
INFLIGHT_BYTES = 64 * 1024**2
# how often the server looks at a child's memory
WATCH_S = 0.05
# the child's own report of what it read so far is refreshed as members finish, no more often than
# this, and at most a twentieth of the time goes to it
STATE_MIN_S = 0.25
STATE_MAX_S = 5.0
# the settings a parser reads. Nothing else of the server's configuration reaches a child: not the
# access token, the provider keys, the Ollama host or the secret key.
CHILD_SETTINGS = (
    "FILE_UPLOAD_TEMP_DIR",
    "FORENSIC_TMP_MAX_GB",
    "FORENSIC_MAX_MESSAGE_MB",
    "FORENSIC_BROWSER_ONLY",
    "YARA_RULES_DIR",
    "DEBUG",
    "LOGGING",
    "TIME_ZONE",
    "USE_TZ",
)
# the environment a child starts with: what an interpreter needs to start and to tell the time.
# The server's own variables, its token and keys among them, are not passed on.
CHILD_ENVIRONMENT = ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "PATHEXT", "LANG", "LC_ALL", "LC_CTYPE", "TZ")
# the child is started with these; tests point ENTRY at a parser of their own, which still runs
# under the real limits and speaks the real protocol
ENTRY = "services.ingest.isolation:child_main"
ENTRY_PATHS: list[str] = []
BACKEND_DIR = str(Path(__file__).resolve().parents[2])
_BOOT = "import sys; sys.path[:0] = sys.argv[2:]; import importlib; m, _, f = sys.argv[1].partition(':'); getattr(importlib.import_module(m), f)()"
_NAME = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class ParseStopped(Exception):
    """A parse stopped at one of its limits. The message is written for the analyst: what stopped
    it, where, and that what was read before is kept."""


class ParseFailed(Exception):
    """A parse that raised in its process. The parent raises it under the type name the child
    reported, so a client is told the same kind of failure as before."""


class CpuLimit(BaseException):
    """The processor-time limit, raised in the child by SIGXCPU. Not an Exception, so a parser that
    catches every Exception for one member does not swallow it and carry on."""


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------
def enabled() -> bool:
    return bool(getattr(settings, "FORENSIC_PARSE_ISOLATION", True))


def memory_limit() -> int:
    return max(0, int(getattr(settings, "FORENSIC_PARSE_MAX_MB", 0) or 0)) * 1024**2


def cpu_limit() -> int:
    return max(0, int(getattr(settings, "FORENSIC_PARSE_MAX_CPU_S", 0) or 0))


def child_env(home: str | None = None) -> dict[str, str]:
    """The environment of a process that reads evidence: enough to start an interpreter or an
    engine, none of the server's own variables."""
    # copied, not read as configuration: names are upper case on Windows, as CHILD_ENVIRONMENT is
    env = {name: value for name, value in os.environ.items() if name in CHILD_ENVIRONMENT and value}
    if home:
        env.update(HOME=home, TMPDIR=home, TEMP=home, TMP=home)
        if os.name == "nt":
            env.update(USERPROFILE=home, APPDATA=home, LOCALAPPDATA=home)
    return env


def _settings_for_child() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in CHILD_SETTINGS:
        if hasattr(settings, name):
            value = getattr(settings, name)
            out[name] = str(value) if isinstance(value, Path) else value
    return out


_warned_account = False


def parse_account() -> tuple[int, int] | None:
    """The account a parse runs as, when FORENSIC_PARSE_UID names one and the server can switch to
    it, which takes running as root."""
    global _warned_account
    value = str(getattr(settings, "FORENSIC_PARSE_UID", "") or "").strip()
    if not value or os.name != "posix":
        return None
    if os.geteuid() != 0:
        if not _warned_account:
            _warned_account = True
            log.warning("FORENSIC_PARSE_UID is set but the server does not run as root, so parses run as the server's own account")
        return None
    import pwd

    try:
        entry = pwd.getpwuid(int(value)) if value.isdigit() else pwd.getpwnam(value)
        uid, gid = entry.pw_uid, entry.pw_gid
    except KeyError:
        if not value.isdigit():
            raise ImproperlyConfigured("FORENSIC_PARSE_UID names no account on this system") from None
        uid = gid = int(value)
    return None if uid == 0 else (uid, gid)


_reported: dict[str, Any] | None = None


def _note_lockdown(report: dict[str, Any]) -> None:
    """Say once in the log what the system enforces on a parse, and again if that changes."""
    global _reported
    if report != _reported:
        _reported = dict(report)
        log.info(
            "parse processes: memory %s, processor time %s, network %s, account %s",
            report.get("memory"),
            report.get("cpu"),
            report.get("network"),
            report.get("account"),
        )


# ---------------------------------------------------------------------------
# what one parse does, in either process
# ---------------------------------------------------------------------------
Engine = Callable[..., tuple[list[dict[str, Any]], dict[str, Any]]]


class _Work:
    """One parse: its rows, then what the views report about it. The same code runs in the child
    and, with isolation off, in the server."""

    format = "unknown"
    findings: list[dict[str, Any]]

    def __init__(self, spec: dict[str, Any], deadline: float | None, run_engine: Engine) -> None:
        self.name = str(spec["name"])
        self.path = spec.get("path")
        self.data = spec.get("data")
        self.tmp_dir = str(spec["tmp_dir"])
        self.options = spec.get("options") or {}
        self.deadline = deadline
        self.run_engine = run_engine
        self.findings = []

    def __iter__(self) -> Iterator[dict[str, Any]]:
        raise NotImplementedError

    def entries(self) -> int:
        """How many per-file entries there are so far: a new one means a member was finished."""
        return 0

    def state(self) -> dict[str, Any]:
        raise NotImplementedError

    def stop(self) -> None:
        """Called when the parse stops early, before state()."""

    def close(self) -> None:
        """Release what the parse holds."""


class _EvtxWork(_Work):
    def __init__(self, spec: dict[str, Any], deadline: float | None, run_engine: Engine) -> None:
        from services.ingest.pipeline import MAX_MEMBER_BYTES, EvtxSource

        super().__init__(spec, deadline, run_engine)
        o = self.options
        self.source = EvtxSource(
            self.name,
            self.path,
            self.data,
            self.tmp_dir,
            include_raw=bool(o.get("include_raw", True)),
            max_member=int(o.get("max_member") or MAX_MEMBER_BYTES),
            deadline=deadline,
        )
        self.format = self.source.format
        self.summaries: list[dict[str, Any]] = []

    def __iter__(self) -> Iterator[dict[str, Any]]:
        yield from self.source
        if self.options.get("engines"):
            self._scan()

    def _scan(self) -> None:
        from services.analysis import hayabusa

        # an archive gives the engine its .evtx members, and a format it cannot read is said, not run
        staged, said = hayabusa.stage_upload(self.name, self.path, self.data, self.format, self.tmp_dir)
        if staged is None:
            self.summaries = [said]
            return
        try:
            self.findings, summary = self.run_engine(staged, self.tmp_dir)
        finally:
            shutil.rmtree(staged, ignore_errors=True)
        self.summaries = [hayabusa.finish(summary, said)]

    def entries(self) -> int:
        return len(self.source.files)

    def state(self) -> dict[str, Any]:
        stats = self.source.stats.to_dict()
        stats["files"] = self.source.files
        return {"format": self.format, "stats": stats, "engineSummaries": self.summaries}


class _MailWork(_Work):
    def __init__(self, spec: dict[str, Any], deadline: float | None, run_engine: Engine) -> None:
        from services.ingest.pipeline import MAX_MEMBER_BYTES, MailSource
        from services.parsers.mail.common import ParseContext

        super().__init__(spec, deadline, run_engine)
        o = self.options
        ctx = ParseContext(**(o.get("ctx") or {}))
        self.source = MailSource(self.name, self.path, self.data, ctx, self.tmp_dir, max_member=int(o.get("max_member") or MAX_MEMBER_BYTES), deadline=deadline)
        self.format = self.source.format

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.source)

    def entries(self) -> int:
        return len(self.source.members)

    def state(self) -> dict[str, Any]:
        return {"format": self.format, "stats": self.source.stats.to_dict(), "members": self.source.members}


class _PackageWork(_Work):
    def __init__(self, spec: dict[str, Any], deadline: float | None, run_engine: Engine) -> None:
        from services.ingest.package import PackageSource
        from services.parsers.mail.common import ParseContext

        super().__init__(spec, deadline, run_engine)
        o = self.options
        self.package = PackageSource(
            self.name,
            self.path,
            self.data,
            self.tmp_dir,
            ParseContext(**(o.get("ctx") or {})),
            bool(o.get("include_raw", True)),
            str(o.get("package_id") or ""),
            budget=o.get("budget"),
        )
        self.package.engines = list(o.get("engines") or [])
        self.package.filesystem = bool(o.get("filesystem"))
        self.package.run_engine = run_engine
        self.findings = self.package.findings
        self.format = self.package.format
        self._rows: Iterator[dict[str, Any]] | None = None

    def __iter__(self) -> Iterator[dict[str, Any]]:
        self._rows = iter(self.package)
        return self._rows

    def entries(self) -> int:
        return len(self.package.files)

    def state(self) -> dict[str, Any]:
        return {"format": self.format, "stats": self.package.stats(), "engineSummaries": self.package.engine_summaries}

    def stop(self) -> None:
        self.package.inventory_complete = False

    def close(self) -> None:
        # closing the iterator runs the package's own clean-up, which releases every artifact it
        # was holding back for group decoding
        if self._rows is not None:
            closer = getattr(self._rows, "close", None)
            if closer is not None:
                closer()


class _AttachmentWork(_Work):
    format = "attachment"

    def __init__(self, spec: dict[str, Any], deadline: float | None, run_engine: Engine) -> None:
        super().__init__(spec, deadline, run_engine)
        self.result: dict[str, Any] | None = None

    def __iter__(self) -> Iterator[dict[str, Any]]:
        from services.analysis.attachments.analyzer import analyze_attachment

        data = self.data if self.data is not None else Path(str(self.path)).read_bytes()
        self.result = analyze_attachment(self.name, data, self.options.get("content_type"))
        yield from ()

    def state(self) -> dict[str, Any]:
        return {"format": self.format, "result": self.result}


KINDS: dict[str, type[_Work]] = {"evtx": _EvtxWork, "mail": _MailWork, "package": _PackageWork, "attachment": _AttachmentWork}


def empty_state(kind: str, fmt: str) -> dict[str, Any]:
    """What a parse reports when it was stopped before it said anything about itself."""
    from services.parsers import evtx_parser

    if kind == "evtx":
        return {"format": fmt, "stats": {**evtx_parser.Stats().to_dict(), "files": []}, "engineSummaries": []}
    if kind == "mail":
        from services.ingest.pipeline import MailStats

        return {"format": fmt, "stats": MailStats().to_dict(), "members": []}
    if kind == "package":
        stats = {
            "count": 0,
            "events": 0,
            "mails": 0,
            "observations": 0,
            "eventRange": {"firstTs": None, "lastTs": None},
            "mailRange": {"firstTs": None, "lastTs": None},
            "files": [],
            "errors": 0,
            "unsupported": 0,
            "skipped": 0,
            "duplicates": 0,
            "inventoryComplete": False,
            "context": {},
            "reconciliation": [],
        }
        return {"format": fmt, "stats": stats, "engineSummaries": []}
    return {"format": fmt, "result": None}


def mark_stopped(kind: str, state: dict[str, Any], reason: str) -> dict[str, Any]:
    """A result cut short says so: one more error, and the members it was still reading or holding
    back carry the reason rather than looking as if they were never reached."""
    stats = state.get("stats")
    if not isinstance(stats, dict):
        return state
    if kind in ("evtx", "mail"):
        stats["errors"] = int(stats.get("errors") or 0) + 1
    elif kind == "package":
        stats["inventoryComplete"] = False
        for entry in stats.get("files") or []:
            if isinstance(entry, dict) and entry.get("status") == "pending":
                entry.update(status="error", reason=reason[:300])
        stats["errors"] = sum(1 for f in stats.get("files") or [] if isinstance(f, dict) and f.get("status") == "error")
    return state


def _engine_runner(deadline: float | None, notify: Callable[[], None] | None) -> Engine:
    """Hayabusa over a folder of event logs, never past the request's deadline."""

    def run(target: str, tmp_dir: str, *, deadline_s: float | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        from services.analysis import hayabusa

        if deadline is not None:
            remaining = max(1.0, deadline - time.monotonic())
            deadline_s = remaining if deadline_s is None else min(deadline_s, remaining)
        if notify is not None:
            notify()
        return hayabusa.run(target, tmp_dir, deadline_s=deadline_s)

    return run


# ---------------------------------------------------------------------------
# the server's side
# ---------------------------------------------------------------------------
def start(
    kind: str,
    *,
    name: str,
    path: str | None,
    data: bytes | None,
    tmp_dir: str,
    options: dict[str, Any],
    deadline: float | None = None,
    check: Callable[[], None] | None = None,
    notify: Callable[[], None] | None = None,
) -> LocalParse | IsolatedParse:
    """Begin one parse of uploaded evidence: in a child process, or in this one when
    FORENSIC_PARSE_ISOLATION is off. Either way the result is read the same way."""
    options = dict(options)
    ctx = options.get("ctx")
    if dataclasses.is_dataclass(ctx) and not isinstance(ctx, type):
        options["ctx"] = dataclasses.asdict(ctx)
    spec = {"kind": kind, "name": name, "path": path, "data": data, "tmp_dir": tmp_dir, "options": options}
    if not enabled():
        return LocalParse(kind, spec, deadline, notify)
    return IsolatedParse(kind, spec, deadline, check, notify)


class LocalParse:
    """A parse in the server process itself, as before isolation; for debugging only."""

    def __init__(self, kind: str, spec: dict[str, Any], deadline: float | None, notify: Callable[[], None] | None) -> None:
        self.kind = kind
        self._work = KINDS[kind](spec, deadline, _engine_runner(deadline, notify))
        self.format = self._work.format
        self._rows: Iterator[dict[str, Any]] | None = None

    def __iter__(self) -> Iterator[dict[str, Any]]:
        if self._rows is None:
            self._rows = iter(self._work)
        return self._rows

    @property
    def findings(self) -> list[dict[str, Any]]:
        return self._work.findings

    def entries(self) -> int:
        return self._work.entries()

    def stop(self) -> None:
        """Stop reading where the caller stopped: closing the rows runs the parse's own clean-up."""
        closer = getattr(self._rows, "close", None)
        if closer is not None:
            closer()

    def close(self) -> None:
        self.stop()
        self._work.close()

    def result(self, stopped: str | None = None) -> dict[str, Any]:
        if stopped:
            self._work.stop()
        state = self._work.state()
        return mark_stopped(self.kind, state, stopped) if stopped else state


_EOF = object()
_OVERLONG = object()


class IsolatedParse:
    """A parse in a child process, seen from the server.

    Iterating yields the child's rows as they come. The child is watched while that happens: past
    the deadline (with a short grace to stop on its own), past its memory limit, when the caller's
    check raises (a cancelled job) or when it sends something that is not a message, it is killed,
    and what it had sent is kept.
    """

    def __init__(
        self,
        kind: str,
        spec: dict[str, Any],
        deadline: float | None,
        check: Callable[[], None] | None,
        notify: Callable[[], None] | None,
    ) -> None:
        self.kind = kind
        self.findings: list[dict[str, Any]] = []
        self.rows = 0
        self._spec = spec
        self._deadline = deadline
        self._check = check
        self._run_engine = _engine_runner(deadline, notify)
        self._root = str(spec["tmp_dir"])
        self._format: str | None = None
        self._state: dict[str, Any] | None = None
        self._lockdown: dict[str, Any] = {}
        self._failure: BaseException | None = None
        self._ended = False
        self._closed = False
        self._member = ""
        self._memory = memory_limit()
        self._max_line = 64 * 1024**2 + 2 * int(getattr(settings, "FORENSIC_MAX_MESSAGE_MB", 256) or 256) * 1024**2
        self._queue: queue.Queue[Any] = queue.Queue()
        self._inflight = 0
        self._room = threading.Condition()
        self._watched = self._touched = time.monotonic()
        self._killed: Callable[[], BaseException] | None = None
        self._drain_until = 0.0
        self._proc: subprocess.Popen[bytes] | None = None
        self._monitor: psutil.Process | None = None
        self._reader: threading.Thread | None = None
        self._work = tempfile.mkdtemp(dir=self._root, suffix=WORK_SUFFIX)
        try:
            self._spawn()
        except BaseException:
            self.close()
            raise

    # -- start ------------------------------------------------------------
    def _spawn(self) -> None:
        account = parse_account()
        path = self._spec.get("path")
        if self._spec.get("data") is not None:
            # a small upload arrives in memory; the child reads it from a file in its own folder
            path = os.path.join(self._work, "upload")
            with open(path, "wb") as out:
                out.write(self._spec["data"])
        if account is not None:
            path = self._hand_over(path, account)
        deadline_s = None if self._deadline is None else max(0.0, self._deadline - time.monotonic())
        job = {
            "kind": self.kind,
            "name": self._spec["name"],
            "path": path,
            "tmp_dir": self._work,
            "options": self._spec["options"],
            "deadline_s": deadline_s,
            "limits": {"memory": self._memory, "cpu": cpu_limit()},
            "settings": _settings_for_child(),
        }
        command = [sys.executable, "-I", "-X", "utf8", "-c", _BOOT, ENTRY, BACKEND_DIR, *ENTRY_PATHS]
        kwargs: dict[str, Any] = {}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        else:
            # its own process group, so a kill reaches the decoders it starts as well
            kwargs["start_new_session"] = True
            if account is not None:
                kwargs.update(user=account[0], group=account[1], extra_groups=[])
        self._proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=child_env(self._work), cwd=self._work, **kwargs)
        try:
            self._monitor = psutil.Process(self._proc.pid)
        except psutil.Error:
            self._monitor = None
        self._reader = threading.Thread(target=self._read, name="remn-parse-reader", daemon=True)
        self._reader.start()
        self._send(job)

    def _hand_over(self, path: str | None, account: tuple[int, int]) -> str | None:
        """Give the parse account its folder and its evidence. The staging area must let it pass
        through to its own folder; the files in it stay private to the server account."""
        uid, gid = account
        root = os.stat(self._root)
        if not root.st_mode & 0o001:
            os.chmod(self._root, root.st_mode | 0o001)
        os.chown(self._work, uid, gid)
        os.chmod(self._work, 0o700)
        if path is None:
            return None
        inside = os.path.join(self._work, "upload")
        if os.path.abspath(path) != inside:
            try:
                os.link(path, inside)
            except OSError:
                shutil.copyfile(path, inside)
        os.chown(inside, uid, gid)
        return inside

    def _send(self, message: dict[str, Any]) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        self._proc.stdin.write(json.dumps(message, ensure_ascii=True, default=json_default, separators=(",", ":")).encode("ascii") + b"\n")
        self._proc.stdin.flush()

    # -- the child's output -------------------------------------------------
    def _read(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        stream = self._proc.stdout
        try:
            while True:
                line = stream.readline(self._max_line + 1)
                if not line:
                    break
                if len(line) > self._max_line or not line.endswith(b"\n"):
                    self._queue.put(_OVERLONG)
                    return
                with self._room:
                    while self._inflight and self._inflight + len(line) > INFLIGHT_BYTES and not self._closed:
                        self._room.wait(0.1)
                    if self._closed:
                        return
                    self._inflight += len(line)
                self._queue.put(line)
        except (OSError, ValueError):
            pass
        self._queue.put(_EOF)

    def _next(self, until: float | None = None) -> dict[str, Any] | None:
        """The child's next message. With an end time, None once it has passed and no limit is
        watched: the caller is already stopping the child."""
        while True:
            if until is None:
                self._watch()
            elif time.monotonic() >= until:
                return None
            try:
                item = self._queue.get(timeout=WATCH_S)
            except queue.Empty:
                continue
            if item is _EOF:
                if self._killed is not None:
                    raise self._killed()
                raise self._ended_early()
            if item is _OVERLONG:
                self._kill()
                raise self._stopped(f"the parse process sent a record longer than {self._max_line // 1024**2:,} MiB and was stopped")
            with self._room:
                self._inflight -= len(item)
                self._room.notify_all()
            try:
                message = json.loads(item)
            except ValueError:
                message = None
            if not isinstance(message, dict) or not isinstance(message.get("t"), str):
                self._kill()
                raise self._stopped("the parse process sent output that is not a record and was stopped")
            return message

    def _message(self) -> dict[str, Any]:
        message = self._next()
        assert message is not None
        return message

    def _watch(self) -> None:
        now = time.monotonic()
        if self._check is not None:
            self._check()
        if self._killed is not None:
            # what the child wrote before it was killed is still read, for a short while: a process
            # it started may hold its output open
            if now > self._drain_until:
                raise self._killed()
            return
        if self._deadline is not None and now > self._deadline + GRACE_S:
            self._kill_for(DeadlineExceeded)
            return
        if now - self._watched >= WATCH_S and self._monitor is not None and self._memory:
            self._watched = now
            try:
                used = _memory_used(self._monitor.memory_info())
            except psutil.Error:
                used = 0
            # Where the kernel holds the child's private memory to the limit this is a backstop, with
            # room for the shared libraries resident memory also counts; elsewhere it is the limit.
            ceiling = self._memory + (max(128 * 1024**2, self._memory // 4) if self._lockdown.get("memory") == "kernel" else 0)
            if used > ceiling:
                self._kill_for(
                    lambda: self._stopped(f"the parse process reached its {self._memory // 1024**2:,} MiB memory limit (FORENSIC_PARSE_MAX_MB) and was stopped")
                )
                return
        if now - self._touched >= 60:
            # the sweep goes by age: a parse that runs for hours keeps its folder
            self._touched = now
            with contextlib.suppress(OSError):
                os.utime(self._work)

    def _kill_for(self, reason: Callable[[], BaseException]) -> None:
        """Kill the child at a limit. The rows it sent before are still delivered, and the reason is
        raised once its output ends."""
        self._kill()
        self._killed = reason
        self._drain_until = time.monotonic() + 2.0

    # -- the parse --------------------------------------------------------
    @property
    def format(self) -> str:
        """The format the child detected. A child that failed before saying it reports "unknown",
        and the failure is raised when the rows are read."""
        if self._format is None:
            try:
                message = self._message()
                if message.get("t") != "hello":
                    self._kill()
                    raise self._stopped("the parse process sent output that is not a record and was stopped")
                self._format = str(message.get("format") or "unknown")
                lockdown = message.get("lockdown")
                self._lockdown = lockdown if isinstance(lockdown, dict) else {}
                _note_lockdown(self._lockdown)
            except BaseException as exc:  # noqa: BLE001
                self._format = "unknown"
                self._failure = exc
                if not isinstance(exc, Exception):
                    raise
        return self._format

    @property
    def lockdown(self) -> dict[str, Any]:
        """What the system enforced on the child, as it reported before reading any evidence."""
        _ = self.format
        return dict(self._lockdown)

    def __iter__(self) -> Iterator[dict[str, Any]]:
        try:
            _ = self.format
            if self._failure is not None:
                failure, self._failure = self._failure, None
                raise failure
            while not self._ended:
                message = self._message()
                kind = message["t"]
                if kind == "rows":
                    rows = message.get("rows")
                    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                        self._kill()
                        raise self._stopped("the parse process sent output that is not a record and was stopped")
                    if rows:
                        last = rows[-1]
                        self._member = str(last.get("sourceFile") or last.get("sourceName") or self._member)[:512]
                    for row in rows:
                        self.rows += 1
                        yield row
                elif kind == "state":
                    self._take_state(message.get("state"))
                elif kind == "engine":
                    self._engine(message)
                elif kind == "end":
                    self._end(message)
                else:
                    self._kill()
                    raise self._stopped("the parse process sent output that is not a record and was stopped")
        finally:
            if not self._ended:
                self.close()

    def _take_state(self, state: Any) -> None:
        if isinstance(state, dict) and isinstance(state.get("stats", {}), dict):
            self._state = state

    def _end(self, message: dict[str, Any]) -> None:
        self._ended = True
        self._take_state(message.get("state"))
        self.close()
        stop = message.get("stop")
        if not isinstance(stop, dict):
            return
        what = stop.get("kind")
        if what == "stopped":
            # the server asked for it and says why itself
            return
        if what == "deadline":
            raise DeadlineExceeded()
        if what == "memory":
            raise self._stopped(f"the parse reached its {self._memory // 1024**2:,} MiB memory limit (FORENSIC_PARSE_MAX_MB)")
        if what == "cpu":
            raise self._stopped(f"the parse reached its {cpu_limit():,} s processor-time limit (FORENSIC_PARSE_MAX_CPU_S)")
        type_name = str(stop.get("type") or "")
        cls = type(type_name if _IDENTIFIER.match(type_name) else "Exception", (ParseFailed,), {"__module__": __name__})
        raise cls(str(stop.get("message") or "")[:500])

    def _ended_early(self) -> ParseStopped:
        """The child went away without saying why: a crash, a kill by the system, or a limit the
        kernel enforces by killing."""
        assert self._proc is not None
        if os.name != "nt":
            # its output closed, so it has ended or broken the protocol: the decoders it started go
            # too, through its process group, whose id stays reserved until the child is reaped
            with contextlib.suppress(OSError):
                os.killpg(self._proc.pid, signal.SIGKILL)
        try:
            code = self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._kill()
            code = self._proc.returncode
        self.close()
        if os.name != "nt" and code is not None and code < 0:
            number = -code
            if number == getattr(signal, "SIGXCPU", None):
                why = f"reached its {cpu_limit():,} s processor-time limit (FORENSIC_PARSE_MAX_CPU_S)"
            elif number == signal.SIGKILL:
                why = "was killed by the system (its processor-time limit, or the machine running out of memory)"
            else:
                try:
                    why = f"ended on signal {signal.Signals(number).name}"
                except ValueError:
                    why = f"ended on signal {number}"
        else:
            why = f"ended unexpectedly (exit status {code if code is None or code < 1024 else hex(code)})"
        return self._stopped(f"the parse process {why}")

    def _stopped(self, what: str) -> ParseStopped:
        where = f" while reading {self._member}" if self._member else ""
        return ParseStopped(f"{what}{where}; the {self.rows:,} record(s) read before it are kept and the result is incomplete")

    def _engine(self, message: dict[str, Any]) -> None:
        """Run the detection engine for the child over the logs it staged. The engine runs here,
        under the server's own limit on how many runs share the machine; the logs are first moved
        out of the child's folder, and only regular files are taken."""
        from services.analysis import hayabusa

        summary: dict[str, Any] = {
            "engine": hayabusa.ENGINE,
            "status": "error",
            "findings": 0,
            "seconds": 0.0,
            "reason": "the logs staged for the engine were not found",
        }
        name = message.get("dir")
        source = os.path.join(self._work, name) if isinstance(name, str) and _NAME.match(name) and name not in (".", "..") else None
        target = tempfile.mkdtemp(dir=self._root, suffix=".evtx")
        try:
            taken = 0
            if source and os.path.isdir(source) and not os.path.islink(source):
                for entry in os.scandir(source):
                    if _NAME.match(entry.name) and entry.is_file(follow_symlinks=False):
                        os.rename(entry.path, os.path.join(target, entry.name))
                        taken += 1
            if taken:
                deadline_s = message.get("deadline_s")
                findings, summary = self._run_engine(target, self._root, deadline_s=float(deadline_s) if isinstance(deadline_s, (int, float)) else None)
                if self.kind == "package":
                    for finding in findings:
                        finding["packageId"] = self._spec["options"].get("package_id") or ""
                self.findings.extend(findings)
        except OSError as exc:
            summary["reason"] = f"{hayabusa.ENGINE} could not be given the logs ({type(exc).__name__})"
        finally:
            shutil.rmtree(target, ignore_errors=True)
        # a child that went away meanwhile is reported when its output ends
        with contextlib.suppress(OSError, ValueError):
            self._send({"t": "engine", "summary": summary})

    def stop(self) -> None:
        """Ask the child to stop where it is and to report what it read, because the caller stops
        reading its rows (its own deadline check, an error). Rows still on their way are dropped.
        A child that does not answer within the grace period is killed, and the last report it
        sent stands."""
        if self._ended or self._closed or self._proc is None:
            self.close()
            return
        # a child that has already ended cannot take the request, and its last report may still be
        # waiting to be read
        with contextlib.suppress(OSError, ValueError):
            self._send({"t": "stop"})
        try:
            until = time.monotonic() + GRACE_S
            while not self._ended:
                message = self._next(until)
                if message is None:
                    break
                kind = message["t"]
                if kind == "hello" and self._format is None:
                    self._format = str(message.get("format") or "unknown")
                elif kind == "state":
                    self._take_state(message.get("state"))
                elif kind == "engine":
                    with contextlib.suppress(OSError, ValueError):
                        self._send({"t": "engine", "summary": None})
                elif kind == "end":
                    self._ended = True
                    self._take_state(message.get("state"))
        except (ParseStopped, DeadlineExceeded):
            # the caller already has its reason to stop; this one came while it was stopping
            pass
        finally:
            self.close()

    def entries(self) -> int:
        state = self._state or {}
        stats = state.get("stats") or {}
        listed = stats.get("files") if self.kind != "mail" else state.get("members")
        return len(listed) if isinstance(listed, list) else 0

    def result(self, stopped: str | None = None) -> dict[str, Any]:
        state = self._state
        if state is None:
            state = empty_state(self.kind, self._format or "unknown")
            if isinstance(state.get("stats"), dict):
                state["stats"]["count"] = self.rows
        state.setdefault("format", self._format or "unknown")
        return mark_stopped(self.kind, state, stopped) if stopped else state

    # -- the end ----------------------------------------------------------
    def _kill(self) -> None:
        proc = self._proc
        # returncode is set once the child is reaped; until then its process group id is still its
        # own, so killing the group cannot reach anything else
        if proc is None or proc.returncode is not None:
            return
        # the decoders the child started go with it
        with contextlib.suppress(psutil.Error):
            for child in psutil.Process(proc.pid).children(recursive=True):
                with contextlib.suppress(psutil.Error):
                    child.kill()
        with contextlib.suppress(OSError):
            if os.name == "nt":
                proc.kill()
            else:
                os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=10)

    def close(self) -> None:
        """Stop the child if it still runs, and remove its folder. Safe to call more than once."""
        if self._closed:
            return
        self._closed = True
        proc = self._proc
        if proc is not None:
            self._kill()
            with self._room:
                self._room.notify_all()
            if self._reader is not None:
                self._reader.join(timeout=5)
            for stream in (proc.stdin, proc.stdout):
                with contextlib.suppress(OSError, ValueError):
                    if stream is not None:
                        stream.close()
        shutil.rmtree(self._work, ignore_errors=True)


def _memory_used(info: Any) -> int:
    """The memory a process holds: its resident size, and on Windows its committed private memory
    when that is larger. Resident size counts shared memory too, so a process cannot hide what it
    holds by sharing it with nobody."""
    return max(int(info.rss), int(getattr(info, "private", 0) or 0))


# ---------------------------------------------------------------------------
# the child's side
# ---------------------------------------------------------------------------
class _Channel:
    """The child's half of the protocol: rows in batches, other messages after the rows before them."""

    def __init__(self, out: Any) -> None:
        self._out = out
        self._lock = threading.Lock()
        self._rows: list[bytes] = []
        self._size = 0
        self._since = 0.0

    @staticmethod
    def encode(message: Any) -> bytes:
        # ASCII with escapes: a lone surrogate the parsers left in a string crosses intact
        return json.dumps(message, ensure_ascii=True, default=json_default, separators=(",", ":")).encode("ascii")

    def row(self, row: dict[str, Any]) -> None:
        data = self.encode(row)
        with self._lock:
            if not self._rows:
                self._since = time.monotonic()
            self._rows.append(data)
            self._size += len(data)
            if self._size >= BATCH_BYTES or len(self._rows) >= BATCH_ROWS:
                self._flush()

    def send(self, message: dict[str, Any]) -> None:
        data = self.encode(message)
        with self._lock:
            self._flush()
            self._out.write(data + b"\n")
            self._out.flush()

    def tick(self) -> None:
        with self._lock:
            if self._rows and time.monotonic() - self._since >= BATCH_S:
                self._flush()

    def _flush(self) -> None:
        if self._rows:
            self._out.write(b'{"t":"rows","rows":[' + b",".join(self._rows) + b"]}\n")
            self._out.flush()
            self._rows = []
            self._size = 0


class _StopRequested(Exception):
    """The server asked the child to stop."""


class _Inbox:
    """What the server sends the child after the job: a request to stop, and the answers to the
    engine runs the child asked for. Read on a thread of its own so the parse need not look."""

    def __init__(self, stream: Any) -> None:
        self.stopping = threading.Event()
        self.replies: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._stream = stream
        threading.Thread(target=self._read, name="remn-parse-inbox", daemon=True).start()

    def _read(self) -> None:
        while True:
            try:
                line = self._stream.readline(64 * 1024**2)
            except (OSError, ValueError):
                line = b""
            if not line:
                # the server went away: stop, and do not wait for an answer that cannot come
                self.stopping.set()
                self.replies.put(None)
                return
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if isinstance(message, dict) and message.get("t") == "stop":
                self.stopping.set()
                self.replies.put(None)
            elif isinstance(message, dict) and message.get("t") == "engine":
                self.replies.put(message)


def _lock_down(limits: dict[str, Any]) -> dict[str, Any]:
    """Apply what this system enforces without privileges, before any evidence is read, and say
    what took effect. Must run while the process has a single thread."""
    report: dict[str, Any] = {"memory": "watched by the server", "cpu": "none", "network": "not isolated", "account": "the server's"}
    # a network namespace of its own with nothing in it: no route anywhere, loopback included
    if hasattr(os, "unshare") and hasattr(os, "CLONE_NEWNET"):
        try:
            os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)
            report["network"] = "none (namespace)"
        except OSError as exc:
            report["network"] = f"not isolated: no unprivileged network namespace here ({exc.strerror or type(exc).__name__})"
    else:
        report["network"] = "not isolated: this system offers no unprivileged way"
    try:
        import resource
    except ImportError:
        resource = None  # type: ignore[assignment]
    if resource is not None:
        # a crash would otherwise write the evidence it held to disk
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        memory = int(limits.get("memory") or 0)
        if memory and sys.platform.startswith("linux"):
            # the private writable memory the process may map: allocations past it fail, and the
            # parse stops with a MemoryError rather than taking the machine
            try:
                resource.setrlimit(resource.RLIMIT_DATA, (memory, memory))
                report["memory"] = "kernel"
            except (ValueError, OSError):
                pass
        cpu = int(limits.get("cpu") or 0)
        if cpu and hasattr(resource, "RLIMIT_CPU"):
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + int(GRACE_S)))
                signal.signal(signal.SIGXCPU, _cpu_limit)
                report["cpu"] = "kernel"
            except (ValueError, OSError):
                pass
    if os.name == "posix":
        report["account"] = os.getuid()
    return report


def _cpu_limit(signum: int, frame: Any) -> None:
    raise CpuLimit()


def child_main(kinds: dict[str, type[_Work]] | None = None) -> None:
    """The child: read the job, lock down, parse, report, exit."""
    # the protocol gets the real stdout; anything a library prints goes to stderr instead
    out = os.fdopen(os.dup(1), "wb")
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    if os.name == "nt":
        import msvcrt

        msvcrt.setmode(out.fileno(), os.O_BINARY)
    job = json.loads(sys.stdin.buffer.readline(64 * 1024**2))
    settings.configure(**job["settings"])
    logging.config.dictConfig(settings.LOGGING)
    report = _lock_down(job.get("limits") or {})
    channel = _Channel(out)
    inbox = _Inbox(sys.stdin.buffer)
    reserve = bytearray(8 * 1024**2)  # given back on a MemoryError, so the report can still be sent

    def flusher() -> None:
        while True:
            time.sleep(BATCH_S)
            channel.tick()

    threading.Thread(target=flusher, name="remn-parse-flush", daemon=True).start()
    from services.analysis.attachments import yara_scan

    yara_scan.configure(settings.YARA_RULES_DIR)
    deadline = time.monotonic() + float(job["deadline_s"]) if job.get("deadline_s") is not None else None
    registry = kinds or KINDS
    work: _Work | None = None
    rows: Iterator[dict[str, Any]] | None = None
    stop: dict[str, Any] | None = None
    hello = False
    try:
        work = registry[job["kind"]](job, deadline, _remote_engine(channel, inbox))
        channel.send({"t": "hello", "format": work.format, "lockdown": report})
        hello = True
        entries, noted, cost = 0, time.monotonic(), 0.0
        rows = iter(work)
        for row in rows:
            channel.row(row)
            if inbox.stopping.is_set():
                raise _StopRequested()
            if deadline is not None and time.monotonic() > deadline:
                raise DeadlineExceeded()
            now = time.monotonic()
            since = now - noted
            if since >= max(20 * cost, STATE_MIN_S) and (since >= STATE_MAX_S or work.entries() != entries):
                entries = work.entries()
                channel.send({"t": "state", "state": work.state()})
                noted = time.monotonic()
                cost = noted - now
    except _StopRequested:
        stop = {"kind": "stopped"}
    except DeadlineExceeded:
        stop = {"kind": "deadline"}
    except MemoryError:
        del reserve
        stop = {"kind": "memory"}
    except CpuLimit:
        stop = {"kind": "cpu"}
    except Exception as exc:  # noqa: BLE001
        stop = {"kind": "error", "type": type(exc).__name__, "message": str(exc)[:500]}
    state = None
    if work is not None:
        try:
            if stop is not None:
                work.stop()
            closer = getattr(rows, "close", None)
            if closer is not None:
                closer()
            work.close()
            state = work.state()
        except (Exception, CpuLimit):  # noqa: BLE001
            state = None
    if not hello:
        channel.send({"t": "hello", "format": work.format if work is not None else "unknown", "lockdown": report})
    channel.send({"t": "end", "state": state, "stop": stop})
    out.flush()
    os._exit(0)


def _remote_engine(channel: _Channel, inbox: _Inbox) -> Engine:
    """In the child, the engine is asked of the server: it runs there, under the server's limit on
    how many engine runs share the machine, and the findings stay there."""

    def run(target: str, tmp_dir: str, *, deadline_s: float | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        summary = None
        if not inbox.stopping.is_set():
            channel.send({"t": "engine", "dir": os.path.basename(os.path.normpath(target)), "deadline_s": deadline_s})
            reply = inbox.replies.get()
            summary = reply.get("summary") if reply is not None else None
        if isinstance(summary, dict):
            return [], summary
        return [], {"engine": "hayabusa", "status": "error", "findings": 0, "seconds": 0.0, "reason": "not run: the parse was stopped"}

    return run
