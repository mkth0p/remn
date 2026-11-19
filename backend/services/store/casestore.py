"""
Server-side case store for gigabyte-scale evidence: one DuckDB file per case
under DATA_DIR/cases/<key>/case.duckdb. Column names are the same camelCase
keys the browser rows use, so the filter DSL, the rules and the AI prompts
work identically for browser-stored and server-stored cases.
"""

from __future__ import annotations

import atexit
import importlib.util
import json
import logging
import os
import re
import shutil
import sys
import threading
import time
import weakref
from collections.abc import Callable, Iterable
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb

# DuckDB probes for pandas while binding every "?" parameter. When pandas is not installed the
# failed import rescans sys.path on disk each time (about 90 stats per rule with list-heavy
# community rules, 50 ms instead of 6). A None entry makes that import fail instantly.
if "pandas" not in sys.modules and importlib.util.find_spec("pandas") is None:
    sys.modules["pandas"] = None  # type: ignore[assignment]
import pyarrow as pa

from services.parsers.evtx_parser import FIELD_MAP

log = logging.getLogger(__name__)

KEY_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")

# The layout of the store this code writes. It goes up by one, with a step in MIGRATIONS, when a
# store needs changing before this code can read it, or when an older REMN would misread a store
# this code wrote. A column added for new rows needs neither: an older store gets it when opened,
# and an older REMN does not read it.
SCHEMA_VERSION = 1


def _to_version_1(con: duckdb.DuckDBPyConnection) -> None:
    """Version 1 is the layout stores had when the version began to be recorded. A store written
    before reaches it with what every open does anyway, adding the tables and columns it lacks, so
    this step has nothing of its own to change."""


# MIGRATIONS[n] brings a store at version n - 1 to version n. The steps run in order, in the same
# transaction as the version they lead to, when the store is opened.
MIGRATIONS: dict[int, Callable[[duckdb.DuckDBPyConnection], None]] = {1: _to_version_1}


class StoreVersionError(RuntimeError):
    """A case store this version cannot read. It is refused before anything in it is changed."""


class StoreBusyError(RuntimeError):
    """A case store another program holds open (a backup, a restore, a second server on the same folder)."""


class QueryStopped(Exception):
    """A query on a store stopped at its time limit. The message says which limit and what to do."""


def schema_version(con: duckdb.DuckDBPyConnection) -> int | None:
    """The schema version a store records, or None when it records none: a new file, or a store
    written before the version was recorded."""
    if not con.execute("SELECT count(*) FROM duckdb_tables() WHERE schema_name = 'main' AND table_name = 'meta'").fetchone()[0]:
        return None
    row = con.execute("SELECT value FROM meta WHERE key = 'schema-version'").fetchone()
    if row is None:
        return None
    try:
        return int(row[0])
    except (TypeError, ValueError):
        raise StoreVersionError(
            f"this case store records a schema version this version of REMN cannot read ({str(row[0])[:40]!r}). It was not opened and nothing in it was changed."
        ) from None


def _held_elsewhere(exc: duckdb.Error) -> bool:
    """Whether opening a store failed because another connection holds the file."""
    text = str(exc)
    return "Could not set lock" in text or "different configuration" in text


_time_limit: ContextVar[TimeLimit | None] = ContextVar("store_time_limit", default=None)


class TimeLimit:
    """Stops the queries a block runs on case stores once `seconds` have passed, and raises
    QueryStopped with `message` ("{seconds}" in it is filled in). 0 or less is no limit.

    DuckDB has no statement timeout. A watcher interrupts every cursor that CaseStore.cursor() hands
    out inside the block, and repeats the interrupt until the block ends, since an interrupt that
    lands between two statements is cleared by the next one. A block inside another is watched by
    both."""

    def __init__(self, seconds: float, message: str) -> None:
        self.seconds = float(seconds or 0)
        self.message = message
        self.stopped = False
        self._cursors: list[duckdb.DuckDBPyConnection] = []
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._outer: TimeLimit | None = None
        self._token: Any = None

    def watch(self, con: duckdb.DuckDBPyConnection) -> duckdb.DuckDBPyConnection:
        limit: TimeLimit | None = self
        while limit is not None:
            with limit._lock:
                limit._cursors.append(con)
            limit = limit._outer
        return con

    def _interrupt(self) -> None:
        if self._done.wait(self.seconds):
            return
        self.stopped = True
        while True:
            with self._lock:
                cursors = list(self._cursors)
            for con in cursors:
                try:
                    con.interrupt()
                except duckdb.Error:
                    pass
            if self._done.wait(0.05):
                return

    def __enter__(self) -> TimeLimit:
        if self.seconds > 0:
            self._outer = _time_limit.get()
            self._token = _time_limit.set(self)
            threading.Thread(target=self._interrupt, name="store-time-limit", daemon=True).start()
        return self

    def __exit__(self, kind: type[BaseException] | None, exc: BaseException | None, tb: Any) -> None:
        if self._token is None:
            return
        self._done.set()
        _time_limit.reset(self._token)
        self._token = None
        if self.stopped and isinstance(exc, duckdb.InterruptException):
            raise QueryStopped(self.message.replace("{seconds}", f"{self.seconds:g}")) from exc


def settle(con: duckdb.DuckDBPyConnection) -> None:
    """Drop what is left of the connection's last result, so the next call may register a table.

    DuckDB 2 refuses register() while a result of execute() is unfinished, and fetchone() on a
    one-row answer leaves it unfinished. Before DuckDB 2 there is no abort() and nothing to drop.
    """
    abort = getattr(con, "abort", None)
    if abort is not None:
        abort()


# ---------------------------------------------------------------------------
# Schemas. (name, duckdb type, pyarrow type)
# ---------------------------------------------------------------------------
_S = ("VARCHAR", pa.string())
_I = ("INTEGER", pa.int32())
_L = ("BIGINT", pa.int64())
_B = ("BOOLEAN", pa.bool_())
_LS = ("VARCHAR[]", pa.list_(pa.string()))

EVENT_COLUMNS: list[tuple[str, tuple[str, Any]]] = [
    ("id", _L),
    ("evidenceId", _I),
    ("sourceFile", _S),
    ("recordKind", _S),
    ("artifactType", _S),
    ("observedAt", _L),
    ("processStart", _S),
    ("processEnd", _S),
    ("bootId", _S),
    ("packageId", _S),
    ("sourceSha256", _S),
    ("sourceIndex", _L),
    ("memberIndex", _I),
    ("parserVersion", _S),
    # a cloud record's own identity (UAL AuditData.Id, Graph sign-in id): a record already in
    # the case is not added again from a later export
    ("recordKey", _S),
    ("recordId", _L),
    ("ts", _L),
    ("tsIso", _S),
    ("eventId", _I),
    ("qualifiers", _I),
    ("version", _I),
    ("level", _I),
    ("levelName", _S),
    ("task", _I),
    ("opcode", _I),
    ("keywords", _S),
    ("provider", _S),
    ("providerGuid", _S),
    ("channel", _S),
    ("computer", _S),
    ("userSid", _S),
    ("processId", _I),
    ("threadId", _I),
    ("activityId", _S),
    ("category", _S),
    ("description", _S),
    ("summary", _S),
    ("targetUser", _S),
    ("targetDomain", _S),
    ("targetSid", _S),
    ("targetLogonId", _S),
    ("targetServer", _S),
    ("subjectUser", _S),
    ("subjectDomain", _S),
    ("subjectSid", _S),
    ("subjectLogonId", _S),
    ("logonType", _I),
    ("logonTypeName", _S),
    ("logonProcess", _S),
    ("authPackage", _S),
    ("elevatedToken", _S),
    ("keyLength", _I),
    ("ipAddress", _S),
    ("ipPort", _I),
    ("workstation", _S),
    ("sourceIp", _S),
    ("sourcePort", _I),
    ("status", _S),
    ("subStatus", _S),
    ("statusText", _S),
    ("failureReason", _S),
    ("processName", _S),
    ("newProcessId", _S),
    ("callerProcessId", _S),
    ("commandLine", _S),
    ("parentProcessName", _S),
    ("parentProcessId", _S),
    ("tokenElevationType", _S),
    ("serviceName", _S),
    ("serviceFile", _S),
    ("serviceType", _S),
    ("serviceStartType", _S),
    ("serviceAccount", _S),
    ("serviceState", _S),
    ("taskName", _S),
    ("taskContent", _S),
    ("memberName", _S),
    ("memberSid", _S),
    ("groupName", _S),
    ("groupDomain", _S),
    ("privilegeList", _S),
    ("shareName", _S),
    ("shareLocalPath", _S),
    ("relativeTargetName", _S),
    ("objectName", _S),
    ("objectType", _S),
    ("accessMask", _S),
    ("objectValueName", _S),
    ("newValue", _S),
    ("oldValue", _S),
    ("objectDn", _S),
    ("attributeName", _S),
    ("attributeValue", _S),
    ("ticketEncryption", _S),
    ("ticketOptions", _S),
    ("preAuthType", _S),
    ("scriptBlockText", _S),
    ("scriptBlockId", _S),
    ("path", _S),
    ("messageNumber", _I),
    ("messageTotal", _I),
    ("payload", _S),
    ("deceptionEpisodeId", _S),
    ("deceptionExhibitId", _S),
    ("deceptionParentExhibitId", _S),
    ("deceptionScope", _S),
    ("deceptionAction", _S),
    ("deceptionResult", _S),
    ("deceptionStage", _I),
    ("deviceDescription", _S),
    ("deviceId", _S),
    ("className", _S),
    ("previousTime", _S),
    ("newTime", _S),
    ("subcategoryGuid", _S),
    ("auditPolicyChanges", _S),
    ("channelCleared", _S),
    ("samAccountName", _S),
    ("displayName", _S),
    ("upn", _S),
    ("sessionId", _I),
    ("user", _S),
    ("reason", _S),
    ("param1", _S),
    ("param2", _S),
    ("param3", _S),
    ("param4", _S),
    ("image", _S),
    ("parentImage", _S),
    ("parentCommandLine", _S),
    ("originalFileName", _S),
    ("hashes", _S),
    ("currentDirectory", _S),
    ("integrityLevel", _S),
    ("processGuid", _S),
    ("parentProcessGuid", _S),
    ("destinationIp", _S),
    ("destinationPort", _I),
    ("destinationHostname", _S),
    ("sourceHostname", _S),
    ("protocol", _S),
    ("initiated", _S),
    ("query", _S),
    ("queryResults", _S),
    ("targetFilename", _S),
    ("targetObject", _S),
    ("details", _S),
    ("eventType", _S),
    ("imageLoaded", _S),
    ("signed", _S),
    ("signature", _S),
    ("signatureStatus", _S),
    # the source process's code signer on Sysmon 8 / 10, from its own image load (parsers/evtx_parser.py)
    ("sourceSigner", _S),
    ("sourceImage", _S),
    ("targetImage", _S),
    ("grantedAccess", _S),
    ("callTrace", _S),
    ("pipeName", _S),
    ("ruleName", _S),
    ("company", _S),
    ("product", _S),
    ("wmiConsumer", _S),
    ("wmiFilter", _S),
    ("wmiQuery", _S),
    ("operation", _S),
    ("name", _S),
    ("threatName", _S),
    ("severityName", _S),
    ("categoryName", _S),
    ("actionName", _S),
    ("detectionSource", _S),
    ("url", _S),
    ("action", _S),
    ("direction", _S),
    ("applicationPath", _S),
    ("message", _S),
    ("data", _S),
    ("raw", _S),
    # what the parser filled in from another event (evtx_parser.Lineage)
    ("enriched", _S),
]
# Every other field the EVTX parser puts on a row. A field without a column was dropped when the
# row was written, and the rules reading it (accessList, objectClass, startModule ... 65 converted
# Sigma rules) then gave other answers here than in the browser: a condition on it never matched,
# and one under `not` always did.
_PARSER_ONLY = sorted(set(FIELD_MAP.values()) - {n for n, _ in EVENT_COLUMNS} - {"dataList"})
EVENT_COLUMNS += [(n, _S) for n in _PARSER_ONLY]
# where the parser took each of those fields from, to fill them in on stores written before they had a column
PARSER_SOURCES: dict[str, list[str]] = {n: [k for k, v in FIELD_MAP.items() if v == n] for n in _PARSER_ONLY}
EVENT_INT = {n for n, t in EVENT_COLUMNS if t in (_I, _L)}

MAIL_COLUMNS: list[tuple[str, tuple[str, Any]]] = [
    ("sourceFile", _S),
    ("packageId", _S),
    ("sourceSha256", _S),
    ("memberIndex", _I),
    ("parserVersion", _S),
    ("recordKind", _S),
    ("id", _L),
    ("evidenceId", _I),
    ("sourceIndex", _I),
    ("sourceFormat", _S),
    ("sourceName", _S),
    ("folder", _S),
    ("subject", _S),
    ("date", _L),
    ("dateIso", _S),
    ("dateRaw", _S),
    ("fromName", _S),
    ("fromNameNorm", _S),
    ("fromAddr", _S),
    ("fromDomain", _S),
    ("fromRegistrable", _S),
    ("senderAddr", _S),
    ("replyToAddr", _S),
    ("replyToDomain", _S),
    ("replyToList", _LS),
    ("returnPath", _S),
    ("toList", _LS),
    ("ccList", _LS),
    ("bccList", _LS),
    ("recipientCount", _I),
    ("messageId", _S),
    ("inReplyTo", _S),
    ("xMailer", _S),
    ("priority", _S),
    ("listId", _S),
    ("originIp", _S),
    ("originIpSource", _S),
    ("originHelo", _S),
    ("originRdns", _S),
    ("hopCount", _I),
    ("totalDelayS", _I),
    ("spf", _S),
    ("dkim", _S),
    ("dmarc", _S),
    ("compauth", _S),
    ("textPreview", _S),
    ("urlCount", _I),
    ("attachmentCount", _I),
    ("maxAttachmentRisk", _I),
    ("risk", _I),
    ("flags", _LS),
    ("size", _L),
    ("contentType", _S),
    ("reputationWorst", _S),
    ("reputationOriginIp", _S),
    # sender baseline / campaign enrichment (services/analysis/baseline.py), NULL until the pass runs
    ("senderPrevalence", _S),
    ("senderPriorCount", _I),
    ("senderFirstSeen", _L),
    ("senderDaysKnown", _I),
    ("senderSolicited", _B),
    ("senderAuthRegression", _B),
    ("campaignId", _S),
    ("campaignSize", _I),
    ("campaignSenders", _I),
    # JSON payloads (stored as text, parsed on read)
    ("auth", _S),
    ("sender", _S),
    ("replyTo", _S),
    ("to", _S),
    ("cc", _S),
    ("bcc", _S),
    ("references", _S),
    ("hops", _S),
    ("urls", _S),
    ("attachments", _S),
    ("keywordHits", _S),
    ("hiddenText", _S),
    ("lookalike", _S),
    ("replyToLookalike", _S),
    ("htmlInfo", _S),
    ("reputation", _S),
    ("labels", _S),
    ("assessment", _S),
]
MAIL_INT = {n for n, t in MAIL_COLUMNS if t in (_I, _L)}
MAIL_BOOL = {n for n, t in MAIL_COLUMNS if t == _B}
MAIL_LIST = {n for n, t in MAIL_COLUMNS if t == _LS}
MAIL_JSON = {
    "auth",
    "sender",
    "replyTo",
    "to",
    "cc",
    "bcc",
    "references",
    "hops",
    "urls",
    "attachments",
    "keywordHits",
    "hiddenText",
    "lookalike",
    "replyToLookalike",
    "htmlInfo",
    "reputation",
    "labels",
    "assessment",
}

ATTACHMENT_COLUMNS: list[tuple[str, tuple[str, Any]]] = [
    ("id", _L),
    ("mailId", _L),
    ("evidenceId", _I),
    ("name", _S),
    ("ext", _S),
    ("realExt", _S),
    ("realMime", _S),
    ("size", _L),
    ("sha256", _S),
    ("md5", _S),
    ("risk", _I),
    ("flags", _LS),
    ("category", _S),
    ("inline", _B),
    ("details", _S),
    ("date", _L),
    ("fromAddr", _S),
    ("mailSubject", _S),
]
URL_COLUMNS: list[tuple[str, tuple[str, Any]]] = [
    ("id", _L),
    ("mailId", _L),
    ("evidenceId", _I),
    ("url", _S),
    ("normalized", _S),
    ("defanged", _S),
    ("host", _S),
    ("domain", _S),
    ("scheme", _S),
    ("flags", _LS),
    ("text", _S),
    ("source", _S),
    ("date", _L),
]
BODY_COLUMNS: list[tuple[str, tuple[str, Any]]] = [
    ("mailId", _L),
    ("bodyText", _S),
    ("bodyHtml", _S),
    ("headersText", _S),
    ("visibleText", _S),
]
IOC_COLUMNS: list[tuple[str, tuple[str, Any]]] = [
    ("kind", _S),
    ("value", _S),
    ("evidenceId", _I),
    ("count", _L),
    ("firstSeen", _L),
    ("lastSeen", _L),
    ("sources", _LS),
]

TABLES = {
    "events": EVENT_COLUMNS,
    "mails": MAIL_COLUMNS,
    "attachments": ATTACHMENT_COLUMNS,
    "urls": URL_COLUMNS,
    "mail_bodies": BODY_COLUMNS,
    "iocs": IOC_COLUMNS,
}
# No secondary ART indexes: they make bulk inserts an order of magnitude slower and DuckDB's
# zone maps + parallel scans already answer the analytical filters used here in well under a second.
INDEXES: list[str] = []


def q(name: str) -> str:
    """Quote a camelCase identifier."""
    return '"' + name.replace('"', '""') + '"'


def _ddl(table: str, columns: list[tuple[str, tuple[str, Any]]], pk: str | None = None) -> str:
    cols = ", ".join(f"{q(n)} {t[0]}" for n, t in columns)
    if pk:
        cols += f", PRIMARY KEY ({pk})"
    return f"CREATE TABLE IF NOT EXISTS {table} ({cols})"


def as_bool(value: Any) -> bool | None:
    """Preserve unknowns and parse serialized booleans without string truthiness."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        value = value.strip().lower()
        if value in ("true", "1"):
            return True
        if value in ("false", "0"):
            return False
        return None
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    return None


def _arrow_table(columns: list[tuple[str, tuple[str, Any]]], rows: list[dict[str, Any]]) -> pa.Table:
    """Build an Arrow table from sparse row dicts: absent columns become null arrays without per-row work."""
    n = len(rows)
    present: set[str] = set()
    for r in rows:
        present.update(r.keys())
    arrays = {}
    for name, (_, patype) in columns:
        if name not in present:
            arrays[name] = pa.nulls(n, type=patype)
            continue
        values = [r.get(name) for r in rows]
        try:
            arrays[name] = pa.array(values, type=patype)
        except (pa.ArrowInvalid, pa.ArrowTypeError, OverflowError, TypeError):
            # coerce defensively: numbers -> None when not castable, others -> str
            if patype in (pa.int32(), pa.int64()):
                fixed = []
                for v in values:
                    try:
                        fixed.append(int(v) if v not in (None, "") else None)
                    except (TypeError, ValueError):
                        fixed.append(None)
                arrays[name] = pa.array(fixed, type=patype)
            elif patype == pa.list_(pa.string()):
                arrays[name] = pa.array(
                    [[str(x) for x in (v or [])] if isinstance(v, (list, tuple)) else ([] if v is None else [str(v)]) for v in values], type=patype
                )
            elif patype == pa.bool_():
                arrays[name] = pa.array([as_bool(v) for v in values], type=patype)
            else:
                arrays[name] = pa.array([None if v is None else (v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)) for v in values], type=patype)
    return pa.table(arrays)


def _release(con: duckdb.DuckDBPyConnection, key: str) -> None:
    """Close a store's connection: its memory goes back and the file is free for another program."""
    try:
        con.close()
    except duckdb.Error as exc:
        log.debug("case store %s: close: %s", key, exc)


class CaseStore:
    """One DuckDB database per case. Writes are serialised with a lock; reads use per-call cursors.

    `memory_mb` and `threads` are what DuckDB may use for this store (threads 0: one fewer than the
    processors, between 2 and 8). The connection is closed by close(), or when nothing holds the
    store any more."""

    def __init__(self, root: Path, key: str, memory_mb: int = 2048, threads: int = 0) -> None:
        if not KEY_RE.match(key):
            raise ValueError("invalid case key")
        self.key = key
        self.dir = root / key
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "case.duckdb"
        self.lock = threading.RLock()
        try:
            self._con = duckdb.connect(str(self.path))
        except duckdb.Error as exc:
            if _held_elsewhere(exc):
                raise StoreBusyError(
                    "the case store is open in another program (a backup or restore with tools/store_backup.py, or a second REMN server on the "
                    "same folder), so it was not opened. Try again when that program has finished."
                ) from exc
            raise
        threads = threads if threads > 0 else max(2, min(8, (os.cpu_count() or 4) - 1))
        for statement in (f"SET threads TO {int(threads)}", f"SET memory_limit = '{int(memory_mb)}MiB'"):
            try:
                self._con.execute(statement)
            except duckdb.Error as exc:
                log.warning("case store %s: %s did not apply: %s", key, statement, exc)
        # the store never reads or writes files through SQL: block read_csv / COPY TO / ATTACH / extension
        # loading so the raw SQL endpoint and the analyst's `sql` tool cannot touch the server's filesystem.
        # The settings are read back, and a store whose lockdown did not take effect (a setting renamed
        # in a new engine version, say) is closed rather than opened without it. A statement may fail
        # with the lockdown in place: a second connection to a database this process has open shares
        # its configuration, already locked.
        for statement in ("SET enable_external_access = false", "SET lock_configuration = true"):
            try:
                self._con.execute(statement)
            except duckdb.Error as exc:
                log.debug("case store %s: %s: %s", key, statement, exc)
        try:
            applied = self._con.execute("SELECT current_setting('enable_external_access'), current_setting('lock_configuration')").fetchall()
        except duckdb.Error as exc:
            applied = [str(exc)]
        if applied != [(False, True)]:
            self._con.close()
            log.error("case store %s not opened: its lockdown did not take effect (%s)", key, applied)
            raise RuntimeError("case store not opened: its lockdown did not take effect")
        # a store this code cannot read, or whose upgrade fails, is closed rather than kept half-open
        try:
            self._init_schema()
            self._next: dict[str, int] = {}
            for t in ("events", "mails", "attachments", "urls"):
                self._next[t] = int(self._con.execute(f"SELECT coalesce(max(id), 0) FROM {t}").fetchone()[0]) + 1
        except BaseException:
            _release(self._con, key)
            raise
        self.last_used = time.time()
        self._closer = weakref.finalize(self, _release, self._con, key)

    def _init_schema(self) -> None:
        """Bring the store to SCHEMA_VERSION: check the version it records before anything is changed,
        then run the upgrade steps it needs and add the tables and columns it lacks, all in one
        transaction, and record what was done in the store and in the log."""
        con = self._con
        with self.lock:
            found = schema_version(con)
            if found is None and con.execute("SELECT count(*) FROM duckdb_tables() WHERE schema_name = 'main'").fetchone()[0]:
                found = 0  # written before the version was recorded
            if found is not None and found > SCHEMA_VERSION:
                raise StoreVersionError(
                    f"this case store was written by a newer version of REMN (store schema {found}; this version reads up to {SCHEMA_VERSION}). "
                    "It was not opened and nothing in it was changed. Run the version that wrote it, or restore the backup taken before that "
                    "version was installed (docs/setup.md, Backup and upgrade)."
                )
            added: dict[str, list[str]] = {}
            con.execute("BEGIN TRANSACTION")
            try:
                for step in range((found or 0) + 1, SCHEMA_VERSION + 1) if found is not None else ():
                    MIGRATIONS[step](con)
                for t, cols in TABLES.items():
                    con.execute(_ddl(t, cols, pk='kind, value, "evidenceId"' if t == "iocs" else ('"mailId"' if t == "mail_bodies" else None)))
                con.execute(
                    'CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY, name VARCHAR, kind VARCHAR, format VARCHAR, size BIGINT, "sha256Client" VARCHAR, "sha256Server" VARCHAR, count BIGINT, stats VARCHAR, "addedAt" BIGINT, status VARCHAR)'
                )
                con.execute(
                    'CREATE TABLE IF NOT EXISTS ioc_reputation (kind VARCHAR, value VARCHAR, verdict VARCHAR, tags VARCHAR[], summary VARCHAR, verdicts VARCHAR, "checkedAt" BIGINT, PRIMARY KEY (kind, value))'
                )
                con.execute("CREATE TABLE IF NOT EXISTS meta (key VARCHAR PRIMARY KEY, value VARCHAR)")
                # columns added after a store was created (enrichment passes): add them in place
                for t, cols in TABLES.items():
                    have = {r[1] for r in con.execute(f"PRAGMA table_info('{t}')").fetchall()}
                    for n, typ in cols:
                        if n not in have:
                            con.execute(f"ALTER TABLE {t} ADD COLUMN {q(n)} {typ[0]}")
                            added.setdefault(t, []).append(n)
                            if t == "events" and n in PARSER_SOURCES:
                                # rows written before the column existed: the same value from the EventData
                                src = ", ".join(f"nullif(trim(json_extract_string(data, '$.\"{k}\"')), '-')" for k in PARSER_SOURCES[n])
                                con.execute(f"UPDATE events SET {q(n)} = coalesce({src}) WHERE data IS NOT NULL")
                if found != SCHEMA_VERSION:
                    con.execute("INSERT OR REPLACE INTO meta VALUES ('schema-version', ?)", [str(SCHEMA_VERSION)])
                if found is not None and (found != SCHEMA_VERSION or added):
                    row = con.execute("SELECT value FROM meta WHERE key = 'schema-history'").fetchone()
                    history = json.loads(row[0]) if row else []
                    history.append({"from": found, "to": SCHEMA_VERSION, "at": datetime.now(UTC).isoformat(timespec="seconds"), "added": added})
                    con.execute("INSERT OR REPLACE INTO meta VALUES ('schema-history', ?)", [json.dumps(history)])
                con.execute("COMMIT")
            except BaseException:
                try:
                    con.execute("ROLLBACK")
                except duckdb.Error as exc:
                    log.debug("case store %s: rollback: %s", self.key, exc)
                raise
            if found is not None and found != SCHEMA_VERSION:
                log.info("case store %s upgraded from schema %d to %d", self.key, found, SCHEMA_VERSION)
            if found is not None and added:
                log.info("case store %s: columns added %s", self.key, added)
            for ddl in INDEXES:
                try:
                    con.execute(ddl)
                except duckdb.Error as exc:  # pragma: no cover
                    log.debug("index: %s", exc)

    # -- connections ---------------------------------------------------------
    def cursor(self) -> duckdb.DuckDBPyConnection:
        self.last_used = time.time()
        con = self._con.cursor()
        limit = _time_limit.get()
        return limit.watch(con) if limit is not None else con

    def close(self) -> None:
        with self.lock:
            self._closer()

    # -- ids ----------------------------------------------------------------
    def reserve_ids(self, table: str, n: int) -> int:
        with self.lock:
            start = self._next[table]
            self._next[table] = start + n
            return start

    # -- writes -------------------------------------------------------------
    def insert_rows(self, table: str, rows: list[dict[str, Any]]) -> int:
        if not rows:
            return 0
        columns = TABLES[table]
        tbl = _arrow_table(columns, rows)
        cols = ", ".join(q(n) for n, _ in columns)
        with self.lock:
            con = self._con
            settle(con)
            con.register("_batch", tbl)
            try:
                if table == "iocs":
                    con.execute(
                        f'INSERT INTO iocs ({cols}) SELECT {cols} FROM _batch ON CONFLICT (kind, value, "evidenceId") DO UPDATE SET '
                        'count = iocs.count + excluded.count, "firstSeen" = least(coalesce(iocs."firstSeen", excluded."firstSeen"), coalesce(excluded."firstSeen", iocs."firstSeen")), '
                        '"lastSeen" = greatest(coalesce(iocs."lastSeen", excluded."lastSeen"), coalesce(excluded."lastSeen", iocs."lastSeen")), '
                        "sources = list_distinct(list_concat(iocs.sources, excluded.sources))"
                    )
                elif table == "mail_bodies":
                    con.execute(f"INSERT OR REPLACE INTO mail_bodies ({cols}) SELECT {cols} FROM _batch")
                else:
                    con.execute(f"INSERT INTO {table} ({cols}) SELECT {cols} FROM _batch")
            finally:
                con.unregister("_batch")
        return len(rows)

    def existing_record_keys(self, keys: list[str]) -> set[str]:
        """The keys of ``keys`` some event of the case already carries."""
        if not keys:
            return set()
        with self.lock:
            rows = self._con.execute('SELECT DISTINCT "recordKey" FROM events WHERE "recordKey" IN (SELECT unnest(?::VARCHAR[]))', [keys]).fetchall()
        return {r[0] for r in rows}

    def upsert_evidence(self, ev: dict[str, Any]) -> None:
        with self.lock:
            self._con.execute(
                'INSERT OR REPLACE INTO evidence (id, name, kind, format, size, "sha256Client", "sha256Server", count, stats, "addedAt", status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    int(ev["id"]),
                    ev.get("name"),
                    ev.get("kind"),
                    ev.get("format"),
                    ev.get("size"),
                    ev.get("sha256Client"),
                    ev.get("sha256Server"),
                    ev.get("count"),
                    json.dumps(ev.get("stats")) if ev.get("stats") is not None else None,
                    ev.get("addedAt"),
                    ev.get("status"),
                ],
            )

    def delete_evidence(self, evidence_id: int) -> dict[str, int]:
        out: dict[str, int] = {}
        with self.lock:
            con = self._con
            for t in ("events", "attachments", "urls", "iocs"):
                out[t] = con.execute(f'SELECT count(*) FROM {t} WHERE "evidenceId" = ?', [evidence_id]).fetchone()[0]
                con.execute(f'DELETE FROM {t} WHERE "evidenceId" = ?', [evidence_id])
            out["mail_bodies"] = con.execute(
                'SELECT count(*) FROM mail_bodies WHERE "mailId" IN (SELECT id FROM mails WHERE "evidenceId" = ?)', [evidence_id]
            ).fetchone()[0]
            con.execute('DELETE FROM mail_bodies WHERE "mailId" IN (SELECT id FROM mails WHERE "evidenceId" = ?)', [evidence_id])
            out["mails"] = con.execute('SELECT count(*) FROM mails WHERE "evidenceId" = ?', [evidence_id]).fetchone()[0]
            con.execute('DELETE FROM mails WHERE "evidenceId" = ?', [evidence_id])
            out["evidence"] = con.execute("SELECT count(*) FROM evidence WHERE id = ?", [evidence_id]).fetchone()[0]
            con.execute("DELETE FROM evidence WHERE id = ?", [evidence_id])
            # write the deletes out and fold the WAL: the rows are gone from disk now, not at the next
            # automatic checkpoint, and the freed blocks are reused by the next ingestion
            con.execute("CHECKPOINT")
        try:
            out["bytes"] = self.path.stat().st_size
        except OSError:
            pass
        return out

    def set_reputation(self, items: list[dict[str, Any]]) -> int:
        n = 0
        with self.lock:
            for it in items:
                self._con.execute(
                    'INSERT OR REPLACE INTO ioc_reputation (kind, value, verdict, tags, summary, verdicts, "checkedAt") VALUES (?, ?, ?, ?, ?, ?, ?)',
                    [
                        it["kind"],
                        it["value"],
                        it.get("verdict"),
                        list(it.get("tags") or []),
                        json.dumps(it.get("summary")),
                        json.dumps(it.get("verdicts")),
                        it.get("checkedAt"),
                    ],
                )
                n += 1
        return n

    def apply_mail_enrichment(self, rows: list[dict[str, Any]]) -> int:
        """UPDATE mails with the enrichment columns of services/analysis/baseline.py (rows keyed by id)."""
        if not rows:
            return 0
        from services.analysis.baseline import ENRICH_COLUMNS

        types = dict(MAIL_COLUMNS)
        schema = pa.schema([("id", pa.int64())] + [(c, types[c][1]) for c in ENRICH_COLUMNS])
        norm = [{"id": int(r["id"]), **{c: r.get(c) for c in ENRICH_COLUMNS}} for r in rows]
        table = pa.Table.from_pylist(norm, schema=schema)
        sets = ", ".join(f"{q(c)} = e.{q(c)}" for c in ENRICH_COLUMNS)
        with self.lock:
            con = self._con
            settle(con)
            con.register("_enrich", table)
            try:
                con.execute(f"UPDATE mails SET {sets} FROM _enrich e WHERE mails.id = e.id")
            finally:
                con.unregister("_enrich")
        return len(norm)

    def mirror_reputation_to_mails(self) -> int:
        """Copy the worst verdict of related IOCs onto mails (reputationWorst / reputationOriginIp) for the rules."""
        with self.lock:
            con = self._con
            con.execute("""
                UPDATE mails SET "reputationOriginIp" = r.verdict
                FROM ioc_reputation r WHERE r.kind = 'ip' AND r.value = lower(mails."originIp") AND r.verdict IN ('malicious', 'suspicious', 'clean')
            """)
            # Verdicts are ranked as numbers: max() over the labels themselves is alphabetical,
            # which put 'suspicious' above 'malicious' on a mail that has both.
            con.execute("""
                UPDATE mails SET "reputationWorst" = sub.worst FROM (
                    SELECT m.id, CASE max(CASE r.verdict WHEN 'malicious' THEN 3 WHEN 'suspicious' THEN 2 ELSE 1 END)
                        WHEN 3 THEN 'malicious' WHEN 2 THEN 'suspicious' ELSE 'clean' END AS worst
                    FROM mails m
                    JOIN ioc_reputation r ON (
                        (r.kind = 'ip' AND r.value = lower(m."originIp"))
                        OR (r.kind = 'domain' AND r.value = lower(m."fromRegistrable"))
                        OR (r.kind = 'url' AND r.value IN (SELECT lower(coalesce(u.normalized, u.url)) FROM urls u WHERE u."mailId" = m.id))
                        OR (r.kind = 'domain' AND r.value IN (SELECT lower(u.domain) FROM urls u WHERE u."mailId" = m.id))
                        OR (r.kind = 'hash' AND r.value IN (SELECT lower(a.sha256) FROM attachments a WHERE a."mailId" = m.id))
                    )
                    WHERE r.verdict IN ('malicious', 'suspicious', 'clean')
                    GROUP BY m.id
                ) sub WHERE mails.id = sub.id
            """)
            return con.execute('SELECT count(*) FROM mails WHERE "reputationWorst" IS NOT NULL').fetchone()[0]

    # -- reads --------------------------------------------------------------
    def counts(self) -> dict[str, int]:
        cur = self.cursor()
        out = {}
        for t in ("events", "mails", "attachments", "urls"):
            out[t] = int(cur.execute(f"SELECT count(*) FROM {t}").fetchone()[0])
        out["iocs"] = int(cur.execute("SELECT count(*) FROM (SELECT DISTINCT kind, value FROM iocs)").fetchone()[0])
        return out

    def size_bytes(self) -> int:
        try:
            return sum(p.stat().st_size for p in self.dir.iterdir() if p.is_file())
        except OSError:
            return 0


class StoreRegistry:
    """The open stores, one per case. A store unused for `idle_s` seconds is let go: it is closed as
    soon as no request or job holds it any more, and a later get() opens it again. One still held is
    handed out again rather than opened a second time, so a file never has two stores."""

    def __init__(self) -> None:
        self.root: Path | None = None
        self.memory_mb = 2048
        self.threads = 0
        self.idle_s = 600
        self._stores: dict[str, CaseStore] = {}
        self._let_go: weakref.WeakValueDictionary[str, CaseStore] = weakref.WeakValueDictionary()
        self._lock = threading.Lock()
        self._sweeper: threading.Thread | None = None
        self._stop = threading.Event()
        _registries.add(self)

    def configure(self, root: Path, *, memory_mb: int | None = None, threads: int | None = None, idle_s: float | None = None) -> None:
        """Where the stores live, and the limits of the stores opened from now on (None keeps the current one)."""
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        if memory_mb is not None:
            self.memory_mb = memory_mb
        if threads is not None:
            self.threads = threads
        if idle_s is not None:
            self.idle_s = idle_s

    def get(self, key: str, create: bool = True) -> CaseStore:
        if self.root is None:
            raise RuntimeError("store not configured")
        if not KEY_RE.match(key or ""):
            raise ValueError("invalid case key")
        with self._lock:
            st = self._stores.get(key) or self._let_go.get(key)
            if st is None:
                if not create and not (self.root / key / "case.duckdb").exists():
                    raise FileNotFoundError(key)
                st = CaseStore(self.root, key, memory_mb=self.memory_mb, threads=self.threads)
            self._stores[key] = st
            self._let_go.pop(key, None)
            st.last_used = time.time()
            idle = self._take_idle(time.time())
            self._start_sweeper()
        # the stores let go are released here, outside the lock: closing one may write out its log
        del idle
        return st

    def _take_idle(self, now: float) -> list[CaseStore]:
        """Move the stores unused for idle_s out of the held set; the caller drops the list outside the lock."""
        if self.idle_s <= 0:
            return []
        idle = [st for st in self._stores.values() if now - st.last_used >= self.idle_s]
        for st in idle:
            del self._stores[st.key]
            self._let_go[st.key] = st
        return idle

    def evict_idle(self, now: float | None = None) -> int:
        """Let go of the stores unused for idle_s; the number let go."""
        with self._lock:
            idle = self._take_idle(time.time() if now is None else now)
        return len(idle)

    def _start_sweeper(self) -> None:
        """A thread that lets idle stores go without waiting for the next request (called with the
        lock held). It holds the registry weakly and ends once no store is held, so a registry
        dropped is not kept alive by it."""
        if self.idle_s <= 0 or self._sweeper is not None:
            return
        ref, every = weakref.ref(self), max(0.5, min(60.0, self.idle_s / 2))
        stop = self._stop = threading.Event()

        def sweep() -> None:
            while not stop.wait(every):
                reg = ref()
                if reg is None:
                    return
                reg.evict_idle()
                with reg._lock:
                    if not reg._stores:
                        reg._sweeper = None
                        return
                del reg

        self._sweeper = threading.Thread(target=sweep, name="store-sweeper", daemon=True)
        self._sweeper.start()

    def exists(self, key: str) -> bool:
        return bool(self.root) and KEY_RE.match(key or "") is not None and (self.root / key / "case.duckdb").exists()

    def delete(self, key: str) -> bool:
        if not KEY_RE.match(key or ""):
            raise ValueError("invalid case key")
        with self._lock:
            st = self._stores.pop(key, None) or self._let_go.pop(key, None)
            if st:
                st.close()
        target = (self.root or Path(".")) / key
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=True)
            return True
        return False

    def list(self) -> list[dict[str, Any]]:
        if not self.root or not self.root.is_dir():
            return []
        out = []
        for d in self.root.iterdir():
            if d.is_dir() and KEY_RE.match(d.name) and (d / "case.duckdb").exists():
                size = sum(p.stat().st_size for p in d.iterdir() if p.is_file())
                out.append({"key": d.name, "sizeBytes": size, "modified": int(max(p.stat().st_mtime for p in d.iterdir() if p.is_file()) * 1000)})
        return out

    def close_all(self) -> None:
        with self._lock:
            for st in [*self._stores.values(), *self._let_go.values()]:
                st.close()
            self._stores.clear()
            self._let_go.clear()
            self._stop.set()
            self._sweeper = None


_registries: weakref.WeakSet[StoreRegistry] = weakref.WeakSet()


@atexit.register
def _stop_sweepers() -> None:
    """End the sweeper threads before the interpreter ends. A daemon thread still waiting at exit
    keeps this module, and DuckDB with it, alive past the end, and DuckDB then reports a leak."""
    for reg in list(_registries):
        reg._stop.set()
        sweeper = reg._sweeper
        if sweeper is not None:
            sweeper.join(timeout=2)


registry = StoreRegistry()


def rows_to_dicts(cur: duckdb.DuckDBPyConnection, json_columns: Iterable[str] = ()) -> list[dict[str, Any]]:
    names = [d[0] for d in cur.description]
    jc = set(json_columns)
    out = []
    for rec in cur.fetchall():
        row = {}
        for name, value in zip(names, rec):
            if name in jc and isinstance(value, str):
                try:
                    value = json.loads(value)
                except ValueError:
                    pass
            row[name] = value
        out.append(row)
    return out
