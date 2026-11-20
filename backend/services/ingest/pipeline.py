"""
Shared ingestion pipeline: format detection, archive walking (zip / tar of
EVTX files or mail corpora), mail statistics. Used by the NDJSON streaming
views (browser storage) and by the server-store jobs.
"""

from __future__ import annotations

import bz2
import contextlib
import gzip
import io
import logging
import lzma
import os
import re
import tarfile
import tempfile
import time
import zipfile
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any

from services.common import AnalystMessage, sha256_file
from services.ingest.staging import member_ceiling
from services.parsers import evtx_parser, m365

# The mail parsers are imported where mail is read. They bring the attachment analyser, the URL
# and look-alike checks, tldextract and requests, about half the start of a parse process, which
# a parse of event logs does not need.
if TYPE_CHECKING:
    from services.parsers.mail.common import ParseContext

log = logging.getLogger(__name__)

_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_PST = b"!BDN"
_EVTX = b"ElfFile\x00"
MAX_MEMBER_BYTES = 4 * 1024 * 1024 * 1024
_HEADER_LINE = re.compile(rb"^[A-Za-z][A-Za-z0-9-]{1,40}:\s")
_MAIL_MARKERS = (b"\nFrom:", b"\nSubject:", b"\nReceived:", b"\nMessage-ID:", b"\nMessage-Id:", b"\nTo:", b"\nDate:", b"\nReturn-Path:")


def looks_like_mail(head: bytes) -> bool:
    h = head.lstrip()[:4096]
    if not h:
        return False
    if h.startswith(b"From ") and b"\n" in h:
        return True
    first = h.split(b"\n", 1)[0]
    if not _HEADER_LINE.match(first):
        return False
    return sum(1 for m in _MAIL_MARKERS if m in b"\n" + h) >= 2


def detect_archive(name: str, head: bytes) -> str | None:
    n = (name or "").lower()
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b") or n.endswith((".tar.gz", ".tgz")):
        return "tar"
    if head.startswith(b"BZh") or n.endswith((".tar.bz2", ".tbz2")):
        return "tar"
    if head.startswith(b"\xfd7zXZ\x00") or n.endswith((".tar.xz", ".txz")):
        return "tar"
    if n.endswith(".tar") or (len(head) > 262 and head[257:262] == b"ustar"):
        return "tar"
    return None


def detect_mail_format(name: str, head: bytes) -> str:
    n = (name or "").lower()
    arc = detect_archive(name, head)
    if arc:
        return arc
    if head.startswith(_PST):
        return "pst"
    if head.startswith(_OLE):
        return "msg"
    from services.parsers.mail import mbox as mbox_mod

    if mbox_mod.looks_like_mbox(head) or n.endswith((".mbox", ".mbx")):
        return "mbox"
    if n.endswith((".pst", ".ost")):
        return "pst"
    if n.endswith(".msg"):
        return "msg"
    return "eml"


# how much of a file the format is told from: a Unified Audit Log record whose keys are in
# alphabetical order (as Splunk and some exporters write them) names its Operation well past the
# first kilobyte
SNIFF_BYTES = 64 * 1024


UNRECOGNISED = "unrecognised"


def detect_evtx_format(name: str, head: bytes) -> str:
    arc = detect_archive(name, head)
    if arc:
        return arc
    if evtx_parser.looks_like_event_xml(head):
        return evtx_parser.XML_FORMAT
    fmt = m365.detect_format(name, head)
    if fmt:
        return fmt
    # a table or a JSON document that is none of the cloud exports is not an event log either:
    # read as one, it failed on the EVTX header and the analyst was told the wrong thing
    return UNRECOGNISED if m365.looks_like_export(name, head) and not head.startswith(_EVTX) else "evtx"


# ---------------------------------------------------------------------------
# archive walking
# ---------------------------------------------------------------------------
class Member:
    """A file inside an archive, opened lazily."""

    def __init__(self, name: str, size: int, opener: Callable[[], io.BufferedIOBase]) -> None:
        self.name = name
        self.size = size
        self._opener = opener

    def open(self) -> io.BufferedIOBase:
        return self._opener()

    def read(self) -> bytes:
        with self.open() as fh:
            return fh.read()


# an archive may expand to at most this many times its own size. Collections and mail archives
# expand a few to twenty times; empty event logs and zero-padded artifacts take a small part of
# one much further, so the ratio is judged over the whole archive, and only past RATIO_FLOOR,
# below which nothing costs much to read. A CAB has its own ratio in the native worker.
MAX_RATIO = 200
RATIO_FLOOR = 64 * 1024**2
# the name under which a walk that stopped early reports the members it could not list
REST_OF_ARCHIVE = "(rest of archive)"


class ExpansionLimit(ValueError):
    """An archive expanded, or would expand, past what its own size allows."""


class Expansion:
    """What one archive has expanded to so far, against what its size allows."""

    def __init__(self, compressed: int) -> None:
        self.limit = max(RATIO_FLOOR, MAX_RATIO * compressed)
        self.used = 0
        self.reason = f"the archive expands past {MAX_RATIO} times its own size ({self.limit / 2**20:,.0f} MiB)"

    def fits(self, size: int) -> bool:
        return self.used + size <= self.limit

    def charge(self, n: int) -> None:
        self.used += n
        if self.used > self.limit:
            raise ExpansionLimit(self.reason)


class _Walk:
    """The decompressed stream of a compressed tar, charged for every byte it decompresses: those
    read, those passed over to reach the next header, and those decompressed again when a reader
    goes back. A tar reader skips a member it does not read by decompressing all of it, so this is
    what bounds a walk over a member that declares terabytes. The last mebibyte is kept, so taking
    the head of a member to sniff it and then copying it from its start costs nothing more."""

    WINDOW = 1024**2

    def __init__(self, raw: Any, expansion: Expansion) -> None:
        self._raw = raw
        self._expansion = expansion
        self._pos = 0  # where the reader is
        self._end = 0  # how far the stream has been decompressed
        self._kept = b""  # the bytes just before _end

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence not in (io.SEEK_SET, io.SEEK_CUR):
            raise io.UnsupportedOperation("a tar walk seeks from the start or the current position")
        target = offset if whence == io.SEEK_SET else self._pos + offset
        if self._end - len(self._kept) <= target <= self._end:
            self._pos = target
            return target
        # going forward decompresses what lies between; going back further than what is kept
        # decompresses everything again from the start
        if not self._expansion.fits(target - self._end if target > self._end else target):
            raise ExpansionLimit(self._expansion.reason)
        self._raw.seek(target)
        self._expansion.charge(target - self._end if target > self._end else target)
        self._pos = self._end = self._raw.tell()
        self._kept = b""
        return self._pos

    def read(self, size: int = -1) -> bytes:
        out = b""
        if self._pos < self._end:
            start = len(self._kept) - (self._end - self._pos)
            out = self._kept[start : None if size < 0 else start + size]
            self._pos += len(out)
            if size >= 0:
                size -= len(out)
                if size == 0:
                    return out
        if size < 0:
            size = self._expansion.limit - self._expansion.used + 1
        if not self._expansion.fits(size):
            raise ExpansionLimit(self._expansion.reason)
        data = self._raw.read(size)
        self._expansion.charge(len(data))
        self._kept = (self._kept + data)[-self.WINDOW :]
        self._pos = self._end = self._end + len(data)
        return out + data


def _decompressing(src: Any) -> Any:
    """The decompressed stream of a gzip, bz2 or xz file, or None for anything else."""
    head = src.read(6)
    src.seek(0)
    if head.startswith(b"\x1f\x8b"):
        return gzip.GzipFile(fileobj=src)
    if head.startswith(b"BZh"):
        return bz2.BZ2File(src)
    if head.startswith(b"\xfd7zXZ\x00"):
        return lzma.LZMAFile(src)
    return None


@contextlib.contextmanager
def open_tar(path: str | None, data: bytes | None) -> Iterator[tuple[tarfile.TarFile, Expansion]]:
    """A tar archive opened for walking, with what the walk has cost so far. A compressed one is
    read through a stream that charges everything it decompresses to the archive's expansion
    allowance; a plain one costs no more than the bytes read, which its member sizes bound."""
    with open(path, "rb") if path else io.BytesIO(data or b"") as src:
        walk = Expansion(os.fstat(src.fileno()).st_size if path else len(data or b""))
        raw = _decompressing(src)
        if raw is None:
            with tarfile.open(fileobj=src, mode="r:") as tf:
                yield tf, walk
            return
        with raw, tarfile.open(fileobj=_Walk(raw, walk), mode="r:") as tf:  # type: ignore[call-overload]
            yield tf, walk


class DeadlineExceeded(Exception):
    """The request's parse time (FORENSIC_INGEST_MAX_S) ran out between archive members."""


def check_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() > deadline:
        raise DeadlineExceeded()


def skip_record(skipped: list[dict[str, Any]] | None, name: str, size: int, reason: str) -> None:
    """Note a member that was not read, so the stream can say what it left out and why."""
    if skipped is not None:
        skipped.append({"name": name[:512], "size": size, "status": "skipped", "reason": reason})


def iter_archive(
    path: str | None,
    data: bytes | None,
    kind: str,
    skipped: list[dict[str, Any]] | None = None,
    max_member: int = MAX_MEMBER_BYTES,
    deadline: float | None = None,
) -> Iterator[Member]:
    """Yield members of a zip or tar(.gz/.bz2/.xz) archive. Directories are passed over; members
    that are too large, encrypted or compressed with an unsupported method are recorded in skipped,
    as are those past the archive's expansion allowance. A member is never larger than half what
    the staging area may hold, whatever max_member says."""
    max_member = min(max_member, member_ceiling())
    limit = f"larger than the {max_member // 2**20} MiB per-member limit"
    if kind == "zip":
        zf = zipfile.ZipFile(path) if path else zipfile.ZipFile(io.BytesIO(data or b""))
        # zipfile writes no more of a member than it declares, so the declared sizes bound what
        # reading the members can expand to
        expansion = Expansion(os.path.getsize(path) if path else len(data or b""))
        with zf:
            for zi in zf.infolist():
                check_deadline(deadline)
                if zi.is_dir():
                    continue
                if zi.file_size > max_member:
                    skip_record(skipped, zi.filename, zi.file_size, limit)
                    continue
                if zi.flag_bits & 0x1:
                    skip_record(skipped, zi.filename, zi.file_size, "encrypted")
                    continue
                if zi.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    # zipfile expands bzip2 and LZMA members without an output bound
                    skip_record(skipped, zi.filename, zi.file_size, f"compression method {zi.compress_type} is not read")
                    continue
                if not expansion.fits(zi.file_size):
                    skip_record(skipped, zi.filename, zi.file_size, f"{expansion.reason}; not read")
                    continue
                expansion.charge(zi.file_size)
                yield Member(zi.filename, zi.file_size, lambda zi=zi: zf.open(zi))  # type: ignore[misc]
    elif kind == "tar":
        with open_tar(path, data) as (tf, walk):
            try:
                for m in tf:
                    check_deadline(deadline)
                    if m.isdir():
                        continue
                    if not m.isfile():
                        skip_record(skipped, m.name, 0, "not a regular file (link or device)")
                        continue
                    if m.size > max_member:
                        skip_record(skipped, m.name, m.size, limit)
                        continue
                    if not walk.fits(m.size):
                        skip_record(skipped, m.name, m.size, f"{walk.reason}; not read")
                        continue
                    yield Member(m.name, m.size, lambda m=m: tf.extractfile(m))  # type: ignore[misc,return-value]
            except ExpansionLimit as exc:
                # passing over a member decompresses it, so a walk past the allowance cannot list more
                skip_record(skipped, REST_OF_ARCHIVE, 0, f"{exc}; the members after this point were not listed")
    else:
        raise ValueError(f"not an archive: {kind}")


def member_to_tempfile(member: Member, tmp_dir: str, suffix: str = ".member") -> tuple[str, str]:
    """Copy an archive member to a temp file (parsers that need a path). Returns (path, sha256)."""
    import hashlib

    h = hashlib.sha256()
    fd, tmp_path = tempfile.mkstemp(suffix=suffix, dir=tmp_dir)
    with os.fdopen(fd, "wb") as out, member.open() as src:
        while True:
            chunk = src.read(4 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            out.write(chunk)
    return tmp_path, h.hexdigest()


# ---------------------------------------------------------------------------
# EVTX
# ---------------------------------------------------------------------------
class EvtxSource:
    """Iterates events from a single EVTX, event records exported as XML, a cloud export, or an
    archive of them, tagging rows with sourceFile."""

    def __init__(
        self,
        name: str,
        path: str | None,
        data: bytes | None,
        tmp_dir: str,
        include_raw: bool = True,
        max_member: int = MAX_MEMBER_BYTES,
        deadline: float | None = None,
        seen: m365.RecordKeys | None = None,
        dates: m365.DateSetting | None = None,
    ) -> None:
        self.name = name
        self.path = path
        self.data = data
        self.tmp_dir = tmp_dir
        self.include_raw = include_raw
        self.max_member = max_member
        self.deadline = deadline
        self.stats = evtx_parser.Stats()
        # the date order and time zone the analyst set for this evidence, for the cloud exports in it
        self.dates = dates
        if dates is not None:
            self.stats.dates = dates.to_dict()
        # one entry per archive member: parsed (with its count and hash), skipped or error, with the reason
        self.files: list[dict[str, Any]] = []
        # the keys of the cloud records read so far, for every file of this upload (a package
        # passes its own set, shared by all its members)
        self.seen_records = m365.RecordKeys() if seen is None else seen
        head = (data or b"")[:SNIFF_BYTES] if data is not None else _read_head(path, SNIFF_BYTES)
        self.format = detect_evtx_format(name, head)

    def __iter__(self) -> Iterator[dict[str, Any]]:
        if self.format in ("evtx", evtx_parser.XML_FORMAT):
            src: Any = self.path if self.path else io.BytesIO(self.data or b"")
            yield from self._iter_one(src, self.name, self.format)
            return
        if self.format in m365.FORMATS:
            yield from self._iter_m365(self.path, self.data, self.format, self.name)
            return
        if self.format == UNRECOGNISED:
            raise AnalystMessage(m365.UNRECOGNISED)
        for member in iter_archive(self.path, self.data, self.format, self.files, self.max_member, self.deadline):
            low = member.name.lower()
            if low.endswith(".evtx"):
                suffix, fmt = ".evtx", "evtx"
            elif low.endswith((".csv", ".json", ".jsonl", ".ndjson", ".xml", ".log", ".txt")):
                with member.open() as fh:
                    head = fh.read(SNIFF_BYTES)
                fmt = evtx_parser.XML_FORMAT if evtx_parser.looks_like_event_xml(head) else m365.detect_format(member.name, head) or ""
                if not fmt:
                    table = low.endswith((".csv", ".json", ".jsonl", ".ndjson"))
                    skip_record(self.files, member.name, member.size, m365.UNRECOGNISED if table else "not an event log or cloud export")
                    continue
                suffix = ".xml" if fmt == evtx_parser.XML_FORMAT else ".member"
            else:
                skip_record(self.files, member.name, member.size, "not an event log or cloud export")
                continue
            tmp_path, sha = member_to_tempfile(member, self.tmp_dir, suffix)
            try:
                before, dup_before, rep_before = self.stats.count, self.stats.duplicates, self.stats.repaired
                cloud_before = m365.counts(self.stats)
                if fmt in ("evtx", evtx_parser.XML_FORMAT):
                    yield from self._iter_one(tmp_path, member.name, fmt)
                else:
                    yield from self._iter_m365(tmp_path, None, fmt, member.name)
                entry = {"name": member.name, "size": member.size, "sha256": sha, "count": self.stats.count - before, "format": fmt, "status": "parsed"}
                if self.stats.duplicates > dup_before:
                    entry["duplicates"] = self.stats.duplicates - dup_before
                if self.stats.repaired > rep_before:
                    entry["repaired"] = self.stats.repaired - rep_before
                if cloud_note := m365.note({k: v - cloud_before[k] for k, v in m365.counts(self.stats).items()}, self.dates):
                    entry["note"] = cloud_note
                self.files.append(entry)
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def _iter_m365(self, path: str | None, data: bytes | None, fmt: str, source_file: str) -> Iterator[dict[str, Any]]:
        try:
            for row in m365.iter_records(path, data, fmt, stats=self.stats, include_raw=self.include_raw, seen=self.seen_records, dates=self.dates):
                row["sourceFile"] = source_file
                yield row
        except Exception as exc:  # noqa: BLE001
            log.warning("cloud export failed: %s", type(exc).__name__)
            self.stats.errors += 1
            self.files.append({"name": source_file, "status": "error", "error": error_text(exc)})

    def _iter_one(self, src: Any, source_file: str, fmt: str = "evtx") -> Iterator[dict[str, Any]]:
        try:
            rows = (
                evtx_parser.iter_xml_events(src, include_raw=self.include_raw, stats=self.stats)
                if fmt == evtx_parser.XML_FORMAT
                else evtx_parser.iter_events(src, include_raw=self.include_raw, stats=self.stats, source_file=source_file)
            )
            for row in rows:
                row["sourceFile"] = source_file
                yield row
        except Exception as exc:  # noqa: BLE001
            log.warning("event log failed: %s", type(exc).__name__)
            self.stats.errors += 1
            self.files.append({"name": source_file, "status": "error", "error": error_text(exc)})


def error_text(exc: BaseException, limit: int = 200) -> str:
    """What the entry of a member that failed says. A MemoryError has no text of its own; in a
    parse process it means the member took the parse to its memory limit."""
    if isinstance(exc, MemoryError):
        return "the parse ran out of memory reading this (FORENSIC_PARSE_MAX_MB)"
    return str(exc)[:limit]


def _read_head(path: str | None, n: int = 512) -> bytes:
    if not path:
        return b""
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


# ---------------------------------------------------------------------------
# Mail
# ---------------------------------------------------------------------------
class MailStats:
    def __init__(self) -> None:
        self.count = 0
        self.errors = 0
        self.flagged = 0
        self.max_risk = 0
        self.first: int | None = None
        self.last: int | None = None
        self.domains: dict[str, int] = {}
        self.folders: dict[str, int] = {}
        self.attachments = 0
        self.risky_attachments = 0
        self.flags: dict[str, int] = {}
        self.files = 0

    def add(self, row: dict[str, Any]) -> None:
        self.count += 1
        if "parse_error" in (row.get("flags") or ()):
            self.errors += 1
        r = int(row.get("risk") or 0)
        self.max_risk = max(self.max_risk, r)
        if r >= 50:
            self.flagged += 1
        d = row.get("date")
        if d is not None:
            self.first = d if self.first is None or d < self.first else self.first
            self.last = d if self.last is None or d > self.last else self.last
        dom = row.get("fromDomain") or "(none)"
        self.domains[dom] = self.domains.get(dom, 0) + 1
        fo = row.get("folder") or ""
        self.folders[fo] = self.folders.get(fo, 0) + 1
        for a in row.get("attachments") or []:
            self.attachments += 1
            if (a.get("risk") or 0) >= 60:
                self.risky_attachments += 1
        for fl in row.get("flags") or []:
            self.flags[fl] = self.flags.get(fl, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "errors": self.errors,
            "flagged": self.flagged,
            "maxRisk": self.max_risk,
            "files": self.files,
            "firstTs": self.first,
            "lastTs": self.last,
            "attachments": self.attachments,
            "riskyAttachments": self.risky_attachments,
            "domains": dict(sorted(self.domains.items(), key=lambda kv: -kv[1])[:100]),
            "folders": dict(sorted(self.folders.items(), key=lambda kv: -kv[1])[:100]),
            "flags": dict(sorted(self.flags.items(), key=lambda kv: -kv[1])[:150]),
        }


class MessageTooLarge(ValueError):
    def __init__(self, size: int, limit: int) -> None:
        super().__init__(f"message of {size / 2**20:.1f} MiB is above the {limit // 2**20} MiB per-message limit (FORENSIC_MAX_MESSAGE_MB) and was not parsed")


def _check_message_size(size: int, ctx: ParseContext) -> None:
    if size > ctx.max_message_bytes:
        raise MessageTooLarge(size, ctx.max_message_bytes)


def _error_row(folder: str, exc: Exception, fmt: str) -> dict[str, Any]:
    return {
        "folder": folder,
        "subject": "(unparseable message)",
        "flags": ["parse_error"],
        "risk": 10,
        "error": error_text(exc),
        "attachments": [],
        "urls": [],
        "sourceFormat": fmt,
        "fromName": "",
        "fromNameNorm": "",
        "fromAddr": "",
        "fromDomain": "",
        "fromRegistrable": "",
        "replyTo": [],
        "to": [],
        "cc": [],
        "bcc": [],
        "hops": [],
        "auth": {},
        "keywordHits": {},
        "recipientCount": 0,
        "hopCount": 0,
        "urlCount": 0,
        "attachmentCount": 0,
        "maxAttachmentRisk": 0,
        "lookalike": {},
        "date": None,
    }


def iter_mbox_fileobj(fileobj: Any, ctx: ParseContext, folder: str) -> Iterator[dict[str, Any]]:
    """Split an mbox stream on 'From ' separator lines without needing a path."""
    from services.parsers.mail.common import parse_message_bytes

    from_line = re.compile(rb"^From .*\r?\n$")
    buf: list[bytes] = []
    buffered = 0  # bytes of the current message, counted past the limit without keeping them
    prev_blank = True
    index = 0

    def flush() -> dict[str, Any] | None:
        nonlocal index, buffered
        if not buf:
            return None
        size, data = buffered, b"".join(buf)
        buf.clear()
        buffered = 0
        try:
            _check_message_size(size, ctx)
            data = re.sub(rb"(?m)^>(>*From )", rb"\1", data)
            if not data.strip():
                return None
            row = parse_message_bytes(data, ctx, folder=folder)
        except Exception as exc:  # noqa: BLE001
            row = _error_row(folder, exc, "mbox")
        row["sourceIndex"] = index
        row["sourceFormat"] = "mbox"
        index += 1
        return row

    for line in fileobj:
        if prev_blank and from_line.match(line):
            row = flush()
            if row is not None:
                yield row
            prev_blank = False
            continue
        buffered += len(line)
        if buffered <= ctx.max_message_bytes:
            buf.append(line)
        elif not buf:
            buf.append(b"")  # keep the message so flush() reports it
        prev_blank = line in (b"\n", b"\r\n")
    row = flush()
    if row is not None:
        yield row


class MailSource:
    """Iterates parsed mails from any supported container (eml, msg, mbox, pst, zip/tar corpora)."""

    def __init__(
        self,
        name: str,
        path: str | None,
        data: bytes | None,
        ctx: ParseContext,
        tmp_dir: str,
        max_member: int = MAX_MEMBER_BYTES,
        deadline: float | None = None,
    ) -> None:
        self.name = name
        self.path = path
        self.data = data
        self.ctx = ctx
        self.tmp_dir = tmp_dir
        self.max_member = max_member
        self.deadline = deadline
        self.stats = MailStats()
        # for an archive, one entry per member: parsed (with its row count), skipped or error, with the reason
        self.members: list[dict[str, Any]] = []
        head = (data or b"")[:4096] if data is not None else _read_head(path, 4096)
        self.format = detect_mail_format(name, head)

    def __iter__(self) -> Iterator[dict[str, Any]]:
        from services.parsers.mail import pst as pst_mod
        from services.parsers.mail.common import parse_message_bytes
        from services.parsers.mail.msg import parse_msg_bytes

        fmt = self.format
        if fmt == "pst" and not pst_mod.available():
            raise AnalystMessage("PST/OST support requires libpff-python (see backend/requirements-optional.txt)")
        if fmt in ("eml", "msg"):
            size = len(self.data) if self.data is not None else os.path.getsize(self.path or "")
            try:
                _check_message_size(size, self.ctx)
                blob = self.data if self.data is not None else open(self.path, "rb").read()  # noqa: SIM115
                row = parse_message_bytes(blob, self.ctx, folder="") if fmt == "eml" else parse_msg_bytes(blob, self.ctx, folder="")
            except MessageTooLarge as exc:
                row = _error_row("", exc, fmt)
            if fmt == "eml":
                row["sourceFormat"] = "eml"
            row["sourceIndex"] = 0
            yield self._tag(row, self.name)
        elif fmt == "mbox":
            fh = open(self.path, "rb") if self.path else io.BytesIO(self.data or b"")  # noqa: SIM115
            try:
                for row in iter_mbox_fileobj(fh, self.ctx, folder=self.name):
                    yield self._tag(row, self.name)
            finally:
                fh.close()
        elif fmt == "pst":
            if self.path is None:
                tmp = tempfile.NamedTemporaryFile(suffix=".pst", dir=self.tmp_dir, delete=False)
                tmp.write(self.data or b"")
                tmp.close()
                try:
                    for row in pst_mod.iter_pst(tmp.name, self.ctx):
                        yield self._tag(row, self.name)
                finally:
                    os.unlink(tmp.name)
            else:
                for row in pst_mod.iter_pst(self.path, self.ctx):
                    yield self._tag(row, self.name)
        elif fmt in ("zip", "tar"):
            yield from self._iter_archive()
        else:
            raise RuntimeError(f"unsupported mail format {fmt}")

    def _tag(self, row: dict[str, Any], source_name: str) -> dict[str, Any]:
        row["sourceName"] = row.get("sourceName") or source_name
        self.stats.add(row)
        return row

    def _iter_archive(self) -> Iterator[dict[str, Any]]:
        from services.parsers.mail import mbox as mbox_mod
        from services.parsers.mail import pst as pst_mod
        from services.parsers.mail.common import parse_message_bytes
        from services.parsers.mail.msg import parse_msg_bytes

        index = 0
        for member in iter_archive(self.path, self.data, self.format, self.members, self.max_member, self.deadline):
            low = member.name.lower()
            base = low.rsplit("/", 1)[-1]
            if base.startswith((".", "__macosx")) or low.endswith(
                (".png", ".jpg", ".jpeg", ".gif", ".md", ".html", ".htm", ".json", ".xml", ".csv", ".yml", ".yaml", ".py", ".txt.gz", ".evtx")
            ):
                skip_record(self.members, member.name, member.size, "not a mail file (by name)")
                continue
            folder = member.name.rsplit("/", 1)[0] if "/" in member.name else ""
            entry: dict[str, Any] = {"name": member.name[:512], "size": member.size, "status": "parsed", "count": 0}
            first = index
            try:
                with member.open() as fh:
                    head = fh.read(4096)
                if low.endswith(".msg") or head.startswith(_OLE):
                    entry["format"] = "msg"
                    _check_message_size(member.size, self.ctx)
                    row = parse_msg_bytes(member.read(), self.ctx, folder=folder)
                    row["sourceIndex"] = index
                    index += 1
                    yield self._tag(row, member.name)
                elif low.endswith(".pst") or head.startswith(_PST):
                    entry["format"] = "pst"
                    if not pst_mod.available():
                        entry.update(status="skipped", reason="PST support (libpff) is not installed on this server")
                        self.members.append(entry)
                        continue
                    tmp_path, entry["sha256"] = member_to_tempfile(member, self.tmp_dir, ".pst")
                    try:
                        for row in pst_mod.iter_pst(tmp_path, self.ctx):
                            row["sourceIndex"] = index
                            index += 1
                            yield self._tag(row, member.name)
                    finally:
                        os.unlink(tmp_path)
                elif low.endswith((".mbox", ".mbx")) or (mbox_mod.looks_like_mbox(head) and not low.endswith(".eml")):
                    entry["format"] = "mbox"
                    with member.open() as fh:
                        for row in iter_mbox_fileobj(fh, self.ctx, folder=member.name):
                            row["sourceIndex"] = index
                            index += 1
                            yield self._tag(row, member.name)
                    self.stats.files += 1
                elif low.endswith(".eml") or looks_like_mail(head):
                    entry["format"] = "eml"
                    _check_message_size(member.size, self.ctx)
                    row = parse_message_bytes(member.read(), self.ctx, folder=folder)
                    row["sourceFormat"] = "eml"
                    row["sourceIndex"] = index
                    index += 1
                    self.stats.files += 1
                    yield self._tag(row, member.name)
                else:
                    skip_record(self.members, member.name, member.size, "not a mail file (by content)")
                    continue
            except DeadlineExceeded:
                raise
            except Exception as exc:  # noqa: BLE001
                log.warning("archive member #%d failed: %s", index, type(exc).__name__)
                entry.update(status="error", error=error_text(exc))
                row = _error_row(folder, exc, "archive")
                row["sourceIndex"] = index
                index += 1
                yield self._tag(row, member.name)
            entry["count"] = index - first
            self.members.append(entry)


def hash_path(path: str) -> str:
    with open(path, "rb") as fh:
        return sha256_file(fh)
