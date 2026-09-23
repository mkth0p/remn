"""
Shared ingestion pipeline: format detection, archive walking (zip / tar of
EVTX files or mail corpora), mail statistics. Used by the NDJSON streaming
views (browser storage) and by the server-store jobs.
"""

from __future__ import annotations

import io
import logging
import os
import re
import tarfile
import tempfile
import time
import zipfile
from collections.abc import Callable, Iterator
from typing import Any

from services.common import sha256_file
from services.parsers import evtx_parser, m365
from services.parsers.mail import mbox as mbox_mod
from services.parsers.mail import pst as pst_mod
from services.parsers.mail.common import ParseContext, parse_message_bytes
from services.parsers.mail.msg import parse_msg_bytes

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
    if mbox_mod.looks_like_mbox(head) or n.endswith((".mbox", ".mbx")):
        return "mbox"
    if n.endswith((".pst", ".ost")):
        return "pst"
    if n.endswith(".msg"):
        return "msg"
    return "eml"


def detect_evtx_format(name: str, head: bytes) -> str:
    arc = detect_archive(name, head)
    if arc:
        return arc
    return m365.detect_format(name, head) or "evtx"


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
    that are too large, encrypted or compressed with an unsupported method are recorded in skipped."""
    limit = f"larger than the {max_member // 2**20} MiB per-member limit"
    if kind == "zip":
        zf = zipfile.ZipFile(path) if path else zipfile.ZipFile(io.BytesIO(data or b""))
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
                yield Member(zi.filename, zi.file_size, lambda zi=zi: zf.open(zi))  # type: ignore[misc]
    elif kind == "tar":
        tf = tarfile.open(name=path, mode="r:*") if path else tarfile.open(fileobj=io.BytesIO(data or b""), mode="r:*")
        with tf:
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
                yield Member(m.name, m.size, lambda m=m: tf.extractfile(m))  # type: ignore[misc,return-value]
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
    """Iterates events from a single EVTX or an archive of EVTX files, tagging rows with sourceFile."""

    def __init__(
        self,
        name: str,
        path: str | None,
        data: bytes | None,
        tmp_dir: str,
        include_raw: bool = True,
        max_member: int = MAX_MEMBER_BYTES,
        deadline: float | None = None,
        seen: set[int] | None = None,
    ) -> None:
        self.name = name
        self.path = path
        self.data = data
        self.tmp_dir = tmp_dir
        self.include_raw = include_raw
        self.max_member = max_member
        self.deadline = deadline
        self.stats = evtx_parser.Stats()
        # one entry per archive member: parsed (with its count and hash), skipped or error, with the reason
        self.files: list[dict[str, Any]] = []
        # the keys of the cloud records read so far, for every file of this upload (a package
        # passes its own set, shared by all its members)
        self.seen_records: set[int] = set() if seen is None else seen
        head = (data or b"")[:512] if data is not None else _read_head(path)
        self.format = detect_evtx_format(name, head)

    def __iter__(self) -> Iterator[dict[str, Any]]:
        if self.format == "evtx":
            src: Any = self.path if self.path else io.BytesIO(self.data or b"")
            yield from self._iter_one(src, self.name)
            return
        if self.format in m365.FORMATS:
            yield from self._iter_m365(self.path, self.data, self.format, self.name)
            return
        for member in iter_archive(self.path, self.data, self.format, self.files, self.max_member, self.deadline):
            low = member.name.lower()
            if low.endswith(".evtx"):
                suffix, fmt = ".evtx", "evtx"
            elif low.endswith((".csv", ".json", ".jsonl", ".ndjson")):
                with member.open() as fh:
                    head = fh.read(512)
                fmt = m365.detect_format(member.name, head) or ""
                if not fmt:
                    skip_record(self.files, member.name, member.size, "not a recognised Microsoft 365 or Entra export")
                    continue
                suffix = ".member"
            else:
                skip_record(self.files, member.name, member.size, "not an event log or cloud export")
                continue
            tmp_path, sha = member_to_tempfile(member, self.tmp_dir, suffix)
            try:
                before, dup_before = self.stats.count, self.stats.duplicates
                if fmt == "evtx":
                    yield from self._iter_one(tmp_path, member.name)
                else:
                    yield from self._iter_m365(tmp_path, None, fmt, member.name)
                entry = {"name": member.name, "size": member.size, "sha256": sha, "count": self.stats.count - before, "format": fmt, "status": "parsed"}
                if self.stats.duplicates > dup_before:
                    entry["duplicates"] = self.stats.duplicates - dup_before
                self.files.append(entry)
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def _iter_m365(self, path: str | None, data: bytes | None, fmt: str, source_file: str) -> Iterator[dict[str, Any]]:
        try:
            for row in m365.iter_records(path, data, fmt, stats=self.stats, include_raw=self.include_raw, seen=self.seen_records):
                row["sourceFile"] = source_file
                yield row
        except Exception as exc:  # noqa: BLE001
            log.warning("cloud export failed: %s", type(exc).__name__)
            self.stats.errors += 1
            self.files.append({"name": source_file, "status": "error", "error": str(exc)[:200]})

    def _iter_one(self, src: Any, source_file: str) -> Iterator[dict[str, Any]]:
        try:
            for row in evtx_parser.iter_events(src, include_raw=self.include_raw, stats=self.stats):
                row["sourceFile"] = source_file
                yield row
        except Exception as exc:  # noqa: BLE001
            log.warning("event log failed: %s", type(exc).__name__)
            self.stats.errors += 1
            self.files.append({"name": source_file, "status": "error", "error": str(exc)[:200]})


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
        "error": str(exc)[:200],
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
        fmt = self.format
        if fmt == "pst" and not pst_mod.available():
            raise RuntimeError("PST/OST support requires libpff-python (see backend/requirements-optional.txt)")
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
                entry.update(status="error", error=str(exc)[:200])
                row = _error_row(folder, exc, "archive")
                row["sourceIndex"] = index
                index += 1
                yield self._tag(row, member.name)
            entry["count"] = index - first
            self.members.append(entry)


def hash_path(path: str) -> str:
    with open(path, "rb") as fh:
        return sha256_file(fh)
