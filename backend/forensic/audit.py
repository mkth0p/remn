"""
The audit log of a server with accounts: one JSON line per recorded request, in the data directory
(FORENSIC_AUDIT_LOG).

Each entry carries the time, the account and its role, the client address, the method, the route
and the path, the case, the HTTP status and the outcome, the code of the entry before it (`prev`)
and its own code (`mac`): an HMAC-SHA-256, under the server's audit key, of `prev` and the entry's
other fields. Whoever holds the key can check that no entry was changed, inserted, removed or
reordered, and can tell where; whoever does not hold it cannot write an entry that passes. The
newest entries can still be cut off the end without a break in the chain: that is found by
comparing the chain with a head (the code of an entry) noted earlier, which `verify` reports and
accepts.

The key is FORENSIC_AUDIT_KEY, or, when that is empty, a random key written beside the log at first
use. Whoever runs the server can read the key, and so can rewrite the whole log so that it passes:
the log protects against everyone else, not against the server's own administrator.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from django.conf import settings

from forensic.accounts import file_lock, now, owned_like_folder, write_private

ZERO = "0" * 64
# the fields of an entry, in the order they are written
FIELDS = ("seq", "time", "account", "role", "address", "method", "route", "path", "case", "status", "outcome", "prev")


def _canonical(entry: dict[str, Any]) -> bytes:
    return json.dumps({k: entry.get(k) for k in FIELDS}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _mac(key: bytes, entry: dict[str, Any]) -> str:
    return hmac.new(key, _canonical(entry), hashlib.sha256).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.key_path = self.path.with_name(self.path.name.rsplit(".", 1)[0] + ".key")
        self._key: bytes | None = None
        self._guard = threading.Lock()
        # the entry this process wrote last: a log cut short below it is found while the server runs
        self.last_written: dict[str, Any] | None = None

    def key(self) -> bytes:
        configured = str(getattr(settings, "FORENSIC_AUDIT_KEY", "") or "")
        if configured:
            return configured.encode("utf-8")
        with self._guard:
            if self._key is None:
                with file_lock(self.lock_path):
                    try:
                        self._key = bytes.fromhex(self.key_path.read_text(encoding="ascii").strip())
                    except FileNotFoundError:
                        self._key = secrets.token_bytes(32)
                        write_private(self.key_path, self._key.hex() + "\n")
            return self._key

    def _tail(self, fh) -> tuple[dict[str, Any] | None, bool]:
        """The last entry of the open log that reads as one, and whether the file ends a line."""
        size = fh.seek(0, os.SEEK_END)
        if size == 0:
            return None, True
        block = min(size, 1 << 16)
        fh.seek(size - block)
        data = fh.read(block)
        ends = data.endswith(b"\n")
        for line in reversed(data.splitlines()):
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict) and isinstance(entry.get("mac"), str):
                return entry, ends
        return None, ends

    def append(self, **fields: Any) -> dict[str, Any]:
        """Write one entry at the end of the chain and return it."""
        key = self.key()
        with file_lock(self.lock_path):
            if not self.path.exists():
                # created readable by the server's account only, before anything is written to it
                os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600))
                owned_like_folder(self.path)
            with open(self.path, "ab+") as fh:
                last, ends = self._tail(fh)
                entry: dict[str, Any] = {k: fields.get(k) for k in FIELDS}
                entry["seq"] = int(last["seq"]) + 1 if last and isinstance(last.get("seq"), int) else 1
                entry["time"] = fields.get("time") or now()
                entry["prev"] = last["mac"] if last else ZERO
                entry["mac"] = _mac(key, entry)
                # a line a crash left unfinished stays as it is, and shows in verify; the next starts on a line of its own
                fh.write((b"" if ends else b"\n") + json.dumps(entry, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n")
                fh.flush()
                os.fsync(fh.fileno())
        self.last_written = entry
        return entry

    def lines(self) -> Iterator[tuple[int, str]]:
        try:
            with open(self.path, encoding="utf-8", errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    if line.strip():
                        yield n, line
        except FileNotFoundError:
            return

    def entries(self, after: int = 0, limit: int = 200, case: str | None = None, account: str | None = None) -> list[dict[str, Any]]:
        """Entries after sequence number `after`, oldest first, optionally of one case or one account."""
        out: list[dict[str, Any]] = []
        for _, line in self.lines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if not isinstance(entry, dict) or not isinstance(entry.get("seq"), int) or entry["seq"] <= after:
                continue
            if (case and entry.get("case") != case) or (account and entry.get("account") != account):
                continue
            out.append(entry)
            if len(out) >= limit:
                break
        return out

    def verify(self, heads: list[str] | None = None) -> dict[str, Any]:
        """Check every entry against the key and the one before it.

        `heads` are entry codes (or prefixes of at least 16 characters) noted earlier: each must
        still be in the chain, or the entries up to it were removed from the end. The result says
        whether the chain holds, the first problems found, and its newest entry."""
        key = self.key()
        prev, expected, count = ZERO, 1, 0
        problems: list[str] = []
        seen: set[str] = set()
        last: dict[str, Any] | None = None
        for n, line in self.lines():
            try:
                entry = json.loads(line)
                if not isinstance(entry, dict) or not isinstance(entry.get("mac"), str):
                    raise ValueError
            except ValueError:
                problems.append(f"line {n} is not an entry: it was damaged or written by something else")
                continue
            count += 1
            seq = entry.get("seq")
            if entry.get("prev") != prev:
                problems.append(f"line {n} (entry {seq}) does not follow the entry before it: an entry was removed, inserted or moved")
            elif seq != expected:
                problems.append(f"line {n} is entry {seq} where {expected} was expected")
            if not hmac.compare_digest(_mac(key, entry), entry["mac"]):
                problems.append(f"line {n} (entry {seq}) was changed, or written without this server's audit key")
            prev = entry["mac"]
            seen.add(entry["mac"])
            expected = (seq + 1) if isinstance(seq, int) else expected + 1
            last = entry
        missing = []
        for head in heads or []:
            head = head.strip().lower()
            if len(head) < 16 or not any(m.startswith(head) for m in seen):
                missing.append(head)
        for head in missing:
            problems.append(f"the entry {head[:16]} noted earlier is no longer in the log: the entries up to it were removed")
        return {
            "ok": not problems,
            "entries": count,
            "problems": problems[:20],
            "problemCount": len(problems),
            "head": {"seq": last.get("seq"), "time": last.get("time"), "mac": last["mac"]} if last else None,
        }


_logs: dict[str, AuditLog] = {}
_logs_guard = threading.Lock()


def log() -> AuditLog:
    """The audit log of the file the settings name."""
    path = Path(settings.FORENSIC_AUDIT_LOG)
    with _logs_guard:
        return _logs.setdefault(str(path), AuditLog(path))
