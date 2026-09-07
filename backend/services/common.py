"""Small helpers shared by parsers and analyzers."""

from __future__ import annotations

import functools
import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any, BinaryIO

_ISO_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,](\d+))?\s*(Z|UTC|[+-]\d{2}:?\d{2})?$")


def parse_timestamp(value: Any) -> tuple[int | None, str | None]:
    """Return (epoch_ms, iso_utc) for datetimes, ISO strings or RFC 2822 dates."""
    if value is None or value == "":
        return None, None
    dt: datetime | None = None
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip()
        m = _ISO_RE.match(s)
        if m:
            date, time_, frac, tz = m.groups()
            frac = (frac or "0")[:6].ljust(6, "0")
            try:
                dt = datetime.fromisoformat(f"{date}T{time_}.{frac}")
            except ValueError:
                dt = None
            if dt is not None:
                if tz and tz not in ("Z", "UTC"):
                    sign = 1 if tz[0] == "+" else -1
                    hh, mm = int(tz[1:3]), int(tz[-2:])
                    dt = dt.replace(tzinfo=timezone(sign * timedelta(hours=hh, minutes=mm)))
                else:
                    dt = dt.replace(tzinfo=UTC)
        if dt is None:
            try:
                dt = parsedate_to_datetime(s)
            except (TypeError, ValueError, IndexError):
                dt = None
        if dt is None:
            try:
                dt = datetime.fromisoformat(s)
            except ValueError:
                return None, None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    try:
        dt = dt.astimezone(UTC)
        ms = int(dt.timestamp() * 1000)
    except (OverflowError, OSError, ValueError):
        return None, None
    return ms, dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()  # noqa: S324 - forensic identifier, not security


def sha256_chunks(chunks: Iterable[bytes]) -> str:
    h = hashlib.sha256()
    for chunk in chunks:
        h.update(chunk)
    return h.hexdigest()


def sha256_file(fh: BinaryIO, chunk_size: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    fh.seek(0)
    while True:
        chunk = fh.read(chunk_size)
        if not chunk:
            break
        h.update(chunk)
    fh.seek(0)
    return h.hexdigest()


def json_default(obj: Any) -> Any:
    if isinstance(obj, (bytes, bytearray)):
        return obj.decode("utf-8", "replace")
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return sorted(obj)
    return str(obj)


def dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=json_default, separators=(",", ":"))


def ndjson_line(obj: Any) -> bytes:
    return (dumps(obj) + "\n").encode("utf-8")


def is_public_ip(value: str | None) -> bool:
    """True for globally routable IPs, False for private/reserved/invalid."""
    if not value:
        return False
    return _is_public_ip_cached(value)


@functools.lru_cache(maxsize=65536)
def _is_public_ip_cached(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global


def normalize_ip(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s or s in ("-", "::", "::0", "0.0.0.0"):
        return None
    if s.lower().startswith("::ffff:"):
        s = s[7:]
    if s == "::1":
        s = "127.0.0.1"
    try:
        ipaddress.ip_address(s)
    except ValueError:
        return None
    return s


def truncate(s: str | None, limit: int) -> str | None:
    if s is None:
        return None
    return s if len(s) <= limit else s[:limit] + "…"


def safe_str(value: Any, limit: int | None = None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    s = str(value)
    return truncate(s, limit) if limit else s
