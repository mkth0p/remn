"""Which code this server runs: the release version and the source commit it was built from.

The commit is what a visitor can check the running code against, and what every parse result is
stamped with, so rows can be traced to the parser that produced them. An image build passes it in
REMN_BUILD_ID (the checkout's .git is not copied into the image); a checkout reads it from .git."""

from __future__ import annotations

import functools
import os
import re
from pathlib import Path

VERSION = "0.1.1"
SOURCE_URL = os.environ.get("REMN_SOURCE_URL", "https://github.com/mkth0p/remn").rstrip("/")

_ROOT = Path(__file__).resolve().parents[2]
_SHA = re.compile(r"^[0-9a-f]{40}$")


def _git_commit(root: Path) -> str:
    git = root / ".git"
    try:
        head = (git / "HEAD").read_text().strip()
    except OSError:
        return ""
    if _SHA.match(head):
        return head
    if not head.startswith("ref: "):
        return ""
    ref = head[5:].strip()
    try:
        value = (git / ref).read_text().strip()
        return value if _SHA.match(value) else ""
    except OSError:
        pass
    try:
        for line in (git / "packed-refs").read_text().splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref and _SHA.match(parts[0]):
                return parts[0]
    except OSError:
        pass
    return ""


@functools.cache
def commit() -> str:
    """The full source commit, or "" when neither the environment nor a checkout says."""
    value = os.environ.get("REMN_BUILD_ID", "").strip().lower()
    return value if _SHA.match(value) else _git_commit(_ROOT)


def build_id() -> str:
    """Short, stable identifier of this build, for stamping parse results and the UI."""
    c = commit()
    return f"{VERSION}+{c[:12]}" if c else f"{VERSION}+unknown"


def source_url() -> str:
    """Where the exact source of this build can be read."""
    c = commit()
    return f"{SOURCE_URL}/tree/{c}" if c else SOURCE_URL
