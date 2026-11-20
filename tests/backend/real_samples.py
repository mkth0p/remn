"""Samples written by the real tools and services, for the parser tests.

The small ones are committed under tests/fixtures/real/, each family with a README that names
where every file comes from, its licence, its SHA-256 and what was trimmed. The others are not
committed, because they are too large, because their licence does not allow it, or because they
name people: a test marked heavy downloads one by its URL, pinned to a commit, and checks its
SHA-256 before reading it. Downloads are kept in the directory named by REMN_REAL_SAMPLES
(by default ~/.cache/remn/real-samples), so a second run reads them from there.

    REMN_REAL_SAMPLES=/tmp/samples python -m pytest -m heavy tests/backend/test_real_*.py
"""

from __future__ import annotations

import hashlib
import os
import urllib.request
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "real"


def cache_dir() -> Path:
    return Path(os.environ.get("REMN_REAL_SAMPLES") or Path.home() / ".cache" / "remn" / "real-samples")


def download(url: str, sha256: str) -> Path:
    """The file at url, checked against sha256, from the cache when it is there already.

    The file keeps its own name, under a directory named by its hash, because several parsers
    choose by the name's extension. A download that fails or does not match fails the test: a
    heavy test is run on purpose, and a sample it could not read must not pass as checked.
    """
    target = cache_dir() / sha256[:16] / url.rsplit("/", 1)[-1].replace("%20", " ")
    if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == sha256:
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != sha256:
        raise AssertionError(f"{url} has SHA-256 {digest}, not the pinned {sha256}")
    partial = target.with_name(target.name + ".part")
    partial.write_bytes(data)
    partial.replace(target)
    return target
