"""
Built-in reference lists usable with ``in_setting`` / ``nin_setting`` when the case settings do not
define a list of that name (a case setting with the same name always wins, so analysts can override).

    tranco_10k   the top 10,000 of the Tranco list (https://tranco-list.eu), see tranco.json for the
                 list id and fetch date. Regenerate with tools/import_community_rules.py tranco.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path

_DIR = Path(__file__).resolve().parent
_FILES = {"tranco_10k": "tranco_top10k.txt"}


def builtin_names() -> list[str]:
    return sorted(_FILES)


@functools.cache
def builtin_list(name: str) -> tuple[str, ...] | None:
    """The list's entries (lower-cased), or None when no built-in list has that name."""
    fname = _FILES.get(name)
    if not fname:
        return None
    path = _DIR / fname
    if not path.is_file():
        return None
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip().lower()
        if s and not s.startswith("#"):
            out.append(s)
    return tuple(out)


def builtin_info(name: str) -> dict | None:
    if name == "tranco_10k" and (_DIR / "tranco.json").is_file():
        return json.loads((_DIR / "tranco.json").read_text(encoding="utf-8"))
    return None
