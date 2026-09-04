"""Optional YARA scanning of attachments (yara-python + rules dropped in a directory)."""
from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_lock = threading.Lock()
_rules = None
_rules_mtime: float = -1.0
_rules_dir: Path | None = None


def available() -> bool:
    try:
        import yara  # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        return False


def configure(rules_dir: str | os.PathLike[str] | None) -> None:
    global _rules_dir, _rules, _rules_mtime
    with _lock:
        _rules_dir = Path(rules_dir) if rules_dir else None
        _rules = None
        _rules_mtime = -1.0


def _load() -> Any | None:
    global _rules, _rules_mtime
    if _rules_dir is None or not _rules_dir.is_dir():
        return None
    try:
        import yara
    except Exception:  # noqa: BLE001
        return None
    files = sorted(p for p in _rules_dir.iterdir() if p.suffix.lower() in (".yar", ".yara"))
    if not files:
        return None
    mtime = max(p.stat().st_mtime for p in files)
    with _lock:
        if _rules is not None and mtime == _rules_mtime:
            return _rules
        try:
            _rules = yara.compile(filepaths={p.stem: str(p) for p in files})
            _rules_mtime = mtime
            log.info("compiled %d YARA rule file(s)", len(files))
        except Exception as exc:  # noqa: BLE001
            log.warning("YARA compile failed: %s", exc)
            _rules = None
        return _rules


def rule_count() -> int:
    if _rules_dir is None or not _rules_dir.is_dir():
        return 0
    return len([p for p in _rules_dir.iterdir() if p.suffix.lower() in (".yar", ".yara")])


def scan(data: bytes, timeout: int = 20) -> list[dict[str, Any]] | None:
    rules = _load()
    if rules is None:
        return None
    try:
        matches = rules.match(data=data, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        log.debug("YARA scan failed: %s", exc)
        return None
    out: list[dict[str, Any]] = []
    for m in matches[:50]:
        try:
            strings = len(m.strings)
        except Exception:  # noqa: BLE001
            strings = 0
        out.append({"rule": m.rule, "namespace": getattr(m, "namespace", None), "tags": list(m.tags),
                    "meta": {k: str(v)[:200] for k, v in dict(m.meta).items()}, "strings": strings})
    return out
