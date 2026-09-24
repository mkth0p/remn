"""
How each event rule fared when it was measured (rules/measures.json, written by
tools/measure_rules.py): on recorded attacks, whether it fires on a recording of what it looks
for, and on the logs of clean Windows machines, how often it fires anyway.

A measure holds for the rule it was taken on. Each carries a hash of the rule's logic (everything
but its title, description and other metadata); a rule whose logic has changed since is served
as changed rather than with a measure that is not its own.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from pathlib import Path
from typing import Any

from django.conf import settings

log = logging.getLogger(__name__)

# what a rule says about itself rather than what it matches
META_KEYS = frozenset({"id", "title", "description", "severity", "confidence", "attack", "tags", "references", "sigma", "sublime", "enabled", "author", "date", "modified", "falsepositives", "status"})

_lock = threading.Lock()
_cache: tuple[tuple[int, int], dict[str, Any]] | None = None


def logic_hash(rule: dict[str, Any]) -> str:
    logic = {k: v for k, v in rule.items() if k not in META_KEYS}
    text = json.dumps(logic, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def path() -> Path:
    return Path(settings.RULES_DIR) / "measures.json"


def signature() -> str:
    """Changes when the measures file does, for caches of rules that carry its measures."""
    try:
        st = path().stat()
    except OSError:
        return "none"
    return f"{st.st_size}:{st.st_mtime_ns}"


def load() -> dict[str, Any]:
    """{"sources": {...}, "rules": {rule id: measure}}; empty when the rules were never measured."""
    global _cache
    p = path()
    try:
        st = p.stat()
    except OSError:
        return {}
    key = (st.st_size, st.st_mtime_ns)
    with _lock:
        if _cache and _cache[0] == key:
            return _cache[1]
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.warning("rule measures %s unreadable: %s", p, exc)
        data = {}
    if not isinstance(data, dict) or not isinstance(data.get("rules"), dict):
        data = {}
    with _lock:
        _cache = (key, data)
    return data


def for_rule(rule: Any) -> dict[str, Any] | None:
    """The rule's measure without its hash, {"changed": True} when the rule was measured in another form, or None."""
    if not isinstance(rule, dict) or not rule.get("id"):
        return None
    m = load().get("rules", {}).get(str(rule["id"]))
    if not isinstance(m, dict):
        return None
    if m.get("h") != logic_hash(rule):
        return {"changed": True}
    return {k: v for k, v in m.items() if k != "h"}


def summary() -> dict[str, Any] | None:
    """What the rules were measured on, for the pages that show a measure."""
    data = load()
    if not data:
        return None
    return {k: v for k, v in data.items() if k != "rules"}
