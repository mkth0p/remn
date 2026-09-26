"""
Community rule packs: rules/community/<pack>/ (pack.json + multi-document REMN YAML).

The core catalogue (rules/windows, rules/mail, rules/m365) is small and ships inside /api/meta.
The community packs (SigmaHQ, Sublime Security - written by tools/import_community_rules.py)
are ~3,000 rules and several megabytes of YAML, so they are listed in /api/meta from their
manifests only and served on demand by GET /api/rules/packs/<id> when an analyst enables them.
Parsed packs are cached in-process and invalidated when any file in the pack changes.

rules/community/levels.json changes the level of pack rules measured too noisy or too quiet at the
upstream level (tools/measure_rules.py: detections on the recorded attacks, findings on the clean
machines). It is kept apart from the packs so that a re-import does not undo it; each entry keeps
the upstream level and the reason.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from pathlib import Path
from typing import Any

import yaml
from django.conf import settings

from services.rules import measures

log = logging.getLogger(__name__)

_Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

_lock = threading.Lock()
_cache: dict[str, tuple[str, dict[str, Any]]] = {}


def community_dir() -> Path:
    return Path(settings.RULES_DIR) / "community"


def is_pack_path(path: Path, rules_dir: Path) -> bool:
    """True for files under rules/community (excluded from the core catalogue)."""
    try:
        return "community" in path.relative_to(rules_dir).parts
    except ValueError:
        return False


def levels_path() -> Path:
    return community_dir() / "levels.json"


def _signature(pack_dir: Path) -> str:
    h = hashlib.sha1()
    for p in [*sorted(pack_dir.iterdir()), levels_path()]:
        if p.suffix in (".yaml", ".yml", ".json") and p.is_file():
            st = p.stat()
            h.update(f"{p.name}:{st.st_size}:{st.st_mtime_ns}\n".encode())
    return h.hexdigest()[:16]


def _levels() -> dict[str, str]:
    """Rule id -> level from rules/community/levels.json ({} when absent or invalid)."""
    try:
        data = json.loads(levels_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        log.warning("invalid %s: %s", levels_path(), exc)
        return {}
    return {str(rid): str(e["severity"]) for rid, e in (data.get("levels") or {}).items() if isinstance(e, dict) and e.get("severity")}


def _manifest(pack_dir: Path) -> dict[str, Any] | None:
    mf = pack_dir / "pack.json"
    if not mf.is_file():
        return None
    try:
        data = json.loads(mf.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.warning("pack %s: invalid pack.json: %s", pack_dir.name, exc)
        return None
    if not isinstance(data, dict) or not data.get("id"):
        return None
    data["id"] = str(data["id"])
    return data


def list_packs() -> list[dict[str, Any]]:
    """Manifests (plus a content hash) of every pack on disk - cheap, no YAML parsing."""
    root = community_dir()
    if not root.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for pack_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        m = _manifest(pack_dir)
        if m is None:
            continue
        if m["id"] != pack_dir.name:
            log.warning("pack %s: manifest id %r differs from the directory name", pack_dir.name, m["id"])
            m["id"] = pack_dir.name
        m["hash"] = _signature(pack_dir)
        m["licenseText"] = (pack_dir / "LICENSE").is_file()
        out.append(m)
    return out


def _parse_pack(pack_dir: Path) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    levels = _levels()
    for path in sorted(pack_dir.glob("*.y*ml")):
        rel = f"community/{pack_dir.name}/{path.name}"
        try:
            docs = [d for d in yaml.load_all(path.read_text(encoding="utf-8"), Loader=_Loader) if isinstance(d, dict)]
        except Exception as exc:  # noqa: BLE001
            log.warning("pack rule file %s invalid: %s", path, exc)
            rules.append({"file": rel, "error": str(exc)[:200], "yaml": ""})
            continue
        for i, d in enumerate(docs):
            if d.get("id") in levels:
                d["severity"] = levels[d["id"]]
            entry = {"file": f"{rel}#{i}", "rule": d}  # no yaml text: the client re-dumps a rule when it is copied
            measured = measures.for_rule(d)
            if measured is not None:
                entry["measured"] = measured
            rules.append(entry)
    return rules


def load_pack(pack_id: str) -> dict[str, Any] | None:
    """{"pack": manifest, "rules": [{file, rule} | {file, error, yaml: ""}]} or None when the pack does not exist."""
    if not pack_id or "/" in pack_id or "\\" in pack_id or pack_id.startswith("."):
        return None
    pack_dir = community_dir() / pack_id
    if not pack_dir.is_dir():
        return None
    manifest = _manifest(pack_dir)
    if manifest is None:
        return None
    sig = _signature(pack_dir)
    # the rules carry their measures (rules/measures.json): a new measurement is a new payload
    key = f"{sig}|{measures.signature()}"
    with _lock:
        hit = _cache.get(pack_id)
        if hit and hit[0] == key:
            return hit[1]
    rules = _parse_pack(pack_dir)
    manifest["hash"] = sig
    payload = {"pack": manifest, "rules": rules}
    with _lock:
        _cache[pack_id] = (key, payload)
    return payload


def license_text(pack_id: str) -> str | None:
    if not pack_id or "/" in pack_id or "\\" in pack_id or pack_id.startswith("."):
        return None
    p = community_dir() / pack_id / "LICENSE"
    return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else None
