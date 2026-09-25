#!/usr/bin/env python
"""
Bring the converted Sigma packs in line with the converter fixes of 2026-09-23, without a new import.

    python tools/migrate_community_packs.py            # rewrite rules/community/sigma-*/ in place
    python tools/migrate_community_packs.py --check    # exit 1 if a pack still needs it

The fixes (services/rules/sigma.py) change how three Sigma constructs are written in the REMN rule
language; a pack converted before them still has the old form, and a new import needs the upstream
archive. This applies the same change to the rules as they are, so the result is what the fixed
converter writes (up to which EventData key a "-" is looked for under), and running it twice
changes nothing:

* the Sigma field Data (classic events: MSSQL, MsiInstaller, Windows PowerShell 800) was written
  to `dataList`, a key no row has; the parser writes it to `message`;
* a comparison with "-", the Windows "no value", was made against the column, which the parser
  leaves empty for "-"; it is made against the EventData, which keeps it;
* "Image has no value" was "image or processName has no value", always true on a Sysmon row;
  it is "image and processName have no value";
* Sysmon 25's Type was read from `type`, which the ingest stream overwrites; it is `typeName`.

A re-import with tools/import_community_rules.py makes this script unnecessary.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "tools"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "forensic.settings")

import yaml  # noqa: E402

from services.rules.sigma import CATEGORY_MAP, PARSER_SOURCES  # noqa: E402

COMBINATOR = re.compile(r"^(any_of|all_of)(_\d+)?$")
RENAMED = {"dataList": "message", "type": "typeName"}
ALIAS_GROUPS = [tuple(v) for v in CATEGORY_MAP["process_creation"]["aliases"].values() if len(v) > 1]
MARK = "migrate_community_packs 2026-09-23: Data -> message, '-' in EventData, alias empty checks, Sysmon 25 Type"


def _field(key: str) -> tuple[str, str]:
    f, _, op = key.partition("|")
    return f, op


def _dash(field: str, op: str, value: Any) -> tuple[list[dict[str, Any]], Any] | None:
    """The "-" part of a condition as EventData checks, and what is left of the value."""
    if op not in ("", "in") or field not in PARSER_SOURCES or field in ("eventId", "channel", "provider"):
        return None
    values = value if isinstance(value, list) else [value]
    if "-" not in values:
        return None
    rest = [v for v in values if v != "-"]
    return [{f"data.{k}": "-"} for k in PARSER_SOURCES[field]], rest


def _free_key(mapping: dict[str, Any], base: str) -> str:
    if base not in mapping:
        return base
    n = 2
    while f"{base}_{n}" in mapping:
        n += 1
    return f"{base}_{n}"


def migrate(cond: Any) -> Any:
    if isinstance(cond, list):
        return [migrate(c) for c in cond]
    if not isinstance(cond, dict):
        return cond
    out: dict[str, Any] = {}
    extra: list[list[dict[str, Any]]] = []
    for key, value in cond.items():
        if COMBINATOR.match(key) or key == "not":
            v = migrate(value)
            out[key] = _merge_any(v) if key.startswith("any_of") and isinstance(v, list) else v
            continue
        field, op = _field(key)
        field = RENAMED.get(field, field)
        key = f"{field}|{op}" if op else field
        dash = _dash(field, op, value)
        if dash is None:
            out[key] = value
            continue
        checks, rest = dash
        if rest:
            rest_cond = {f"{field}|in" if len(rest) > 1 else field: rest if len(rest) > 1 else rest[0]}
            extra.append(checks + [rest_cond])
        else:
            extra.append(checks)
    for alts in extra:
        if len(alts) == 1:
            k, v = next(iter(alts[0].items()))
            if k not in out:
                out[k] = v
                continue
        out[_free_key(out, "any_of")] = _merge_any(alts)
    return out


def _merge_any(items: list[Any]) -> list[Any]:
    """Splice nested pure any_of blocks, then merge per-alias "no value" checks into one AND."""
    flat: list[Any] = []
    for it in items:
        key = next(iter(it)) if isinstance(it, dict) and len(it) == 1 else ""
        if key.startswith("any_of") and COMBINATOR.match(key) and isinstance(it[key], list):
            flat.extend(it[key])
        else:
            flat.append(it)
    singles = {i: next(iter(d.items())) for i, d in enumerate(flat) if isinstance(d, dict) and len(d) == 1}
    drop: set[int] = set()
    for group in ALIAS_GROUPS:
        for suffix, val in (("|exists", False), ("", "")):
            idx = [next((i for i, kv in singles.items() if kv == (col + suffix, val) and i not in drop), None) for col in group]
            if all(i is not None for i in idx):
                first = min(idx)
                flat[first] = {col + suffix: val for col in group}
                drop.update(i for i in idx if i != first)
    return [d for i, d in enumerate(flat) if i not in drop]


def migrate_rule(rule: dict[str, Any]) -> dict[str, Any]:
    out = dict(rule)
    for key in ("where", "exclude", "any_in_group"):
        if rule.get(key):
            out[key] = migrate(rule[key])
    if isinstance(rule.get("then"), dict) and rule["then"].get("where"):
        out["then"] = {**rule["then"], "where": migrate(rule["then"]["where"])}
    for key in ("group_by", "entities"):
        if isinstance(rule.get(key), list):
            out[key] = [RENAMED.get(f, f) for f in rule[key]]
    if rule.get("distinct"):
        out["distinct"] = RENAMED.get(rule["distinct"], rule["distinct"])
    return out


def main(argv: list[str] | None = None) -> int:
    import import_community_rules as importer

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    changed_rules = 0
    pending = []
    for pack in sorted((ROOT / "rules" / "community").glob("sigma-*")):
        for path in sorted(pack.glob("*.yaml")):
            text = path.read_text(encoding="utf-8")
            header, body = text.split("\n", 1)
            docs = [d for d in yaml.load_all(body, Loader=importer._Loader) if isinstance(d, dict)]
            new = [migrate_rule(d) for d in docs]
            n = sum(1 for x, y in zip(docs, new) if x != y)
            if not n:
                continue
            changed_rules += n
            pending.append(str(path.relative_to(ROOT)))
            if not a.check:
                path.write_text(header + "\n" + "---\n".join(importer._dump(d) for d in new), encoding="utf-8", newline="\n")
        manifest = pack / "pack.json"
        if not a.check and manifest.is_file():
            m = json.loads(manifest.read_text(encoding="utf-8"))
            if MARK not in m.get("postprocessed", []):
                m["postprocessed"] = [*m.get("postprocessed", []), MARK]
                manifest.write_text(json.dumps(m, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"{changed_rules} rule(s) {'to migrate' if a.check else 'migrated'} in {len(pending)} file(s)")
    for p in pending:
        print("  ", p)
    return 1 if a.check and changed_rules else 0


if __name__ == "__main__":
    sys.exit(main())
