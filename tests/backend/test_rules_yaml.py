"""Static checks on the bundled rule catalogue (rules/**/*.yaml)."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

RULES = Path(__file__).resolve().parents[2] / "rules"
OPS = {"eq", "ne", "in", "nin", "contains", "not_contains", "contains_any", "contains_all", "startswith", "not_startswith",
       "endswith", "not_endswith", "re", "not_re", "gt", "gte", "lt", "lte", "exists", "empty", "in_setting", "nin_setting",
       "levenshtein", "length"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
GROUP_KEYS = re.compile(r"^(any_of|all_of)(_\d+)?$|^not$")


class DuplicateKey(Exception):
    pass


class StrictLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node, deep=False):
    seen = set()
    for k, _ in node.value:
        key = loader.construct_object(k, deep=deep)
        if key in seen:
            raise DuplicateKey(f"duplicate key {key!r} at line {k.start_mark.line + 1}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _docs():
    for path in sorted(RULES.rglob("*.yaml")):
        for doc in yaml.load_all(path.read_text(encoding="utf-8"), Loader=StrictLoader):
            if isinstance(doc, dict):
                yield path, doc


def _walk_cond(cond, rule_id: str):
    assert isinstance(cond, dict), f"{rule_id}: condition must be a mapping"
    for key, value in cond.items():
        if GROUP_KEYS.match(key):
            alts = value if isinstance(value, list) else [value]
            for alt in alts:
                _walk_cond(alt, rule_id)
            continue
        field, _, op = key.partition("|")
        assert field, f"{rule_id}: empty field in {key!r}"
        assert not op or op in OPS, f"{rule_id}: unknown operator {op!r} in {key!r}"
        if op in ("re", "not_re"):
            for pat in value if isinstance(value, list) else [value]:
                re.compile(str(pat).replace("(?i)", ""))


def test_rules_have_no_duplicate_keys_and_valid_shape():
    docs = list(_docs())  # raises DuplicateKey on duplicates
    assert len(docs) >= 40
    ids = [d["id"] for _, d in docs]
    assert len(ids) == len(set(ids)), f"duplicate rule ids: {[i for i in ids if ids.count(i) > 1]}"
    for path, d in docs:
        rid = d.get("id")
        assert rid and re.match(r"^[a-z0-9-]+$", rid), f"{path}: bad id {rid!r}"
        assert d.get("title") and d.get("severity") in SEVERITIES and d.get("source") in ("events", "mails"), f"{rid}: missing title/severity/source"
        for key in ("where", "exclude", "any_in_group"):
            if key in d:
                _walk_cond(d[key], rid)
        if "then" in d:
            _walk_cond(d["then"]["where"], rid)
        if "threshold" in d:
            assert re.match(r"^\s*(>=|<=|==|=|>|<|!=)?\s*\d+\s*$", str(d["threshold"])), f"{rid}: bad threshold"
        if "window" in d:
            assert re.match(r"^\d+(ms|s|m|h|d|w)$", str(d["window"])), f"{rid}: bad window"
        for t in d.get("attack", []):
            assert re.match(r"^T\d{4}(\.\d{3})?$", t), f"{rid}: bad ATT&CK id {t}"


@pytest.mark.parametrize("path", sorted(RULES.rglob("*.yaml")))
def test_each_file_parses_strictly(path):
    list(yaml.load_all(path.read_text(encoding="utf-8"), Loader=StrictLoader))
