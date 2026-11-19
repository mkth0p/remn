"""/api/meta parses the bundled rules once and keeps them until a rule file or the measures file
changes, instead of parsing about a second of YAML on every request."""

from __future__ import annotations

import os

import pytest
from django.test import Client, override_settings

from api.views import meta

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
RULE = "id: invented-rule\ntitle: {title}\nseverity: low\nsource: events\nwhere: {{eventId: 4625}}\n"


@pytest.fixture
def counted(monkeypatch):
    calls: list[str] = []
    real = meta.load_rules

    def load_rules(rules_dir):
        calls.append(str(rules_dir))
        return real(rules_dir)

    monkeypatch.setattr(meta, "load_rules", load_rules)
    monkeypatch.setattr(meta, "_parsed", None)
    return calls


def test_the_bundled_rules_are_parsed_once_for_many_requests(counted):
    c = Client()
    first = c.get("/api/meta", **HDR)
    second = c.get("/api/meta", **HDR)
    assert first.status_code == 200 and second.content == first.content
    assert len(counted) == 1


def test_an_added_edited_or_removed_rule_file_is_parsed_again(tmp_path, counted):
    with override_settings(RULES_DIR=tmp_path):
        rule = tmp_path / "events" / "invented.yml"
        rule.parent.mkdir()
        rule.write_text(RULE.format(title="first"), encoding="utf-8")
        assert [r["rule"]["title"] for r in meta.bundled_rules(tmp_path)] == ["first"]
        assert [r["rule"]["title"] for r in meta.bundled_rules(tmp_path)] == ["first"] and len(counted) == 1
        rule.write_text(RULE.format(title="second, edited"), encoding="utf-8")
        assert [r["rule"]["title"] for r in meta.bundled_rules(tmp_path)] == ["second, edited"] and len(counted) == 2
        (tmp_path / "events" / "another.yml").write_text(RULE.format(title="added").replace("invented-rule", "another-rule"), encoding="utf-8")
        assert sorted(r["rule"]["title"] for r in meta.bundled_rules(tmp_path)) == ["added", "second, edited"] and len(counted) == 3
        rule.unlink()
        assert [r["rule"]["title"] for r in meta.bundled_rules(tmp_path)] == ["added"] and len(counted) == 4


def test_a_change_to_the_measures_file_is_parsed_again(tmp_path, counted):
    with override_settings(RULES_DIR=tmp_path):
        (tmp_path / "invented.yml").write_text(RULE.format(title="t"), encoding="utf-8")
        meta.bundled_rules(tmp_path)
        measures_file = tmp_path / "measures.json"
        measures_file.write_text("{}", encoding="utf-8")
        meta.bundled_rules(tmp_path)
        assert len(counted) == 2
        stat = measures_file.stat()
        os.utime(measures_file, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
        meta.bundled_rules(tmp_path)
        assert len(counted) == 3
