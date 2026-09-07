"""Rules pinned to event ids / channels absent from the evidence are skipped and reported, not run silently."""

from __future__ import annotations

import uuid

import pytest

from services.store import rules as R
from services.store.casestore import StoreRegistry
from services.store.writers import EventWriter

T0 = 1_756_800_000_000


@pytest.fixture
def store(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    st = reg.get(str(uuid.uuid4()))
    yield st
    reg.close_all()


def _ev(i: int, **kw):
    row = {
        "id": i,
        "ts": T0 + i * 1000,
        "tsIso": "2025-09-02T08:00:00Z",
        "eventId": 4624,
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "computer": "WS-1",
        "recordId": i,
        "summary": "logon",
        "targetUser": "alice",
        "raw": "{}",
    }
    row.update(kw)
    return row


def test_channel_selectors_mirror_the_browser_engine():
    assert R._rule_channels({"channel": "Security", "eventId": 4688}) == [("security", False)]
    assert R._rule_channels({"channel|contains": "sysmon"}) == [("sysmon", True)]
    assert R._rule_channels({"any_of": [{"channel|contains": "sysmon", "eventId": 1}, {"channel": "Security", "eventId": 4688}]}) == [
        ("sysmon", True),
        ("security", False),
    ]
    # an alternative without a channel pin unpins the whole rule
    assert R._rule_channels({"any_of": [{"channel": "Security"}, {"image|contains": "x"}]}) is None
    assert R._rule_channels({"all_of": [{"image|contains": "x"}, {"channel": "System"}]}) == [("system", False)]
    assert R._rule_channels({"image|contains": "x"}) is None


def test_not_applicable_reasons():
    ids, chans = {4624, 4625}, {"security"}
    assert R.rule_not_applicable({"source": "events", "where": {"eventId": 4688}}, ids, chans) == "no event id 4688 in this evidence"
    assert (
        R.rule_not_applicable({"source": "events", "where": {"eventId": 4624, "channel|contains": "sysmon"}}, ids, chans)
        == 'no "sysmon" channel in this evidence'
    )
    assert R.rule_not_applicable({"source": "events", "where": {"eventId": 4624, "channel": "Security"}}, ids, chans) is None
    assert R.rule_not_applicable({"source": "events", "where": {"targetUser": "alice"}}, ids, chans) is None
    assert R.rule_not_applicable({"source": "mails", "where": {"risk|gte": 80}}, set(), set()) is None


def test_run_rules_skips_inapplicable_rules_and_still_reports_them(store):
    w = EventWriter(store, 1)
    w.add(_ev(1))
    w.add(_ev(2, targetUser="bob"))
    w.flush()
    rules = [
        {"id": "fires", "title": "logon", "severity": "low", "source": "events", "where": {"eventId": 4624}},
        {"id": "sysmon-only", "title": "process", "severity": "high", "source": "events", "where": {"eventId": 1, "channel|contains": "sysmon"}},
        {"id": "no-id-pin", "title": "user", "severity": "low", "source": "events", "where": {"targetUser": "bob"}},
    ]
    res = R.run_rules(store, rules, {})
    assert not res["errors"]
    assert res["byRule"] == {"fires": 2, "sysmon-only": 0, "no-id-pin": 1}
    skipped = [d for d in res["diagnostics"] if d["reason"] == "not_applicable"]
    assert [d["ruleId"] for d in skipped] == ["sysmon-only"]
    assert "no event id 1" in skipped[0]["detail"]
    ids, chans = R.present_selectors(store)
    assert ids == {4624} and chans == {"security"}
