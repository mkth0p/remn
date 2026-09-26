"""Stacking (least-frequency analysis) over the server store: services/store/queries.stack."""

from __future__ import annotations

import uuid

import pytest

from services.store import queries as Q
from services.store.casestore import StoreRegistry
from services.store.sqlfilter import FilterError
from services.store.writers import EventWriter

T0 = 1788300000000


def _ev(i: int, computer: str, image: str | None, **kw):
    row = {"recordId": i, "ts": T0 + i * 1000, "eventId": 1, "provider": "Microsoft-Windows-Sysmon", "channel": "Sysmon", "computer": computer, "image": image}
    row.update(kw)
    return row


@pytest.fixture
def store(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    st = reg.get(str(uuid.uuid4()))
    rows = []
    # svchost on every host, many times; one oddity on one host; a path spelled in two cases on two hosts
    for host in ["WS01.corp.local", "WS02.corp.local", "WS03", "DC01.corp.local"]:
        for _ in range(5):
            rows.append(_ev(len(rows), host, r"C:\Windows\System32\svchost.exe"))
        rows.append(_ev(len(rows), host, None, eventId=4624, provider="Microsoft-Windows-Security-Auditing"))
    rows.append(_ev(len(rows), "WS02.corp.local", r"C:\Users\Public\evil.exe"))
    rows.append(_ev(len(rows), "WS01.corp.local", r"C:\ProgramData\Tool\agent.exe"))
    rows.append(_ev(len(rows), "ws03", r"c:\programdata\tool\AGENT.exe"))
    w = EventWriter(st, 1)
    for r in rows:
        w.add(r)
    w.flush()
    yield st
    reg.close_all()


def test_stack_rarest_first_with_hosts_and_times(store):
    r = Q.stack(store, None, "image")
    assert r["distinct"] == 3 and not r["truncated"]
    assert r["hosts"] == 4 and r["blank"] == 4 and r["events"] == 23
    first, second, last = r["rows"]
    assert first["value"] == r"C:\Users\Public\evil.exe" and first["count"] == 1 and first["hosts"] == 1 and first["hostList"] == ["ws02"]
    assert first["first"] == first["last"] == T0 + 24 * 1000
    # case-insensitive grouping: two spellings of one path on two hosts are one value
    assert second["count"] == 2 and second["hosts"] == 2 and second["hostList"] == ["ws01", "ws03"]
    assert second["value"].lower() == r"c:\programdata\tool\agent.exe"
    assert last["count"] == 20 and last["hosts"] == 4 and last["hostList"] == ["dc01", "ws01", "ws02", "ws03"]


def test_stack_most_frequent_first_limit_and_filter(store):
    r = Q.stack(store, None, "image", order="common", limit=1)
    assert r["order"] == "common" and r["rows"][0]["count"] == 20
    # a limit never hides how many values there are
    assert r["truncated"] and r["distinct"] == 3 and len(r["rows"]) == 1
    # the Events page's filter applies
    r = Q.stack(store, {"conditions": [{"field": "computer", "op": "eq", "value": "WS02.corp.local"}]}, "image")
    assert [x["count"] for x in r["rows"]] == [1, 5] and r["hosts"] == 1
    r = Q.stack(store, {"text": "evil"}, "image")
    assert r["distinct"] == 1


def test_stack_provider_event_pairs_and_unknown_field(store):
    r = Q.stack(store, None, "providerEventId")
    assert [(x["value"], x["count"], x["hosts"]) for x in r["rows"]] == [
        ("Microsoft-Windows-Security-Auditing / 4624", 4, 4),
        ("Microsoft-Windows-Sysmon / 1", 23, 4),
    ]
    with pytest.raises(FilterError):
        Q.stack(store, None, "raw")


def test_stack_endpoint(tmp_path):
    from django.test import Client

    from services.store.casestore import registry

    old = registry.root
    registry.configure(tmp_path / "http")
    try:
        st = registry.get(str(uuid.uuid4()))
        w = EventWriter(st, 1)
        for i, host in enumerate(["WS01", "WS02", "WS02"]):
            w.add(_ev(i, host, rf"C:\Tools\t{i % 2}.exe"))
        w.flush()
        c = Client()

        def post(body):
            return c.post(f"/api/store/{st.key}/stack", data=body, content_type="application/json", HTTP_X_FORENSIC_CLIENT="1")

        r = post({"field": "image", "limit": 1})
        assert r.status_code == 200
        body = r.json()
        assert body["rows"][0]["value"] == r"C:\Tools\t1.exe" and body["rows"][0]["hostList"] == ["ws02"] and body["truncated"] and body["distinct"] == 2
        assert post({"field": "raw"}).status_code == 400
    finally:
        registry.configure(old)
