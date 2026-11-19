"""What one server case store may take from the server: how long a query or a rule may run.

Every store here is invented. A store too large to scan within a limit is made without writing it:
its events table becomes a view of one invented event repeated ten billion times."""

from __future__ import annotations

import json
import threading
import time
import uuid

import duckdb
import pytest
from django.test import Client

from services.store import rules as R
from services.store.casestore import CaseStore, StoreRegistry, registry
from services.store.writers import EventWriter

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
T0 = 1788300000000


@pytest.fixture
def server_registry(tmp_path):
    """The registry the routes use, on a folder of its own for the test."""
    old = registry.root
    registry.configure(tmp_path / "cases")
    yield registry
    registry.close_all()
    if old:
        registry.configure(old)


def _endless(st: CaseStore) -> None:
    """Turn the store's events into ten billion copies of one invented event, each with its own id and time."""
    con = st.cursor()
    con.execute(
        'INSERT INTO events (id, "evidenceId", ts, "eventId", provider, channel, computer, summary, "commandLine", "targetUser") '
        f"VALUES (1, 1, {T0}, 4624, 'Microsoft-Windows-Security-Auditing', 'Security', 'WS01', 'invented event', 'cmd.exe /c echo invented', 'bob')"
    )
    con.execute("ALTER TABLE events RENAME TO events_seed")
    con.execute("CREATE VIEW events AS SELECT * REPLACE (e.id + r.range AS id, e.ts + r.range AS ts) FROM events_seed e, range(10000000000) r")


class _Guard:
    """Stops whatever still runs on the store after `seconds`, so that a server without a limit of its
    own fails the test rather than scanning ten billion rows."""

    def __init__(self, st: CaseStore, seconds: float = 20) -> None:
        self.st = st
        self.seconds = seconds
        self.cursors: list[duckdb.DuckDBPyConnection] = [st._con]
        self.original = st.cursor
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.stop, daemon=True)

    def cursor(self) -> duckdb.DuckDBPyConnection:
        con = self.original()
        self.cursors.append(con)
        return con

    def stop(self) -> None:
        # an interrupt that lands between two statements is forgotten by the next, so it is repeated
        if self.done.wait(self.seconds):
            return
        while not self.done.wait(0.2):
            for con in list(self.cursors):
                try:
                    con.interrupt()
                except duckdb.Error:
                    pass

    def __enter__(self) -> _Guard:
        self.st.cursor = self.cursor  # type: ignore[method-assign]
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.done.set()
        del self.st.cursor


ROUTES = [
    ("post", "search", {"source": "events", "limit": 10}),
    ("post", "count", {"source": "events"}),
    ("post", "aggregate", {"source": "events", "field": "eventId"}),
    ("post", "stack", {"field": "commandLine"}),
    ("post", "timeline", {"source": "events"}),
    ("post", "pivot", {"value": "invented"}),
    ("post", "sql", {"sql": "SELECT count(*) AS n FROM events_seed, range(10000000000)"}),
    ("get", "facets?source=events&field=eventId", None),
    ("get", "row?source=events&id=5", None),
    ("get", "", None),
]


@pytest.mark.parametrize(("method", "route", "body"), ROUTES, ids=[r[1].split("?")[0] or "summary" for r in ROUTES])
def test_a_store_query_past_its_time_limit_is_stopped_and_says_why(server_registry, settings, method, route, body):
    settings.FORENSIC_STORE_QUERY_MAX_S = 0.2
    key = str(uuid.uuid4())
    st = server_registry.get(key)
    _endless(st)
    url = f"/api/store/{key}" + (f"/{route}" if route else "")
    t0 = time.time()
    with _Guard(st):
        if method == "post":
            r = Client().post(url, data=json.dumps(body), content_type="application/json", **HDR)
        else:
            r = Client().get(url, **HDR)
    assert time.time() - t0 < 10
    assert r.status_code == 504, r.content
    answer = r.json()
    assert answer["code"] == "queryStopped"
    assert "stopped after 0.2 s" in answer["error"] and "FORENSIC_STORE_QUERY_MAX_S" in answer["error"]
    # the store is still there for the next query
    assert Client().post(f"/api/store/{key}/count", data=json.dumps({"source": "mails"}), content_type="application/json", **HDR).json() == {"count": 0}


def test_a_query_inside_its_limit_is_answered_as_before(server_registry, settings):
    settings.FORENSIC_STORE_QUERY_MAX_S = 30
    key = str(uuid.uuid4())
    st = server_registry.get(key)
    w = EventWriter(st, 1)
    for i in range(50):
        w.add({"recordId": i, "ts": T0 + i, "eventId": 4624, "computer": "WS01", "summary": f"invented {i}"})
    w.flush()
    r = Client().post(f"/api/store/{key}/count", data=json.dumps({"source": "events"}), content_type="application/json", **HDR)
    assert r.status_code == 200 and r.json() == {"count": 50}


def _wait_for(key: str, job_id: str, seconds: float = 60) -> dict:
    deadline = time.time() + seconds
    while time.time() < deadline:
        j = Client().get(f"/api/jobs/{job_id}?case={key}", **HDR).json()
        if j["status"] in ("done", "error", "cancelled"):
            return j
        time.sleep(0.1)
    raise AssertionError(f"job {job_id} still running")


def test_a_rule_past_its_time_limit_is_stopped_said_and_the_run_goes_on(server_registry, settings):
    settings.FORENSIC_STORE_RULE_MAX_S = 0.2
    key = str(uuid.uuid4())
    st = server_registry.get(key)
    _endless(st)
    st.cursor().execute(f"INSERT INTO mails (id, \"evidenceId\", subject, date) VALUES (1, 2, 'invented subject', {T0})")
    rules = [
        {"id": "invented-slow", "title": "every logon", "severity": "low", "source": "events", "where": {"eventId": 4624}},
        {"id": "invented-quick", "title": "an invented subject", "severity": "low", "source": "mails", "where": {"subject|contains": "invented"}},
    ]
    t0 = time.time()
    with _Guard(st):
        r = Client().post(f"/api/store/{key}/rules/run", data=json.dumps({"rules": rules, "settings": {}}), content_type="application/json", **HDR)
        assert r.status_code == 200, r.content
        job = _wait_for(key, r.json()["jobId"])
    assert time.time() - t0 < 15
    assert job["status"] == "done", job
    result = job["result"]
    assert [e["ruleId"] for e in result["errors"]] == ["invented-slow"]
    said = result["errors"][0]["error"]
    assert "stopped after 0.2 s" in said and "FORENSIC_STORE_RULE_MAX_S" in said
    assert result["byRule"] == {"invented-slow": 0, "invented-quick": 1}


def test_a_rule_run_has_no_time_limit_unless_one_is_given(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path)
    st = reg.get(str(uuid.uuid4()))
    try:
        w = EventWriter(st, 1)
        for i in range(5):
            w.add({"recordId": i, "ts": T0 + i, "eventId": 4625, "computer": "WS01"})
        w.flush()
        out = R.run_rules(st, [{"id": "invented", "source": "events", "where": {"eventId": 4625}}], {})
        assert out["errors"] == [] and out["byRule"] == {"invented": 5}
    finally:
        reg.close_all()
