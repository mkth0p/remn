"""What one server case store may take from the server: how long a query or a rule may run, the
memory and threads each open store gets, and how long a store nobody uses stays open.

Every store here is invented. A store too large to scan within a limit is made without writing it:
its events table becomes a view of one invented event repeated ten billion times."""

from __future__ import annotations

import gc
import json
import threading
import time
import uuid
import weakref

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


def _endless_mails(st: CaseStore) -> None:
    """Turn the store's mails into a view that scans ten billion rows to find one invented mail."""
    con = st.cursor()
    con.execute(f"INSERT INTO mails (id, \"evidenceId\", subject, date) VALUES (1, 2, 'invented subject', {T0})")
    con.execute("ALTER TABLE mails RENAME TO mails_seed")
    con.execute("CREATE VIEW mails AS SELECT * REPLACE (m.id + r.range AS id) FROM mails_seed m, range(10000000000) r WHERE r.range = 9999999999")


BUILDS = [
    ("stories/build", {"findings": [{"ruleId": "invented", "source": "events", "refs": [5]}], "settings": {}}),
    ("relationships/build", {}),
    ("enrich/mails", {"settings": {}}),
]


@pytest.mark.parametrize(("route", "body"), BUILDS, ids=[b[0].split("/")[0] for b in BUILDS])
def test_a_build_that_reads_a_store_past_the_query_time_limit_is_stopped_and_says_why(server_registry, settings, route, body):
    settings.FORENSIC_STORE_QUERY_MAX_S = 0.2
    key = str(uuid.uuid4())
    st = server_registry.get(key)
    _endless(st)
    _endless_mails(st)
    t0 = time.time()
    with _Guard(st):
        r = Client().post(f"/api/{route}", data=json.dumps({**body, "storeKey": key}), content_type="application/json", **HDR)
    assert time.time() - t0 < 10
    assert r.status_code == 504, r.content
    answer = r.json()
    assert answer["code"] == "queryStopped"
    assert "stopped after 0.2 s" in answer["error"] and "FORENSIC_STORE_QUERY_MAX_S" in answer["error"]


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


def test_the_scan_for_long_values_before_the_rules_is_held_to_their_time_limit(server_registry, settings):
    # a regex rule first has the run look for values too long to read whole, over the same rows
    settings.FORENSIC_STORE_RULE_MAX_S = 0.2
    key = str(uuid.uuid4())
    st = server_registry.get(key)
    _endless(st)
    rules = [{"id": "invented-slow", "title": "an invented command", "severity": "low", "source": "events", "where": {"commandLine|re": "invented$"}}]
    t0 = time.time()
    with _Guard(st):
        r = Client().post(f"/api/store/{key}/rules/run", data=json.dumps({"rules": rules, "settings": {}}), content_type="application/json", **HDR)
        assert r.status_code == 200, r.content
        job = _wait_for(key, r.json()["jobId"])
    assert time.time() - t0 < 10
    assert job["status"] == "done", job
    assert [e["ruleId"] for e in job["result"]["errors"]] == ["invented-slow"]


def test_cancelling_a_rule_run_stops_the_rule_that_is_running(server_registry, settings):
    settings.FORENSIC_STORE_RULE_MAX_S = 0
    key = str(uuid.uuid4())
    st = server_registry.get(key)
    _endless_mails(st)
    rules = [
        {"id": "invented-slow", "title": "an invented subject", "severity": "low", "source": "mails", "where": {"subject|contains": "invented"}},
        {"id": "invented-next", "title": "another invented subject", "severity": "low", "source": "mails", "where": {"subject|contains": "other"}},
    ]
    with _Guard(st) as guard:
        r = Client().post(f"/api/store/{key}/rules/run", data=json.dumps({"rules": rules, "settings": {}}), content_type="application/json", **HDR)
        assert r.status_code == 200, r.content
        job_id = r.json()["jobId"]
        # the cancel is sent once the first rule's query has started
        deadline = time.time() + 10
        while len(guard.cursors) < 2 and time.time() < deadline:
            time.sleep(0.05)
        time.sleep(0.3)
        t0 = time.time()
        assert Client().delete(f"/api/jobs/{job_id}?case={key}", **HDR).json() == {"cancelled": True}
        job = _wait_for(key, job_id)
    assert time.time() - t0 < 5
    assert job["status"] == "cancelled", job
    # the rule that was stopped is neither counted nor reported as failed, and the next one did not run
    assert job["result"]["byRule"] == {} and job["result"]["errors"] == []
    # the run says how many of its rules did not run: the one stopped and the one after it
    assert job["result"]["notRun"] == 2


def test_a_cancelled_rule_run_counts_the_enabled_rules_it_did_not_run(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path)
    st = reg.get(str(uuid.uuid4()))
    try:
        w = EventWriter(st, 1)
        for i in range(5):
            w.add({"recordId": i, "ts": T0 + i, "eventId": 4625, "computer": "WS01"})
        w.flush()
        rules = [
            {"id": "invented-first", "source": "events", "where": {"eventId": 4625}},
            {"id": "invented-second", "source": "events", "where": {"eventId": 4625}},
            {"id": "invented-off", "source": "events", "where": {"eventId": 4625}, "enabled": False},
            {"id": "invented-third", "source": "events", "where": {"eventId": 4625}},
        ]
        done: list[str] = []
        out = R.run_rules(st, rules, {}, progress=lambda p: done.append(p["ruleId"]), cancelled=lambda: len(done) >= 1)
        assert out["byRule"] == {"invented-first": 5}
        # the second and third did not run; the one turned off is not counted
        assert out["notRun"] == 2
        assert R.run_rules(st, rules, {})["notRun"] == 0
    finally:
        reg.close_all()


def test_a_mail_rescore_that_reads_a_store_past_the_query_time_limit_is_stopped_and_says_why(server_registry, settings):
    settings.FORENSIC_STORE_QUERY_MAX_S = 0.2
    key = str(uuid.uuid4())
    st = server_registry.get(key)
    _endless_mails(st)
    t0 = time.time()
    with _Guard(st):
        r = Client().post("/api/enrich/mails/rescore", data=json.dumps({"storeKey": key, "settings": {}}), content_type="application/json", **HDR)
        assert r.status_code == 202, r.content
        job = _wait_for(key, r.json()["jobId"])
    assert time.time() - t0 < 10
    assert job["status"] == "error", job
    assert "stopped after 0.2 s" in job["error"] and "FORENSIC_STORE_QUERY_MAX_S" in job["error"] and "ref" not in job["error"]
    # the store is still there for the next query
    assert Client().post(f"/api/store/{key}/count", data=json.dumps({"source": "events"}), content_type="application/json", **HDR).json() == {"count": 0}


def test_each_read_of_a_mail_rescore_is_held_to_the_query_time_limit(server_registry, monkeypatch):
    from services.analysis import baseline, rescore
    from services.store.casestore import QueryStopped, TimeLimit

    st = server_registry.get(str(uuid.uuid4()))
    _endless_mails(st)
    # past the sender history read, the rescore reads the mails in pages
    monkeypatch.setattr(baseline, "enrich_store", lambda store, settings: {})
    t0 = time.time()
    with _Guard(st), pytest.raises(QueryStopped, match="invented limit"):
        rescore.store(st, {}, limit=lambda: TimeLimit(0.2, "invented limit"))
    assert time.time() - t0 < 10


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


def test_each_open_store_takes_its_memory_and_threads_from_the_configuration(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path, memory_mb=256, threads=2)
    st = reg.get(str(uuid.uuid4()))
    try:
        assert st.cursor().execute("SELECT current_setting('memory_limit'), current_setting('threads')").fetchone() == ("256.0 MiB", 2)
    finally:
        reg.close_all()


def test_the_server_gives_its_stores_the_limits_of_its_settings(settings):
    assert (registry.memory_mb, registry.threads, registry.idle_s) == (
        settings.FORENSIC_STORE_MEMORY_MB,
        settings.FORENSIC_STORE_THREADS,
        settings.FORENSIC_STORE_IDLE_S,
    )


def _store_with_rows(reg: StoreRegistry, n: int = 20) -> tuple[str, CaseStore]:
    key = str(uuid.uuid4())
    st = reg.get(key)
    w = EventWriter(st, 1)
    for i in range(n):
        w.add({"recordId": i, "ts": T0 + i, "eventId": 4624, "computer": "WS01", "summary": f"invented {i}"})
    w.flush()
    return key, st


def test_a_store_unused_for_the_idle_time_is_closed_and_opens_again_with_its_rows(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path, idle_s=60)
    key, st = _store_with_rows(reg)
    path, gone = st.path, weakref.ref(st)
    del st
    assert reg.evict_idle(now=time.time() + 61) == 1
    gc.collect()
    assert gone() is None
    # closed, not only forgotten: another connection may open the file again
    duckdb.connect(str(path), read_only=True).close()
    again = reg.get(key, create=False)
    assert again.counts()["events"] == 20
    reg.close_all()


def test_a_store_still_held_by_a_request_or_a_job_is_not_closed_and_is_handed_out_again(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path, idle_s=60)
    key, st = _store_with_rows(reg)
    assert reg.evict_idle(now=time.time() + 61) == 1
    # still open for whoever holds it, and never a second store on the same file
    assert st.cursor().execute("SELECT count(*) FROM events").fetchone() == (20,)
    assert reg.get(key) is st
    reg.close_all()


def test_a_store_used_within_the_idle_time_stays_open(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path, idle_s=60)
    _store_with_rows(reg)
    assert reg.evict_idle(now=time.time() + 30) == 0
    reg.close_all()


def test_idle_stores_are_closed_without_waiting_for_a_request(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path, idle_s=1)
    _, st = _store_with_rows(reg)
    gone = weakref.ref(st)
    del st
    deadline = time.time() + 15
    while gone() is not None and time.time() < deadline:
        time.sleep(0.2)
        gc.collect()
    assert gone() is None
    reg.close_all()


def test_an_idle_time_of_zero_keeps_every_store_open(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path, idle_s=0)
    _store_with_rows(reg)
    assert reg.evict_idle(now=time.time() + 10**6) == 0
    reg.close_all()
