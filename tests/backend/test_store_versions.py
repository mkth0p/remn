"""A server case store records the schema version it is written in. An older store is brought up to
date when it is opened, in one step that either completes or leaves the store as it was; a store
written by a newer version is refused with a message, and nothing in it is changed.

Every store here is invented."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

import duckdb
import pytest
from django.test import Client

from services.store import casestore
from services.store.casestore import TABLES, CaseStore, StoreVersionError, _ddl, registry

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
T0 = 1788300000000


def _version(st: CaseStore) -> int | None:
    row = st.cursor().execute("SELECT value FROM meta WHERE key = 'schema-version'").fetchone()
    return int(row[0]) if row else None


def _history(st: CaseStore) -> list[dict]:
    row = st.cursor().execute("SELECT value FROM meta WHERE key = 'schema-history'").fetchone()
    return json.loads(row[0]) if row else []


def _store_before_versions(root: Path, key: str, without: str = "enriched") -> Path:
    """A store as REMN wrote it before stores carried a version: the tables of the time, one events
    column fewer (a column added since), two invented events and an evidence row."""
    path = root / key / "case.duckdb"
    path.parent.mkdir(parents=True)
    con = duckdb.connect(str(path))
    for t, cols in TABLES.items():
        cols = [c for c in cols if not (t == "events" and c[0] == without)]
        con.execute(_ddl(t, cols, pk='kind, value, "evidenceId"' if t == "iocs" else ('"mailId"' if t == "mail_bodies" else None)))
    con.execute(
        'CREATE TABLE evidence (id INTEGER PRIMARY KEY, name VARCHAR, kind VARCHAR, format VARCHAR, size BIGINT, "sha256Client" VARCHAR, "sha256Server" VARCHAR, count BIGINT, stats VARCHAR, "addedAt" BIGINT, status VARCHAR)'
    )
    con.execute("CREATE TABLE meta (key VARCHAR PRIMARY KEY, value VARCHAR)")
    con.execute(
        f"INSERT INTO events (id, \"evidenceId\", ts, \"eventId\", computer, summary) VALUES (1, 1, {T0}, 4624, 'WS01', 'invented one'), (2, 1, {T0 + 1}, 4625, 'WS02', 'invented two')"
    )
    con.execute("INSERT INTO evidence (id, name, kind, count, status) VALUES (1, 'invented.evtx', 'evtx', 2, 'done')")
    con.close()
    return path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_a_new_store_records_the_schema_version_it_is_written_in(tmp_path):
    st = CaseStore(tmp_path, str(uuid.uuid4()))
    assert _version(st) == casestore.SCHEMA_VERSION
    assert _history(st) == []
    st.close()


def test_a_store_written_before_versions_were_kept_is_upgraded_when_opened_and_keeps_every_row(tmp_path, caplog):
    key = str(uuid.uuid4())
    _store_before_versions(tmp_path, key)
    st = CaseStore(tmp_path, key)
    assert _version(st) == casestore.SCHEMA_VERSION
    assert st.cursor().execute('SELECT id, "evidenceId", ts, "eventId", computer, summary, enriched FROM events ORDER BY id').fetchall() == [
        (1, 1, T0, 4624, "WS01", "invented one", None),
        (2, 1, T0 + 1, 4625, "WS02", "invented two", None),
    ]
    assert st.cursor().execute("SELECT name, count FROM evidence").fetchall() == [("invented.evtx", 2)]
    # the change is recorded in the store and said in the log, not made silently
    [step] = _history(st)
    assert step["from"] == 0 and step["to"] == casestore.SCHEMA_VERSION and step["added"] == {"events": ["enriched"]} and step["at"]
    assert any("upgraded" in r.getMessage() and key in r.getMessage() for r in caplog.records)
    st.close()
    # opened again, there is nothing left to do
    again = CaseStore(tmp_path, key)
    assert len(_history(again)) == 1
    again.close()


def test_a_store_written_by_a_newer_version_is_refused_and_left_as_it_was(tmp_path):
    key = str(uuid.uuid4())
    st = CaseStore(tmp_path, key)
    st.cursor().execute("UPDATE meta SET value = ? WHERE key = 'schema-version'", [str(casestore.SCHEMA_VERSION + 1)])
    # a table this version does not know, as a later version might add
    st.cursor().execute("CREATE TABLE later_table (x INTEGER)")
    st.close()
    before = _sha256(st.path)
    with pytest.raises(StoreVersionError) as refused:
        CaseStore(tmp_path, key)
    said = str(refused.value)
    assert f"store schema {casestore.SCHEMA_VERSION + 1}" in said and f"reads up to {casestore.SCHEMA_VERSION}" in said
    assert "nothing in it was changed" in said
    assert _sha256(st.path) == before
    # and the file is not left open: another connection may take it
    duckdb.connect(str(st.path), read_only=True).close()


def test_a_store_whose_version_cannot_be_read_is_refused(tmp_path):
    key = str(uuid.uuid4())
    st = CaseStore(tmp_path, key)
    st.cursor().execute("UPDATE meta SET value = 'invented' WHERE key = 'schema-version'")
    st.close()
    with pytest.raises(StoreVersionError, match="cannot read"):
        CaseStore(tmp_path, key)


def test_the_store_routes_answer_a_newer_store_with_what_to_do(tmp_path):
    old = registry.root
    registry.configure(tmp_path / "cases")
    try:
        key = str(uuid.uuid4())
        st = CaseStore(tmp_path / "cases", key)
        st.cursor().execute("UPDATE meta SET value = ? WHERE key = 'schema-version'", [str(casestore.SCHEMA_VERSION + 1)])
        st.close()
        for r in (
            Client().get(f"/api/store/{key}", **HDR),
            Client().post(f"/api/store/{key}/count", data=json.dumps({"source": "events"}), content_type="application/json", **HDR),
        ):
            assert r.status_code == 409, r.content
            assert r.json()["code"] == "storeVersion" and "newer version of REMN" in r.json()["error"]
    finally:
        registry.close_all()
        if old:
            registry.configure(old)


def test_every_schema_version_has_its_upgrade_step():
    assert sorted(casestore.MIGRATIONS) == list(range(1, casestore.SCHEMA_VERSION + 1))


def test_an_upgrade_runs_each_step_once_in_order_and_records_it(tmp_path, monkeypatch):
    key = str(uuid.uuid4())
    CaseStore(tmp_path, key).close()
    ran: list[int] = []

    def step(n: int):
        def run(con: duckdb.DuckDBPyConnection) -> None:
            ran.append(n)
            con.execute(f"INSERT INTO evidence (id, name) VALUES ({n}, 'step {n}')")

        return run

    monkeypatch.setattr(casestore, "SCHEMA_VERSION", casestore.SCHEMA_VERSION + 2)
    monkeypatch.setitem(casestore.MIGRATIONS, casestore.SCHEMA_VERSION - 1, step(casestore.SCHEMA_VERSION - 1))
    monkeypatch.setitem(casestore.MIGRATIONS, casestore.SCHEMA_VERSION, step(casestore.SCHEMA_VERSION))
    st = CaseStore(tmp_path, key)
    assert ran == [casestore.SCHEMA_VERSION - 1, casestore.SCHEMA_VERSION]
    assert _version(st) == casestore.SCHEMA_VERSION
    assert [(h["from"], h["to"]) for h in _history(st)] == [(casestore.SCHEMA_VERSION - 2, casestore.SCHEMA_VERSION)]
    st.close()
    CaseStore(tmp_path, key).close()
    assert len(ran) == 2


def test_an_upgrade_that_fails_part_way_leaves_the_store_as_it_was(tmp_path, monkeypatch):
    key = str(uuid.uuid4())
    path = _store_before_versions(tmp_path, key)

    def breaks(con: duckdb.DuckDBPyConnection) -> None:
        con.execute("DELETE FROM events")
        raise RuntimeError("an invented failure part-way through an upgrade")

    monkeypatch.setitem(casestore.MIGRATIONS, 1, breaks)
    with pytest.raises(RuntimeError, match="invented failure"):
        CaseStore(tmp_path, key)
    con = duckdb.connect(str(path), read_only=True)
    try:
        assert con.execute("SELECT count(*) FROM events").fetchone() == (2,)
        assert con.execute("SELECT count(*) FROM meta").fetchone() == (0,)
        assert "enriched" not in {r[1] for r in con.execute("PRAGMA table_info('events')").fetchall()}
    finally:
        con.close()
