"""Backup and restore of the server case stores (tools/store_backup.py).

A backup is the store's own files, copied while the tool holds the store so nothing writes to it,
with a manifest of their sizes, digests, schema version and row counts, and checked by opening the
copy. A restore checks the backup before it changes anything and never writes over a case.

Every store here is invented."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import duckdb
import pytest
from django.test import Client

from services.store import casestore
from services.store.casestore import CaseStore, StoreRegistry, registry
from services.store.writers import EventWriter

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "store_backup.py"
_spec = importlib.util.spec_from_file_location("store_backup", TOOL)
store_backup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(store_backup)

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
T0 = 1788300000000
TABLES = ("events", "mails", "attachments", "urls", "mail_bodies", "iocs", "evidence", "ioc_reputation", "meta")


def _invented_case(cases: Path) -> str:
    """A store with rows in every table, then closed, as the server leaves a case nobody is using."""
    reg = StoreRegistry()
    reg.configure(cases)
    key = str(uuid.uuid4())
    st = reg.get(key)
    w = EventWriter(st, 1)
    for i in range(30):
        w.add({"recordId": i, "ts": T0 + i * 1000, "eventId": 4624 + i % 2, "computer": "WS01", "summary": f"invented event {i}", "ipAddress": "192.0.2.7"})
    w.flush()
    st.insert_rows("mails", [{"id": 1, "evidenceId": 2, "subject": "invented subject", "date": T0, "fromAddr": "someone@example.org", "flags": ["invented"]}])
    st.insert_rows("attachments", [{"id": 1, "mailId": 1, "evidenceId": 2, "name": "invented.pdf", "sha256": "0" * 64}])
    st.insert_rows("urls", [{"id": 1, "mailId": 1, "evidenceId": 2, "url": "https://example.org/invented"}])
    st.insert_rows("mail_bodies", [{"mailId": 1, "bodyText": "invented body"}])
    st.upsert_evidence({"id": 1, "name": "invented.evtx", "kind": "evtx", "count": 30, "status": "done"})
    st.set_reputation([{"kind": "ip", "value": "192.0.2.7", "verdict": "clean", "tags": [], "checkedAt": T0}])
    reg.close_all()
    return key


def _rows(path: Path) -> dict[str, list[tuple]]:
    con = duckdb.connect(str(path), read_only=True)
    try:
        return {t: con.execute(f"SELECT * FROM {t} ORDER BY ALL").fetchall() for t in TABLES}
    finally:
        con.close()


def test_a_backup_restores_every_row_of_every_table(tmp_path, capsys):
    cases, dest = tmp_path / "cases", tmp_path / "backups" / "invented-day"
    key = _invented_case(cases)
    before = _rows(cases / key / "case.duckdb")
    assert store_backup.main(["backup", "--cases-dir", str(cases), str(dest)]) == 0
    said = capsys.readouterr().out
    assert f"backed up {key}" in said and "30 events" in said
    manifest = json.loads((dest / key / "manifest.json").read_text())
    assert manifest["key"] == key and manifest["schemaVersion"] == casestore.SCHEMA_VERSION
    assert manifest["rows"]["events"] == 30 and manifest["rows"]["mails"] == 1
    assert set(manifest["files"]) == {"case.duckdb"}
    assert store_backup.main(["verify", str(dest)]) == 0

    shutil.rmtree(cases / key)
    assert store_backup.main(["restore", "--cases-dir", str(cases), str(dest)]) == 0
    assert f"restored {key}" in capsys.readouterr().out
    assert _rows(cases / key / "case.duckdb") == before
    # and the server opens the restored case as it opened the original
    st = CaseStore(cases, key)
    assert st.counts()["events"] == 30
    st.close()
    # no working folder is left beside the cases
    assert sorted(p.name for p in cases.iterdir()) == [key]


def test_a_store_open_in_the_server_is_skipped_with_the_reason_while_the_others_are_backed_up(tmp_path):
    cases, dest = tmp_path / "cases", tmp_path / "backups"
    idle, busy = _invented_case(cases), _invented_case(cases)
    held = CaseStore(cases, busy)  # this process stands for the running server
    try:
        run = subprocess.run([sys.executable, str(TOOL), "backup", "--cases-dir", str(cases), str(dest)], capture_output=True, text=True, timeout=120)
    finally:
        held.close()
    assert run.returncode == 1, run.stdout + run.stderr
    assert f"backed up {idle}" in run.stdout
    assert f"skipped {busy}" in run.stdout and "open in a running REMN server" in run.stdout and "FORENSIC_STORE_IDLE_S" in run.stdout
    assert sorted(p.name for p in dest.iterdir()) == [idle]


def test_a_backup_is_never_written_over(tmp_path, capsys):
    cases, dest = tmp_path / "cases", tmp_path / "backups"
    key = _invented_case(cases)
    assert store_backup.main(["backup", "--cases-dir", str(cases), str(dest)]) == 0
    first = (dest / key / "case.duckdb").read_bytes()
    st = CaseStore(cases, key)
    st.cursor().execute("DELETE FROM events")
    st.close()
    assert store_backup.main(["backup", "--cases-dir", str(cases), str(dest)]) == 1
    assert "already" in capsys.readouterr().out
    assert (dest / key / "case.duckdb").read_bytes() == first


def test_a_restore_does_not_replace_a_case_unless_asked_and_then_keeps_the_one_it_replaced(tmp_path, capsys):
    cases, dest = tmp_path / "cases", tmp_path / "backups"
    key = _invented_case(cases)
    assert store_backup.main(["backup", "--cases-dir", str(cases), str(dest)]) == 0
    st = CaseStore(cases, key)
    st.cursor().execute("DELETE FROM events WHERE id > 10")
    st.close()
    changed = _rows(cases / key / "case.duckdb")
    assert store_backup.main(["restore", "--cases-dir", str(cases), str(dest)]) == 1
    assert "--replace" in capsys.readouterr().out
    assert _rows(cases / key / "case.duckdb") == changed

    assert store_backup.main(["restore", "--cases-dir", str(cases), "--replace", str(dest)]) == 0
    assert len(_rows(cases / key / "case.duckdb")["events"]) == 30
    [kept] = [p for p in cases.iterdir() if p.name != key]
    assert kept.name.startswith(f"{key}.before-restore-")
    assert _rows(kept / "case.duckdb") == changed
    # the case kept aside is not taken for a case by the server
    reg = StoreRegistry()
    reg.configure(cases)
    assert [s["key"] for s in reg.list()] == [key]


def test_a_damaged_backup_is_refused_and_nothing_is_restored(tmp_path, capsys):
    cases, dest = tmp_path / "cases", tmp_path / "backups"
    key = _invented_case(cases)
    assert store_backup.main(["backup", "--cases-dir", str(cases), str(dest)]) == 0
    copy = dest / key / "case.duckdb"
    data = bytearray(copy.read_bytes())
    data[len(data) // 2] ^= 0xFF
    copy.write_bytes(bytes(data))
    assert store_backup.main(["verify", str(dest)]) == 1
    assert "does not match" in capsys.readouterr().out
    shutil.rmtree(cases / key)
    assert store_backup.main(["restore", "--cases-dir", str(cases), str(dest)]) == 1
    assert "does not match" in capsys.readouterr().out
    assert list(cases.iterdir()) == []


def test_a_backup_of_a_newer_store_is_kept_but_not_restored_by_this_version(tmp_path, capsys):
    cases, dest = tmp_path / "cases", tmp_path / "backups"
    key = _invented_case(cases)
    con = duckdb.connect(str(cases / key / "case.duckdb"))
    con.execute("UPDATE meta SET value = ? WHERE key = 'schema-version'", [str(casestore.SCHEMA_VERSION + 1)])
    con.close()
    assert store_backup.main(["backup", "--cases-dir", str(cases), str(dest)]) == 0
    shutil.rmtree(cases / key)
    assert store_backup.main(["restore", "--cases-dir", str(cases), str(dest)]) == 1
    assert "newer version of REMN" in capsys.readouterr().out
    assert list(cases.iterdir()) == []


@pytest.fixture
def server_cases(tmp_path):
    old = registry.root
    registry.configure(tmp_path / "cases")
    yield tmp_path / "cases"
    registry.close_all()
    if old:
        registry.configure(old)


def test_the_server_answers_busy_while_another_program_holds_a_store(server_cases):
    key = _invented_case(server_cases)
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import duckdb, sys, time\nc = duckdb.connect(sys.argv[1], read_only=True)\nprint('held', flush=True)\ntime.sleep(60)",
            str(server_cases / key / "case.duckdb"),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout.readline().strip() == "held"
        r = Client().get(f"/api/store/{key}", **HDR)
        assert r.status_code == 503, r.content
        assert r.json()["code"] == "storeBusy" and "another program" in r.json()["error"]
        assert r["Retry-After"]
    finally:
        holder.kill()
        holder.wait()
    # once the other program has let go, the case opens as before
    assert Client().get(f"/api/store/{key}", **HDR).json()["counts"]["events"] == 30


def test_rows_still_in_the_write_ahead_log_are_backed_up_and_restored_with_the_store(tmp_path):
    cases, dest = tmp_path / "cases", tmp_path / "backups"
    key = _invented_case(cases)
    # a server stopped before it folded its log into the store leaves the last writes in case.duckdb.wal
    con = duckdb.connect(str(cases / key / "case.duckdb"))
    con.execute("PRAGMA disable_checkpoint_on_shutdown")
    con.execute("SET checkpoint_threshold = '1TB'")
    con.execute("INSERT INTO evidence (id, name) VALUES (9, 'written last')")
    con.close()
    assert (cases / key / "case.duckdb.wal").is_file()
    before = _rows(cases / key / "case.duckdb")
    assert store_backup.main(["backup", "--cases-dir", str(cases), str(dest)]) == 0
    assert set(json.loads((dest / key / "manifest.json").read_text())["files"]) == {"case.duckdb", "case.duckdb.wal"}
    shutil.rmtree(cases / key)
    assert store_backup.main(["restore", "--cases-dir", str(cases), str(dest)]) == 0
    assert _rows(cases / key / "case.duckdb") == before
    assert (9, "written last") in [r[:2] for r in before["evidence"]]


def test_a_manifest_that_names_another_case_or_a_file_outside_its_folder_is_refused(tmp_path, capsys):
    cases, dest = tmp_path / "cases", tmp_path / "backups"
    key = _invented_case(cases)
    assert store_backup.main(["backup", "--cases-dir", str(cases), str(dest)]) == 0
    path = dest / key / "manifest.json"
    good = json.loads(path.read_text())
    for bad in ({**good, "key": str(uuid.uuid4())}, {**good, "files": {**good["files"], "../outside": good["files"]["case.duckdb"]}}):
        path.write_text(json.dumps(bad))
        shutil.rmtree(cases / key, ignore_errors=True)
        assert store_backup.main(["restore", "--cases-dir", str(cases), str(dest)]) == 1
        assert "does not describe a store of this case" in capsys.readouterr().out
        assert list(cases.iterdir()) == []
