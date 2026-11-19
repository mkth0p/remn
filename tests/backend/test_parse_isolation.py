"""Each parse of uploaded evidence runs in a process of its own.

A memory-safety bug in libpff, the EVTX reader or an attachment analyser gives its process to
whoever wrote the file. These tests show that process is not the server's: it holds neither the
access token nor the provider keys nor the server's settings, it is stopped at its memory and
processor-time limits and at the ingest deadline, and what it read before a stop reaches the analyst
with the reason. The misbehaving parsers are in hostile_parsers.py; all evidence here is invented.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from datetime import datetime
from pathlib import Path

import psutil
import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings

from services.ingest import isolation, pipeline
from services.ingest.isolation import ParseStopped
from services.ingest.pipeline import DeadlineExceeded

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "samples" / "synthetic"))
from evtx_writer import EvtxWriter, event_node  # noqa: E402

HERE = str(Path(__file__).resolve().parent)
HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
STAMP = "2024-03-05T10:00:00+00:00"


@pytest.fixture
def hostile(monkeypatch):
    """Make the parse process run one of the misbehaving parsers for every kind of evidence."""

    def use(name: str) -> None:
        monkeypatch.setattr(isolation, "ENTRY", f"hostile_parsers:{name}")
        monkeypatch.setattr(isolation, "ENTRY_PATHS", [HERE])

    return use


def evtx_bytes(count: int = 3) -> bytes:
    """A small invented Security log."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "Security.evtx"
        ms = int(datetime.fromisoformat(STAMP).timestamp() * 1000)
        with EvtxWriter(path) as writer:
            for i in range(1, count + 1):
                writer.add(
                    event_node(i, STAMP, "Microsoft-Windows-Security-Auditing", "Security", "WS01", 4624, {"TargetUserName": f"user{i}", "LogonType": "3"}),
                    ms + i,
                )
        return path.read_bytes()


def post(route: str, blob: bytes, name: str, **fields) -> list[dict]:
    response = Client().post(route, {"file": SimpleUploadedFile(name, blob), **fields}, **HDR)
    assert response.status_code == 200, response.content
    return [json.loads(line) for line in b"".join(response.streaming_content).splitlines() if line.strip()]


def start(kind: str = "evtx", tmp_dir: str | None = None, **options):
    return isolation.start(kind, name="invented.evtx", path=None, data=b"invented", tmp_dir=tmp_dir or tempfile.gettempdir(), options=options)


def gone(pid: int) -> bool:
    try:
        return psutil.Process(pid).status() == psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return True


# ---------------------------------------------------------------------------
# where the parse runs and what it can see
# ---------------------------------------------------------------------------
def test_an_event_log_is_parsed_outside_the_server_process(tmp_path, monkeypatch):
    seen = []
    original = pipeline.EvtxSource.__iter__

    def spy(self):
        seen.append((os.getpid(), os.environ.get("FORENSIC_AUTH_TOKEN")))
        return original(self)

    monkeypatch.setattr(pipeline.EvtxSource, "__iter__", spy)
    monkeypatch.setenv("FORENSIC_AUTH_TOKEN", "invented-token-for-this-test")
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path):
        lines = post("/api/ingest/evtx", evtx_bytes(), "Security.evtx", engines="0")

    assert [line["type"] for line in lines].count("event") == 3 and lines[-1]["type"] == "done"
    assert lines[-1]["stats"]["count"] == 3 and lines[-1]["emitted"] == 3
    assert seen == [], "the parser ran in the server process, with its token in reach"
    assert not list(tmp_path.iterdir()), "the parse process's folder is removed"


def test_a_parser_sees_neither_the_token_nor_the_keys_nor_the_server_settings(tmp_path, hostile, monkeypatch):
    hostile("environ")
    monkeypatch.setenv("FORENSIC_AUTH_TOKEN", "invented-token-for-this-test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "invented-key-for-this-test")
    monkeypatch.setenv("REMN_TEST_MARKER", "set by the server")
    with override_settings(
        FORENSIC_AUTH_TOKEN="invented-token-for-this-test", REPUTATION_KEYS={"virustotal": "invented-key-for-this-test"}, SECRET_KEY="invented-secret"
    ):
        parse = start(tmp_dir=str(tmp_path))
        rows = list(parse)
        parse.close()

    seen = rows[0]["data"]
    assert seen["pid"] != os.getpid()
    assert seen["token"] is None and seen["settingsToken"] is None and seen["reputationKeys"] is None
    assert seen["secretKey"] != "invented-secret"
    assert not {"FORENSIC_AUTH_TOKEN", "VIRUSTOTAL_API_KEY", "REMN_TEST_MARKER"} & set(seen["environ"])
    own = {"HOME", "TMPDIR", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "__CF_USER_TEXT_ENCODING"}
    assert set(seen["environ"]) <= set(isolation.CHILD_ENVIRONMENT) | own
    assert Path(seen["cwd"]).parent.resolve() == tmp_path.resolve(), "it works in a folder of its own in the staging area"


def test_the_external_decoders_and_the_engine_start_without_the_server_environment(tmp_path, monkeypatch):
    from services.analysis import hayabusa
    from services.parsers import native

    monkeypatch.setenv("FORENSIC_AUTH_TOKEN", "invented-token-for-this-test")
    assert "FORENSIC_AUTH_TOKEN" not in native._environment(str(tmp_path))

    seen = tmp_path / "seen.json"
    script = tmp_path / "engine.py"
    script.write_text(f"import json, os\njson.dump(sorted(os.environ), open({str(seen)!r}, 'w'))\n", encoding="utf-8")
    monkeypatch.setattr(hayabusa, "binary", lambda: sys.executable)
    monkeypatch.setattr(hayabusa, "command", lambda target, output: [sys.executable, str(script)])
    (tmp_path / "Security.evtx").write_bytes(evtx_bytes(1))
    hayabusa.run(str(tmp_path / "Security.evtx"), str(tmp_path))

    assert "FORENSIC_AUTH_TOKEN" not in json.loads(seen.read_text(encoding="utf-8"))


def test_a_decoder_finds_its_home_in_its_own_staging_folder(tmp_path):
    # dissect asks for the home folder when it opens a target; a Windows interpreter started with
    # no USERPROFILE has none, and the worker died before its first record
    from services.parsers import native

    done = subprocess.run(
        [sys.executable, "-c", "from pathlib import Path; import tempfile; print(Path.home()); print(tempfile.gettempdir())"],
        env=native._environment(str(tmp_path)),
        capture_output=True,
        text=True,
        check=True,
    )
    home, temp = done.stdout.splitlines()
    assert Path(home) == tmp_path and Path(temp) == tmp_path


def test_rows_cross_from_the_parse_process_unchanged(tmp_path, hostile):
    hostile("odd")
    parse = start(tmp_dir=str(tmp_path))
    rows = list(parse)

    assert rows[0] == {"text": "a\ud800b", "emoji": "\U0001f600", "big": 2**62, "neg": -1, "float": 1.5, "nested": {"list": [1, "two", None]}, "none": None}
    assert rows[1] == {"n": 2, "empty": "", "line": "one\ntwo\r\n", "quote": '"{"t":"end"}"'}
    assert parse.result()["stats"]["count"] == 2


def test_the_golden_corpus_is_what_crosses_from_the_parse_process(tmp_path, monkeypatch):
    import importlib.util

    from services.parsers.mail.common import ParseContext

    spec = importlib.util.spec_from_file_location("golden_corpus", Path(__file__).resolve().parents[2] / "tools" / "golden_corpus.py")
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)

    def parse(lab, name, tmp):
        if name.endswith(".mbox"):
            s = json.loads((lab / "case-settings.json").read_text(encoding="utf-8"))
            ctx = ParseContext(
                internal_domains=list(s.get("internalDomains") or []),
                brands=list(s.get("brands") or []),
                vip_names=list(s.get("vipNames") or []),
                trusted_senders=list(s.get("trustedSenders") or []),
                trusted_arc_sealers=[str(x).lower() for x in (s.get("trustedArcSealers") or [])],
            )
            kind, options = "mail", {"ctx": ctx}
        else:
            kind, options = "evtx", {"include_raw": True}
        run = isolation.start(kind, name=name, path=str(lab / name), data=None, tmp_dir=tmp, options=options)
        assert isinstance(run, isolation.IsolatedParse)
        try:
            return list(run)
        finally:
            run.close()

    lab = golden.generate_lab(tmp_path)
    monkeypatch.setattr(golden, "parse", parse)
    diff = golden.differences(golden.load(), golden.build(lab), lab)
    assert not diff, "\n".join(diff)


# ---------------------------------------------------------------------------
# limits
# ---------------------------------------------------------------------------
def test_a_parse_that_holds_ever_more_memory_is_stopped_and_keeps_what_it_sent(tmp_path, hostile):
    hostile("allocate")
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_PARSE_MAX_MB=256):
        started = time.monotonic()
        lines = post("/api/ingest/evtx", b"invented", "big.evtx", engines="0")

    kinds = [line["type"] for line in lines]
    assert kinds.count("event") == 2 and kinds[-1] == "done", kinds
    error = next(line for line in lines if line["type"] == "error")["error"]
    assert "256 MiB memory limit" in error and "FORENSIC_PARSE_MAX_MB" in error and "kept" in error, error
    assert lines[-1]["emitted"] == 2 and lines[-1]["stats"]["errors"] >= 1
    assert time.monotonic() - started < 60
    assert gone(lines[1]["data"]["pid"])
    assert not list(tmp_path.iterdir())


def test_memory_a_parse_shares_with_nobody_counts_against_its_limit(tmp_path, hostile):
    hostile("share")
    with override_settings(FORENSIC_PARSE_MAX_MB=256):
        parse = start(tmp_dir=str(tmp_path))
        rows = []
        with pytest.raises(ParseStopped) as stopped:
            for row in parse:
                rows.append(row)

    assert len(rows) == 1
    assert "reached its 256 MiB memory limit (FORENSIC_PARSE_MAX_MB) and was stopped" in str(stopped.value)
    assert gone(rows[0]["data"]["pid"])


def test_a_parse_that_never_sends_another_row_is_stopped_at_the_deadline(tmp_path, hostile, monkeypatch):
    hostile("silent")
    monkeypatch.setattr(isolation, "GRACE_S", 0.5)
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_INGEST_MAX_S=1):
        started = time.monotonic()
        lines = post("/api/ingest/evtx", b"invented", "stuck.evtx", engines="0")
        took = time.monotonic() - started

    kinds = [line["type"] for line in lines]
    assert kinds.count("event") == 1 and kinds[-1] == "done", kinds
    assert any(line["type"] == "error" and "FORENSIC_INGEST_MAX_S" in line["error"] for line in lines)
    assert took < 15, f"stopped after {took:.1f} s"
    assert gone(lines[1]["data"]["pid"]), "the process is killed, not left running"
    assert not list(tmp_path.iterdir())


@pytest.mark.skipif(os.name == "nt", reason="Windows has no processor-time limit for a process without a job object")
def test_a_parse_that_spins_is_stopped_at_its_processor_time_limit(tmp_path, hostile):
    hostile("spin")
    with override_settings(FORENSIC_PARSE_MAX_CPU_S=1):
        parse = start(tmp_dir=str(tmp_path))
        rows = []
        with pytest.raises(ParseStopped) as stopped:
            for row in parse:
                rows.append(row)

    assert len(rows) == 1
    assert "processor-time limit" in str(stopped.value) and "FORENSIC_PARSE_MAX_CPU_S" in str(stopped.value)
    assert parse.lockdown["cpu"] == "kernel"


def test_a_parse_process_that_crashes_is_reported_with_what_it_had_sent(tmp_path, hostile):
    hostile("crash")
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path):
        lines = post("/api/ingest/evtx", b"invented", "crash.evtx", engines="0")

    kinds = [line["type"] for line in lines]
    assert kinds.count("event") == 1 and kinds[-1] == "done", kinds
    error = next(line for line in lines if line["type"] == "error")["error"]
    assert error.startswith("the parse process ended") and "1 record(s) read before it are kept" in error, error
    assert ("SIGSEGV" in error) if os.name != "nt" else ("0xc0000005" in error)


def test_a_cancelled_job_stops_its_parse_process(tmp_path, hostile):
    hostile("silent")

    class Cancelled(Exception):
        pass

    cancel = {"now": False}

    def check():
        if cancel["now"]:
            raise Cancelled()

    parse = isolation.start("evtx", name="stuck.evtx", path=None, data=b"invented", tmp_dir=str(tmp_path), options={}, check=check)
    rows = iter(parse)
    first = next(rows)
    cancel["now"] = True
    started = time.monotonic()
    with pytest.raises(Cancelled):
        next(rows)

    assert time.monotonic() - started < 5
    assert gone(first["data"]["pid"])
    assert not list(tmp_path.iterdir())


def test_a_parse_cannot_reach_the_server_over_the_network(tmp_path, hostile):
    hostile("environ")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        parse = start(tmp_dir=str(tmp_path), port=listener.getsockname()[1])
        network = parse.lockdown["network"]
        rows = list(parse)
    finally:
        listener.close()
    if not network.startswith("none"):
        pytest.skip(f"this system gives a process no network of its own without privileges: {network}")
    assert rows[0]["data"]["reached"] is not True, "the parse process connected to the server's loopback"


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="switching account takes a server running as root")
def test_a_parse_runs_as_the_configured_account_when_the_server_is_root(hostile):
    hostile("environ")
    # a staging area every account can pass through, as the server's own under its install folder is
    root = tempfile.mkdtemp(dir="/tmp")
    os.chmod(root, 0o711)
    try:
        with override_settings(FORENSIC_PARSE_UID="65534"):
            parse = start(tmp_dir=root)
            rows = list(parse)
        assert rows[0]["data"]["uid"] == 65534
        assert parse.lockdown["account"] == 65534
        assert not os.listdir(root), "the server removes the folder the other account wrote in"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_without_isolation_the_parse_runs_in_the_server_as_before(tmp_path, monkeypatch):
    seen = []
    original = pipeline.EvtxSource.__iter__

    def spy(self):
        seen.append(os.getpid())
        return original(self)

    monkeypatch.setattr(pipeline.EvtxSource, "__iter__", spy)
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_PARSE_ISOLATION=False):
        lines = post("/api/ingest/evtx", evtx_bytes(), "Security.evtx", engines="0")

    assert seen == [os.getpid()]
    assert [line["type"] for line in lines].count("event") == 3 and lines[-1]["stats"]["count"] == 3


# ---------------------------------------------------------------------------
# the other routes
# ---------------------------------------------------------------------------
def test_a_mail_upload_stopped_at_its_memory_limit_says_so(tmp_path, hostile):
    hostile("allocate")
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_PARSE_MAX_MB=256):
        lines = post("/api/ingest/mail", b"From invented@example.org\n\nbody\n", "big.mbox")

    assert [line["type"] for line in lines].count("mail") == 2 and lines[-1]["type"] == "done"
    assert any(line["type"] == "error" and "memory limit" in line["error"] for line in lines)


def test_a_package_stopped_at_its_memory_limit_marks_the_member_it_was_reading(tmp_path, hostile):
    hostile("allocate")
    blob = io.BytesIO()
    with zipfile.ZipFile(blob, "w") as z:
        z.writestr("invented.txt", "invented")
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_PARSE_MAX_MB=256):
        lines = post("/api/ingest/package", blob.getvalue(), "pkg.zip")

    done = lines[-1]
    assert done["type"] == "done" and done["stats"]["inventoryComplete"] is False
    assert any(line.get("type") == "error" and "memory limit" in line["error"] for line in lines)


def test_a_single_attachment_stopped_at_its_memory_limit_is_refused_with_the_reason(tmp_path, hostile):
    hostile("allocate")
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_PARSE_MAX_MB=256):
        response = Client().post("/api/analyze/attachment", {"file": SimpleUploadedFile("invented.bin", b"invented")}, **HDR)

    assert response.status_code == 422 and "memory limit" in response.json()["error"]


def test_a_single_attachment_is_analysed_in_a_parse_process(tmp_path):
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path):
        response = Client().post("/api/analyze/attachment", {"file": SimpleUploadedFile("invented.txt", b"plain invented text")}, **HDR)

    assert response.status_code == 200 and response.json()["type"] == "attachment"
    assert response.json()["result"]["name"] == "invented.txt"


def _store_job(c: Client, key: str, blob: bytes, name: str, kind: str) -> dict:
    r = c.post("/api/upload/init", data=json.dumps({"name": name, "size": len(blob)}), content_type="application/json", **HDR)
    assert r.status_code == 200, r.content
    upload_id = r.json()["uploadId"]
    assert c.generic("PUT", f"/api/upload/{upload_id}/chunk?offset=0", blob, content_type="application/octet-stream", **HDR).status_code == 200
    assert c.post(f"/api/upload/{upload_id}/complete", **HDR).status_code == 200
    r = c.post(
        f"/api/store/{key}/ingest",
        data=json.dumps({"uploadId": upload_id, "kind": kind, "evidence": {"id": 7, "name": name}, "options": {}}),
        content_type="application/json",
        **HDR,
    )
    assert r.status_code == 200, r.content
    job_id = r.json()["jobId"]
    for _ in range(600):
        job = c.get(f"/api/jobs/{job_id}?case={key}", **HDR).json()
        if job["status"] in ("done", "error", "cancelled"):
            return job
        time.sleep(0.1)
    raise AssertionError(f"the job did not end: {job}")


@pytest.fixture
def store_root(settings, tmp_path):
    from services.store.casestore import registry

    old = registry.root
    settings.CASES_DIR = tmp_path / "cases"
    registry.configure(settings.CASES_DIR)
    yield registry
    registry.close_all()
    if old:
        registry.configure(old)


def test_a_store_job_parses_in_a_parse_process(store_root):
    c = Client()
    key = str(uuid.uuid4())
    job = _store_job(c, key, evtx_bytes(), "Security.evtx", "evtx")

    assert job["status"] == "done", job
    assert job["result"]["count"] == 3 and job["result"]["format"] == "evtx" and job["result"]["stats"]["count"] == 3
    assert c.get(f"/api/store/{key}", **HDR).json()["counts"]["events"] == 3


def test_a_store_job_stopped_at_its_memory_limit_says_so_and_keeps_its_rows(store_root, hostile):
    hostile("allocate")
    c = Client()
    key = str(uuid.uuid4())
    with override_settings(FORENSIC_PARSE_MAX_MB=256):
        job = _store_job(c, key, b"invented", "big.evtx", "evtx")

    assert job["status"] == "error", job
    assert "256 MiB memory limit" in job["error"] and "2 record(s) read before it are kept" in job["error"], job["error"]
    summary = c.get(f"/api/store/{key}", **HDR).json()
    assert summary["counts"]["events"] == 2
    evidence = summary["evidence"][0]
    assert evidence["status"] == "error" and evidence["count"] == 2


# ---------------------------------------------------------------------------
# protocol details
# ---------------------------------------------------------------------------
def test_a_parse_past_its_deadline_that_does_not_stop_itself_is_killed(tmp_path, hostile, monkeypatch):
    hostile("silent")
    monkeypatch.setattr(isolation, "GRACE_S", 0.5)
    parse = isolation.start("evtx", name="stuck.evtx", path=None, data=b"invented", tmp_dir=str(tmp_path), options={}, deadline=time.monotonic() + 0.5)
    with pytest.raises(DeadlineExceeded):
        list(parse)

    result = parse.result("stopped")
    assert result["stats"]["count"] == 1 and result["stats"]["errors"] == 1


def test_a_member_that_runs_the_parse_out_of_memory_says_so_and_the_next_is_read(tmp_path, monkeypatch):
    from services.parsers import evtx_parser

    original = evtx_parser.iter_events

    def iter_events(src, **kwargs):
        if kwargs.get("source_file") == "first.evtx":
            raise MemoryError()
        return original(src, **kwargs)

    monkeypatch.setattr(evtx_parser, "iter_events", iter_events)
    blob = io.BytesIO()
    with zipfile.ZipFile(blob, "w") as z:
        z.writestr("first.evtx", evtx_bytes(2))
        z.writestr("second.evtx", evtx_bytes(2))
    source = pipeline.EvtxSource("logs.zip", None, blob.getvalue(), str(tmp_path))
    rows = list(source)

    assert len(rows) == 2 and {row["sourceFile"] for row in rows} == {"second.evtx"}
    first = next(f for f in source.files if f["name"] == "first.evtx")
    assert first["status"] == "error" and "ran out of memory" in first["error"] and "FORENSIC_PARSE_MAX_MB" in first["error"]
