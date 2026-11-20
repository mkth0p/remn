"""A failure on the server answers with what failed, the exception's type and a reference that is
also in the log, never with the exception's text: that text is often a piece of the evidence or a
path on the server. Every value below is invented for these tests."""

from __future__ import annotations

import json
import logging
import runpy
import sys
import threading
import time
import uuid
from pathlib import Path

import httpx
import make_samples
import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings

from api.errors import failure
from api.jobs import manager
from api.views import ingest
from forensic.logfilter import RedactEvidence
from services.common import AnalystMessage
from services.reputation.base import Provider, Registry, Verdict
from services.store.casestore import registry

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
EVTX = Path(__file__).resolve().parents[1] / "fixtures" / "evtx" / "lab-Defender.evtx"
# what an exception might carry: a fragment of evidence and a path on the server
SECRET = "invented-evidence-fragment /srv/remn/cases/invented/case.duckdb"


def _boom(*args, **kwargs):
    raise ValueError(SECRET)


def _assert_reference(error: str, ref: str, what: str, kind: str = "ValueError") -> None:
    assert SECRET not in error and "invented" not in error
    assert error.startswith(f"{what} failed on the server ({kind})") and error.endswith(f"reference {ref}")


def _lines(response) -> list[dict]:
    return [json.loads(line) for line in b"".join(response.streaming_content).splitlines() if line.strip()]


@pytest.fixture
def store_key(tmp_path):
    old = registry.root
    registry.configure(tmp_path / "cases")
    key = str(uuid.uuid4())
    registry.get(key, create=True)
    yield key
    registry.close_all()
    if old:
        registry.configure(old)


def test_a_failure_names_what_failed_its_type_and_a_reference_and_logs_the_same_reference(caplog):
    log = logging.getLogger("api.test")
    try:
        _boom()
    except ValueError as exc:
        with caplog.at_level(logging.ERROR, logger="api.test"):
            said = failure("the thing", exc, log)
    _assert_reference(said["error"], said["ref"], "the thing")
    (record,) = caplog.records
    assert f"[ref {said['ref']}]" in record.getMessage() and SECRET not in record.getMessage()
    # the exception reaches the log only as exc_info, which the log filter reduces to type and place
    RedactEvidence().filter(record)
    assert SECRET not in record.getMessage() and record.getMessage().startswith("the thing failed [ref") and "ValueError at" in record.getMessage()


def test_the_place_of_a_logged_error_is_its_file_name_whatever_the_path_separator():
    # a server on Windows gives tracebacks backslash paths, which named the whole checkout
    code = compile(f"raise ValueError({SECRET!r})", r"C:\srv\remn\backend\services\parsers\invented.py", "exec")
    try:
        exec(code, {})
    except ValueError as exc:
        record = logging.LogRecord("services.test", logging.ERROR, __file__, 1, "parse failed", None, (ValueError, exc, exc.__traceback__))
    RedactEvidence().filter(record)
    assert record.getMessage() == "parse failed [ValueError at invented.py:1]"


def test_text_written_for_the_analyst_is_passed_through_and_any_other_text_is_not(caplog):
    log = logging.getLogger("api.test")
    said = failure("the thing", AnalystMessage("the file is not a recognised export; nothing was read"), log)
    assert said == {"error": "the file is not a recognised export; nothing was read"}
    # a ValueError that was not written for the analyst still says only its type and a reference
    hidden = failure("the thing", ValueError(SECRET), log)
    _assert_reference(hidden["error"], hidden["ref"], "the thing")


# an invented user list: a table, but none of the Microsoft 365 or Entra exports REMN reads
USERS_CSV = (
    b"Id,DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime,UserType\n1d2c,Invented User,invented@example.org,True,1/15/2024 10:11:12 AM,Member\n"
)


def test_an_export_the_event_log_import_cannot_read_is_named_to_the_analyst(tmp_path):
    from services.parsers import m365

    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path):
        r = Client().post("/api/ingest/evtx", {"file": SimpleUploadedFile("Users.csv", USERS_CSV), "engines": "0"}, **HDR)
        (error,) = [line for line in _lines(r) if line["type"] == "error"]
    assert error["error"] == m365.UNRECOGNISED and "ref" not in error


def test_an_export_a_server_case_cannot_read_is_named_in_the_job(store_key, tmp_path):
    from services.parsers import m365

    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path):
        c = Client()
        uid = c.post("/api/upload/init", json.dumps({"name": "Users.csv", "size": len(USERS_CSV)}), content_type="application/json", **HDR).json()["uploadId"]
        assert c.generic("PUT", f"/api/upload/{uid}/chunk?offset=0", USERS_CSV, content_type="application/octet-stream", **HDR).status_code == 200
        assert c.post(f"/api/upload/{uid}/complete", **HDR).status_code == 200
        body = {"uploadId": uid, "kind": "evtx", "evidence": {"id": 1, "name": "Users.csv"}}
        job_id = c.post(f"/api/store/{store_key}/ingest", json.dumps(body), content_type="application/json", **HDR).json()["jobId"]
        job = manager.get(job_id)
        for _ in range(500):
            if job.finished:
                break
            time.sleep(0.02)
    assert job.status == "error" and job.error == m365.UNRECOGNISED


def test_a_view_that_raises_answers_a_json_500_with_a_reference(monkeypatch):
    monkeypatch.setattr("services.reputation.base.registry.list", _boom)
    r = Client(raise_request_exception=False).get("/api/reputation/providers", **HDR)
    assert r.status_code == 500 and r["Content-Type"] == "application/json"
    _assert_reference(r.json()["error"], r.json()["ref"], "the request")


def test_django_still_answers_its_own_client_errors():
    c = Client(raise_request_exception=False)
    assert c.get("/api/no-such-route", **HDR).status_code == 404
    assert c.get("/api/reputation/lookup", **HDR).status_code == 405


def test_a_store_query_that_fails_answers_a_reference(store_key, monkeypatch):
    monkeypatch.setattr("services.store.queries.search", _boom)
    r = Client().post(f"/api/store/{store_key}/search", data=json.dumps({}), content_type="application/json", **HDR)
    assert r.status_code == 500
    _assert_reference(r.json()["error"], r.json()["ref"], "the store query")


def test_a_query_the_database_cannot_run_keeps_its_diagnostic_as_a_400(store_key):
    c = Client()
    for sql in ("SELECT no_such_column FROM events", "SELECT CAST('not a number' AS INTEGER)"):
        r = c.post(f"/api/store/{store_key}/sql", data=json.dumps({"sql": sql}), content_type="application/json", **HDR)
        assert r.status_code == 400, (sql, r.content)
        assert "Error" in r.json()["error"] and "ref" not in r.json()


def test_a_failed_job_says_what_failed_and_a_reference_and_logs_no_job_id(caplog):
    with caplog.at_level(logging.ERROR, logger="api.jobs"):
        job = manager.submit("rules", str(uuid.uuid4()), _boom)
        for _ in range(100):
            if job.finished:
                break
            time.sleep(0.02)
    assert job.status == "error"
    ref = job.error.rsplit(" ", 1)[-1]
    _assert_reference(job.error, ref, "the rules job")
    logged = " ".join(r.getMessage() for r in caplog.records if r.name == "api.jobs")
    assert ref in logged and job.id not in logged


def test_a_failed_event_log_parse_streams_a_reference(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest, "_expired", _boom)
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path):
        r = Client().post("/api/ingest/evtx", {"file": SimpleUploadedFile("Defender.evtx", EVTX.read_bytes()), "engines": "0"}, **HDR)
        (error,) = [line for line in _lines(r) if line["type"] == "error"]
    _assert_reference(error["error"], error["ref"], "the parse of the event log")


def test_a_failed_mail_parse_streams_a_reference(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest, "_expired", _boom)
    data = make_samples.mail("a@example.org", "b@example.org", "invented subject", "invented body")
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path):
        r = Client().post("/api/ingest/mail", {"file": SimpleUploadedFile("one.eml", data)}, **HDR)
        (error,) = [line for line in _lines(r) if line["type"] == "error"]
    _assert_reference(error["error"], error["ref"], "the parse of the mail")


def test_a_failed_package_parse_streams_a_reference(tmp_path, monkeypatch):
    import io
    import zipfile

    monkeypatch.setattr(ingest, "_expired", _boom)
    blob = io.BytesIO()
    with zipfile.ZipFile(blob, "w") as z:
        z.writestr("mail/one.eml", make_samples.mail("a@example.org", "b@example.org", "invented subject", "invented body"))
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path):
        r = Client().post("/api/ingest/package", {"file": SimpleUploadedFile("pkg.zip", blob.getvalue()), "engines": "0"}, **HDR)
        (error,) = [line for line in _lines(r) if line["type"] == "error"]
    _assert_reference(error["error"], error["ref"], "the parse of the package")


@pytest.mark.parametrize(
    ("path", "target", "what"),
    [
        ("/api/chains/build", "services.analysis.chains.build_chains", "the chain build"),
        ("/api/stories/build", "services.analysis.stories.build_stories", "the story build"),
        ("/api/enrich/mails", "services.analysis.baseline.enrich", "the enrichment"),
    ],
)
def test_a_failed_analysis_answers_a_reference(monkeypatch, path, target, what):
    monkeypatch.setattr(target, _boom)
    r = Client().post(path, data=json.dumps({"mails": [], "events": []}), content_type="application/json", **HDR)
    assert r.status_code == 500
    _assert_reference(r.json()["error"], r.json()["ref"], what)


def test_the_relationship_model_returns_only_its_own_messages(monkeypatch):
    c = Client(raise_request_exception=False)
    r = c.post("/api/relationships/build", data=json.dumps({"events": "not a list"}), content_type="application/json", **HDR)
    assert r.status_code == 400 and r.json()["error"].startswith("events and mails must be arrays")
    monkeypatch.setattr("api.views.relationships.build", _boom)
    r = c.post("/api/relationships/build", data=json.dumps({"events": [{"id": 1}]}), content_type="application/json", **HDR)
    assert r.status_code == 500
    _assert_reference(r.json()["error"], r.json()["ref"], "the request")


def test_the_rescore_returns_only_its_own_messages(monkeypatch):
    c = Client(raise_request_exception=False)
    r = c.post("/api/enrich/mails/rescore", data=json.dumps({"mails": [{}]}), content_type="application/json", **HDR)
    assert r.status_code == 400 and r.json()["error"].startswith("mails must contain")
    monkeypatch.setattr("services.analysis.rescore.batch", _boom)
    r = c.post("/api/enrich/mails/rescore", data=json.dumps({"mails": [{"id": 1}]}), content_type="application/json", **HDR)
    assert r.status_code == 500
    _assert_reference(r.json()["error"], r.json()["ref"], "the request")


class _Failing(Provider):
    name = "failing"
    kinds = ("domain",)

    def __init__(self, exc: Exception) -> None:
        super().__init__({})
        self.exc = exc

    def lookup(self, kind: str, value: str) -> Verdict:
        raise self.exc


def test_a_failed_lookup_says_what_failed_and_not_the_url_it_called():
    # the URL of a provider call can carry its key and the value looked up
    url = "https://provider.invalid/v1/invented-value.example?key=invented-provider-key"
    request = httpx.Request("GET", url)
    cases = [
        (
            httpx.HTTPStatusError(f"Client error '403 Forbidden' for url '{url}'", request=request, response=httpx.Response(403, request=request)),
            "the provider answered HTTP 403",
        ),
        (httpx.ConnectError(f"cannot connect to {url}", request=request), "the provider could not be reached (ConnectError)"),
        (httpx.ReadTimeout(f"timed out reading {url}", request=request), "the provider did not answer in time"),
        (ValueError(SECRET), "the lookup failed (ValueError)"),
    ]
    for exc, said in cases:
        reg = Registry()
        reg.providers = {"failing": _Failing(exc)}
        (verdict,) = reg.lookup([("domain", "invented-value.example")])
        assert verdict["verdict"] == "error" and verdict["details"] == {"error": said}


def test_a_rule_file_that_cannot_be_read_does_not_name_the_server_path(tmp_path):
    from api.views.meta import load_rules

    (tmp_path / "broken.yml").write_text("title: [unclosed\n", encoding="utf-8")
    (tmp_path / "binary.yml").write_bytes(b"title: \xff\xfe invented\n")
    by_file = {r["file"]: r for r in load_rules(tmp_path)}
    # what is wrong with the YAML is for the reader of the rule list
    assert "flow sequence" in by_file["broken.yml"]["error"] or "expected" in by_file["broken.yml"]["error"]
    assert by_file["binary.yml"]["error"] == "the file could not be read (UnicodeDecodeError)"
    assert str(tmp_path) not in json.dumps(by_file)


def test_the_log_filter_covers_the_request_log_and_the_web_server():
    for name in ("django.request", "waitress", "waitress.queue"):
        try:
            _boom()
        except ValueError:
            record = logging.LogRecord(name, logging.ERROR, __file__, 1, "Internal Server Error: %s", ("/api/x",), sys.exc_info())
        RedactEvidence().filter(record)
        assert SECRET not in record.getMessage() and record.exc_info is None and "ValueError at" in record.getMessage(), name


@pytest.mark.parametrize(
    ("env", "redacted"),
    [({}, True), ({"FORENSIC_DEBUG": "1"}, False), ({"FORENSIC_DEBUG": "1", "FORENSIC_BROWSER_ONLY": "1"}, True), ({"FORENSIC_BROWSER_ONLY": "1"}, True)],
)
def test_the_log_filter_is_on_in_every_mode_but_a_developer_debug_run(monkeypatch, env, redacted):
    for name in ("FORENSIC_DEBUG", "FORENSIC_BROWSER_ONLY"):
        monkeypatch.setenv(name, env.get(name, "0"))
    module = runpy.run_path(str(Path(__file__).resolve().parents[2] / "backend" / "forensic" / "settings.py"))
    assert (module["LOGGING"]["handlers"]["console"]["filters"] == ["redact"]) is redacted


def test_a_pst_store_ingest_without_libpff_is_refused_before_the_job(store_key, monkeypatch, tmp_path):
    from api.views import store as store_views

    monkeypatch.setattr(store_views.pst_mod, "available", lambda: False)
    submitted = threading.Event()
    monkeypatch.setattr(store_views.manager, "submit", lambda *a, **k: submitted.set())
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path):
        c = Client()
        data = b"!BDN" + b"\0" * 1020
        uid = c.post("/api/upload/init", json.dumps({"name": "box.pst", "size": len(data)}), content_type="application/json", **HDR).json()["uploadId"]
        assert c.generic("PUT", f"/api/upload/{uid}/chunk?offset=0", data, content_type="application/octet-stream", **HDR).status_code == 200
        assert c.post(f"/api/upload/{uid}/complete", **HDR).status_code == 200
        body = {"uploadId": uid, "kind": "mail", "evidence": {"id": 1, "name": "box.pst"}}
        r = c.post(f"/api/store/{store_key}/ingest", json.dumps(body), content_type="application/json", **HDR)
    assert r.status_code == 501 and "libpff-python" in r.json()["error"]
    assert not submitted.is_set()
