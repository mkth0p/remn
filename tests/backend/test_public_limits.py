"""The limits that keep a public, browser-only instance answering: one visitor's request cannot
take the memory, the worker threads, the staging area or the log of everyone else's."""

from __future__ import annotations

import io
import json
import logging
import zipfile

from django.test import Client, override_settings
from django.test.client import RequestFactory

from forensic import middleware as mw

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}


def _post_mail(blob: bytes, name: str) -> list[dict]:
    from django.core.files.uploadedfile import SimpleUploadedFile

    resp = Client().post("/api/ingest/mail", {"file": SimpleUploadedFile(name, blob)}, **HDR)
    return [json.loads(line) for line in b"".join(resp.streaming_content).splitlines() if line.strip()]


def _eml(subject: str, body: bytes = b"hello") -> bytes:
    return b"From: a@example.com\r\nTo: b@example.org\r\nSubject: " + subject.encode() + b"\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\n" + body


@override_settings(FORENSIC_MAX_MESSAGE_MB=1)
def test_a_message_over_the_limit_is_an_error_row_not_a_parse():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("inbox/big.eml", _eml("big", b"A" * (2 * 1024 * 1024)))
        z.writestr("inbox/small.eml", _eml("small"))
        z.writestr("inbox/photo.png", b"\x89PNG")
    lines = _post_mail(buf.getvalue(), "mailbox.zip")
    mails = [line for line in lines if line["type"] == "mail"]
    big = next(m for m in mails if m["sourceName"] == "inbox/big.eml")
    assert "parse_error" in big["flags"] and "per-message limit" in big["error"]
    assert any(m["subject"] == "small" for m in mails)
    done = lines[-1]
    assert done["type"] == "done" and done["stats"]["errors"] == 1
    members = {m["name"]: m for m in done["stats"]["members"]}
    assert members["inbox/big.eml"]["status"] == "error"
    assert members["inbox/small.eml"]["status"] == "parsed" and members["inbox/small.eml"]["count"] == 1
    assert members["inbox/photo.png"] == {"name": "inbox/photo.png", "size": 4, "status": "skipped", "reason": "not a mail file (by name)"}
    assert done["stats"]["memberCounts"] == {"parsed": 1, "skipped": 1, "error": 1}
    assert done["parser"]


@override_settings(FORENSIC_MAX_MESSAGE_MB=1)
def test_an_mbox_message_over_the_limit_does_not_take_the_next_one_with_it():
    mbox = b"From a@example.com Mon Jan  1 00:00:00 2024\n" + _eml("big", b"B" * (2 * 1024 * 1024)) + b"\n\n"
    mbox += b"From a@example.com Mon Jan  1 00:00:00 2024\n" + _eml("after") + b"\n"
    mails = [line for line in _post_mail(mbox, "box.mbox") if line["type"] == "mail"]
    assert len(mails) == 2 and "per-message limit" in mails[0]["error"] and mails[1]["subject"] == "after"


def test_encrypted_and_bzip2_members_are_listed_as_skipped():
    from services.ingest.pipeline import iter_archive

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.eml", _eml("a"), compress_type=zipfile.ZIP_BZIP2)
        z.writestr("b.eml", _eml("b"))
    skipped: list[dict] = []
    names = [m.name for m in iter_archive(None, buf.getvalue(), "zip", skipped)]
    assert names == ["b.eml"]
    assert skipped[0]["name"] == "a.eml" and "compression method 12" in skipped[0]["reason"]


def test_the_deadline_holds_between_members_that_yield_nothing():
    import time

    import pytest

    from services.ingest.pipeline import DeadlineExceeded, EvtxSource

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(5):
            z.writestr(f"logs/{i}.evtx", b"\0" * 1024)
    src = EvtxSource("logs.zip", None, buf.getvalue(), ".", deadline=time.monotonic() - 1)
    with pytest.raises(DeadlineExceeded):
        list(src)


def test_a_client_that_goes_away_leaves_no_staged_upload(tmp_path, settings):
    from api.views import upload as up

    settings.FILE_UPLOAD_TEMP_DIR = tmp_path
    c = Client()
    blob = b"From a@example.com Mon Jan  1 00:00:00 2024\n" + b"".join(
        b"From a@example.com Mon Jan  1 00:00:00 2024\n" + _eml(f"m{i}") + b"\n" for i in range(50)
    )
    init = c.post("/api/upload/init", data=json.dumps({"name": "box.mbox", "size": len(blob)}), content_type="application/json", **HDR).json()
    uid = init["uploadId"]
    c.put(f"/api/upload/{uid}/chunk?offset=0", data=blob, content_type="application/octet-stream", **HDR)
    assert c.post(f"/api/upload/{uid}/complete", **HDR).status_code == 200
    resp = c.post("/api/ingest/mail", {"uploadId": uid, "name": "box.mbox"}, **HDR)
    stream = iter(resp.streaming_content)
    next(stream), next(stream)  # the client reads two lines, then hangs up
    resp.close()
    assert not list(up.upload_dir().glob(f"{uid}*"))


@override_settings(FORENSIC_MAX_HEAVY_REQUESTS=3, FORENSIC_MAX_HEAVY_PER_CLIENT=2, FORENSIC_MAX_JSON_INFLIGHT_MB=0)
def test_heavy_requests_in_flight_are_capped_and_given_back_on_close():
    from django.http import StreamingHttpResponse

    guard = mw.ConcurrencyGuardMiddleware(lambda request: StreamingHttpResponse(iter([b"x"])))
    rf = RequestFactory()

    def req(addr: str):
        return rf.post("/api/ingest/mail", REMOTE_ADDR=addr)

    first, second = guard(req("198.51.100.1")), guard(req("198.51.100.1"))
    assert guard(req("198.51.100.1")).status_code == 503  # a third from the same address
    third = guard(req("198.51.100.2"))
    busy = guard(req("198.51.100.3"))
    assert busy.status_code == 503 and busy["Retry-After"] and json.loads(busy.content)["code"] == "busy"
    for resp in (first, second, third):
        resp.close()
    assert mw.ConcurrencyGuardMiddleware.in_flight() == 0
    assert guard(req("198.51.100.3")).status_code == 200


@override_settings(FORENSIC_MAX_HEAVY_REQUESTS=0, FORENSIC_MAX_HEAVY_PER_CLIENT=0, FORENSIC_MAX_JSON_INFLIGHT_MB=1)
def test_json_bodies_in_flight_are_budgeted_by_size():
    from django.http import StreamingHttpResponse

    guard = mw.ConcurrencyGuardMiddleware(lambda request: StreamingHttpResponse(iter([b"x"])))
    rf = RequestFactory()
    body = json.dumps({"events": ["x" * 700_000]})
    first = guard(rf.post("/api/chains/build", data=body, content_type="application/json", REMOTE_ADDR="198.51.100.1"))
    assert first.status_code == 200
    # a second large body waits while the first is being worked on
    assert guard(rf.post("/api/chains/build", data=body, content_type="application/json", REMOTE_ADDR="198.51.100.2")).status_code == 503
    first.close()
    assert guard(rf.post("/api/chains/build", data=body, content_type="application/json", REMOTE_ADDR="198.51.100.2")).status_code == 200


def test_an_ipv6_client_is_budgeted_per_64():
    rf = RequestFactory()
    assert mw.client_key(rf.get("/", REMOTE_ADDR="2001:db8:1:2::a")) == mw.client_key(rf.get("/", REMOTE_ADDR="2001:db8:1:2:ffff::1")) == "2001:db8:1:2::/64"
    assert mw.client_key(rf.get("/", REMOTE_ADDR="2001:db8:1:3::a")) != "2001:db8:1:2::/64"
    assert mw.client_key(rf.get("/", REMOTE_ADDR="203.0.113.5")) == "203.0.113.5"


@override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=1024)
def test_a_body_over_the_limit_gets_json_not_an_html_400():
    resp = Client().post("/api/chains/build", data=json.dumps({"events": ["x" * 4096]}), content_type="application/json", **HDR)
    assert resp.status_code == 413 and resp.json()["code"] == "tooLarge"


def test_uploaded_rules_with_yaml_aliases_are_refused_not_expanded():
    lines = ["title: t", "logsource: {product: windows}", "detection:", "  l0: &l0 ['aaaaaaaaaa']"]
    for d in range(1, 9):
        lines.append(f"  l{d}: &l{d} [" + ",".join([f"*l{d - 1}"] * 10) + "]")
    lines += ["  selection: {CommandLine|contains: *l8}", "  condition: selection"]
    resp = Client().post("/api/rules/convert/sigma", data=json.dumps({"text": "\n".join(lines)}), content_type="application/json", **HDR)
    assert len(resp.content) < 10_000 and "aliases" in resp.content.decode()


def test_the_log_filter_keeps_evidence_text_out():
    from forensic.logfilter import RedactEvidence

    try:
        b"Project Falcon \xff acquisition".decode("utf-8")
    except UnicodeDecodeError as exc:
        record = logging.LogRecord("services.ingest.pipeline", logging.WARNING, __file__, 1, "archive member #%d failed: %s", (3, exc), None)
    RedactEvidence().filter(record)
    text = record.getMessage()
    assert "Falcon" not in text and text.startswith("archive member #3 failed: UnicodeDecodeError")
    try:
        raise ValueError("invalid literal: alice.smith@contoso.com")
    except ValueError:
        import sys

        record = logging.LogRecord("api.views.chains", logging.ERROR, __file__, 1, "chain build failed", None, sys.exc_info())
    RedactEvidence().filter(record)
    assert "alice" not in record.getMessage() and record.exc_info is None and "ValueError" in record.getMessage()
    # records from elsewhere are left alone
    other = logging.LogRecord("django.request", logging.WARNING, __file__, 1, "Not Found: %s", ("/x",), None)
    assert RedactEvidence().filter(other) and other.getMessage() == "Not Found: /x"
