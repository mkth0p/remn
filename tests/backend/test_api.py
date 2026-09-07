from __future__ import annotations

import hashlib
import json
from pathlib import Path

import make_samples
import pytest
from django.test import Client

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}


def _ndjson(resp) -> list[dict]:
    body = b"".join(resp.streaming_content)
    return [json.loads(line) for line in body.decode("utf-8").splitlines() if line.strip()]


def test_missing_client_header_is_rejected():
    c = Client()
    assert c.get("/api/health").status_code == 403
    assert c.post("/api/ingest/evtx").status_code == 403
    assert c.options("/api/health").status_code == 403


def test_health_and_meta():
    c = Client()
    h = c.get("/api/health", **HDR)
    assert h.status_code == 200
    body = h.json()
    assert body["stateless"] is True and "ollama" in body and isinstance(body["providers"], list)
    m = c.get("/api/meta", **HDR).json()
    assert any(e["eventId"] == 4625 for e in m["events"])
    assert m["flags"]["spf_fail"]
    rules = [r for r in m["rules"] if "rule" in r]
    assert len(rules) >= 40
    ids = [r["rule"]["id"] for r in rules]
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    assert all(r["rule"].get("severity") in ("info", "low", "medium", "high", "critical") for r in rules)
    assert all(r["rule"].get("source") in ("events", "mails") for r in rules)


def test_frontend_placeholder_when_not_built():
    c = Client()
    r = c.get("/")
    assert r.status_code in (200, 503)


def test_ingest_eml_streams_rows(tmp_path):
    c = Client()
    data = make_samples.mail(
        '"Marie Lefevre" <marie.lefevre@interne-fr.co>',
        "j@interne.fr",
        "URGENT",
        "virement urgent",
        attachments=[("x.docm", make_samples.docm_with_macro(), "application", "octet-stream")],
        extra_headers=make_samples.RECEIVED_BAD,
    )
    p = tmp_path / "spoof.eml"
    p.write_bytes(data)
    with open(p, "rb") as fh:
        resp = c.post("/api/ingest/mail", {"file": fh, "settings": json.dumps({"internalDomains": ["interne.fr"]})}, **HDR)
    assert resp.status_code == 200
    rows = _ndjson(resp)
    assert rows[0]["type"] == "meta" and rows[0]["format"] == "eml"
    assert rows[0]["sha256"] == hashlib.sha256(data).hexdigest()
    mails = [r for r in rows if r["type"] == "mail"]
    assert len(mails) == 1 and "sender_lookalike_internal" in mails[0]["flags"] and "att_office_macro" in mails[0]["flags"]
    assert rows[-1]["type"] == "done" and rows[-1]["stats"]["count"] == 1


def test_ingest_zip_of_emls_and_mbox(tmp_path):
    c = Client()
    make_samples.build(str(tmp_path))
    with open(tmp_path / "emls.zip", "rb") as fh:
        rows = _ndjson(c.post("/api/ingest/mail", {"file": fh}, **HDR))
    assert rows[0]["format"] == "zip"
    assert sum(1 for r in rows if r["type"] == "mail") == 5
    # without organisation context (internal domains / VIPs) only the mails with intrinsic
    # strong indicators stay >= 50: the display-name spoof and the malicious-attachment mail
    assert rows[-1]["stats"]["flagged"] >= 2
    with open(tmp_path / "mailbox.mbox", "rb") as fh:
        rows = _ndjson(c.post("/api/ingest/mail", {"file": fh}, **HDR))
    assert rows[0]["format"] == "mbox"
    assert sum(1 for r in rows if r["type"] == "mail") == 5


@pytest.mark.skipif(not (SAMPLES / "System-last7d.evtx").exists(), reason="local sample not exported")
def test_ingest_evtx_large_upload_uses_temp_file_and_cleans_up(settings):
    c = Client()
    path = SAMPLES / "System-last7d.evtx"
    with open(path, "rb") as fh:
        resp = c.post("/api/ingest/evtx", {"file": fh, "raw": "0"}, **HDR)
    assert resp.status_code == 200
    rows = _ndjson(resp)
    assert rows[0]["type"] == "meta" and rows[0]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    events = [r for r in rows if r["type"] == "event"]
    assert len(events) > 100 and "raw" not in events[0]
    assert rows[-1]["type"] == "done" and rows[-1]["stats"]["errors"] == 0
    resp.close()
    leftovers = [p for p in Path(settings.FILE_UPLOAD_TEMP_DIR).iterdir() if p.suffix.startswith(".upload") or ".upload" in p.name]
    assert leftovers == [], f"temp upload files left behind: {leftovers}"


def test_upload_too_large_rejected(settings):
    settings.FORENSIC_MAX_UPLOAD_MB = 0
    c = Client()
    r = c.post("/api/ingest/evtx", {"file": ("x.evtx", b"x" * 10)}, **HDR)
    assert r.status_code in (400, 413)


def test_analyze_single_attachment():
    c = Client()
    from django.core.files.uploadedfile import SimpleUploadedFile

    f = SimpleUploadedFile("photo.jpg", b"MZ" + b"\x00" * 100, content_type="image/jpeg")
    r = c.post("/api/analyze/attachment", {"file": f}, **HDR)
    assert r.status_code == 200
    assert "extension_mismatch_executable" in r.json()["result"]["flags"]


def test_reputation_offline_provider_lists():
    c = Client()
    r = c.get("/api/reputation/providers", **HDR).json()
    names = {p["name"] for p in r["providers"]}
    assert {"urlhaus", "virustotal", "spamhaus", "offline", "rdap"} <= names


def test_reputation_lookup_validates_input():
    c = Client()
    r = c.post("/api/reputation/lookup", data="not json", content_type="application/json", **HDR)
    assert r.status_code == 400
    r = c.post(
        "/api/reputation/lookup",
        data=json.dumps({"items": [{"kind": "ip", "value": "10.0.0.1"}], "providers": ["offline"]}),
        content_type="application/json",
        **HDR,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["results"] and body["results"][0]["provider"] == "offline"


def test_ai_query_requires_question():
    c = Client()
    r = c.post("/api/ai/query", data=json.dumps({}), content_type="application/json", **HDR)
    assert r.status_code == 400
