"""
Heavy-file validation (multi-GB, hundreds of thousands of rows). Excluded from
the default run; execute deliberately before real case exports:

    .venv\\Scripts\\python.exe -m pytest -m heavy -s

Sizes are tunable through environment variables so a quick pass is possible:
    REMN_HEAVY_BLOB_MB   (default 1024)  chunked-upload fixture size
    REMN_HEAVY_MAILS     (default 300000) mbox ingest size
    REMN_HEAVY_EVENTS    (default 200000) NDJSON import size
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path

import make_big
import pytest
from django.test import Client

from services.ingest.pipeline import MailSource
from services.parsers.mail.common import ParseContext
from services.store import queries as Q
from services.store import rules as R
from services.store.casestore import StoreRegistry, registry as global_registry
from services.store.writers import MailWriter

pytestmark = pytest.mark.heavy

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
BLOB_MB = int(os.environ.get("REMN_HEAVY_BLOB_MB", "1024"))
N_MAILS = int(os.environ.get("REMN_HEAVY_MAILS", "300000"))
N_EVENTS = int(os.environ.get("REMN_HEAVY_EVENTS", "200000"))
CHUNK = 16 * 1024 * 1024


@pytest.fixture
def tmp_registry(tmp_path):
    """Point the process-global registry (used by the HTTP views) at tmp."""
    old = global_registry.root
    global_registry.configure(tmp_path / "cases")
    yield global_registry
    if old:
        global_registry.configure(old)


def _upload_blob(c: Client, blob: Path, interrupt_at: float | None = None) -> tuple[str, int]:
    size = blob.stat().st_size
    r = c.post("/api/upload/init", json.dumps({"name": blob.name, "size": size}), content_type="application/json", **HDR)
    assert r.status_code == 200, r.content
    uid = r.json()["uploadId"]
    sent = 0
    with open(blob, "rb") as fh:
        while sent < size:
            if interrupt_at is not None and sent >= size * interrupt_at:
                return uid, sent
            piece = fh.read(CHUNK)
            r = c.generic("PUT", f"/api/upload/{uid}/chunk?offset={sent}", piece, content_type="application/octet-stream", **HDR)
            assert r.status_code == 200, r.content
            sent = r.json()["received"]
    return uid, sent


def test_chunked_upload_interrupt_and_resume(tmp_path):
    """>= 1 GB upload, killed halfway, resumed from the server's offset."""
    blob = tmp_path / "big.blob"
    make_big.write_blob(blob, BLOB_MB / 1024, progress=False)
    size = blob.stat().st_size
    sha = hashlib.sha256()
    with open(blob, "rb") as fh:
        for piece in iter(lambda: fh.read(CHUNK), b""):
            sha.update(piece)
    c = Client()
    t0 = time.time()
    uid, sent = _upload_blob(c, blob, interrupt_at=0.5)
    assert 0 < sent < size
    # what the resuming client does after a reload: read the server's offset
    st = c.get(f"/api/upload/{uid}", **HDR).json()
    assert st["received"] == sent and not st["complete"]
    # resume from that offset
    with open(blob, "rb") as fh:
        fh.seek(sent)
        while sent < size:
            piece = fh.read(CHUNK)
            r = c.generic("PUT", f"/api/upload/{uid}/chunk?offset={sent}", piece, content_type="application/octet-stream", **HDR)
            assert r.status_code == 200, r.content
            sent = r.json()["received"]
    done = c.post(f"/api/upload/{uid}/complete", "{}", content_type="application/json", **HDR).json()
    assert done["sha256"] == sha.hexdigest() and done["size"] == size
    print(f"\n  upload+resume {size / 1e9:.2f} GB in {time.time() - t0:.0f}s")
    # a wrong offset must resync, not corrupt
    r = c.generic("PUT", f"/api/upload/{uid}/chunk?offset=0", b"x", content_type="application/octet-stream", **HDR)
    assert r.status_code == 409
    c.delete(f"/api/upload/{uid}", **HDR)


def test_big_mbox_server_store_ingest(tmp_path):
    """300k-mail mbox through the real pipeline into DuckDB, then queries + rules."""
    mbox = tmp_path / "big.mbox"
    make_big.write_mbox(mbox, N_MAILS, attach_ratio=0.01, progress=False)
    print(f"\n  mbox: {mbox.stat().st_size / 1e6:.0f} MB, {N_MAILS:,} messages")
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    try:
        st = reg.get(str(uuid.uuid4()))
        ctx = ParseContext(internal_domains=["interne.fr"], vip_names=["Marie Lefevre"],
                           analyze_attachments=False)  # deepAttachments off: the fast first pass
        t0 = time.time()
        w = MailWriter(st, 1)
        n = 0
        for row in MailSource(mbox.name, str(mbox), None, ctx, str(tmp_path)):
            w.add(row)
            n += 1
        w.flush()
        dt = time.time() - t0
        rate = n / dt
        print(f"  ingested {n:,} mails in {dt:.0f}s ({rate:,.0f}/s), store {st.size_bytes() / 1e6:.0f} MB")
        assert n == N_MAILS
        assert rate > 60, f"ingest too slow: {rate:.0f} mails/s"
        assert Q.count(st, "mails", {}) == N_MAILS
        t = time.time()
        agg = Q.aggregate(st, "mails", {}, "fromRegistrable", 20)
        assert agg["total"] == N_MAILS and (time.time() - t) < 5
        t = time.time()
        assert Q.count(st, "mails", {"conditions": [{"field": "risk", "op": "gte", "value": 80}]}) > 0
        assert (time.time() - t) < 5
        # planted BEC spoofs must surface through a real rule
        import yaml

        docs = list(yaml.safe_load_all(Path("rules/mail/spoofing.yaml").read_text(encoding="utf-8")))
        vip = next(d for d in docs if d["id"] == "mail-vip-impersonation")
        t = time.time()
        hits = R.run_rule(st, vip, {"vip_names": ["Marie Lefevre"], "internal_domains": ["interne.fr"], "trusted_senders": []})
        print(f"  vip rule: {len(hits)} findings in {time.time() - t:.1f}s")
        assert hits, "planted interne-fr.co spoofs not detected"
        # sampled deep-attachment pass: the slow analyzers still work at scale
        ctx_deep = ParseContext(internal_domains=["interne.fr"], analyze_attachments=True)
        deep_n = 0
        t = time.time()
        for row in MailSource(mbox.name, str(mbox), None, ctx_deep, str(tmp_path)):
            deep_n += 1
            if deep_n >= 5000:
                break
        print(f"  deep pass: 5,000 mails in {time.time() - t:.0f}s")
    finally:
        reg.close_all()


def test_job_cancel_mid_ingest_leaves_consistent_store(tmp_path, tmp_registry):
    """Cancelling the server ingest job mid-run must leave a queryable store."""
    mbox = tmp_path / "cancel.mbox"
    make_big.write_mbox(mbox, 40000, attach_ratio=0.0, progress=False)
    c = Client()
    uid, _ = _upload_blob(c, mbox)
    assert c.post(f"/api/upload/{uid}/complete", "{}", content_type="application/json", **HDR).status_code == 200
    key = str(uuid.uuid4())
    r = c.post(f"/api/store/{key}/ingest", json.dumps({
        "uploadId": uid, "kind": "mail",
        "evidence": {"id": 1, "name": "cancel.mbox", "size": mbox.stat().st_size},
        "options": {"settings": {"internalDomains": ["interne.fr"]}},
    }), content_type="application/json", **HDR)
    assert r.status_code == 200, r.content
    job_id = r.json()["jobId"]
    # let it get going, then cancel
    deadline = time.time() + 60
    while time.time() < deadline:
        j = c.get(f"/api/jobs/{job_id}", **HDR).json()
        if j["status"] == "running" and (j.get("progress") or {}).get("rows", 0) > 500:
            break
        if j["status"] in ("done", "error", "cancelled"):
            break
        time.sleep(0.2)
    c.delete(f"/api/jobs/{job_id}", **HDR)
    deadline = time.time() + 60
    while time.time() < deadline:
        j = c.get(f"/api/jobs/{job_id}", **HDR).json()
        if j["status"] in ("cancelled", "done", "error"):
            break
        time.sleep(0.2)
    assert j["status"] == "cancelled", j
    st = tmp_registry.get(key, create=False)
    partial = Q.count(st, "mails", {})
    assert 0 <= partial < 40000
    # store still consistent and writable after the cancel
    assert Q.aggregate(st, "mails", {}, "fromRegistrable", 5)["total"] == partial
    print(f"\n  cancelled with {partial:,} rows persisted; store still queryable")


def test_import_bulk_ndjson_and_delete(tmp_registry):
    """200k parsed events through /import, then evidence delete cleans up."""
    sys_path_hack = Path("samples/synthetic")
    import sys

    if str(sys_path_hack) not in sys.path:
        sys.path.insert(0, str(sys_path_hack))
    import scale_test

    c = Client()
    key = str(uuid.uuid4())
    t0 = time.time()
    sent = 0
    batch: list[str] = []
    for i in range(N_EVENTS):
        row = scale_test.gen(i)
        row["type"] = "event"
        batch.append(json.dumps(row))
        if len(batch) >= 5000:
            r = c.generic("POST", f"/api/store/{key}/import?evidenceId=7", "\n".join(batch).encode(), content_type="application/x-ndjson", **HDR)
            assert r.status_code == 200, r.content
            sent += len(batch)
            batch = []
    if batch:
        r = c.generic("POST", f"/api/store/{key}/import?evidenceId=7", "\n".join(batch).encode(), content_type="application/x-ndjson", **HDR)
        assert r.status_code == 200
        sent += len(batch)
    dt = time.time() - t0
    st = tmp_registry.get(key, create=False)
    assert Q.count(st, "events", {}) == N_EVENTS
    print(f"\n  imported {N_EVENTS:,} events in {dt:.0f}s ({N_EVENTS / dt:,.0f}/s)")
    r = c.delete(f"/api/store/{key}/evidence/7", **HDR)
    assert r.status_code == 200
    assert Q.count(st, "events", {}) == 0
