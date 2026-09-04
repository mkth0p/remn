from __future__ import annotations

import io
import json
import tarfile
import time
import uuid
import zipfile
from pathlib import Path

import make_samples
import pytest
from django.test import Client

from services.ingest.pipeline import EvtxSource, MailSource, detect_mail_format, looks_like_mail
from services.parsers.mail.common import ParseContext
from services.store import queries as Q
from services.store import rules as R
from services.store.casestore import StoreRegistry
from services.store.sqlfilter import Ctx, FilterError, compile_condition, compile_filter
from services.store.writers import EventWriter, MailWriter

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
T0 = 1788300000000


def _event(i: int, **kw):
    row = {"recordId": i, "ts": T0 + i * 1000, "tsIso": "2026-09-01T22:00:00Z", "eventId": 4624, "provider": "Microsoft-Windows-Security-Auditing",
           "channel": "Security", "computer": "WS01", "level": 0, "levelName": "LogAlways", "summary": f"event {i}", "data": {"X": i}, "raw": json.dumps({"i": i})}
    row.update(kw)
    return row


@pytest.fixture
def store(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    st = reg.get(str(uuid.uuid4()))
    yield st
    reg.close_all()


def test_write_and_search_events(store):
    w = EventWriter(store, 1)
    for i in range(1000):
        w.add(_event(i, eventId=4625 if i % 4 == 0 else 4624, ipAddress=f"10.0.0.{i % 5}" if i % 4 == 0 else None, targetUser="admin" if i % 8 == 0 else "bob"))
    w.flush()
    assert store.counts()["events"] == 1000
    s = {"internal_ips": ["10.0.0.0/8"]}
    r = Q.search(store, "events", {"conditions": [{"field": "eventId", "op": "eq", "value": 4625}]}, limit=10, settings=s)
    assert len(r["rows"]) == 10 and r["truncated"] and r["rows"][0]["ts"] > r["rows"][1]["ts"]
    assert Q.count(store, "events", {"conditions": [{"field": "eventId", "op": "eq", "value": 4625}]}) == 250
    assert Q.count(store, "events", {"conditions": [{"field": "targetUser", "op": "eq", "value": "ADMIN"}]}) == 125
    assert Q.count(store, "events", {"conditions": [{"field": "ipAddress", "op": "in_setting", "value": "internal_ips"}]}, s) == 250
    assert Q.count(store, "events", {"conditions": [{"field": "ipAddress", "op": "nin_setting", "value": "internal_ips"}, {"field": "eventId", "op": "eq", "value": 4625}]}, s) == 0
    assert Q.count(store, "events", {"text": "event 99"}) == 11  # 99, 990..999
    assert Q.count(store, "events", {"regex": {"field": "summary", "pattern": "^event 1\\d$"}}) == 10
    assert Q.count(store, "events", {"conditions": [{"field": "data.X", "op": "gte", "value": 990}]}) == 10
    assert Q.count(store, "events", {"timeRange": {"from": T0 + 10_000, "to": T0 + 19_000}}) == 10
    agg = Q.aggregate(store, "events", {"conditions": [{"field": "eventId", "op": "eq", "value": 4625}]}, "ipAddress", 10)
    assert agg["total"] == 250 and agg["distinct"] == 5 and agg["groups"][0]["count"] == 50
    tl = Q.timeline(store, "events", {}, "minute")
    assert sum(b["count"] for b in tl) == 1000
    assert Q.facets(store, "events", "computer")[0] == {"value": "WS01", "count": 1000}
    full = Q.get_row(store, "events", r["rows"][0]["id"])
    assert full["data"] == {"X": full["recordId"]} and full["raw"]
    p = Q.pivot(store, "10.0.0.1")
    assert p["events"]["count"] == 50 and p["events"]["byEventId"] == {"4625": 50}
    sq = Q.run_sql(store, 'SELECT "eventId", count(*) AS c FROM events GROUP BY 1 ORDER BY c DESC')
    assert sq["rows"][0]["c"] == 750
    with pytest.raises(FilterError):
        Q.run_sql(store, "DELETE FROM events")
    with pytest.raises(FilterError):
        Q.run_sql(store, "SELECT 1; SELECT 2")


def test_mail_write_nested_filters_and_iocs(store):
    ctx = ParseContext(internal_domains=["interne.fr"], vip_names=["Marie Lefevre"])
    src = MailSource("emls.zip", None, _zip_of_samples(), ctx, str(store.dir))
    w = MailWriter(store, 2)
    for row in src:
        w.add(row)
    w.flush()
    assert src.format == "zip" and store.counts()["mails"] == 5
    s = {"internal_domains": ["interne.fr"], "vip_names": ["Marie Lefevre"]}
    macro = Q.search(store, "mails", {"conditions": [{"field": "attachments.flags", "op": "contains", "value": "office_macro"}]}, settings=s)["rows"]
    assert [m["subject"] for m in macro] == ["URGENT: facture a regler avant 18h"]
    vip = Q.search(store, "mails", {"conditions": [{"field": "fromNameNorm", "op": "in_setting", "value": "vip_names"}, {"field": "fromRegistrable", "op": "nin_setting", "value": "internal_domains"}]}, settings=s)["rows"]
    assert {m["fromAddr"] for m in vip} == {"marie.lefevre@interne-fr.co", "ceo.office.2026@gmail.com"}
    assert Q.count(store, "mails", {"conditions": [{"field": "flags", "op": "contains_any", "value": "lexicon_gift_card,att_html_smuggling"}]}) == 2
    assert Q.count(store, "mails", {"conditions": [{"field": "urls.host", "op": "eq", "value": "185.220.101.4"}]}) == 1
    assert Q.count(store, "mails", {"conditions": [{"field": "bodyText", "op": "re", "value": "gift cards"}]}) == 1
    assert Q.count(store, "mails", {"conditions": [{"field": "auth.spf", "op": "eq", "value": "fail"}]}) == 1
    assert Q.count(store, "mails", {"conditions": [{"field": "risk", "op": "gte", "value": 90}]}) == 3
    detail = Q.get_row(store, "mails", macro[0]["id"])
    assert len(detail["attachments"]) == 2 and detail["body"]["bodyText"].startswith("Bonjour")
    iocs = Q.list_iocs(store)
    kinds = iocs["kinds"]
    assert kinds["email"] == 5 and kinds["hash"] >= 3 and kinds["ip"] >= 3
    store.set_reputation([{"kind": "ip", "value": "185.220.101.4", "verdict": "malicious", "tags": ["c2"], "checkedAt": 1}])
    assert store.mirror_reputation_to_mails() >= 1
    assert Q.count(store, "mails", {"conditions": [{"field": "reputation.worst", "op": "eq", "value": "malicious"}]}) == 1
    bad = Q.list_iocs(store, only_bad=True)
    assert bad["total"] == 1 and bad["rows"][0]["verdict"] == "malicious"
    assert Q.facets(store, "mails", "riskBand")[0]["value"] in ("critical", "high", "clean", "low", "medium")
    assert any(f["value"] == "docx" for f in Q.facets(store, "mails", "attExt"))


def test_server_rules_engine(store):
    w = EventWriter(store, 1)
    # brute force burst from 10.9.9.9 then a success; scattered failures elsewhere; night logon
    for i in range(6):
        w.add(_event(i, eventId=4625, ipAddress="10.9.9.9", targetUser="admin", logonType=3))
    w.add(_event(20, eventId=4624, ipAddress="10.9.9.9", targetUser="admin", logonType=3))
    for i in range(3):
        w.add(_event(100 + i * 120, eventId=4625, ipAddress="10.8.8.8", targetUser="bob"))
    for u in ("a", "b", "c", "d"):
        w.add(_event(500 + ord(u), eventId=4625, ipAddress="1.1.1.1", targetUser=u))
    w.add(_event(900, eventId=4624, logonType=10, targetUser="alice", ipAddress="203.0.113.5"))
    w.add(_event(901, eventId=1102, subjectUser="eve"))
    w.flush()
    settings = {"businessHours": {"start": 8, "end": 19, "tz": "UTC"}, "weekendDays": [0, 6], "internal_ips": ["10.0.0.0/8"], "service_accounts": []}
    brute = {"id": "bf", "title": "brute", "severity": "high", "source": "events", "where": {"eventId": 4625, "ipAddress|exists": True}, "group_by": ["ipAddress"],
             "window": "5m", "threshold": ">= 5", "then": {"where": {"eventId": 4624}, "join": ["ipAddress"], "within": "15m", "severity": "critical", "title": "success after burst"}}
    f = R.run_rule(store, brute, settings)
    assert len(f) == 1 and f[0]["entities"]["ipAddress"] == "10.9.9.9" and f[0]["count"] == 6 and f[0]["severity"] == "critical" and "success after burst" in f[0]["title"]
    spray = {"id": "spray", "title": "s", "severity": "high", "source": "events", "where": {"eventId": 4625}, "group_by": ["ipAddress"], "window": "30m", "distinct": "targetUser", "threshold": ">= 3"}
    f = R.run_rule(store, spray, settings)
    assert len(f) == 1 and f[0]["entities"]["ipAddress"] == "1.1.1.1" and "a, b, c" in f[0]["entities"]["targetUser"]
    night = {"id": "night", "title": "n", "severity": "medium", "source": "events", "where": {"eventId": 4624, "logonType|in": [2, 10]}, "time": {"outside_business_hours": True}, "exclude": {"targetUser|in_setting": "service_accounts"}}
    f = R.run_rule(store, night, settings)
    assert len(f) == 1 and f[0]["entities"]["targetUser"] == "alice"
    rdp = {"id": "rdp", "title": "r", "severity": "high", "source": "events", "where": {"eventId": 4624, "logonType": 10}, "exclude": {"ipAddress|in_setting": "internal_ips"}}
    assert len(R.run_rule(store, rdp, settings)) == 1
    grouped = {"id": "lock", "title": "l", "severity": "low", "source": "events", "where": {"eventId": 4625}, "group_by": ["targetUser"], "threshold": ">= 3"}
    f = R.run_rule(store, grouped, settings)
    assert {x["entities"]["targetUser"] for x in f} == {"admin", "bob"}
    simple = {"id": "clear", "title": "c", "severity": "critical", "source": "events", "where": {"eventId": 1102}}
    f = R.run_rule(store, simple, settings)
    assert len(f) == 1 and f[0]["entities"]["subjectUser"] == "eve" and f[0]["refs"]
    res = R.run_rules(store, [brute, spray, {"id": "bad", "title": "b", "severity": "low", "source": "events", "where": {"x|bogus": 1}}], settings)
    assert res["byRule"]["bf"] == 1 and res["errors"][0]["ruleId"] == "bad"


def test_rule_diagnostics_explain_silent_rules(store):
    w = EventWriter(store, 1)
    for i in range(3):
        w.add(_event(i, eventId=4625, ipAddress="9.9.9.9", targetUser="bob"))
    w.add(_event(10, eventId=4624, logonType=10, targetUser="svc_x", ipAddress="10.0.0.5"))
    w.flush()
    settings = {"businessHours": {"start": 0, "end": 24, "tz": "UTC"}, "weekendDays": [], "internal_ips": [], "service_accounts": ["svc_x"], "vip_names": []}
    rules = [
        {"id": "absent", "title": "a", "severity": "low", "source": "events", "where": {"eventId": 1102}},
        {"id": "vip", "title": "v", "severity": "low", "source": "events", "where": {"targetUser|in_setting": "vip_names"}},
        {"id": "req", "title": "r", "severity": "low", "source": "events", "where": {"eventId": 4624}, "require_setting": "internal_ips"},
        {"id": "excl", "title": "e", "severity": "low", "source": "events", "where": {"eventId": 4624}, "exclude": {"targetUser|in_setting": "service_accounts"}},
        {"id": "thr", "title": "t", "severity": "low", "source": "events", "where": {"eventId": 4625}, "group_by": ["ipAddress"], "window": "5m", "threshold": ">= 10"},
        {"id": "time", "title": "ti", "severity": "low", "source": "events", "where": {"eventId": 4625}, "time": {"hours": [5, 5]}},
        {"id": "ok", "title": "o", "severity": "low", "source": "events", "where": {"eventId": 4625}},
    ]
    res = R.run_rules(store, rules, settings)
    d = {x["ruleId"]: x for x in res["diagnostics"]}
    assert d["absent"]["reason"] == "no_selector_match" and "1102" in (d["absent"]["detail"] or "")
    assert d["vip"]["reason"] == "missing_setting" and "vip_names" in d["vip"]["detail"]
    assert d["req"]["reason"] == "missing_setting" and "internal_ips" in d["req"]["detail"]
    assert d["excl"]["reason"] == "all_excluded" and d["excl"]["matched"] == 1
    assert d["thr"]["reason"] == "below_threshold" and d["thr"]["matched"] == 3
    assert d["time"]["reason"] == "outside_time_window"
    assert "ok" not in d and res["byRule"]["ok"] == 3


def test_sql_compiler_edge_cases():
    ctx = Ctx(source="events", settings={})
    sql = compile_condition("eventId", "in", "4624, 4625", ctx)
    assert "IN" in sql and ctx.params == ["4624", "4625"] or len(ctx.params) == 2
    ctx = Ctx(source="mails", settings={})
    sql = compile_condition("attachments.name", "not_contains", ".exe", ctx)
    assert sql.startswith("NOT EXISTS")
    ctx = Ctx(source="events", settings={"businessHours": {"tz": "Europe/Paris"}})
    sql = compile_filter({"hourRange": {"from": 8, "to": 19, "outside": True}, "text": "x"}, ctx)
    assert "timezone(" in sql and sql.count("?") == len(ctx.params)
    with pytest.raises(FilterError):
        compile_condition("nope", "eq", 1, Ctx(source="mails"))


def _zip_of_samples() -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for name, data in _samples().items():
            z.writestr(f"Inbox/{name}", data)
    return b.getvalue()


def _samples() -> dict[str, bytes]:
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        make_samples.build(d)
        return {p.name: p.read_bytes() for p in sorted(Path(d).glob("*.eml"))}


def test_pipeline_corpus_formats(tmp_path):
    samples = _samples()
    assert looks_like_mail(next(iter(samples.values()))[:4096])
    assert not looks_like_mail(b"\x89PNG\r\n")
    # tar.bz2 of extensionless messages (SpamAssassin / Enron maildir style)
    tar_path = tmp_path / "corpus.tar.bz2"
    with tarfile.open(tar_path, "w:bz2") as tf:
        for i, (name, data) in enumerate(samples.items()):
            info = tarfile.TarInfo(name=f"easy_ham/{i:04d}.{name[:2]}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    head = tar_path.read_bytes()[:512]
    assert detect_mail_format("corpus.tar.bz2", head) == "tar"
    rows = list(MailSource("corpus.tar.bz2", str(tar_path), None, ParseContext(), str(tmp_path)))
    assert len(rows) == 5 and all(r["sourceFormat"] == "eml" for r in rows)
    # zip of evtx
    if (SAMPLES / "TerminalServices-LSM.evtx").exists():
        zp = tmp_path / "logs.zip"
        with zipfile.ZipFile(zp, "w") as z:
            z.write(SAMPLES / "TerminalServices-LSM.evtx", "host1/TS.evtx")
            z.write(SAMPLES / "TerminalServices-LSM.evtx", "host2/TS.evtx")
        src = EvtxSource("logs.zip", str(zp), None, str(tmp_path))
        rows = list(src)
        assert src.format == "zip" and len(rows) == 2 * 1436 and {r["sourceFile"] for r in rows} == {"host1/TS.evtx", "host2/TS.evtx"}
        assert len(src.files) == 2 and src.files[0]["sha256"]


@pytest.mark.skipif(not (SAMPLES / "System-last7d.evtx").exists(), reason="local sample not exported")
def test_chunked_upload_store_ingest_and_query(settings, tmp_path):
    settings.CASES_DIR = tmp_path / "cases"
    from services.store.casestore import registry

    registry.configure(settings.CASES_DIR)
    c = Client()
    key = str(uuid.uuid4())
    data = (SAMPLES / "System-last7d.evtx").read_bytes()
    r = c.post("/api/upload/init", data=json.dumps({"name": "System.evtx", "size": len(data)}), content_type="application/json", **HDR)
    assert r.status_code == 200
    upload_id = r.json()["uploadId"]
    chunk = 700_000
    for off in range(0, len(data), chunk):
        r = c.generic("PUT", f"/api/upload/{upload_id}/chunk?offset={off}", data[off:off + chunk], content_type="application/octet-stream", **HDR)
        assert r.status_code == 200, r.content
    r = c.post(f"/api/upload/{upload_id}/complete", **HDR)
    assert r.status_code == 200
    sha = r.json()["sha256"]
    r = c.post(f"/api/store/{key}/ingest", data=json.dumps({"uploadId": upload_id, "kind": "evtx", "evidence": {"id": 7, "name": "System.evtx", "sha256Client": sha}, "options": {"includeRaw": False}}), content_type="application/json", **HDR)
    assert r.status_code == 200
    job_id = r.json()["jobId"]
    for _ in range(600):
        j = c.get(f"/api/jobs/{job_id}", **HDR).json()
        if j["status"] in ("done", "error", "cancelled"):
            break
        time.sleep(0.1)
    assert j["status"] == "done", j
    assert j["result"]["count"] > 1000 and j["result"]["integrity"] == "verified"
    r = c.post(f"/api/store/{key}/search", data=json.dumps({"source": "events", "filter": {"text": "service"}, "limit": 5}), content_type="application/json", **HDR)
    assert r.status_code == 200 and len(r.json()["rows"]) == 5
    r = c.get(f"/api/store/{key}/facets?source=events&field=eventId&limit=3", **HDR)
    assert r.status_code == 200 and len(r.json()) == 3
    r = c.get(f"/api/store/{key}", **HDR)
    assert r.json()["counts"]["events"] == j["result"]["count"] and r.json()["evidence"][0]["id"] == 7
    r = c.post(f"/api/store/{key}/rules/run", data=json.dumps({"rules": [{"id": "svc", "title": "s", "severity": "info", "source": "events", "where": {"eventId": 7045}}], "settings": {}}), content_type="application/json", **HDR)
    job_id = r.json()["jobId"]
    for _ in range(300):
        j = c.get(f"/api/jobs/{job_id}", **HDR).json()
        if j["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    assert j["status"] == "done" and j["result"]["byRule"]["svc"] >= 1
    r = c.post(f"/api/store/{key}/sql", data=json.dumps({"sql": "SELECT count(*) AS n FROM events"}), content_type="application/json", **HDR)
    assert r.json()["rows"][0]["n"] > 1000
    # import path (browser -> server migration) and deletion
    lines = "\n".join(json.dumps({"type": "event", **_event(i)}) for i in range(10))
    r = c.generic("POST", f"/api/store/{key}/import?evidenceId=8", lines.encode(), content_type="application/x-ndjson", **HDR)
    assert r.status_code == 200 and r.json()["events"] == 10
    r = c.delete(f"/api/store/{key}/evidence/8", **HDR)
    assert r.json()["deleted"]["events"] == 10
    assert not Path(settings.FILE_UPLOAD_TEMP_DIR, "uploads", f"{upload_id}.part").exists()
    r = c.delete(f"/api/store/{key}", **HDR)
    assert r.json()["deleted"] is True


def test_trusted_sender_rule_exclusion(store):
    """The spoofing rules must skip trusted senders, both via the ingest-time
    flag and retroactively via the trusted_senders setting (no re-ingest)."""
    from pathlib import Path

    import yaml

    docs = list(yaml.safe_load_all((Path(__file__).resolve().parents[2] / "rules" / "mail" / "spoofing.yaml").read_text(encoding="utf-8")))
    vip_rule = next(d for d in docs if d["id"] == "mail-vip-impersonation")
    ctx = ParseContext(internal_domains=["interne.fr"], vip_names=["Marie Lefevre"])
    teams = make_samples.mail(
        '"Marie Lefevre" <noreply@email.teams.microsoft.com>', "j.dupont@interne.fr",
        "Marie Lefevre mentioned you", "Open Teams to reply.",
        extra_headers=[("Authentication-Results", "mx.interne.fr; spf=pass smtp.mailfrom=email.teams.microsoft.com; dkim=pass header.d=microsoft.com; dmarc=pass")],
        date="Tue, 01 Sep 2026 10:00:00 +0000")
    legacy_saas = make_samples.mail(  # no auth headers: unflagged at ingest, like a pre-feature ingest
        '"Marie Lefevre" <mentions@old-tool.example-saas.com>', "j.dupont@interne.fr",
        "Marie commented", "See the comment.",
        date="Tue, 01 Sep 2026 10:01:00 +0000")
    spoof = make_samples.mail(
        '"Marie Lefevre" <marie.lefevre@interne-fr.co>', "j.dupont@interne.fr",
        "Urgent request", "Please call me.",
        date="Tue, 01 Sep 2026 10:02:00 +0000")
    from services.parsers.mail.common import parse_message_bytes

    w = MailWriter(store, 7)
    for raw in (teams, legacy_saas, spoof):
        w.add(parse_message_bytes(raw, ctx))
    w.flush()
    settings = {"vip_names": ["Marie Lefevre"], "internal_domains": ["interne.fr"], "trusted_senders": []}
    hits = R.run_rule(store, vip_rule, settings)
    froms = {h["entities"].get("fromAddr") or h["entities"].get("fromRegistrable") for h in hits}
    # teams mail excluded by its trusted_sender flag; legacy SaaS still flagged (not yet trusted)
    assert "microsoft.com" not in str(froms)
    assert any("example-saas.com" in str(x) for x in froms)
    assert any("interne-fr.co" in str(x) for x in froms)
    # analyst adds the SaaS domain to trusted_senders: retroactive exclusion, no re-ingest
    settings["trusted_senders"] = ["example-saas.com"]
    hits = R.run_rule(store, vip_rule, settings)
    froms = {str(h["entities"]) for h in hits}
    assert not any("example-saas.com" in x for x in froms)
    assert any("interne-fr.co" in x for x in froms)


def test_export_roundtrip(tmp_path):
    """/export must emit NDJSON that /import-format writers can rebuild losslessly
    enough: same counts, same risks/flags/auth, attachments and bodies intact."""
    from django.test import Client

    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    try:
        src_st = reg.get(str(uuid.uuid4()))
        ctx = ParseContext(internal_domains=["interne.fr"], vip_names=["Marie Lefevre"])
        msrc = MailSource("emls.zip", None, _zip_of_samples(), ctx, str(src_st.dir))
        mw = MailWriter(src_st, 2)
        for row in msrc:
            mw.add(row)
        mw.flush()
        ew = EventWriter(src_st, 1)
        for i in range(50):
            ew.add(_event(i, eventId=4625, ipAddress="10.9.9.9", targetUser="admin"))
        ew.flush()
        src_st.upsert_evidence({"id": 1, "name": "log.evtx", "kind": "evtx", "count": 50, "status": "done"})
        src_st.upsert_evidence({"id": 2, "name": "emls.zip", "kind": "mail", "count": 5, "status": "done"})

        # export through the actual HTTP view (registry is process-global: point it at tmp)
        from services.store.casestore import registry as global_reg

        old_dir = global_reg.root
        global_reg.configure(tmp_path / "cases")
        try:
            c = Client()
            resp = c.get(f"/api/store/{src_st.key}/export", HTTP_X_FORENSIC_CLIENT="1")
            assert resp.status_code == 200
            lines = [json.loads(x) for x in b"".join(resp.streaming_content).decode("utf-8").splitlines() if x.strip()]
        finally:
            if old_dir:
                global_reg.configure(old_dir)
        kinds = {}
        for ln in lines:
            kinds[ln["type"]] = kinds.get(ln["type"], 0) + 1
        assert kinds == {"evidence": 2, "event": 50, "mail": 5}

        # rebuild into a fresh store with the same writers /import uses
        dst = reg.get(str(uuid.uuid4()))
        ew2 = EventWriter(dst, 1)
        mw2 = MailWriter(dst, 2)
        for ln in lines:
            t = ln.pop("type")
            if t == "evidence":
                dst.upsert_evidence(ln)
            elif t == "event":
                ew2.add(ln)
            else:
                mw2.add(ln)
        ew2.flush()
        mw2.flush()
        assert dst.counts()["events"] == 50 and dst.counts()["mails"] == 5
        for st_ in (src_st, dst):
            assert Q.count(st_, "mails", {"conditions": [{"field": "risk", "op": "gte", "value": 90}]}) == 3
            assert Q.count(st_, "mails", {"conditions": [{"field": "auth.spf", "op": "eq", "value": "fail"}]}) == 1
            assert Q.count(st_, "mails", {"conditions": [{"field": "attachments.flags", "op": "contains", "value": "office_macro"}]}) == 1
            assert Q.count(st_, "events", {"conditions": [{"field": "eventId", "op": "eq", "value": 4625}]}) == 50
        macro = Q.search(dst, "mails", {"conditions": [{"field": "attachments.flags", "op": "contains", "value": "office_macro"}]})["rows"]
        detail = Q.get_row(dst, "mails", macro[0]["id"])
        assert len(detail["attachments"]) == 2 and detail["body"]["bodyText"].startswith("Bonjour")
        full_ev = Q.get_row(dst, "events", Q.search(dst, "events", {})["rows"][0]["id"])
        assert full_ev["data"] and full_ev["raw"]
    finally:
        reg.close_all()


def test_grouped_rule_with_any_in_group_and_exclude(store):
    """any_in_group is used in the SELECT list and in HAVING: its placeholders must be bound in SQL
    order. mail-internal-name-external-domain errored on every real store before the fix."""
    from pathlib import Path

    import yaml
    from services.parsers.mail.common import parse_message_bytes

    docs = list(yaml.safe_load_all((Path(__file__).resolve().parents[2] / "rules" / "mail" / "spoofing.yaml").read_text(encoding="utf-8")))
    rule = next(d for d in docs if d["id"] == "mail-internal-name-external-domain")
    ctx = ParseContext(internal_domains=["interne.fr"])
    mails = [
        make_samples.mail('"Jean Dupont" <jean.dupont@interne.fr>', "j.martin@interne.fr", "Budget", "See attached.",
                          date="Tue, 01 Sep 2026 10:00:00 +0000"),
        make_samples.mail('"Jean Dupont" <jean.dupont@gmail.com>', "j.martin@interne.fr", "Urgent", "Call me.",
                          date="Tue, 01 Sep 2026 10:05:00 +0000"),
        make_samples.mail('"Jean Dupont" <noreply@email.teams.microsoft.com>', "j.martin@interne.fr", "Jean mentioned you", "Open Teams.",
                          extra_headers=[("Authentication-Results", "mx.interne.fr; spf=pass smtp.mailfrom=email.teams.microsoft.com; dkim=pass header.d=microsoft.com; dmarc=pass")],
                          date="Tue, 01 Sep 2026 10:10:00 +0000"),
    ]
    w = MailWriter(store, 3)
    for raw in mails:
        w.add(parse_message_bytes(raw, ctx))
    w.flush()
    hits = R.run_rule(store, rule, {"internal_domains": ["interne.fr"], "vip_names": [], "trusted_senders": []})
    assert len(hits) == 1 and hits[0]["count"] == 2  # interne.fr + gmail.com; the Teams relay is excluded
    regs = hits[0]["entities"].get("fromRegistrable", "")
    assert "gmail.com" in regs and "microsoft.com" not in regs
