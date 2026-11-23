from __future__ import annotations

import io
import json
import tarfile
import time
import uuid
import zipfile
from pathlib import Path

import duckdb
import make_samples
import pytest
from django.test import Client

from services.ingest.pipeline import EvtxSource, MailSource, detect_mail_format, looks_like_mail
from services.parsers.mail.common import ParseContext
from services.store import queries as Q
from services.store import rules as R
from services.store.casestore import CaseStore, StoreRegistry
from services.store.sqlfilter import Ctx, FilterError, compile_condition, compile_filter
from services.store.writers import EventWriter, MailWriter

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
T0 = 1788300000000


def _event(i: int, **kw):
    row = {
        "recordId": i,
        "ts": T0 + i * 1000,
        "tsIso": "2026-09-01T22:00:00Z",
        "eventId": 4624,
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "WS01",
        "level": 0,
        "levelName": "LogAlways",
        "summary": f"event {i}",
        "data": {"X": i},
        "raw": json.dumps({"i": i}),
    }
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
    assert (
        Q.count(
            store,
            "events",
            {"conditions": [{"field": "ipAddress", "op": "nin_setting", "value": "internal_ips"}, {"field": "eventId", "op": "eq", "value": 4625}]},
            s,
        )
        == 0
    )
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
    vip = Q.search(
        store,
        "mails",
        {
            "conditions": [
                {"field": "fromNameNorm", "op": "in_setting", "value": "vip_names"},
                {"field": "fromRegistrable", "op": "nin_setting", "value": "internal_domains"},
            ]
        },
        settings=s,
    )["rows"]
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


def test_reputation_worst_ranks_malicious_above_suspicious(store):
    # max() over the labels was alphabetical: a mail with a malicious origin IP and a
    # suspicious sender domain came out 'suspicious'.
    src = MailSource("emls.zip", None, _zip_of_samples(), ParseContext(), str(store.dir))
    w = MailWriter(store, 2)
    for row in src:
        w.add(row)
    w.flush()
    mail = Q.search(store, "mails", {"conditions": [{"field": "originIp", "op": "eq", "value": "185.220.101.4"}]})["rows"][0]
    store.set_reputation(
        [
            {"kind": "ip", "value": "185.220.101.4", "verdict": "malicious", "tags": [], "checkedAt": 1},
            {"kind": "domain", "value": mail["fromRegistrable"], "verdict": "suspicious", "tags": [], "checkedAt": 1},
        ]
    )
    store.mirror_reputation_to_mails()
    assert Q.get_row(store, "mails", mail["id"])["reputationWorst"] == "malicious"


def test_url_indicators_keep_the_case_of_their_path_and_query_and_fold_scheme_and_host(store):
    # invented addresses on a reserved test domain; the two links differ only in the case of their path
    links = ["HTTPS://Files.Example.TEST/Share/AbC?Token=XyZ", "https://files.example.test/share/abc?token=xyz", "https://User:PW@Files.Example.TEST/x"]
    w = MailWriter(store, 1)
    for i, link in enumerate(links):
        w.add({"subject": f"invented {i}", "date": 1788300000000 + i, "urls": [{"url": link, "normalized": link, "scheme": "https", "domain": "example.test"}]})
    w.flush()
    urls = {r["value"] for r in Q.list_iocs(store)["rows"] if r["kind"] == "url"}
    assert urls == {"https://files.example.test/Share/AbC?Token=XyZ", "https://files.example.test/share/abc?token=xyz", "https://User:PW@files.example.test/x"}
    domains = {r["value"] for r in Q.list_iocs(store)["rows"] if r["kind"] == "domain"}
    assert domains == {"example.test"}
    # a verdict on the stored form still reaches the mail that carries the link
    store.set_reputation([{"kind": "url", "value": "https://files.example.test/Share/AbC?Token=XyZ", "verdict": "malicious", "tags": [], "checkedAt": 1}])
    store.mirror_reputation_to_mails()
    flagged = Q.search(store, "mails", {"conditions": [{"field": "reputation.worst", "op": "eq", "value": "malicious"}]})["rows"]
    assert {m["subject"] for m in flagged} == {"invented 0"}
    # and a verdict on a link stored all in lower case, as stores written before kept it, still reaches its mail
    store.set_reputation([{"kind": "url", "value": "https://user:pw@files.example.test/x", "verdict": "suspicious", "tags": [], "checkedAt": 1}])
    store.mirror_reputation_to_mails()
    flagged = Q.search(store, "mails", {"conditions": [{"field": "reputation.worst", "op": "eq", "value": "suspicious"}]})["rows"]
    assert {m["subject"] for m in flagged} == {"invented 2"}


class _UnappliedSetting:
    """A connection on which one statement of the lockdown fails, or does nothing, as it would after an
    engine upgrade renamed the setting."""

    def __init__(self, con: duckdb.DuckDBPyConnection, statement: str, fails: bool) -> None:
        self.con, self.statement, self.fails = con, statement, fails

    def execute(self, sql: str, *args):
        if sql.startswith(self.statement):
            if self.fails:
                raise duckdb.CatalogException("invented: unrecognized configuration parameter")
            return self
        return self.con.execute(sql, *args)

    def __getattr__(self, name: str):
        return getattr(self.con, name)


def test_a_store_opens_only_with_file_access_off_and_its_configuration_locked(tmp_path, monkeypatch):
    st = CaseStore(tmp_path, str(uuid.uuid4()))
    cur = st.cursor()
    assert cur.execute("SELECT current_setting('enable_external_access'), current_setting('lock_configuration')").fetchall() == [(False, True)]
    secret = tmp_path / "invented-secret.txt"
    secret.write_text("not for the case", encoding="utf-8")
    with pytest.raises(duckdb.PermissionException):
        cur.execute(f"SELECT * FROM read_text('{secret}')")
    with pytest.raises(duckdb.Error):
        cur.execute("SET enable_external_access = true")
    st.close()
    connect = duckdb.connect
    for statement in ("SET enable_external_access", "SET lock_configuration"):
        for fails in (True, False):
            opened: list[_UnappliedSetting] = []

            def unapplied(path: str, s: str = statement, f: bool = fails, out: list[_UnappliedSetting] = opened) -> _UnappliedSetting:
                out.append(_UnappliedSetting(connect(path), s, f))
                return out[-1]

            monkeypatch.setattr(duckdb, "connect", unapplied)
            with pytest.raises(RuntimeError, match="lockdown"):
                CaseStore(tmp_path, str(uuid.uuid4()))
            # the connection is closed, not left open without its lockdown
            with pytest.raises(duckdb.ConnectionException):
                opened[0].con.execute("SELECT 1")


def test_a_store_whose_lockdown_did_not_take_effect_answers_503_saying_so(tmp_path, monkeypatch):
    from services.store.casestore import registry

    old = registry.root
    registry.configure(tmp_path / "cases")
    key = str(uuid.uuid4())
    CaseStore(tmp_path / "cases", key).close()
    connect = duckdb.connect
    monkeypatch.setattr(duckdb, "connect", lambda path: _UnappliedSetting(connect(path), "SET lock_configuration", True))
    try:
        c = Client(raise_request_exception=False)
        answers = [
            c.get(f"/api/store/{key}", **HDR),
            c.post(f"/api/store/{key}/count", data=json.dumps({"source": "events"}), content_type="application/json", **HDR),
            c.post("/api/stories/build", data=json.dumps({"storeKey": key}), content_type="application/json", **HDR),
            c.post("/api/relationships/build", data=json.dumps({"storeKey": key}), content_type="application/json", **HDR),
            c.post("/api/enrich/mails", data=json.dumps({"storeKey": key}), content_type="application/json", **HDR),
            c.post("/api/enrich/mails/rescore", data=json.dumps({"storeKey": key}), content_type="application/json", **HDR),
        ]
    finally:
        registry.close_all()
        if old:
            registry.configure(old)
    for r in answers:
        assert r.status_code == 503, (r.request["PATH_INFO"], r.content)
        said = r.json()
        assert said["code"] == "storeLockdown" and "ref" not in said
        assert "lockdown did not take effect" in said["error"] and "enable_external_access" in said["error"]


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
    brute = {
        "id": "bf",
        "title": "brute",
        "severity": "high",
        "source": "events",
        "where": {"eventId": 4625, "ipAddress|exists": True},
        "group_by": ["ipAddress"],
        "window": "5m",
        "threshold": ">= 5",
        "then": {"where": {"eventId": 4624}, "join": ["ipAddress"], "within": "15m", "severity": "critical", "title": "success after burst"},
    }
    f = R.run_rule(store, brute, settings)
    assert (
        len(f) == 1
        and f[0]["entities"]["ipAddress"] == "10.9.9.9"
        and f[0]["count"] == 6
        and f[0]["severity"] == "critical"
        and "success after burst" in f[0]["title"]
    )
    spray = {
        "id": "spray",
        "title": "s",
        "severity": "high",
        "source": "events",
        "where": {"eventId": 4625},
        "group_by": ["ipAddress"],
        "window": "30m",
        "distinct": "targetUser",
        "threshold": ">= 3",
    }
    f = R.run_rule(store, spray, settings)
    assert len(f) == 1 and f[0]["entities"]["ipAddress"] == "1.1.1.1" and "a, b, c" in f[0]["entities"]["targetUser"]
    night = {
        "id": "night",
        "title": "n",
        "severity": "medium",
        "source": "events",
        "where": {"eventId": 4624, "logonType|in": [2, 10]},
        "time": {"outside_business_hours": True},
        "exclude": {"targetUser|in_setting": "service_accounts"},
    }
    f = R.run_rule(store, night, settings)
    assert len(f) == 1 and f[0]["entities"]["targetUser"] == "alice"
    rdp = {
        "id": "rdp",
        "title": "r",
        "severity": "high",
        "source": "events",
        "where": {"eventId": 4624, "logonType": 10},
        "exclude": {"ipAddress|in_setting": "internal_ips"},
    }
    assert len(R.run_rule(store, rdp, settings)) == 1
    grouped = {"id": "lock", "title": "l", "severity": "low", "source": "events", "where": {"eventId": 4625}, "group_by": ["targetUser"], "threshold": ">= 3"}
    f = R.run_rule(store, grouped, settings)
    assert {x["entities"]["targetUser"] for x in f} == {"admin", "bob"}
    simple = {"id": "clear", "title": "c", "severity": "critical", "source": "events", "where": {"eventId": 1102}}
    f = R.run_rule(store, simple, settings)
    assert len(f) == 1 and f[0]["entities"]["subjectUser"] == "eve" and f[0]["refs"]
    res = R.run_rules(store, [brute, spray, {"id": "bad", "title": "b", "severity": "low", "source": "events", "where": {"x|bogus": 1}}], settings)
    assert res["byRule"]["bf"] == 1 and res["errors"][0]["ruleId"] == "bad"


def test_a_rule_whose_source_is_not_a_case_table_is_refused_and_changes_nothing(store):
    w = EventWriter(store, 1)
    for i in range(3):
        w.add(_event(i))
    w.flush()
    rows = "SELECT id, summary FROM events ORDER BY id"
    before = store.cursor().execute(rows).fetchall()
    # the source goes into the SQL text: with no field to resolve, a stacked statement there used to
    # rewrite every row
    stacked = "events; UPDATE events SET summary = 'tampered'; SELECT count(*) FROM events"
    rule = {"id": "invented-injection", "title": "t", "severity": "low", "source": stacked}
    res = R.run_rules(store, [rule, {**rule, "id": "invented-table", "source": "evidence"}], {})
    assert res["findings"] == [] and res["diagnostics"] == []
    assert res["errors"] == [
        {"ruleId": "invented-injection", "error": "source must be events or mails"},
        {"ruleId": "invented-table", "error": "source must be events or mails"},
    ]
    with pytest.raises(FilterError, match="source must be events or mails"):
        R.run_rule(store, rule, {})
    with pytest.raises(FilterError, match="source must be events or mails"):
        R.diagnose_zero(store, rule, {})
    assert store.cursor().execute(rows).fetchall() == before
    assert all(summary != "tampered" for _, summary in before)


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
        {
            "id": "excl",
            "title": "e",
            "severity": "low",
            "source": "events",
            "where": {"eventId": 4624},
            "exclude": {"targetUser|in_setting": "service_accounts"},
        },
        {
            "id": "thr",
            "title": "t",
            "severity": "low",
            "source": "events",
            "where": {"eventId": 4625},
            "group_by": ["ipAddress"],
            "window": "5m",
            "threshold": ">= 10",
        },
        {"id": "time", "title": "ti", "severity": "low", "source": "events", "where": {"eventId": 4625}, "time": {"hours": [5, 5]}},
        {"id": "ok", "title": "o", "severity": "low", "source": "events", "where": {"eventId": 4625}},
    ]
    res = R.run_rules(store, rules, settings)
    d = {x["ruleId"]: x for x in res["diagnostics"]}
    # an event id the evidence does not contain is reported as not applicable before the rule runs
    assert d["absent"]["reason"] == "not_applicable" and "1102" in (d["absent"]["detail"] or "")
    assert d["vip"]["reason"] == "missing_setting" and "vip_names" in d["vip"]["detail"]
    assert d["req"]["reason"] == "missing_setting" and "internal_ips" in d["req"]["detail"]
    assert d["excl"]["reason"] == "all_excluded" and d["excl"]["matched"] == 1
    assert d["thr"]["reason"] == "below_threshold" and d["thr"]["matched"] == 3
    assert d["time"]["reason"] == "outside_time_window"
    assert "ok" not in d and res["byRule"]["ok"] == 3


def test_rules_past_the_finding_cap_keep_the_rarest_groups_and_say_so(store, monkeypatch):
    monkeypatch.setattr(R, "MAX_FINDINGS", 3)
    w = EventWriter(store, 1)
    n = 0
    # five accounts failing 1, 2, 3, 4 and 5 times
    for k, user in enumerate(("u1", "u2", "u3", "u4", "u5"), 1):
        for _ in range(k):
            w.add(_event(n, eventId=4625, targetUser=user))
            n += 1
    w.flush()
    settings = {"internal_ips": [], "service_accounts": []}
    rare = {"id": "rare", "title": "r", "severity": "low", "source": "events", "where": {"eventId": 4625}, "group_by": ["targetUser"]}
    burst = {**rare, "id": "burst", "threshold": ">= 2"}
    res = R.run_rules(store, [rare, burst], settings)
    got = {rid: {f["entities"]["targetUser"] for f in res["findings"] if f["ruleId"] == rid} for rid in ("rare", "burst")}
    # a hunt keeps the accounts seen least, a threshold rule the ones seen most
    assert got["rare"] == {"u1", "u2", "u3"}
    assert got["burst"] == {"u3", "u4", "u5"}
    cut = {d["ruleId"]: d for d in res["diagnostics"] if d["reason"] == "truncated"}
    assert "rarest" in cut["rare"]["detail"] and "largest" in cut["burst"]["detail"]
    # five groups for the hunt, four reach the threshold: the cut says how many were left out
    assert cut["rare"]["dropped"] == 2 and cut["burst"]["dropped"] == 1
    assert cut["rare"]["detail"] == "2 of 5 findings left out past the cap of 3; kept the 3 rarest groups"


def test_a_rule_keeps_its_own_max_findings_and_the_default_cap_on_the_server(store):
    w = EventWriter(store, 1)
    # 2,001 accounts failing once, and three hosts with a burst of three failures each
    for i in range(2001):
        w.add(_event(i, eventId=4625, targetUser=f"user{i:04d}"))
    for h, host in enumerate(("ws03", "ws01", "ws02")):
        for k in range(3):
            w.add(_event(5000 + h * 600 + k, eventId=4771, computer=host))
    w.flush()
    settings = {"internal_ips": [], "service_accounts": []}
    hunt = {"id": "hunt", "title": "h", "severity": "low", "source": "events", "where": {"eventId": 4625}, "group_by": ["targetUser"]}
    few = {**hunt, "id": "few", "max_findings": 5}
    burst = {
        "id": "burst",
        "title": "b",
        "severity": "low",
        "source": "events",
        "where": {"eventId": 4771},
        "group_by": ["computer"],
        "window": "1m",
        "threshold": ">= 2",
    }
    bursts = [{**burst, "id": f"bursts-{n}", "max_findings": n} for n in (2, 3)]
    res = R.run_rules(store, [hunt, few, *bursts], settings)
    cut = {d["ruleId"]: d for d in res["diagnostics"] if d["reason"] == "truncated"}
    assert res["byRule"]["hunt"] == 2000 and cut["hunt"]["dropped"] == 1
    assert res["byRule"]["few"] == 5 and cut["few"]["dropped"] == 1996
    # bursts past the cap are counted to the end, and the bursts kept are whole, in the order of the hosts
    kept = [f for f in res["findings"] if f["ruleId"] == "bursts-2"]
    assert [(f["entities"]["computer"], f["count"]) for f in kept] == [("ws01", 3), ("ws02", 3)]
    assert cut["bursts-2"]["dropped"] == 1
    assert cut["bursts-2"]["detail"] == "1 of 3 findings left out past the cap of 2; kept the first 2 bursts in the order of the grouped fields"
    # exactly as many bursts as the cap: nothing was left out, so nothing is said to be
    assert res["byRule"]["bursts-3"] == 3 and "bursts-3" not in cut


def test_a_rule_reads_the_first_characters_of_a_long_value_with_its_regex_and_says_how_many_rows_held_one(store):
    from services.store.sqlfilter import RE_VALUE_MAX

    pad = "a" * RE_VALUE_MAX
    w = EventWriter(store, 1)
    w.add(_event(1, eventId=4688, computer="WS01", commandLine="x evil"))
    w.add(_event(2, eventId=4688, computer="WS02", commandLine=pad + " evil"))
    w.add(_event(3, eventId=4688, computer="WS03", commandLine="evil " + pad))
    # as many characters as are read, one of them four bytes long: read whole
    w.add(_event(4, eventId=4688, computer="WS04", commandLine="a" * (RE_VALUE_MAX - 6) + "\U0001d400 evil"))
    w.flush()
    ids = {r["computer"]: r["id"] for r in Q.search(store, "events", None, full=True)["rows"]}

    def run(rule):
        res = R.run_rules(store, [{"id": "long", "title": "l", "severity": "low", "source": "events", **rule}], {})
        assert not res["errors"], res["errors"]
        return sorted(int(f["refs"][0]) for f in res["findings"]), [d for d in res["diagnostics"] if d["reason"] == "values_cut"]

    found, cuts = run({"where": {"eventId": 4688, "commandLine|re": r"\bevil$|^evil\b"}})
    assert found == [ids["WS01"], ids["WS03"], ids["WS04"]]
    max_ = f"{RE_VALUE_MAX:,}"
    assert [(d["longValues"], d["detail"]) for d in cuts] == [
        (
            2,
            f"2 row(s) held a value longer than {max_} characters in a field its regular expressions read: they read its first {max_} characters, and a match past them is not found",
        )
    ]
    # not_re passes the row whose match lies past what it reads
    assert run({"where": {"eventId": 4688, "commandLine|not_re": "evil"}})[0] == [ids["WS02"]]
    assert run({"where": {"eventId": 4688, "commandLine|re_cs": "evil$"}})[0] == [ids["WS01"], ids["WS04"]]
    # a nested condition and an exclusion read the same; a rule without a regular expression says nothing
    nested = run({"where": {"eventId": 4688, "any_of": [{"commandLine|re": "nothing"}, {"computer": "WS01"}]}, "exclude": {"parentCommandLine|re": "x"}})
    assert nested[0] == [ids["WS01"]] and [d["longValues"] for d in nested[1]] == [2]
    assert run({"where": {"eventId": 4688, "commandLine|contains": "evil"}}) == ([ids["WS01"], ids["WS02"], ids["WS03"], ids["WS04"]], [])
    # collapsed past its row count, the rule reads the same rows and says so once
    collapsed = run({"where": {"eventId": 4688, "commandLine|re": "evil"}, "entities": ["computer"], "collapse_after": 1})
    assert len(collapsed[0]) == 3 and [d["longValues"] for d in collapsed[1]] == [2]
    # an analyst's search reads the whole value
    assert Q.count(store, "events", {"conditions": [{"field": "commandLine", "op": "re", "value": "a evil$"}]}) == 1


def test_a_long_value_under_data_is_counted_as_one_in_a_column(store):
    from services.store.sqlfilter import RE_VALUE_MAX

    w = EventWriter(store, 1)
    w.add(_event(1, eventId=4104, data={"ScriptBlockText": "a" * RE_VALUE_MAX + " evil"}))
    w.add(_event(2, eventId=4104, data={"ScriptBlockText": "evil"}))
    w.flush()
    rule = {"id": "long", "title": "l", "severity": "low", "source": "events", "where": {"eventId": 4104, "data.ScriptBlockText|re": "evil$"}}
    res = R.run_rules(store, [rule], {})
    assert len(res["findings"]) == 1
    assert [d["longValues"] for d in res["diagnostics"] if d["reason"] == "values_cut"] == [1]


def test_a_rule_counts_a_long_value_in_a_mail_list_or_body_once_per_mail(store):
    from services.store.sqlfilter import RE_VALUE_MAX

    pad = "a" * RE_VALUE_MAX
    w = MailWriter(store, 2)
    w.add({"subject": "one", "date": T0, "to": [{"addr": "a@example.com"}, {"addr": pad + "@example.com"}], "bodyText": pad + " wire transfer"})
    w.add({"subject": "two", "date": T0, "to": [{"addr": "b@example.com"}], "bodyText": "wire transfer " + pad})
    w.flush()

    def run(where):
        res = R.run_rules(store, [{"id": "long", "title": "l", "severity": "low", "source": "mails", "where": where}], {})
        assert not res["errors"], res["errors"]
        return len(res["findings"]), [d["longValues"] for d in res["diagnostics"] if d["reason"] == "values_cut"]

    assert run({"toList|re": "example"}) == (2, [1])
    assert run({"bodyText|re": "wire transfer"}) == (1, [2])
    assert run({"subject|re": "one|two"}) == (2, [])


def test_then_is_checked_for_every_finding(store):
    w = EventWriter(store, 1)
    # 600 accounts each fail once then log on: the follow-up must reach the last of them too
    for i in range(600):
        w.add(_event(i * 10, eventId=4625, targetUser=f"user{i}"))
        w.add(_event(i * 10 + 1, eventId=4624, targetUser=f"user{i}"))
    w.flush()
    rule = {
        "id": "fail-then-ok",
        "title": "f",
        "severity": "low",
        "source": "events",
        "where": {"eventId": 4625},
        "group_by": ["targetUser"],
        "then": {"where": {"eventId": 4624}, "join": ["targetUser"], "within": "5m", "severity": "high", "title": "logged on"},
    }
    f = R.run_rule(store, rule, {"internal_ips": [], "service_accounts": []})
    assert len(f) == 600 and all(x["severity"] == "high" for x in f)


def test_a_rule_asking_for_what_no_engine_does_is_refused_rather_than_run_without_it(store):
    w = EventWriter(store, 1)
    w.add(_event(0, eventId=4625, targetUser="bob"))
    w.add(_event(1, eventId=4624, targetUser="bob"))
    w.flush()
    base = {"title": "t", "severity": "low", "source": "events", "where": {"eventId": 4625}}
    follow = {"where": {"eventId": 4624}, "join": ["targetUser"], "within": "5m", "severity": "high"}
    rules = [
        # one finding per row: a follow-up, a window, a distinct count or a group condition has nothing to act on
        {**base, "id": "row-then", "then": follow},
        {**base, "id": "row-window", "window": "5m"},
        {**base, "id": "row-distinct", "distinct": "ipAddress"},
        {**base, "id": "row-any-in-group", "any_in_group": {"eventId": 4624}},
        {**base, "id": "then-no-where", "group_by": ["targetUser"], "then": {"severity": "high"}},
        # events carry no flags to escalate on
        {**base, "id": "events-flags", "then_flags": [{"reply_to_mismatch": "high"}]},
        {**base, "id": "fine", "group_by": ["targetUser"], "then": follow},
    ]
    res = R.run_rules(store, rules, {"internal_ips": [], "service_accounts": []})
    refused = {e["ruleId"]: e["error"] for e in res["errors"]}
    assert set(refused) == {"row-then", "row-window", "row-distinct", "row-any-in-group", "then-no-where", "events-flags"}
    assert "group_by or threshold" in refused["row-then"] and "then" in refused["row-then"]
    assert "where" in refused["then-no-where"]
    assert "mail" in refused["events-flags"]
    assert {f["ruleId"] for f in res["findings"]} == {"fine"}
    assert R.rule_problem(rules[-1]) is None


def _sql_store(store):
    w = EventWriter(store, 1)
    for i, (line, service) in enumerate(
        [
            ("powershell Set-MpPreference -DisableRealtimeMonitoring $true", None),
            ("powershell Import-Module .\\invented.psm1; copy a.txt b.txt", None),
            ("sc create invented", "install"),
        ]
    ):
        w.add(_event(i, commandLine=line, serviceName=service, summary="update" if i == 0 else f"event {i}"))
    w.flush()


@pytest.mark.parametrize(
    "sql, rows",
    [
        # words a keyword list refused, inside literals and names
        ("""SELECT count(*) AS n FROM events WHERE "commandLine" ILIKE '%Set-MpPreference%'""", [{"n": 1}]),
        ("SELECT count(*) AS n FROM events WHERE summary = 'update'", [{"n": 1}]),
        ('SELECT 1 AS "load"', [{"load": 1}]),
        ("""SELECT count(*) AS n FROM events WHERE "commandLine" ILIKE '%Import-Module%' AND "commandLine" ILIKE '%copy %'""", [{"n": 1}]),
        ("""SELECT count(*) AS n FROM events WHERE "serviceName" = 'install'""", [{"n": 1}]),
        # a semicolon inside a literal is not a second statement
        ("""SELECT count(*) AS n FROM events WHERE "commandLine" LIKE '%;%'""", [{"n": 1}]),
        ("WITH t AS (SELECT computer FROM events) SELECT count(*) AS n FROM t", [{"n": 3}]),
        ("FROM events SELECT count(*) AS n;", [{"n": 3}]),
        ("SELECT count(*) AS n FROM main.events -- a closing comment", [{"n": 3}]),
        ("SELECT sum(range) AS n FROM range(4)", [{"n": 6}]),
    ],
)
def test_the_sql_view_answers_a_select_whose_text_holds_a_statement_word(store, sql, rows):
    _sql_store(store)
    assert Q.run_sql(store, sql)["rows"] == rows


def test_the_sql_view_still_describes_and_lists_the_tables(store):
    _sql_store(store)
    assert "commandLine" in {r["column_name"] for r in Q.run_sql(store, "DESCRIBE events", limit=500)["rows"]}
    assert {"events", "mails"} <= {r["name"] for r in Q.run_sql(store, "SHOW TABLES")["rows"]}


@pytest.mark.parametrize(
    "sql",
    [
        # file-reading functions a keyword list let through, and a file path used as a table
        "SELECT * FROM read_csv_auto('{path}')",
        "SELECT * FROM read_json_auto('{path}')",
        "SELECT * FROM read_ndjson_auto('{path}')",
        "SELECT * FROM read_json_objects('{path}')",
        "SELECT * FROM parquet_scan('{path}')",
        "SELECT * FROM sniff_csv('{path}')",
        "SELECT * FROM '{path}'",
        "DESCRIBE '{path}'",
        "SELECT count(*) FROM events WHERE id IN (SELECT 1 FROM read_text('{path}'))",
        # a statement held in a string
        "SELECT * FROM query('SELECT * FROM read_text(''{path}'')')",
        # anything but one SELECT
        "DELETE FROM events",
        "UPDATE events SET summary = 'tampered'",
        "COPY events TO '{path}'",
        "ATTACH '{path}' AS other",
        "SET enable_external_access = true",
        "INSTALL httpfs",
        "PRAGMA table_info('events')",
        "CREATE TABLE invented AS SELECT * FROM events",
        "SELECT 1; SELECT 2",
        "SELECT 1; DROP TABLE events",
    ],
)
def test_the_sql_view_refuses_all_but_one_select_on_the_case_tables(store, tmp_path, sql):
    _sql_store(store)
    path = tmp_path / "invented.csv"
    path.write_text("a,b\n1,2\n", encoding="utf-8")
    with pytest.raises(FilterError):
        Q.run_sql(store, sql.format(path=path))
    assert Q.run_sql(store, "SELECT count(*) AS n FROM events WHERE summary <> 'tampered'")["rows"] == [{"n": 3}]


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
        r = c.generic("PUT", f"/api/upload/{upload_id}/chunk?offset={off}", data[off : off + chunk], content_type="application/octet-stream", **HDR)
        assert r.status_code == 200, r.content
    r = c.post(f"/api/upload/{upload_id}/complete", **HDR)
    assert r.status_code == 200
    sha = r.json()["sha256"]
    r = c.post(
        f"/api/store/{key}/ingest",
        data=json.dumps(
            {"uploadId": upload_id, "kind": "evtx", "evidence": {"id": 7, "name": "System.evtx", "sha256Client": sha}, "options": {"includeRaw": False}}
        ),
        content_type="application/json",
        **HDR,
    )
    assert r.status_code == 200
    job_id = r.json()["jobId"]
    for _ in range(600):
        j = c.get(f"/api/jobs/{job_id}?case={key}", **HDR).json()
        if j["status"] in ("done", "error", "cancelled"):
            break
        time.sleep(0.1)
    assert j["status"] == "done", j
    assert j["result"]["count"] > 1000 and j["result"]["integrity"] == "verified"
    r = c.post(
        f"/api/store/{key}/search", data=json.dumps({"source": "events", "filter": {"text": "service"}, "limit": 5}), content_type="application/json", **HDR
    )
    assert r.status_code == 200 and len(r.json()["rows"]) == 5
    r = c.get(f"/api/store/{key}/facets?source=events&field=eventId&limit=3", **HDR)
    assert r.status_code == 200 and len(r.json()) == 3
    r = c.get(f"/api/store/{key}", **HDR)
    assert r.json()["counts"]["events"] == j["result"]["count"] and r.json()["evidence"][0]["id"] == 7
    r = c.post(
        f"/api/store/{key}/rules/run",
        data=json.dumps({"rules": [{"id": "svc", "title": "s", "severity": "info", "source": "events", "where": {"eventId": 7045}}], "settings": {}}),
        content_type="application/json",
        **HDR,
    )
    job_id = r.json()["jobId"]
    for _ in range(300):
        j = c.get(f"/api/jobs/{job_id}?case={key}", **HDR).json()
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
    deleted = r.json()["deleted"]
    assert deleted["events"] == 10 and "mail_bodies" in deleted and deleted["bytes"] > 0  # the import path creates no evidence row
    r = c.post(
        f"/api/store/{key}/sql", data=json.dumps({"sql": 'SELECT count(*) AS n FROM events WHERE "evidenceId" = 8'}), content_type="application/json", **HDR
    )
    assert r.json()["rows"][0]["n"] == 0
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
        '"Marie Lefevre" <noreply@email.teams.microsoft.com>',
        "j.dupont@interne.fr",
        "Marie Lefevre mentioned you",
        "Open Teams to reply.",
        extra_headers=[
            ("Authentication-Results", "mx.interne.fr; spf=pass smtp.mailfrom=email.teams.microsoft.com; dkim=pass header.d=microsoft.com; dmarc=pass")
        ],
        date="Tue, 01 Sep 2026 10:00:00 +0000",
    )
    legacy_saas = make_samples.mail(  # no auth headers: unflagged at ingest, like a pre-feature ingest
        '"Marie Lefevre" <mentions@old-tool.example-saas.com>',
        "j.dupont@interne.fr",
        "Marie commented",
        "See the comment.",
        date="Tue, 01 Sep 2026 10:01:00 +0000",
    )
    spoof = make_samples.mail(
        '"Marie Lefevre" <marie.lefevre@interne-fr.co>', "j.dupont@interne.fr", "Urgent request", "Please call me.", date="Tue, 01 Sep 2026 10:02:00 +0000"
    )
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
        assert all(isinstance(row.get("id"), int) for row in lines)

        # rebuild into a fresh store with the same writers /import uses
        dst = reg.get(str(uuid.uuid4()))
        ew2 = EventWriter(dst, 1, preserve_ids=True)
        mw2 = MailWriter(dst, 2, preserve_ids=True)
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
        make_samples.mail('"Jean Dupont" <jean.dupont@interne.fr>', "j.martin@interne.fr", "Budget", "See attached.", date="Tue, 01 Sep 2026 10:00:00 +0000"),
        make_samples.mail('"Jean Dupont" <jean.dupont@gmail.com>', "j.martin@interne.fr", "Urgent", "Call me.", date="Tue, 01 Sep 2026 10:05:00 +0000"),
        make_samples.mail(
            '"Jean Dupont" <noreply@email.teams.microsoft.com>',
            "j.martin@interne.fr",
            "Jean mentioned you",
            "Open Teams.",
            extra_headers=[
                ("Authentication-Results", "mx.interne.fr; spf=pass smtp.mailfrom=email.teams.microsoft.com; dkim=pass header.d=microsoft.com; dmarc=pass")
            ],
            date="Tue, 01 Sep 2026 10:10:00 +0000",
        ),
    ]
    w = MailWriter(store, 3)
    for raw in mails:
        w.add(parse_message_bytes(raw, ctx))
    w.flush()
    hits = R.run_rule(store, rule, {"internal_domains": ["interne.fr"], "vip_names": [], "trusted_senders": []})
    assert len(hits) == 1 and hits[0]["count"] == 2  # interne.fr + gmail.com; the Teams relay is excluded
    regs = hits[0]["entities"].get("fromRegistrable", "")
    assert "gmail.com" in regs and "microsoft.com" not in regs
