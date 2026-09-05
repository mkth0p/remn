"""Sender baselining + campaign clustering: pure pass, store write-back, rules, endpoint."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from django.test import Client

from services.analysis import baseline as B
from services.parsers.mail.common import ParseContext, build_row
from services.store import rules as R
from services.store.casestore import StoreRegistry, rows_to_dicts
from services.store.writers import MailWriter

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
T0 = datetime(2026, 8, 1, 9, 0, tzinfo=timezone.utc)
RULES = Path(__file__).resolve().parents[2] / "rules" / "mail" / "baseline.yaml"


def ms(days: float) -> int:
    return int((T0 + timedelta(days=days)).timestamp() * 1000)


def _m(mid, days, frm, to, subject, spf="pass", dkim="pass", dmarc="pass", urls=(), atts=(), risk=20, flags=()):
    return {"id": mid, "date": ms(days), "fromAddr": frm, "fromRegistrable": frm.split("@")[1], "to": [{"addr": a, "domain": a.split("@")[1], "name": ""} for a in to],
            "subject": subject, "spf": spf, "dkim": dkim, "dmarc": dmarc, "flags": list(flags), "risk": risk,
            "urls": [{"domain": d, "host": d, "url": f"https://{d}/x"} for d in urls], "attachments": [{"name": n, "sha256": h} for n, h in atts]}


def scenario():
    mails = []
    # a vendor writing weekly -> common; authenticated
    for i in range(6):
        mails.append(_m(10 + i, i * 7, "news@vendor.com", ["alice@contoso.com"], f"Weekly digest #{i}"))
    # alice wrote to a partner first -> partner's later mail is solicited
    mails.append(_m(30, 3, "alice@contoso.com", ["jo@partner.org"], "Quote request", flags=["exchange_internal"]))
    mails.append(_m(31, 4, "jo@partner.org", ["alice@contoso.com"], "RE: Quote request"))
    # newcomer with lure wording, never contacted -> new + unsolicited
    mails.append(_m(40, 20, "billing@evil-login.net", ["alice@contoso.com"], "Invoice overdue", urls=["evil-login.net"], risk=70, flags=["lexicon_financial", "url_login_link"]))
    # vendor.com passed 6 times, then a spoof fails auth -> regression
    mails.append(_m(41, 45, "news@vendor.com", ["alice@contoso.com"], "Urgent: update your bank details", spf="fail", dkim="none", dmarc="fail", risk=75, flags=["spf_fail", "dmarc_fail"]))
    # campaign: same lure to three mailboxes from rotating senders
    for i, (frm, to) in enumerate([("a1@rot.example", "alice@contoso.com"), ("a2@rot.example", "bob@contoso.com"), ("a3@rot.example", "carol@contoso.com")]):
        mails.append(_m(50 + i, 30 + i * 0.01, frm, [to], f"Your package 4409{i} is waiting", urls=["track-parcel.top"], risk=60, flags=["url_suspicious_tld"]))
    return mails


def test_enrich_pure():
    e = B.enrich(scenario(), {"internal_domains": ["contoso.com"]})
    assert e[10]["senderPrevalence"] == "new" and e[12]["senderPrevalence"] == "rare" and e[15]["senderPrevalence"] == "common"
    assert e[15]["senderPriorCount"] == 5 and e[15]["senderDaysKnown"] == 35 and e[15]["senderFirstSeen"] == ms(0)
    assert e[31]["senderSolicited"] is True and e[40]["senderSolicited"] is False and e[40]["senderPrevalence"] == "new"
    assert e[41]["senderAuthRegression"] is True and e[40]["senderAuthRegression"] is False and e[10]["senderAuthRegression"] is False
    assert e[50]["campaignId"] == e[51]["campaignId"] == e[52]["campaignId"] and e[50]["campaignSize"] == 3 and e[50]["campaignSenders"] == 3
    assert "campaignId" not in e[40] and "campaignId" not in e[31]  # single lure; a thread reply is not a campaign
    # weekly digests share "weekly digest #" -> they form a (benign, single-sender) campaign
    assert e[10].get("campaignSize") == 6 and e[10].get("campaignSenders") == 1
    s = B.summarize(e)
    assert s["newSenders"] >= 6 and s["unsolicitedNew"] >= 4 and s["authRegressions"] == 1 and s["campaigns"] == 2 and s["largestCampaign"] == 6


def test_subject_skeleton_and_fingerprint():
    assert B.subject_skeleton("RE: Fwd: Invoice 2026-0912 overdue") == "invoice #-# overdue"
    assert B.fingerprint({"subject": "hi"}) is None
    assert B.fingerprint({"subject": "hi", "urls": [{"domain": "x.com"}]}) is not None


@pytest.fixture
def store(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    st = reg.get(str(uuid.uuid4()))
    yield st
    reg.close_all()


def test_store_roundtrip_and_rules(store):
    ctx = ParseContext(internal_domains=["contoso.com"])
    w = MailWriter(store, 1)
    for m in scenario():
        headers = [("From", f"<{m['fromAddr']}>"), ("To", ", ".join(f"<{t['addr']}>" for t in m["to"])), ("Subject", m["subject"]),
                   ("Date", (T0 + timedelta(milliseconds=m["date"] - ms(0))).strftime("%a, %d %b %Y %H:%M:%S +0000")),
                   ("Message-ID", f"<{m['id']}@{m['fromRegistrable']}>"),
                   ("Authentication-Results", f"spf={m['spf']} smtp.mailfrom={m['fromRegistrable']}; dkim={m['dkim']} header.d={m['fromRegistrable']}; dmarc={m['dmarc']} header.from={m['fromRegistrable']}")]
        html = "<html><body><p>" + m["subject"] + "</p>" + "".join(f'<a href="{u["url"]}">link</a>' for u in m["urls"]) + "</body></html>"
        row = build_row(headers, None, html, [], ctx, folder="Inbox", size=None, extra={})
        row["risk"] = m["risk"]
        row["flags"] = sorted(set(row["flags"]) | set(m["flags"]))
        w.add(row)
    w.flush()
    summary = B.enrich_store(store, {"internal_domains": ["contoso.com"]})
    assert summary["updated"] == len(scenario()) and summary["campaigns"] >= 1
    cur = store.cursor()
    cur.execute('SELECT "fromAddr", subject, "senderPrevalence", "senderSolicited", "senderAuthRegression", "campaignSize", "campaignSenders" FROM mails ORDER BY id')
    rows = rows_to_dicts(cur)
    by_subject = {r["subject"]: r for r in rows}
    assert by_subject["RE: Quote request"]["senderSolicited"] is True
    assert by_subject["Invoice overdue"]["senderPrevalence"] == "new" and by_subject["Invoice overdue"]["senderSolicited"] is False
    assert by_subject["Urgent: update your bank details"]["senderAuthRegression"] is True
    assert by_subject["Your package 44090 is waiting"]["campaignSize"] == 3 and by_subject["Your package 44090 is waiting"]["campaignSenders"] == 3
    # the DSL sees the new columns; the baseline rules fire
    rules = [d for d in yaml.safe_load_all(RULES.read_text(encoding="utf-8")) if isinstance(d, dict)]
    fired = {}
    for rule in rules:
        hits = R.run_rule(store, rule, {"internal_domains": ["contoso.com"]})
        if hits:
            fired[rule["id"]] = hits
    assert {"mail-first-contact-with-lure", "mail-sender-auth-regression", "mail-campaign-cluster"} <= set(fired), sorted(fired)
    camp = fired["mail-campaign-cluster"][0]
    assert camp["count"] == 3 and "rot.example" in json.dumps(camp["entities"])
    # re-opening the store keeps the columns (migration is idempotent)
    store.apply_mail_enrichment([])


def test_endpoint_with_posted_rows():
    c = Client()
    r = c.post("/api/enrich/mails", json.dumps({"mails": scenario(), "settings": {"internal_domains": ["contoso.com"]}}), content_type="application/json", **HDR)
    assert r.status_code == 200, r.content
    body = r.json()
    rows = {x["id"]: x for x in body["rows"]}
    assert rows[40]["senderPrevalence"] == "new" and rows[41]["senderAuthRegression"] is True and body["summary"]["campaigns"] == 2
    assert c.post("/api/enrich/mails", json.dumps({"storeKey": "00000000-0000-0000-0000-000000000000"}), content_type="application/json", **HDR).status_code == 404
