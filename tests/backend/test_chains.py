"""Cross-source attack chains: mail -> host events -> M365 audit, linked by identity and artifacts."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import make_m365
import pytest
from django.test import Client

from services.analysis import chains as C
from services.parsers import m365
from services.parsers.mail.common import ParseContext, build_row
from services.store.casestore import StoreRegistry
from services.store.writers import EventWriter, MailWriter

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
T0 = datetime(2026, 9, 1, 9, 0, tzinfo=UTC)
VICTIM = make_m365.VICTIM
PHISHER = "billing@evil-login.net"


def ms(minutes: float, day: int = 0) -> int:
    return int((T0 + timedelta(days=day, minutes=minutes)).timestamp() * 1000)


def _mail(mid: int, minutes: float, subject: str, frm: str, to: list[str], risk: int, urls=(), atts=(), message_id=None, in_reply_to=None):
    return {
        "id": mid,
        "date": ms(minutes),
        "subject": subject,
        "fromAddr": frm,
        "fromRegistrable": frm.split("@")[1],
        "to": [{"name": "", "addr": a, "domain": a.split("@")[1]} for a in to],
        "cc": [],
        "bcc": [],
        "replyTo": [],
        "risk": risk,
        "flags": ["url_login_link"],
        "urls": [{"url": f"https://{d}/login", "host": d, "domain": d, "flags": []} for d in urls],
        "attachments": [{"name": n, "ext": n.rsplit(".", 1)[-1]} for n in atts],
        "messageId": message_id,
        "inReplyTo": in_reply_to,
    }


def _ev(eid: int, minutes: float, **kw):
    row = {
        "ts": ms(minutes, kw.pop("day", 0)),
        "eventId": eid,
        "channel": kw.pop("channel", "Security"),
        "provider": kw.pop("provider", "Microsoft-Windows-Security-Auditing"),
        "computer": kw.pop("computer", "PC1"),
        "data": {},
    }
    row.update(kw)
    return row


def scenario():
    """Seed phish to alice, her reply, host artifacts, then the make_m365 BEC records; plus noise."""
    mails = [
        _mail(
            1, 5, "Invoice overdue - action required", PHISHER, [VICTIM], 85, urls=["evil-login.net"], atts=["invoice.zip"], message_id="<p1@evil-login.net>"
        ),
        _mail(2, 12, "RE: Invoice overdue - action required", VICTIM, [PHISHER], 5, message_id="<r1@contoso.com>", in_reply_to="<p1@evil-login.net>"),
        _mail(3, 25, "Second reminder", PHISHER, [VICTIM], 70, urls=["evil-login.net"]),  # related seed, merged
        _mail(4, 5, "Team lunch", "carol@contoso.com", ["bob@contoso.com"], 3),  # not a seed
    ]
    sysmon = "Microsoft-Windows-Sysmon/Operational"
    host = [
        _ev(4624, 7, targetUser="alice", targetDomain="CONTOSO", logonType=2, logonTypeName="Interactive", ipAddress="10.0.0.5"),
        _ev(
            22,
            8,
            channel=sysmon,
            provider="Microsoft-Windows-Sysmon",
            user="CONTOSO\\alice",
            subjectUser="alice",
            query="evil-login.net",
            image=r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
        ),
        _ev(
            1,
            9,
            channel=sysmon,
            provider="Microsoft-Windows-Sysmon",
            user="CONTOSO\\alice",
            subjectUser="alice",
            image=r"C:\Windows\System32\cmd.exe",
            parentImage=r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
            commandLine=r'cmd /c "C:\Users\alice\Downloads\invoice.zip\run.bat"',
        ),
        _ev(
            1,
            9.5,
            channel=sysmon,
            provider="Microsoft-Windows-Sysmon",
            user="CONTOSO\\alice",
            subjectUser="alice",
            image=r"C:\Windows\notepad.exe",
            parentImage=r"C:\Windows\explorer.exe",
            commandLine="notepad",
        ),
        _ev(4624, 10, targetUser="bob", targetDomain="CONTOSO", logonType=2, logonTypeName="Interactive", ipAddress="10.0.0.6"),  # other identity
        _ev(4624, 60, day=5, targetUser="alice", targetDomain="CONTOSO", logonType=2, logonTypeName="Interactive", ipAddress="10.0.0.5"),  # outside window
    ]
    m365_rows = [m365.ual_row(r) for r in make_m365.ual_records()] + [m365.entra_row(s) for s in make_m365.entra_signins()]
    events = host + m365_rows
    for i, e in enumerate(events, 1):
        e["id"] = i
    inbox = next(e for e in events if e.get("operation") == "New-InboxRule")
    findings = [
        {"ruleId": "mail-credential-phishing", "title": "Credential phishing", "severity": "critical", "source": "mails", "refs": [1], "ts": ms(5)},
        {
            "ruleId": "m365-inbox-rule-forwarding",
            "title": "Inbox rule forwards or redirects mail",
            "severity": "high",
            "source": "events",
            "refs": [inbox["id"]],
            "ts": inbox["ts"],
        },
    ]
    return mails, events, findings


def test_chain_links_mail_host_and_m365_by_identity_and_artifacts():
    mails, events, findings = scenario()
    res = C.build_chains(mails, events, findings, {"expected_countries": ["FR"], "internal_domains": ["contoso.com"]})
    assert res["stats"]["seeds"] == 2 and len(res["chains"]) == 1, res["stats"]
    c = res["chains"][0]
    assert c["identity"] == "alice" and c["identityLabel"] == VICTIM and c["severity"] == "critical" and c["score"] >= 80
    assert c["seed"]["id"] == 1 and c["seed"]["findings"][0]["ruleId"] == "mail-credential-phishing"
    assert [s["seed"]["id"] if isinstance(s, dict) and "seed" in s else s["id"] for s in c["relatedSeeds"]] == [3]
    steps = c["steps"]
    assert steps == sorted(steps, key=lambda s: s["ts"])
    titles = [s["title"] for s in steps]
    # host artifacts: DNS query for the mail domain and a process naming the attachment under Outlook
    dns = next(s for s in steps if s["title"].startswith("DNS query"))
    assert "mail URL domain evil-login.net" in dns["artifacts"]
    proc = next(s for s in steps if s["title"].startswith("process cmd.exe"))
    assert any(a.startswith("mail attachment invoice.zip") for a in proc["artifacts"]) and any("child of a mail client" in a for a in proc["artifacts"])
    # the victim's reply, in thread
    reply = next(s for s in steps if s["kind"] == "mail")
    assert "same thread" in reply["artifacts"] and reply["id"] == 2
    # bursts collapse, findings attach
    mia = next(s for s in steps if s["title"].startswith("mailbox items accessed"))
    assert mia["count"] == 30 and "×30" in mia["title"] and len(mia["refs"]) == 30
    rule = next(s for s in steps if "inbox rule created" in s["title"])
    assert "forward to attacker@proton-mail.example" in rule["title"] and rule["findings"][0]["ruleId"] == "m365-inbox-rule-forwarding"
    assert any("sign-in from RU" in t and "legacy authentication" in " ".join(s["artifacts"]) for t, s in zip(titles, steps))
    assert any("role assigned: Global Administrator" in t for t in titles)
    # noise excluded: bob's own logon (bob still appears as the *target* of alice's role assignment), and alice five days later
    bob_ids = {e["id"] for e in events if e.get("targetUser") == "bob"}
    assert not any(bob_ids & set(s.get("refs") or [s.get("id")]) for s in steps)
    assert all(s["ts"] <= ms(5) + 72 * 3600_000 for s in steps)
    assert (
        make_m365.RU_IP in c["entities"]["ips"]
        and "attacker@proton-mail.example" in c["entities"]["attackerAddresses"]
        and PHISHER in c["entities"]["attackerAddresses"]
    )
    assert "inbox rule" in c["summary"] and c["artifactLinks"] >= 2


def test_identity_normalisation():
    assert C.identity_key("Alice@Contoso.com") == "alice"
    assert C.identity_key("CONTOSO\\alice") == "alice"
    assert C.identity_key("PC1$") is None and C.identity_key("SYSTEM") is None and C.identity_key("-") is None
    assert C.identity_key("DWM-1") is None and C.identity_key("S-1-5-18") is None


def test_no_chain_without_steps_or_below_score():
    mails, events, findings = scenario()
    only_noise = [e for e in events if e.get("targetUser") == "bob"]
    no_reply = [m for m in mails if m["id"] != 2]
    res = C.build_chains(no_reply, only_noise, findings, {})
    assert res["chains"] == []
    # the victim replying to the phisher is a chain on its own
    res2 = C.build_chains(mails, only_noise, findings, {})
    assert len(res2["chains"]) == 1 and res2["chains"][0]["steps"][0]["kind"] == "mail"


@pytest.fixture
def store(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    st = reg.get(str(uuid.uuid4()))
    yield st
    reg.close_all()


def test_chains_for_store_selects_identities_via_sql(store):
    ctx = ParseContext(internal_domains=["contoso.com"])
    mw = MailWriter(store, 1)
    seed = build_row(
        [
            ("From", f"Billing <{PHISHER}>"),
            ("To", f"<{VICTIM}>"),
            ("Subject", "Invoice overdue"),
            ("Date", "Tue, 1 Sep 2026 09:05:00 +0000"),
            ("Message-ID", "<p1@evil-login.net>"),
        ],
        None,
        '<html><body><a href="https://evil-login.net/login">pay now</a></body></html>',
        [],
        ctx,
        folder="Inbox",
        size=None,
        extra={},
    )
    mw.add(seed)
    mw.add(
        build_row(
            [
                ("From", f"Alice <{VICTIM}>"),
                ("To", f"<{PHISHER}>"),
                ("Subject", "RE: Invoice overdue"),
                ("Date", "Tue, 1 Sep 2026 09:12:00 +0000"),
                ("Message-ID", "<r1@contoso.com>"),
                ("In-Reply-To", "<p1@evil-login.net>"),
            ],
            "ok, paying",
            None,
            [],
            ctx,
            folder="Sent Items",
            size=None,
            extra={},
        )
    )
    mw.flush()
    ew = EventWriter(store, 2)
    _, events, _ = scenario()
    for e in events:
        e.pop("id", None)
        ew.add(e)
    ew.flush()
    findings = [{"ruleId": "mail-credential-phishing", "title": "Credential phishing", "severity": "critical", "source": "mails", "refs": [1], "ts": ms(5)}]
    res = C.chains_for_store(store, {"expected_countries": ["FR"]}, findings, seed_min_risk=45)
    assert len(res["chains"]) == 1
    c = res["chains"][0]
    assert c["identity"] == "alice" and res["stats"]["events"] > 30
    assert any(s["kind"] == "mail" and "same thread" in s["artifacts"] for s in c["steps"])
    assert any("DNS query evil-login.net" in s["title"] and s["artifacts"] for s in c["steps"])
    assert any("role assigned" in s["title"] for s in c["steps"])


def test_build_endpoint_accepts_posted_rows():
    mails, events, findings = scenario()
    c = Client()
    r = c.post(
        "/api/chains/build",
        json.dumps({"mails": mails, "events": events, "findings": findings, "settings": {"expected_countries": ["FR"]}, "windowHours": 72}),
        content_type="application/json",
        **HDR,
    )
    assert r.status_code == 200, r.content
    body = r.json()
    assert len(body["chains"]) == 1 and body["chains"][0]["identity"] == "alice" and body["stats"]["chains"] == 1
    r2 = c.post("/api/chains/build", json.dumps({"storeKey": "00000000-0000-0000-0000-000000000000"}), content_type="application/json", **HDR)
    assert r2.status_code == 404


def test_routine_activity_and_own_domain_links_do_not_make_a_chain():
    """A supplier invoice at risk 13 with a medium (approximate) finding, linking to the intranet portal,
    followed by two days of logons, DNS and sign-ins of the recipient: context, not an attack chain."""
    t0 = ms(0)
    seed = {
        "id": 1,
        "date": t0,
        "subject": "Supplier invoice NS-0000018",
        "fromAddr": "reports@vendor.example",
        "fromRegistrable": "vendor.example",
        "to": [{"addr": "employee019@northstar.example"}],
        "risk": 13,
        "attachments": [],
        "urls": [{"url": "https://portal.northstar.example/x", "host": "portal.northstar.example", "domain": "northstar.example"}],
    }
    findings = [{"ruleId": "sublime-mixed-case", "title": "Link: Mixed case HTTPS protocol", "severity": "medium", "source": "mails", "refs": [1]}]
    events = []
    for i in range(14):
        ts = t0 + (i + 1) * 3_600_000
        if i % 3 == 2:
            events.append(
                {
                    "id": 100 + i,
                    "ts": ts,
                    "eventId": 22,
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "provider": "Microsoft-Windows-Sysmon",
                    "computer": "WS-019",
                    "user": "NORTHSTAR\\employee019",
                    "subjectUser": "employee019",
                    "query": "portal.northstar.example",
                    "image": "C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE",
                }
            )
        elif i % 3 == 1:
            events.append(
                {
                    "id": 100 + i,
                    "ts": ts,
                    "provider": "Microsoft 365 Unified Audit Log",
                    "category": "M365 Entra",
                    "operation": "UserLoggedIn",
                    "subjectUser": "employee019@northstar.example",
                    "upn": "employee019@northstar.example",
                    "ipAddress": "82.64.10.3",
                    "status": "Succeeded",
                    "data": {"UserId": "employee019@northstar.example"},
                }
            )
        else:
            events.append(
                {
                    "id": 100 + i,
                    "ts": ts,
                    "eventId": 4624,
                    "channel": "Security",
                    "provider": "Microsoft-Windows-Security-Auditing",
                    "computer": "WS-019",
                    "targetUser": "employee019",
                    "targetDomain": "NORTHSTAR",
                    "ipAddress": "10.20.6.208",
                    "logonType": 3,
                    "logonTypeName": "Network",
                }
            )
    settings = {"internal_domains": ["northstar.example"], "expected_countries": ["FR"]}
    art = C.seed_artifacts(seed, settings)
    assert art["domains"] == set() and art["hosts"] == set()
    res = C.build_chains([seed], events, findings, settings)
    assert res["stats"]["seeds"] == 1 and res["chains"] == [], res["chains"][:1]
    # an external lure link changes nothing while no event names it: still no chain
    lure = dict(seed, urls=[{"url": "https://login-northstar.evil-login.net/x", "host": "login-northstar.evil-login.net", "domain": "evil-login.net"}])
    assert C.build_chains([lure], events, findings, settings)["chains"] == []
    # one DNS query for the lure domain is the click: now there is a chain, tied to the mail by that link
    click = dict(events[2], id=999, query="login-northstar.evil-login.net")
    res2 = C.build_chains([lure], events + [click], findings, settings)
    assert len(res2["chains"]) == 1
    c = res2["chains"][0]
    assert c["artifactLinks"] >= 1 and any("mail URL domain evil-login.net" in a for s in c["steps"] for a in s["artifacts"])
    assert c["severity"] in ("medium", "high") and c["score"] < 80


def test_score_is_bounded_and_explained():
    """Long windows of routine activity cannot saturate the score; no artifact link means no critical."""

    def step(w, arts=(), findings=(), kind="event", origin="m365"):
        return {
            "kind": kind,
            "origin": origin,
            "weight": w,
            "artifacts": list(arts),
            "findings": [{"severity": s} for s in findings],
        }

    # 40 routine sign-ins and nothing tying them to the mail: medium at most
    steps = [step(1) for _ in range(40)]
    routine = {id(s) for s in steps}
    score, b = C.score_chain(95, steps, routine, 0, 5, 0)
    assert b["cap"] == 54 and score <= 54 and b["steps"] <= 20
    # a finding on a step but still no artifact link: high at most
    steps = [step(4, findings=("high",))] + [step(1) for _ in range(40)]
    routine = {id(s) for s in steps[1:]}
    score, b = C.score_chain(95, steps, routine, 0, 5, 4)
    assert b["cap"] == 79 and 55 <= score <= 79
    # the same with one step tied to the mail: critical, and every part is bounded
    steps = [step(4, arts=("mail URL domain evil.test",), findings=("high",)), step(4, kind="mail", origin=None, arts=("victim engaged with the sender",))] + [
        step(1) for _ in range(40)
    ]
    routine = {id(s) for s in steps[2:]}
    score, b = C.score_chain(95, steps, routine, 2, 5, 4)
    assert b["cap"] is None and score >= 80
    assert b["seed"] <= 30 and b["links"] <= 30 and b["steps"] <= 20 and b["findings"] <= 15 and b["sources"] <= 5 and b["linkSteps"] == 2
    assert C.is_link("victim engaged with the sender") and C.is_link("mail attachment x.html") and not C.is_link("unexpected country")


def test_chain_result_carries_the_breakdown():
    mails, events, findings = scenario()
    res = C.build_chains(mails, events, findings, {"expected_countries": ["FR"], "internal_domains": ["contoso.com"]})
    c = res["chains"][0]
    b = c["scoreBreakdown"]
    assert set(b) == {"seed", "links", "steps", "findings", "sources", "cap", "linkSteps"}
    assert c["score"] == min(100, b["seed"] + b["links"] + b["steps"] + b["findings"] + b["sources"])
    assert c["artifactLinks"] >= b["linkSteps"] >= 1
