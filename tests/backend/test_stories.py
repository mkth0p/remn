"""Stories: one per person or host incident, read as ATT&CK phases, each step with why it belongs and how surely."""

from __future__ import annotations

from services.analysis.identity import MEDIUM, STRONG
from services.analysis.stories import build_stories, finding_phase, record_phase

SEC = {"provider": "Microsoft-Windows-Security-Auditing", "channel": "Security"}
SCM = {"provider": "Service Control Manager", "channel": "System"}
UAL = {"provider": "Microsoft 365 Unified Audit Log", "category": "M365 Exchange"}
ENTRA = {"provider": "Microsoft Entra ID Sign-in", "category": "Entra sign-in", "operation": "SignIn"}
T0 = 1_788_510_000_000
SETTINGS = {"internal_domains": ["northstar.example"]}
DANIEL = "daniel.roy@northstar.example"


def ev(n, minutes, base=SEC, **fields):
    return {"id": n, "ts": T0 + int(minutes * 60_000), **base, **fields}


def finding(rule, severity, refs, source="events", tags=(), attack=(), **entities):
    return {
        "ruleId": rule,
        "title": rule.replace("-", " "),
        "severity": severity,
        "source": source,
        "refs": list(refs),
        "tags": list(tags),
        "attack": list(attack),
        "entities": entities,
        "key": f"{rule}|{refs[0]}",
    }


def _intrusion():
    """A spray from one address, an RDP logon it wins, a group change and a log clear in that session, an admin share and a service on a server, mailbox forwarding."""
    host = "WS-004.northstar.example"
    events = [
        # the spray: daniel's account, and two others'
        *[ev(i, i * 0.1, eventId=4625, computer=host, targetUser="daniel.roy", targetDomain="NORTHSTAR", ipAddress="203.0.113.69", logonType=3) for i in range(1, 11)],
        ev(11, 1.1, eventId=4625, computer=host, targetUser="employee019", targetDomain="NORTHSTAR", ipAddress="203.0.113.69", logonType=3),
        ev(12, 1.2, eventId=4625, computer=host, targetUser="employee020", targetDomain="NORTHSTAR", ipAddress="203.0.113.69", logonType=3),
        ev(20, 10, eventId=4624, computer=host, targetUser="daniel.roy", targetDomain="NORTHSTAR", targetLogonId="0x9a01", logonType=10, ipAddress="203.0.113.69"),
        ev(21, 16, eventId=4732, computer=host, subjectUser="daniel.roy", subjectDomain="NORTHSTAR", subjectLogonId="0x9a01", memberSid="S-1-5-21-111-222-333-1042"),
        ev(22, 26, eventId=1102, computer=host, subjectUser="daniel.roy", subjectDomain="NORTHSTAR", subjectLogonId="0x9a01"),
        ev(23, 20, eventId=5140, computer="FS-001.northstar.example", subjectUser="daniel.roy", subjectDomain="NORTHSTAR", ipAddress="203.0.113.69", shareName="\\\\*\\ADMIN$"),
        # the service names no one: its tie to daniel is the admin share opened a minute before
        ev(24, 21, base=SCM, eventId=7045, computer="FS-001.northstar.example", serviceName="NSLabUpdater", serviceFile="C:\\Users\\Public\\x.exe"),
        *[ev(30 + i, 30 + i * 0.2, base=UAL, operation="MailItemsAccessed", user=DANIEL, upn=DANIEL, subjectUser=DANIEL, ipAddress="203.0.113.69") for i in range(5)],
        ev(40, 35, base=UAL, operation="Set-Mailbox", user=DANIEL, upn=DANIEL, subjectUser=DANIEL, ipAddress="203.0.113.69",
           summary=f"Set-Mailbox by {DANIEL} from 203.0.113.69 ForwardingSmtpAddress=smtp:finance@secure-documents.example"),
        # a sign-in of daniel's from his usual address, with no finding: not in the story
        ev(41, 40, base=ENTRA, user=DANIEL, upn=DANIEL, subjectUser=DANIEL, targetUser=DANIEL, ipAddress="198.51.100.10", status="0"),
    ]  # fmt: skip
    findings = [
        finding("win-bruteforce-4625-by-ip", "critical", [*range(1, 13), 20], tags=["brute-force"], attack=["T1110"], ipAddress="203.0.113.69"),
        finding("win-rdp-logon-external", "high", [20], tags=["lateral-movement"], attack=["T1021.001"], ipAddress="203.0.113.69"),
        finding("win-user-added-privileged-group", "medium", [21], tags=["persistence"], attack=["T1098"]),
        finding("win-audit-log-cleared", "critical", [22], tags=["defense-evasion", "log-tampering"], attack=["T1685.005"]),
        finding("win-admin-share-access", "medium", [23], tags=["lateral-movement"], attack=["T1021.002"], ipAddress="203.0.113.69"),
        finding("win-service-installed-suspicious", "high", [24], tags=["persistence"], attack=["T1543.003"]),
        finding("m365-mailitemsaccessed-burst", "medium", range(30, 35), tags=["collection"], attack=["T1114.002"], ipAddress="203.0.113.69"),
        finding("m365-mailbox-forwarding", "critical", [40], tags=["forwarding"], attack=["T1114.003"], ipAddress="203.0.113.69"),
    ]
    return events, findings


def test_an_intrusion_reads_as_one_story_in_phases_with_every_step_tied():
    events, findings = _intrusion()
    res = build_stories(events, [], findings, SETTINGS)
    [story] = res["stories"]
    assert story["kind"] == "person" and story["subject"]["label"] == DANIEL and story["severity"] == "critical"
    assert [p["phase"] for p in story["phases"]] == [
        "credential-access",
        "initial-access",
        "persistence",
        "lateral-movement",
        "defense-impairment",
        "collection",
    ]
    by_ref = {r: s for s in story["steps"] for r in s["refs"]}
    # the spray folds into two steps: daniel's failures, and the other accounts the same address tried
    spray = by_ref["event:1"]
    assert spray["count"] == 10 and spray["phase"] == "credential-access" and by_ref["event:11"] is by_ref["event:12"]
    assert by_ref["event:11"]["tie"]["kind"] == "address" and len(by_ref["event:11"]["accounts"]) == 2
    # the RDP logon from outside is initial access whatever the brute force before it reads as
    rdp = by_ref["event:20"]
    assert rdp["phase"] == "initial-access" and rdp["session"] and rdp["tie"]["confidence"] == STRONG
    # the log clear happened in that session: defense impairment, the technique deciding what defense-evasion means in ATT&CK v19
    clear = by_ref["event:22"]
    assert clear["phase"] == "defense-impairment" and clear["session"] == rdp["session"]
    # the admin share on the server: the same outside source was already in, so it is lateral movement
    assert by_ref["event:23"]["phase"] == "lateral-movement"
    # the service names no one; the admin share a minute before is its tie to the story
    service = by_ref["event:24"]
    assert service["phase"] == "persistence" and service["hops"] and service["tie"]["confidence"] == STRONG
    # five mailbox reads are one step
    assert by_ref["event:30"]["count"] == 5 and by_ref["event:30"]["phase"] == "collection"
    assert "event:41" not in by_ref
    assert story["attackerAddresses"] == ["203.0.113.69"] and story["hosts"] == ["fs-001", "ws-004"]
    assert story["headline"].startswith("win bruteforce 4625 by ip")
    assert any("FS-001" in g and "What ran" in g for g in story["gaps"])
    assert [h["kind"] for h in story["lineage"]["hops"]] == ["rdp", "remote-service"]
    # the same rows give the same story
    again = build_stories(events, [], findings, SETTINGS)["stories"][0]
    assert again["id"] == story["id"] and again["steps"] == story["steps"]


def test_the_address_and_what_it_left_make_a_campaign_with_the_accounts_it_tried():
    events, findings = _intrusion()
    res = build_stories(events, [], findings, SETTINGS)
    [camp] = res["campaigns"]
    assert camp["label"] == "203.0.113.69" and camp["stories"] == [res["stories"][0]["id"]]
    assert {(a["kind"], a["value"]) for a in camp["artifacts"]} >= {("ip", "203.0.113.69"), ("forwarding", "finance@secure-documents.example")}
    assert [(t["account"], t["how"]) for t in camp["targets"]] == [("northstar\\employee019", ["failed logon"]), ("northstar\\employee020", ["failed logon"])]


def test_a_mail_received_or_failed_logons_alone_start_no_story():
    mails = [{"id": 7, "date": T0, "fromAddr": "it-support@northstar-helpdesk.example", "subject": "Password expiry", "to": [{"addr": DANIEL}]}]
    events = [
        ev(i, i * 0.1, eventId=4625, computer="WS-004", targetUser="carla.morel", targetDomain="NORTHSTAR", ipAddress="203.0.113.99") for i in range(1, 11)
    ]
    findings = [
        finding("mail-credential-phishing", "high", [7], source="mails", tags=["phishing"]),
        finding("win-bruteforce-4625-by-account", "high", range(1, 11), tags=["brute-force"], ipAddress="203.0.113.99"),
    ]
    res = build_stories(events, mails, findings, SETTINGS)
    assert res["stories"] == []
    assert {u["ref"] for u in res["unstoried"]} == {"mail:7", *(f"event:{i}" for i in range(1, 11))}
    # they are still there to see: the sender's mails and the address's guesses
    assert {(c["labelKind"], c["label"]) for c in res["campaigns"]} == {("sender-domain", "northstar-helpdesk.example"), ("ip", "203.0.113.99")}


def test_a_flagged_mail_starts_a_story_only_once_its_recipient_acts_on_it():
    """A reply-to diverted to a vendor, a link to the organisation's own portal, and the recipient's
    routine day after it: a chain, but a mail received. The link to the vendor's site resolved is the click."""
    sysmon = {"provider": "Microsoft-Windows-Sysmon", "channel": "Microsoft-Windows-Sysmon/Operational"}
    mail = {
        "id": 8,
        "date": T0,
        "fromAddr": "employee027@northstar.example",
        "replyTo": [{"addr": "accounts@billing.vendor.example"}],
        "subject": "Approved purchase order NS-0000013",
        "to": [{"addr": DANIEL}],
        "risk": 28,
        "urls": [{"url": "https://northstar.example/reports/13", "host": "northstar.example", "domain": "northstar.example"}],
    }
    me = {"computer": "WS-004", "user": "NORTHSTAR\\daniel.roy", "subjectUser": "daniel.roy", "subjectDomain": "NORTHSTAR"}
    events = [
        ev(1, 30, base=sysmon, eventId=22, query="portal.northstar.example", **me),
        ev(2, 90, eventId=4648, targetServerName="FS-001", **me),
    ]
    findings = [finding("mail-replyto-diverted", "medium", [8], source="mails", tags=["spoofing", "bec"], attack=["T1566.002"])]
    res = build_stories(events, [mail], findings, {})
    [chain] = res["chains"]["chains"]
    assert chain["artifactLinks"] == 0
    assert res["stories"] == [] and "mail:8" in {u["ref"] for u in res["unstoried"]}
    # the vendor's link resolved on daniel's host: he acted on the mail, and that is a story
    lure = dict(
        mail,
        urls=[*mail["urls"], {"url": "https://docs.vendor-billing.example/inv", "host": "docs.vendor-billing.example", "domain": "vendor-billing.example"}],
    )
    clicked = [*events, ev(3, 5, base=sysmon, eventId=22, query="docs.vendor-billing.example", **me)]
    [story] = build_stories(clicked, [lure], findings, {})["stories"]
    assert story["subject"]["label"] == DANIEL and [p["phase"] for p in story["phases"]][:2] == ["initial-access", "execution"]


def test_flags_two_days_apart_are_two_incidents_and_a_namesake_elsewhere_is_its_own_story():
    events = [
        ev(1, 0, eventId=4698, computer="WS-001", subjectUser="alice.martin", subjectDomain="NORTHSTAR", taskName="\\Updater"),
        ev(2, 60 * 72, eventId=4698, computer="WS-001", subjectUser="alice.martin", subjectDomain="NORTHSTAR", taskName="\\Updater2"),
        # the other tenant's alice.martin, named beside its own UPN
        ev(3, 30, eventId=1102, computer="OTHER-WS-001.other-tenant.example", subjectUser="alice.martin@other-tenant.example", subjectDomain="OTHER"),
        ev(4, 31, eventId=4624, computer="OTHER-WS-001.other-tenant.example", subjectUser="alice.martin@other-tenant.example", subjectDomain="OTHER", targetUser="alice.martin", targetDomain="OTHER", targetLogonId="0x5", logonType=2),
    ]  # fmt: skip
    findings = [
        finding("win-scheduled-task-suspicious-content", "high", [1], tags=["persistence"]),
        finding("win-scheduled-task-suspicious-content", "high", [2], tags=["persistence"]),
        finding("win-audit-log-cleared", "critical", [3], tags=["defense-evasion"], attack=["T1685.005"]),
    ]
    res = build_stories([*events], [], findings, SETTINGS)
    labels = sorted((s["subject"]["label"], s["steps"][0]["id"]) for s in res["stories"])
    assert labels == [("alice.martin@other-tenant.example", "event:3"), ("northstar\\alice.martin", "event:1"), ("northstar\\alice.martin", "event:2")]
    home = [s for s in res["stories"] if s["subject"]["label"] == "northstar\\alice.martin"]
    assert all("event:3" not in {r for st in s["steps"] for r in st["refs"]} for s in home)
    other = next(i for i in res["identities"] if i["label"] == "alice.martin@other-tenant.example")
    assert other["org"] == "other-tenant.example"


def test_a_sign_in_from_a_joined_device_happened_on_that_host():
    events, findings = _intrusion()
    signin = dict(
        ev(50, 45, base=ENTRA, user=DANIEL, upn=DANIEL, subjectUser=DANIEL, targetUser=DANIEL, ipAddress="203.0.113.69", status="0"),
        data={"deviceName": "WS-004", "deviceId": "b1c2", "trustType": "Hybrid Azure AD joined"},
    )
    findings.append(finding("m365-signin-risky", "high", [50], tags=["initial-access"], attack=["T1078.004"], ipAddress="203.0.113.69"))
    [story] = build_stories([*events, signin], [], findings, SETTINGS)["stories"]
    [step] = [st for st in story["steps"] if "event:50" in st["refs"]]
    assert step["host"] == "ws-004" and "from the Entra device WS-004 (Hybrid Azure AD joined)" in step["notes"]


def test_a_flag_on_a_host_that_names_no_one_is_a_host_story_and_false_positives_are_left_out():
    events = [
        ev(1, 0, base=SCM, eventId=7045, computer="FS-002.northstar.example", serviceName="evil", serviceFile="C:\\x.exe"),
        ev(2, 5, eventId=4698, computer="WS-009", subjectUser="bob", subjectDomain="NORTHSTAR", taskName="\\t"),
    ]
    fp = finding("win-scheduled-task-suspicious-content", "high", [2], tags=["persistence"])
    fp["status"] = "false_positive"
    res = build_stories(events, [], [finding("win-service-installed-suspicious", "high", [1], tags=["persistence"]), fp], SETTINGS)
    [story] = res["stories"]
    assert story["kind"] == "host" and story["subject"]["id"] == "fs-002" and story["phases"][0]["phase"] == "persistence"
    assert story["steps"][0]["tie"] == {"kind": "flag", "basis": "a finding on fs-002", "confidence": STRONG}


def _refs(story):
    return {r for st in story["steps"] for r in st["refs"]}


def test_a_persons_routine_programs_neither_join_by_name_nor_push_a_later_foothold_out():
    host = "WS-001.northstar.example"
    me = dict(subjectUser="alice.martin", subjectDomain="NORTHSTAR")
    events = [
        ev(5, -5, eventId=4624, computer=host, targetUser="alice.martin", targetDomain="NORTHSTAR", targetLogonId="0x9001", logonType=2),
        ev(1, 0, eventId=4688, computer=host, newProcessId="0x10", processName="C:\\Users\\Public\\mimikatz.exe", subjectLogonId="0x9001", **me),
        # a program mimikatz started, under another logon: its process tree ties it
        ev(2, 1, eventId=4688, computer=host, newProcessId="0x20", callerProcessId="0x10", processName="C:\\Windows\\System32\\cmd.exe", subjectLogonId="0x9002", **me),
        # her own day on another host: her name alone does not put it in the story
        ev(3, 30, eventId=4688, computer="WS-002.northstar.example", newProcessId="0x30", processName="C:\\Windows\\notepad.exe", subjectLogonId="0x7001", **me),
        # a scheduled task five hours later, with no finding, after six hundred programs of the session
        ev(4, 300, eventId=4698, computer=host, taskName="\\Updater", subjectLogonId="0x9001", **me),
        *[
            ev(100 + i, 2 + i * 0.3, eventId=4688, computer=host, newProcessId=hex(0x1000 + i), processName="C:\\Windows\\System32\\conhost.exe", subjectLogonId="0x9001", **me)
            for i in range(600)
        ],
    ]  # fmt: skip
    res = build_stories(events, [], [finding("win-mimikatz", "critical", [1], tags=["credential-access"])], SETTINGS)
    [story] = res["stories"]
    by_ref = {r: s for s in story["steps"] for r in s["refs"]}
    assert "event:3" not in by_ref
    assert by_ref["event:2"]["tie"]["basis"].endswith("its process descends from mimikatz.exe, a process of the story")
    assert "in the story's logon session 0x9001" in by_ref["event:100"]["tie"]["basis"]
    # past 400 steps the foothold stays and the programs run with no finding go, and the story says so
    assert by_ref["event:4"]["phase"] == "persistence"
    assert by_ref["event:5"]["tie"]["kind"] == "session"
    assert len(story["steps"]) == 400 and story["stepsTruncated"] == 204 and res["stats"]["stepsTruncated"] == 1
    assert any(g.startswith("The story keeps 400 of its 604 steps") for g in story["gaps"])


def test_failed_logons_between_two_intrusions_do_not_make_them_one_story():
    host = "WS-001.northstar.example"
    me = dict(subjectUser="alice.martin", subjectDomain="NORTHSTAR", subjectLogonId="0x9001")
    day = 24 * 60
    fails = [
        ev(10 + d, d * day, eventId=4625, computer=host, targetUser="alice.martin", targetDomain="NORTHSTAR", ipAddress="203.0.113.7", logonType=3)
        for d in range(1, 21)
    ]
    events = [
        ev(1, 0, eventId=4688, computer=host, newProcessId="0x10", processName="C:\\Users\\Public\\a.exe", **me),
        *fails,
        ev(2, 21 * day, eventId=4688, computer=host, newProcessId="0x20", processName="C:\\Users\\Public\\b.exe", **me),
    ]
    findings = [finding("rule-a", "high", [1], tags=["execution"]), finding("rule-b", "high", [2], tags=["execution"])]
    findings += [finding("win-bruteforce-4625-by-account", "medium", [e["id"]], tags=["brute-force"], ipAddress="203.0.113.7") for e in fails]
    res = build_stories(events, [], findings, SETTINGS)
    first, second = sorted(res["stories"], key=lambda s: s["start"])
    # each incident holds the failures of its own days, and the spray's address links the two
    assert {"event:1", "event:11"} <= _refs(first) and "event:2" not in _refs(first) and first["end"] - first["start"] <= 3 * 86_400_000
    assert {"event:2", "event:30"} <= _refs(second) and "event:1" not in _refs(second)
    assert "event:20" in {u["ref"] for u in res["unstoried"]}
    assert any(set(c["stories"]) == {first["id"], second["id"]} for c in res["campaigns"])


def test_the_flags_of_the_stories_past_max_stories_are_listed_as_unstoried():
    events = [
        ev(
            i,
            i,
            eventId=4688,
            computer="WS-001",
            newProcessId=hex(i),
            processName="C:\\x.exe",
            subjectUser=f"user{i}",
            subjectDomain="NORTHSTAR",
            subjectLogonId=hex(0x100 + i),
        )
        for i in range(1, 6)
    ]
    res = build_stories(events, [], [finding(f"rule-{i}", "medium", [i], tags=["execution"]) for i in range(1, 6)], SETTINGS, max_stories=2)
    assert len(res["stories"]) == 2 and res["stats"]["storiesTruncated"] == 1
    lost = {u["ref"]: u["why"] for u in res["unstoried"]}
    assert set(lost) == {f"event:{i}" for i in range(1, 6)} - {r for s in res["stories"] for r in _refs(s)} and len(lost) == 3
    assert all("highest-scoring stories" in why for why in lost.values())


def test_an_address_most_of_the_organisation_signs_in_from_ties_nothing_and_makes_no_campaign():
    """An office's NAT, named by two unrelated findings: two stories, no campaign, no forty targets."""
    nat, carla = "198.51.100.50", "carla.morel@northstar.example"
    events = [
        ev(1, 0, base=ENTRA, upn=DANIEL, user=DANIEL, ipAddress=nat, status="0", appDisplayName="Azure CLI"),
        ev(2, 300, base=ENTRA, upn=carla, user=carla, ipAddress=nat, status="0", appDisplayName="Graph Explorer"),
        *[ev(100 + k, k, base=ENTRA, upn=f"employee{k:03d}@northstar.example", user=f"employee{k:03d}@northstar.example", ipAddress=nat, status="0") for k in range(40)],
    ]  # fmt: skip
    findings = [
        finding("m365-signin-risky-app", "medium", [1], tags=["initial-access"], ipAddress=nat),
        finding("m365-legacy-auth", "medium", [2], tags=["initial-access"], ipAddress=nat),
    ]
    res = build_stories(events, [], findings, SETTINGS)
    assert sorted(s["subject"]["label"] for s in res["stories"]) == [carla, DANIEL] and res["campaigns"] == []
    for s in res["stories"]:
        assert s["attackerAddresses"] == [] and s["sharedAddresses"] == [nat]
        assert f"Most of the organisation's users sign in from {nat}" in s["summary"]
    # four others signing in from it is no organisation's egress: the address links the two stories
    few = build_stories(events[:6], [], findings, SETTINGS)
    [camp] = few["campaigns"]
    assert camp["label"] == nat and len(camp["stories"]) == 2 and len(camp["targets"]) == 4


def test_a_campaign_lists_the_accounts_its_address_reached_around_its_stories_only():
    events, findings = _intrusion()
    # ten days later the same address tries another account: someone else's, as far as the case shows
    events.append(
        ev(
            60,
            10 * 24 * 60,
            eventId=4625,
            computer="WS-004.northstar.example",
            targetUser="employee021",
            targetDomain="NORTHSTAR",
            ipAddress="203.0.113.69",
            logonType=3,
        )
    )
    [camp] = build_stories(events, [], findings, SETTINGS)["campaigns"]
    assert [t["account"] for t in camp["targets"]] == ["northstar\\employee019", "northstar\\employee020"]


def test_phases_from_tags_techniques_and_records():
    assert finding_phase({"tags": ["execution", "persistence"]}) == ("execution", "rule tag execution")
    assert finding_phase({"tags": ["defense-evasion"], "attack": ["T1027"]}) == ("stealth", "rule tag defense-evasion, technique T1027")
    assert finding_phase({"tags": ["defense-evasion"], "attack": ["T1685.005"]}) == ("defense-impairment", "rule tag defense-evasion, technique T1685.005")
    assert finding_phase({"tags": ["sigma"], "attack": ["attack.t1003.001"]}) == ("credential-access", "technique ATTACK.T1003.001")
    assert finding_phase({"tags": ["sigma"]}) == (None, "")
    assert record_phase({"eventId": 4624, "logonType": 10, "ipAddress": "203.0.113.5"}, "events", set())[0] == "initial-access"
    assert record_phase({"eventId": 4624, "logonType": 10, "ipAddress": "10.0.0.5"}, "events", set())[0] == "lateral-movement"
    assert record_phase({"eventId": 4624, "logonType": 3, "ipAddress": "10.0.0.5"}, "events", set())[0] is None
    assert record_phase({**ENTRA, "status": "0", "ipAddress": "203.0.113.5"}, "events", {"203.0.113.5"})[0] == "initial-access"
    assert record_phase({**ENTRA, "status": "0", "ipAddress": "198.51.100.1"}, "events", {"203.0.113.5"})[0] is None
    assert record_phase({**UAL, "operation": "New-InboxRule"}, "events", set())[0] == "collection"
    assert record_phase({"eventId": 1102}, "events", set())[0] == "defense-impairment"
    assert record_phase({"subject": "x"}, "mails", set())[0] == "initial-access"
    assert MEDIUM != STRONG


# --- the API ------------------------------------------------------------------------------------------

import json  # noqa: E402
import uuid  # noqa: E402

import pytest  # noqa: E402
from django.test import Client, override_settings  # noqa: E402

from services.store.casestore import StoreRegistry  # noqa: E402
from services.store.writers import EventWriter  # noqa: E402

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}


@pytest.fixture
def registry(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    yield reg
    reg.close_all()


def _post(body):
    return Client().post("/api/stories/build", json.dumps(body), content_type="application/json", **HDR)


def test_the_api_builds_from_posted_rows_and_returns_the_chains_with_the_stories():
    events, findings = _intrusion()
    r = _post({"events": events, "mails": [], "findings": findings, "settings": SETTINGS, "gapHours": 48})
    assert r.status_code == 200, r.content
    body = r.json()
    assert [s["subject"]["label"] for s in body["stories"]] == [DANIEL] and body["version"] == 1
    assert set(body["chains"]) == {"chains", "stats"} and body["stats"]["stories"] == 1
    assert _post({"events": "x"}).status_code == 400
    assert _post({"storeKey": str(uuid.uuid4())}).status_code == 404


def test_a_server_case_selects_its_rows_by_sql_and_reads_the_same_story(registry, monkeypatch):
    events, findings = _intrusion()
    # the store numbers rows as they are written: the findings cite those numbers
    events.sort(key=lambda e: e["id"])
    renumber = {e["id"]: i for i, e in enumerate(events, 1)}
    key = str(uuid.uuid4())
    store = registry.get(key)
    writer = EventWriter(store, 1)
    for e in events:
        writer.add({k: v for k, v in e.items() if k != "id"})
    writer.flush()
    for f in findings:
        f["refs"] = [renumber[r] for r in f["refs"]]
    monkeypatch.setattr("api.views.stories.registry", registry)
    r = _post({"storeKey": key, "findings": findings, "settings": SETTINGS})
    assert r.status_code == 200, r.content
    [story] = r.json()["stories"]
    rows = [{**e, "id": renumber[e["id"]]} for e in events]
    [direct] = build_stories(rows, [], findings, SETTINGS)["stories"]
    assert story["id"] == direct["id"] and [s["refs"] for s in story["steps"]] == [s["refs"] for s in direct["steps"]]
    assert r.json()["stats"]["truncated"] == []
    with override_settings(FORENSIC_BROWSER_ONLY=True):
        assert _post({"storeKey": key, "findings": findings}).status_code == 403


def test_a_cut_server_selection_reads_the_foothold_and_what_is_nearest_the_flag_first(registry, monkeypatch):
    from services.analysis import stories as S

    host = "WS-001.northstar.example"
    me = dict(subjectUser="alice.martin", subjectDomain="NORTHSTAR", subjectLogonId="0x9001")
    events = [
        ev(5, -1, eventId=4624, computer=host, targetUser="alice.martin", targetDomain="NORTHSTAR", targetLogonId="0x9001", logonType=2),
        ev(1, 0, eventId=4688, computer=host, newProcessId="0x10", processName="C:\\Users\\Public\\mimikatz.exe", **me),
        ev(2, 120, eventId=4688, computer=host, newProcessId="0x11", processName="C:\\Users\\Public\\adfind.exe", subjectUser="bob", subjectDomain="NORTHSTAR", subjectLogonId="0x7001"),
        # a scheduled task twenty hours later
        ev(99, 20 * 60, eventId=4698, computer=host, taskName="\\Updater", **me),
        # thirty programs of the session in the hour before the flag, thirty in the minutes after it
        *[ev(100 + i, -50 + i * 0.5, eventId=4688, computer=host, newProcessId=hex(0x100 + i), processName="C:\\Windows\\System32\\conhost.exe", **me) for i in range(30)],
        *[ev(200 + i, 1 + i * 0.5, eventId=4688, computer=host, newProcessId=hex(0x200 + i), processName="C:\\Windows\\System32\\conhost.exe", **me) for i in range(30)],
    ]  # fmt: skip
    store = registry.get(str(uuid.uuid4()))
    writer = EventWriter(store, 1, preserve_ids=True)
    for e in events:
        writer.add({**e, "recordKey": None})
    writer.flush()
    monkeypatch.setattr(S, "EVENT_CAP", 20)
    monkeypatch.setattr(S, "NAME_KEYS", 1)
    findings = [finding("win-mimikatz", "critical", [1], tags=["credential-access"]), finding("win-adfind", "medium", [2], tags=["discovery"])]
    res = S.stories_for_store(store, SETTINGS, findings)
    [story] = [s for s in res["stories"] if s["subject"]["label"] == "northstar\\alice.martin"]
    # the cut keeps the task, then the records nearest the flag, not the first in time
    assert {"event:99", "event:200"} <= _refs(story) and "event:100" not in _refs(story)
    # and says which selections were cut, the names read around the flags among them
    assert {"identities", "hosts", "name-keys"} <= set(res["stats"]["truncated"])


def test_the_api_holds_the_sizes_it_is_asked_for_to_bounds():
    from api.views.stories import _opts

    asked = {"maxSteps": 10**9, "maxStories": "5000000", "gapHours": "inf", "seedMinRisk": -3}
    assert _opts(asked) == {"max_steps": 2000, "max_stories": 1000, "gap_hours": 720.0, "seed_min_risk": 0}
    assert _opts({"max_steps": 0, "gapHours": "nan", "maxStories": "many"}) == {"max_steps": 1}


def test_the_browser_sends_every_field_the_story_engine_reads():
    """stories.ts sends only these fields of an event, and these keys of its data; a field read here
    and missing there would silently change a browser case's stories, so the lists are compared."""
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    py = "".join((root / f"backend/services/analysis/{m}.py").read_text(encoding="utf-8") for m in ("identity", "lineage", "stories"))
    ts = (root / "frontend/src/data/stories.ts").read_text(encoding="utf-8")

    def listed(name: str) -> set[str]:
        start = ts.index(f"export const {name}")
        return set(re.findall(r"'([^']+)'", ts[start : ts.index("] as const", start)]))

    mail_only = {"date", "fromAddr", "fromName", "replyTo", "urls", "attachments", "messageId", "subject", "first", "n"}
    fields = set(re.findall(r"""\b(?:ev|row)\.get\(["']([A-Za-z]+)["']""", py)) - mail_only
    data = set(re.findall(r"""(?:\bdata|\bd|_data\(\w+\))\.get\(["']([A-Za-z. ]+)["']""", py))
    chain_keys = set(
        re.findall(
            r"'([^']+)'", (root / "frontend/src/data/chains.ts").read_text(encoding="utf-8").split("export const CHAIN_DATA_KEYS")[1].split("] as const")[0]
        )
    )
    assert fields and fields <= listed("STORY_EVENT_FIELDS"), sorted(fields - listed("STORY_EVENT_FIELDS"))
    assert data and data <= listed("STORY_DATA_KEYS") | chain_keys, sorted(data - listed("STORY_DATA_KEYS") - chain_keys)
    # the hosts' records the SQL selection reads are the ones the page reads
    from services.analysis.stories import LINEAGE_EVENT_IDS

    block = ts[ts.index("export const LINEAGE_EVENT_IDS") :]
    assert {int(x) for x in re.findall(r"\d+", block[: block.index("]")])} == set(LINEAGE_EVENT_IDS)
    from services.analysis.stories import LINEAGE_CHANNEL_EVENTS, PRIVATE_ANSWER, REMOTE_SCRIPT

    block = ts[ts.index("export const LINEAGE_CHANNEL_EVENTS") :]
    block = block[: block.index("\n]")]
    assert [(c, tuple(int(i) for i in ids.split(","))) for c, ids in re.findall(r"\['([a-z-]+)', \[([\d, ]+)\]\]", block)] == list(LINEAGE_CHANNEL_EVENTS)
    for name, value in (("REMOTE_SCRIPT", REMOTE_SCRIPT), ("PRIVATE_ANSWER", PRIVATE_ANSWER)):
        literal = re.search(rf"export const {name} = '([^']*)'", ts).group(1)
        assert literal.replace("\\\\", "\\") == value, name
