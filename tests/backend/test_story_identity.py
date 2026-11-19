"""Who is who and where, on cases built to mislead it: one host name in two domains, a shared
account, an office's NAT address, and a flag in SYSTEM's context on a host where a person is
seated. Every name, host and address is invented (example domains, documentation ranges)."""

from __future__ import annotations

from services.analysis.stories import build_stories

SEC = {"provider": "Microsoft-Windows-Security-Auditing", "channel": "Security"}
SYSMON = {"provider": "Microsoft-Windows-Sysmon", "channel": "Microsoft-Windows-Sysmon/Operational"}
T0 = 1_788_510_000_000
SETTINGS = {"internal_domains": ["a.example", "b.example"]}


def ev(n, minutes, base=SEC, **fields):
    return {"id": n, "ts": T0 + int(minutes * 60_000), **base, **fields}


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
