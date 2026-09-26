"""Host lineage: logon sessions, the hops between hosts, process trees, and what each host's evidence covers."""

from __future__ import annotations

from services.analysis.identity import MEDIUM, STRONG
from services.analysis.lineage import build_lineage, host_key, ip_of

SEC = {"provider": "Microsoft-Windows-Security-Auditing", "channel": "Security"}
SYSMON = {"provider": "Microsoft-Windows-Sysmon", "channel": "Microsoft-Windows-Sysmon/Operational"}
SCM = {"provider": "Service Control Manager", "channel": "System"}
T0 = 1_788_510_000_000


def ev(n, eid, host, minutes, base=SEC, **fields):
    return {"id": n, "eventId": eid, "computer": host, "ts": T0 + int(minutes * 60_000), **base, **fields}


def test_an_rdp_session_holds_its_activity_and_is_a_hop_from_its_address():
    events = [
        ev(
            1,
            4624,
            "WS-004.northstar.example",
            0,
            targetUser="daniel.roy",
            targetDomain="NORTHSTAR",
            targetLogonId="0x9a01",
            logonType=10,
            ipAddress="203.0.113.69",
        ),
        ev(2, 4672, "WS-004.northstar.example", 0, subjectUser="daniel.roy", subjectLogonId="0x9a01"),
        ev(3, 4732, "WS-004.northstar.example", 6, subjectUser="daniel.roy", subjectLogonId="0x9a01", memberSid="S-1-5-21-111-222-333-1042"),
        ev(4, 1102, "WS-004.northstar.example", 16, subjectUser="daniel.roy", subjectLogonId="0x9a01"),
        ev(5, 4634, "WS-004.northstar.example", 20, targetUser="daniel.roy", targetLogonId="0x9a01"),
        # the same logon id on another host is another session
        ev(
            6,
            4624,
            "WS-001.northstar.example",
            1,
            targetUser="alice.martin",
            targetDomain="NORTHSTAR",
            targetLogonId="0x9a01",
            logonType=3,
            ipAddress="10.0.0.9",
        ),
    ]
    lin = build_lineage(events)
    s = lin.session_of("event:3")
    assert s and s["host"] == "ws-004" and s["logonId"] == "0x9a01" and s["rdp"] and s["privileged"]
    assert (s["start"], s["end"]) == (T0, T0 + 20 * 60_000) and s["logonRef"] == "event:1" and s["logoffRef"] == "event:5"
    assert s["activity"] == 2 and lin.session_of("event:4") is s
    assert lin.session_of("event:6")["host"] == "ws-001"
    [hop] = lin.hops_of("event:1")
    assert (
        hop["kind"] == "rdp"
        and hop["to"] == "ws-004"
        and hop["from"] == {"host": None, "ip": "203.0.113.69", "workstation": None, "external": True, "basis": None}
    )
    assert hop["confidence"] == STRONG and hop["session"] == s["id"]
    # the activity of the session points at the hop that opened it
    assert lin.hops_of("event:4") == [hop]


def test_activity_whose_logon_is_missing_makes_a_session_marked_as_such_but_not_for_machines():
    events = [
        ev(1, 4720, "DC01", 0, subjectUser="admin.bob", subjectDomain="NORTHSTAR", subjectLogonId="0x5151", targetUser="svc.new"),
        ev(2, 4662, "DC01", 1, subjectUser="DC01$", subjectDomain="NORTHSTAR", subjectLogonId="0x6161"),
        ev(3, 4624, "DC01", 2, targetUser="admin.bob", targetLogonId="0x3e7", logonType=5),
    ]
    lin = build_lineage(events)
    s = lin.session_of("event:1")
    assert s and not s["logonSeen"] and s["typeName"] == "logon not in the evidence" and s["account"] == "NORTHSTAR\\admin.bob"
    assert lin.session_of("event:2") is None
    # SYSTEM's session is no one's
    assert lin.session_of("event:3") is None


def test_a_logon_id_reused_after_a_reboot_is_another_session():
    host = "WS-001.northstar.example"
    events = [
        ev(1, 4624, host, 0, targetUser="alice.martin", targetDomain="NORTHSTAR", targetLogonId="0x5a3f1", logonType=2),
        ev(2, 4634, host, 60, targetUser="alice.martin", targetDomain="NORTHSTAR", targetLogonId="0x5a3f1"),
        # three days later the same id is bob's, whose logon is not in the evidence
        ev(3, 4698, host, 3 * 1440, subjectUser="bob.leroy", subjectDomain="NORTHSTAR", subjectLogonId="0x5a3f1", taskName="\\evil"),
        ev(4, 4688, host, 3 * 1440 - 1, subjectUser="bob.leroy", subjectLogonId="0x5a3f1", processName="C:\\x.exe", newProcessId="0x10"),
        # activity two hours before the only logon of an id is not that logon's session
        ev(5, 5140, host, 0, subjectUser="mallory", subjectDomain="NORTHSTAR", subjectLogonId="0x777", shareName="\\\\*\\C$", ipAddress="10.0.0.9"),
        ev(6, 4624, host, 120, targetUser="carla.morel", targetDomain="NORTHSTAR", targetLogonId="0x777", logonType=3, ipAddress="10.0.0.5"),
        # an open session whose logoff is not in the evidence: another account's activity under its id is not in it
        ev(7, 4624, host, 0, targetUser="farah.benali", targetDomain="NORTHSTAR", targetLogonId="0x888", logonType=2),
        ev(8, 4720, host, 2 * 1440, subjectUser="dave", subjectDomain="NORTHSTAR", subjectLogonId="0x888", targetUser="svc.new"),
        # a record written a moment after its logoff is still in its session
        ev(9, 4624, host, 200, targetUser="carla.morel", targetDomain="NORTHSTAR", targetLogonId="0x999", logonType=3, ipAddress="10.0.0.5"),
        ev(10, 4634, host, 201, targetUser="carla.morel", targetLogonId="0x999"),
        ev(11, 5140, host, 201.05, subjectUser="carla.morel", subjectLogonId="0x999", shareName="\\\\*\\IPC$"),
    ]
    lin = build_lineage(events)
    alice, bob = lin.session_of("event:1"), lin.session_of("event:3")
    assert alice["end"] == T0 + 3_600_000 and alice["activity"] == 0
    assert bob is not alice and bob["user"] == "bob.leroy" and not bob["logonSeen"] and bob["logonId"] == "0x5a3f1"
    # a process bob started just before his first other record is in his session, not alice's
    assert lin.process_of("event:4")["session"] == bob["id"]
    mallory = lin.session_of("event:5")
    assert mallory["user"] == "mallory" and not mallory["logonSeen"] and mallory is not lin.session_of("event:6")
    dave = lin.session_of("event:8")
    assert dave["user"] == "dave" and dave is not lin.session_of("event:7")
    assert lin.session_of("event:11") is lin.session_of("event:9")


def test_psexec_admin_share_pipe_and_service_make_one_hop_from_the_named_workstation():
    host = "FS-001.northstar.example"
    events = [
        ev(1, 4624, host, 0, targetUser="lab.admin", targetDomain="NORTHSTAR", targetLogonId="0x77", logonType=3, ipAddress="10.0.0.21", workstation="WS-001"),
        ev(2, 5140, host, 0.1, subjectUser="lab.admin", subjectLogonId="0x77", shareName="\\\\*\\ADMIN$", ipAddress="10.0.0.21"),
        ev(3, 5145, host, 0.2, subjectUser="lab.admin", subjectLogonId="0x77", shareName="\\\\*\\IPC$", relativeTargetName="svcctl", ipAddress="10.0.0.21"),
        ev(4, 7045, host, 0.5, base=SCM, serviceName="PSEXESVC", serviceFile="%SystemRoot%\\PSEXESVC.exe"),
        # a share people use every day is not a way in
        ev(
            5, 4624, host, 3, targetUser="carla.morel", targetDomain="NORTHSTAR", targetLogonId="0x88", logonType=3, ipAddress="10.0.0.23", workstation="WS-003"
        ),
        ev(6, 5140, host, 3.1, subjectUser="carla.morel", subjectLogonId="0x88", shareName="\\\\*\\SYSVOL", ipAddress="10.0.0.23"),
    ]
    lin = build_lineage(events)
    [hop] = lin.hops.values()
    assert hop["kind"] == "remote-service" and hop["to"] == "fs-001" and hop["from"]["host"] == "ws-001" and hop["account"] == "NORTHSTAR\\lab.admin"
    assert hop["evidence"] == [
        "logon 0x77 (network) from 10.0.0.21",
        "opened the admin share ADMIN$",
        "opened the svcctl pipe",
        "service PSEXESVC installed 0 min after (7045), the svcctl pipe opened in that connection",
    ]
    assert set(hop["refs"]) == {"event:1", "event:4"} and lin.hops_of("event:4") == [hop]
    # the service manager's pipe opened in that connection ties the service to it, not time alone
    assert hop["confidence"] == STRONG and lin.hop_tie(hop, "event:4") == STRONG


def test_an_admin_share_without_its_logon_is_a_hop_from_the_address_the_share_record_names():
    host = "FS-001.northstar.example"
    events = [
        ev(1, 5140, host, 0, subjectUser="daniel.roy", subjectDomain="NORTHSTAR", ipAddress="203.0.113.69", shareName="\\\\*\\ADMIN$"),
        ev(2, 7045, host, 1, base=SCM, serviceName="NSLabUpdater-S04"),
    ]
    lin = build_lineage(events)
    [hop] = lin.hops.values()
    assert hop["kind"] == "remote-service" and hop["from"]["ip"] == "203.0.113.69" and hop["from"]["external"]
    # nothing but time ties the service to the share: the share is surely part of the way in, the service medium
    assert hop["evidence"] == ["service NSLabUpdater-S04 installed 1 min after (7045), by time only"] and hop["confidence"] == MEDIUM
    assert lin.hop_tie(hop, "event:1") == STRONG and lin.hop_tie(hop, "event:2") == MEDIUM


def test_a_service_after_an_admin_share_is_strong_when_its_program_came_through_the_share_or_its_logon_id_installed_it():
    host = "FS-001.northstar.example"
    share = {"subjectUser": "lab.admin", "subjectDomain": "NORTHSTAR", "ipAddress": "10.0.0.21"}
    events = [
        # the service's program written through ADMIN$ by the connection before it
        ev(1, 5145, host, 0, **share, subjectLogonId="0x71", shareName="\\\\*\\ADMIN$", relativeTargetName="svc-8f2a.exe"),
        ev(2, 7045, host, 1, base=SCM, serviceName="svc-8f2a", serviceFile='"%SystemRoot%\\svc-8f2a.exe" -k run'),
        # another host: the service installed under the logon id of the connection that opened C$ (4697)
        ev(3, 5140, "FS-002", 0, **share, subjectLogonId="0x72", shareName="\\\\*\\C$"),
        ev(4, 4697, "FS-002", 2, subjectUser="lab.admin", subjectDomain="NORTHSTAR", subjectLogonId="0x72", serviceName="upd", serviceFile="C:\\upd.exe"),
        # a third: a program of another name written, then a service: time only
        ev(5, 5145, "FS-003", 0, **share, subjectLogonId="0x73", shareName="\\\\*\\ADMIN$", relativeTargetName="notes.txt"),
        ev(6, 7045, "FS-003", 1, base=SCM, serviceName="upd", serviceFile="C:\\Windows\\upd.exe"),
    ]
    lin = build_lineage(events)
    by_host = {h["to"]: h for h in lin.hops.values()}
    assert {k: (h["kind"], h["confidence"]) for k, h in by_host.items()} == {
        "fs-001": ("remote-service", STRONG),
        "fs-002": ("remote-service", STRONG),
        "fs-003": ("remote-service", MEDIUM),
    }
    assert by_host["fs-001"]["evidence"][-1].endswith("its program svc-8f2a.exe written through the admin share")
    assert by_host["fs-002"]["evidence"][-1].endswith("under the logon id of that connection")
    assert lin.hop_tie(by_host["fs-001"], "event:2") == lin.hop_tie(by_host["fs-002"], "event:4") == STRONG
    assert lin.hop_tie(by_host["fs-003"], "event:6") == MEDIUM


def test_explicit_credentials_towards_a_host_are_confirmed_by_the_logon_there():
    events = [
        ev(
            1,
            4648,
            "WS-001.northstar.example",
            0,
            subjectUser="alice.martin",
            targetUser="lab.admin",
            targetDomain="NORTHSTAR",
            targetServer="FS-001",
            processName="C:\\Windows\\System32\\mstsc.exe",
        ),
        ev(
            2,
            4624,
            "FS-001.northstar.example",
            0.5,
            targetUser="lab.admin",
            targetDomain="NORTHSTAR",
            targetLogonId="0x99",
            logonType=3,
            workstation="WS-001",
            ipAddress="10.0.0.21",
        ),
        # towards itself it is no hop, and towards a host with no logon from here it stays medium
        ev(3, 4648, "WS-001.northstar.example", 2, targetUser="alice.martin", targetServer="localhost"),
        ev(4, 4648, "WS-001.northstar.example", 3, targetUser="lab.admin", targetDomain="NORTHSTAR", targetServer="DB-001.northstar.example"),
    ]
    lin = build_lineage(events)
    hops = sorted(lin.hops.values(), key=lambda h: h["ts"])
    # the way in is the client's: mstsc's explicit credentials are an RDP connection
    assert [(h["kind"], h["from"]["host"], h["to"], h["confidence"]) for h in hops] == [
        ("rdp", "ws-001", "fs-001", STRONG),
        ("explicit-credentials", "ws-001", "db-001", MEDIUM),
    ]
    assert hops[0]["session"] == lin.session_of("event:2")["id"] and lin.hops_of("event:2") == [hops[0]]
    assert "mstsc.exe used explicit credentials towards it (4648), and the logon there followed" == hops[0]["basis"]


def test_process_trees_from_4688_ids_and_sysmon_guids_are_one_tree():
    host = "WS-002.northstar.example"
    g = "{e13d7a06-9f48-42c9-880d-6f76e0f4d2%02d}"
    events = [
        ev(1, 4624, host, 0, targetUser="benoit.durand", targetDomain="NORTHSTAR", targetLogonId="0x4242", logonType=2),
        ev(
            2,
            4688,
            host,
            1,
            processName="C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE",
            newProcessId="0x1e6c",
            callerProcessId="0x10",
            subjectLogonId="0x4242",
        ),
        # a process id reused later: the child takes the latest creation before it
        ev(3, 4688, host, 2, processName="C:\\Windows\\System32\\cmd.exe", newProcessId="0x2000", callerProcessId="0x1e6c", subjectLogonId="0x4242"),
        ev(
            4,
            1,
            host,
            2.01,
            base=SYSMON,
            processGuid=g % 1,
            image="C:\\Windows\\System32\\cmd.exe",
            callerProcessId="8192",
            commandLine="cmd /c powershell",
            data={"LogonId": "0x4242"},
        ),
        ev(
            5,
            1,
            host,
            3,
            base=SYSMON,
            processGuid=g % 2,
            parentProcessGuid=g % 1,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            callerProcessId="4000",
        ),
        ev(6, 4688, host, 50, processName="C:\\Windows\\System32\\notepad.exe", newProcessId="0x1e6c", callerProcessId="0x10"),
        ev(7, 4688, host, 51, processName="C:\\Windows\\System32\\calc.exe", newProcessId="0x3000", callerProcessId="0x1e6c"),
    ]
    lin = build_lineage(events)
    ps = lin.process_of("event:5")
    tree = lin.tree(ps["id"])
    assert [p["name"] for p in [tree["process"], *tree["ancestors"]]] == ["powershell.exe", "cmd.exe", "OUTLOOK.EXE"]
    cmd = lin.process_of("event:3")
    assert cmd is lin.process_of("event:4") and cmd["source"] == "both" and cmd["guid"] and cmd["commandLine"] == "cmd /c powershell"
    assert cmd["session"] == lin.session_of("event:1")["id"]
    assert lin.processes[lin.process_of("event:7")["parent"]]["name"] == "notepad.exe"


def test_a_4688_parent_must_be_the_program_the_record_names():
    host = "WS-002.northstar.example"
    events = [
        ev(1, 4688, host, 0, processName="C:\\Windows\\System32\\notepad.exe", newProcessId="0x1a2c", callerProcessId="0x400", subjectLogonId="0x9001"),
        # two days later the id is explorer's, whose creation is not in the evidence: notepad is not the parent
        ev(2, 4688, host, 2 * 1440, processName="C:\\Users\\bob\\evil.exe", newProcessId="0x2b00", callerProcessId="0x1a2c",
           parentProcessName="C:\\Windows\\explorer.exe", subjectLogonId="0x9002"),
        # a program that runs for days: named and matching, its creation three days before is the parent
        ev(3, 4688, host, 0, processName="C:\\Windows\\explorer.exe", newProcessId="0x5000", callerProcessId="0x410", subjectLogonId="0x9001"),
        ev(4, 4688, host, 3 * 1440, processName="C:\\Windows\\System32\\cmd.exe", newProcessId="0x3000", callerProcessId="0x5000",
           parentProcessName="C:\\Windows\\EXPLORER.EXE", subjectLogonId="0x9001"),
        # the parser's own guess at the parent's name is no statement: only the id ties them, for a day at most
        ev(5, 4688, host, 3 * 1440, processName="C:\\Windows\\System32\\calc.exe", newProcessId="0x3100", callerProcessId="0x5000",
           parentProcessName="C:\\Windows\\explorer.exe", enriched="parentProcessName from the 4688 that created the parent process id"),
        ev(6, 4688, host, 3 * 1440 + 60, processName="C:\\Windows\\System32\\whoami.exe", newProcessId="0x3200", callerProcessId="0x3100"),
    ]  # fmt: skip
    lin = build_lineage(events)
    evil = lin.process_of("event:2")
    assert evil["parent"] is None and evil["parentImage"] == "C:\\Windows\\explorer.exe"
    assert lin.process_of("event:4")["parent"] == lin.process_of("event:3")["id"]
    assert lin.process_of("event:5")["parent"] is None
    assert lin.process_of("event:6")["parent"] == lin.process_of("event:5")["id"]


def test_each_host_says_what_its_evidence_cannot_show():
    events = [
        ev(1, 4688, "WS-001", 0, processName="C:\\x.exe", newProcessId="0x10", callerProcessId="0x4"),
        ev(2, 4624, "WS-001", 0, targetUser="a", targetLogonId="0x10", logonType=2),
        ev(3, 7036, "WS-002", 0, base=SCM),
        ev(4, 1102, "WS-002", 5, subjectUser="daniel.roy"),
        ev(5, 1102, "WS-002", 9, subjectUser="daniel.roy"),
    ]
    hosts = build_lineage(events).hosts
    assert hosts["ws-001"]["limits"] == [
        "What ran on WS-001 comes from 4688 alone: parents are found by process id within the log, and there are no process GUIDs or hashes, "
        "nor command lines: the audit policy did not record them."
    ]
    assert hosts["ws-002"]["limits"] == [
        "What ran on WS-002 is not in the evidence: it has no Sysmon process creation (1) and no process creation audit (4688).",
        "Who logged on to WS-002 is not in the evidence: it has no logon events (4624).",
        "The Security log of WS-002 was cleared 2 times between 2026-09-04 08:25 UTC and 2026-09-04 08:29 UTC: what it held before each clear is not in this log.",
    ]


def test_a_host_owns_the_private_address_its_own_connections_come_from():
    events = [
        ev(1, 3, "WS-001", 0, base=SYSMON, sourceIp="10.0.0.21", destinationIp="10.0.0.40", destinationPort=445, initiated="true", image="C:\\x.exe"),
        ev(2, 3, "WS-005", 0, base=SYSMON, sourceIp="10.0.0.99", destinationIp="10.0.0.25", initiated="false"),
        # without the direction, or for a public address, no address is attributed
        ev(3, 3, "WS-006", 0, base=SYSMON, sourceIp="10.0.0.66", destinationIp="10.0.0.77"),
        ev(4, 3, "WS-007", 0, base=SYSMON, sourceIp="203.0.113.5", destinationIp="10.0.0.40", initiated="true"),
        ev(5, 4624, "FS-001", 1, targetUser="x", targetLogonId="0x5", logonType=3, ipAddress="10.0.0.21"),
    ]
    lin = build_lineage(events)
    assert {ip: v["host"] for ip, v in lin.ip_hosts.items()} == {"10.0.0.21": "ws-001", "10.0.0.25": "ws-005"}
    assert lin.session_of("event:5")["from"] == "ws-001"


def test_values():
    assert host_key("WS-004.northstar.example") == host_key("\\\\WS-004") == host_key("WS-004$") == "ws-004"
    assert host_key("10.0.0.5") == host_key("localhost") == host_key("-") == ""
    assert ip_of("::ffff:10.0.0.5") == "10.0.0.5" and ip_of("-") == ip_of("127.0.0.1") == ip_of("WS-001") == ""


WMI = {"provider": "Microsoft-Windows-WMI-Activity", "channel": "Microsoft-Windows-WMI-Activity/Operational"}
WINRM = {"provider": "Microsoft-Windows-WinRM", "channel": "Microsoft-Windows-WinRM/Operational"}
ENTRA = {"provider": "Microsoft Entra ID Sign-in", "category": "Entra sign-in", "operation": "SignIn"}


def _admin_logon(n, host, minutes, lid, ip="10.0.2.17", ws="PC01"):
    return ev(n, 4624, host, minutes, targetUser="Administrator", targetDomain="EXAMPLE", targetLogonId=lid, logonType=3, ipAddress=ip, workstation=ws)


def test_wmi_and_winrm_execution_on_the_target_are_hops_of_their_own_kind():
    fs = "FS-001.example.corp"
    events = [
        # WMI with the caller's logon on the child (4688 target logon id): strong
        _admin_logon(1, fs, 0, "0x10fb01"),
        ev(2, 4688, fs, 0.01, subjectUser="FS-001$", subjectLogonId="0x3e4", processName="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", newProcessId="0xae8"),
        ev(3, 4688, fs, 0.02, subjectUser="Administrator", targetLogonId="0x10fb01", processName="C:\\Windows\\System32\\cmd.exe",
           parentProcessName="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", newProcessId="0x424", callerProcessId="0xae8"),
        # the older 4688 without the caller's logon: the network logon just before it, by time (medium)
        _admin_logon(4, fs, 90, "0x10fc09"),
        ev(5, 4688, fs, 90.001, subjectUser="FS-001$", subjectLogonId="0x3e4", processName="C:\\Windows\\System32\\calc.exe",
           parentProcessName="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", newProcessId="0x500"),
        # PowerShell remoting: WinRM starts a shell (91) for the network logon of that moment
        _admin_logon(6, fs, 200, "0x10fd11"),
        ev(7, 91, fs, 200.02, base=WINRM),
    ]  # fmt: skip
    lin = build_lineage(events)
    [strong] = lin.hops_of("event:1")
    assert (strong["kind"], strong["to"], strong["from"]["host"], strong["confidence"]) == ("wmi", "fs-001", "pc01", STRONG)
    assert "ran a program through WMI" in strong["evidence"]
    [timed] = lin.hops_of("event:4")
    assert (timed["kind"], timed["confidence"]) == ("wmi", MEDIUM) and "ran a program through WMI (by time)" in timed["basis"]
    [shell] = lin.hops_of("event:6")
    assert shell["kind"] == "winrm" and lin.session_of("event:7")["logonId"] == "0x10fd11"
    # each record keeps its own tie: the program by its logon id strong, the one by time and the shell medium
    assert lin.hop_tie(strong, "event:3") == STRONG and lin.session_tie("event:3") == STRONG
    assert lin.hops_of("event:5") == [timed] and lin.hop_tie(timed, "event:5") == MEDIUM and lin.hop_tie(timed, "event:4") == STRONG
    assert lin.session_tie("event:7") == MEDIUM and lin.hop_tie(shell, "event:7") == MEDIUM


def test_remote_execution_named_on_the_source_is_a_hop_confirmed_by_the_logon_there():
    ws, fs = "WS-004.example.corp", "FS-001.example.corp"
    events = [
        ev(1, 1, ws, 0, base=SYSMON, user="EXAMPLE\\daniel", processGuid="{11111111-2222-3333-4444-555555555555}",
           image="C:\\Windows\\System32\\wbem\\WMIC.exe", commandLine='wmic /node:"FS-001" process call create "cmd /c whoami"'),
        ev(2, 4624, fs, 0.2, targetUser="daniel", targetDomain="EXAMPLE", targetLogonId="0x77", logonType=3, ipAddress="10.0.0.4", workstation="WS-004"),
        # PowerShell remoting to a host whose logon is not in the evidence: medium
        ev(3, 4104, ws, 5, subjectUser="daniel", subjectDomain="EXAMPLE", scriptBlockText="Invoke-Command -ComputerName DC-01 -ScriptBlock { whoami }"),
        # WinRM's own record of the session it opened (6)
        ev(4, 6, ws, 9, base=WINRM, user="EXAMPLE\\daniel", data={"connection": "fs-001.example.corp/wsman?PSVersion=5.1.19041.1"}),
        # a WMI call from another host that failed there names its client (5858)
        ev(5, 5858, fs, 12, base=WMI, data={"ClientMachine": "WS-009", "User": "EXAMPLE\\carla", "Operation": "Start IWbemServices::ExecMethod - Win32_Process::Create"}),
        # explicit credentials used by wmic: the way in is WMI
        ev(6, 4648, ws, 15, subjectUser="daniel", targetUser="Administrator", targetServer="FS-001", processName="C:\\Windows\\System32\\wbem\\WMIC.exe"),
        # a command that only names the local host is no hop
        ev(7, 1, ws, 20, base=SYSMON, user="EXAMPLE\\daniel", image="C:\\Windows\\System32\\wbem\\WMIC.exe", commandLine="wmic /node:localhost os get caption"),
    ]  # fmt: skip
    lin = build_lineage(events)
    [wmi] = lin.hops_of("event:1")
    assert (wmi["kind"], wmi["from"]["host"], wmi["to"], wmi["confidence"]) == ("wmi", "ws-004", "fs-001", STRONG)
    assert lin.hops_of("event:2") == [wmi]
    [ps] = lin.hops_of("event:3")
    assert (ps["kind"], ps["to"], ps["confidence"]) == ("winrm", "dc-01", MEDIUM) and "PowerShell remoting" in ps["basis"]
    [six] = lin.hops_of("event:4")
    assert (six["kind"], six["to"]) == ("winrm", "fs-001")
    [failed] = lin.hops_of("event:5")
    assert (failed["kind"], failed["from"]["host"], failed["to"]) == ("wmi", "ws-009", "fs-001") and "failed" in failed["basis"]
    assert [h["kind"] for h in lin.hops_of("event:6")] == ["wmi"]
    assert lin.hops_of("event:7") == []


def test_dns_answers_and_dhcp_leases_give_addresses_to_hosts_and_time_decides_between_two():
    ws = "WS-004.example.corp"
    events = [
        ev(1, 22, ws, 0, base=SYSMON, query="fs-001.example.corp", queryResults="::ffff:10.0.0.21;"),
        # an alias or a domain's own name is not a host's
        ev(2, 22, ws, 1, base=SYSMON, query="files.example.corp", queryResults="type:  5 fs-002.example.corp;::ffff:10.0.0.22;"),
        ev(3, 22, ws, 2, base=SYSMON, query="example.corp", queryResults="::ffff:10.0.0.2;"),
        # the DHCP server's audit log: no time on the timeline, a host for the address
        {"id": 4, "artifactType": "dhcp", "provider": "Microsoft-Windows-DHCP-Server", "ipAddress": "10.0.0.31", "workstation": "WS-007.example.corp",
         "data": {"ID": "10", "Date": "09/04/26", "Time": "08:01:02"}},
        {"id": 5, "artifactType": "dhcp", "provider": "Microsoft-Windows-DHCP-Server", "ipAddress": "10.0.0.32", "workstation": "WS-008.example.corp",
         "data": {"ID": "12", "Date": "09/04/26", "Time": "08:01:02"}},
        # one address, two hosts' own connections a day apart: the host nearest in time
        ev(6, 3, "WS-011.example.corp", 0, base=SYSMON, sourceIp="10.0.0.40", destinationIp="10.0.0.1", initiated="true"),
        ev(7, 3, "WS-012.example.corp", 1440, base=SYSMON, sourceIp="10.0.0.40", destinationIp="10.0.0.1", initiated="true"),
    ]  # fmt: skip
    lin = build_lineage(events)
    assert lin.host_of_ip("10.0.0.21") == "fs-001" and "DNS answer" in lin.ip_hosts["10.0.0.21"]["basis"]
    assert lin.host_of_ip("10.0.0.22") is None and lin.host_of_ip("10.0.0.2") is None
    assert lin.host_of_ip("10.0.0.31") == "ws-007" and "DHCP" in lin.ip_hosts["10.0.0.31"]["basis"]
    assert lin.host_of_ip("10.0.0.32") is None
    assert lin.host_of_ip("10.0.0.40", T0 + 60_000) == "ws-011" and lin.host_of_ip("10.0.0.40", T0 + 1400 * 60_000) == "ws-012"


def test_an_entra_device_named_like_a_host_of_the_case_is_that_host():
    events = [
        ev(1, 4624, "WS-004.example.corp", 0, targetUser="daniel", targetLogonId="0x77", logonType=2),
        {"id": 2, "ts": T0, **ENTRA, "user": "daniel@example.corp", "upn": "daniel@example.corp",
         "data": {"deviceName": "WS-004", "deviceId": "b1c2", "trustType": "Hybrid Azure AD joined"}},
        {"id": 3, "ts": T0, **ENTRA, "user": "daniel@example.corp", "data": {"deviceName": "DESKTOP-9Q1Z", "trustType": ""}},
    ]  # fmt: skip
    lin = build_lineage(events)
    dev = lin.device_of(events[1])
    assert dev["host"] == "ws-004" and dev["trustTypes"] == ["Hybrid Azure AD joined"] and dev["deviceIds"] == ["b1c2"]
    assert lin.hosts["ws-004"]["devices"] == ["b1c2"]
    assert lin.device_of(events[2])["host"] is None
    assert [d["key"] for d in lin.to_dict(refs=["event:2"])["devices"]] == ["ws-004"]


RCM = {
    "provider": "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
    "channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
}


def test_the_lookups_of_each_record_do_not_read_every_session(monkeypatch):
    """A WMI program's logon, WinRM's shell, the logon a 4648 led to and an RDP record's session are looked
    up among the sessions of their host (and account) by time: the work grows with the case, not with its square."""
    from services.analysis import lineage

    reads = {"n": 0}

    class Sessions(dict):
        def values(self):
            reads["n"] += 1
            return super().values()

    init = lineage.Lineage.__init__

    def counting(self):
        init(self)
        self.sessions = Sessions()

    monkeypatch.setattr(lineage.Lineage, "__init__", counting)

    def build(n):
        reads["n"] = 0
        events = []
        for i in range(n):
            t, k = i * 10, 10 * i
            events += [
                _admin_logon(k + 1, "FS-001", t, hex(0x1000 + i), ws="PC01"),
                ev(k + 2, 4688, "FS-001", t + 0.1, subjectUser="FS-001$", subjectLogonId="0x3e4", processName="C:\\Windows\\System32\\cmd.exe",
                   parentProcessName="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", newProcessId=hex(0x500 + i)),
                ev(k + 3, 91, "FS-001", t + 0.2, base=WINRM),
                ev(k + 4, 4648, "PC01", t, subjectUser="Administrator", targetUser="Administrator", targetServer="FS-001", processName="C:\\Windows\\System32\\wbem\\WMIC.exe"),
                ev(k + 5, 4624, "WS-004", t, targetUser="daniel", targetDomain="EXAMPLE", targetLogonId=hex(0x9000 + i), logonType=10, ipAddress="203.0.113.69"),
                ev(k + 6, 1149, "WS-004", t + 0.1, base=RCM, targetUser="daniel", ipAddress="203.0.113.69"),
            ]  # fmt: skip
        lin = build_lineage(events)
        # each record found its session: the WMI program's by time, the shell's, the 4648's, the 1149's
        assert all(lin.hop_tie(h, f"event:{10 * i + 2}") == MEDIUM for i in range(n) for h in lin.hops_of(f"event:{10 * i + 2}"))
        assert lin.session_of("event:3") is lin.session_of("event:1") and lin.session_tie("event:3") == MEDIUM
        assert lin.session_of("event:6") is lin.session_of("event:5") and lin.session_tie("event:6") == MEDIUM
        assert any(h["kind"] == "wmi" and h["confidence"] == STRONG for h in lin.hops_of("event:4"))
        return reads["n"]

    assert build(40) == build(3)


# --- the domain controllers' records and other credentials ------------------------------------------------

DC = "DC-01.northstar.example"
G = "{5b482e77-15dd-f684-f093-e11c7ed66e%02d}"


def _ticket(n, minutes, user, service, ip, guid=None, status="0x0", eid=4769):
    return ev(n, eid, DC, minutes, targetUser=user, targetDomain="NORTHSTAR.EXAMPLE", serviceName=service, ipAddress=ip, logonGuid=guid, status=status)


def _net_logon(n, host, minutes, user, lid, ip=None, ws=None, guid=None, pkg="Kerberos"):
    return ev(n, 4624, host, minutes, targetUser=user, targetDomain="NORTHSTAR", targetLogonId=lid, logonType=3, ipAddress=ip, workstation=ws,
              logonGuid=guid, authPackage=pkg)  # fmt: skip


def test_a_service_ticket_with_the_logons_guid_names_its_source_and_the_service_asked_for():
    fs = "FS-001.northstar.example"
    events = [
        # the logon names neither its address nor its workstation, as a Kerberos logon often does not
        _net_logon(1, fs, 0, "lab.admin", "0x77", guid=G % 1),
        ev(2, 5140, fs, 0.1, subjectUser="lab.admin", subjectLogonId="0x77", shareName="\\\\*\\ADMIN$"),
        # the domain controller issued its ticket, for the server's own account, to the client's address
        _ticket(3, -0.02, "lab.admin@NORTHSTAR.EXAMPLE", "FS-001$", "10.0.0.21", G % 1),
        # and explicit credentials on WS-001 carried the same logon GUID as their target's
        ev(4, 4648, "WS-001.northstar.example", -0.03, subjectUser="alice.martin", targetUser="lab.admin", targetDomain="NORTHSTAR",
           targetServer="FS-001", data={"TargetLogonGuid": G % 1}),
        # a ticket refused names nothing
        _ticket(5, -0.01, "lab.admin@NORTHSTAR.EXAMPLE", "FS-001$", "10.0.0.66", G % 1, status="0x12"),
    ]  # fmt: skip
    lin = build_lineage(events)
    s = lin.session_of("event:1")
    assert s["from"] == "ws-001" and "explicit credentials used on ws-001 carried its logon GUID (4648)" in s["fromBasis"]
    assert [(a["kind"], a["ref"], a["confidence"]) for a in s["auth"]] == [("explicit-credentials", "event:4", STRONG), ("kerberos", "event:3", STRONG)]
    [share] = [h for h in lin.hops_of("event:1") if h["kind"] == "admin-share"]
    assert (share["from"]["host"], share["from"]["ip"], share["confidence"]) == ("ws-001", "10.0.0.21", STRONG)
    # the way in says which service was asked for, and the ticket is part of it
    assert share["basis"].endswith("with a Kerberos ticket for FS-001$ from dc-01 (4769)")
    assert "event:3" in share["refs"] and lin.hop_tie(share, "event:3") == STRONG
    assert "dc-01 issued a Kerberos ticket for FS-001$ to 10.0.0.21 (the same logon GUID, 4769)" in share["evidence"]
    assert "event:5" not in {a["ref"] for a in s["auth"]} and not lin.hops_of("event:5")
    # the explicit credentials' hop: their target logon GUID is the logon's
    [explicit] = lin.hops_of("event:4")
    assert (explicit["kind"], explicit["to"], explicit["confidence"]) == ("explicit-credentials", "fs-001", STRONG)
    assert explicit["basis"].endswith("and the logon there carried their logon GUID")


def test_a_tickets_client_address_is_the_source_when_the_case_knows_whose_it_is():
    fs = "FS-001.northstar.example"
    events = [
        _net_logon(1, fs, 0, "lab.admin", "0x77", guid=G % 1),
        ev(2, 5140, fs, 0.1, subjectUser="lab.admin", subjectLogonId="0x77", shareName="\\\\*\\ADMIN$"),
        _ticket(3, -0.02, "lab.admin@NORTHSTAR.EXAMPLE", "FS-001$", "10.0.0.21", G % 1),
        # the machine account's own ticket-granting ticket went to WS-001's address
        _ticket(4, -300, "WS-001$", "krbtgt", "10.0.0.21", eid=4768),
    ]
    lin = build_lineage(events)
    assert lin.host_of_ip("10.0.0.21") == "ws-001" and "own account a Kerberos ticket" in lin.ip_hosts["10.0.0.21"]["basis"]
    [hop] = lin.hops_of("event:1")
    # the source host is as sure as the address attribution: medium, and it says where it comes from
    assert (hop["from"]["host"], hop["from"]["ip"], hop["confidence"]) == ("ws-001", "10.0.0.21", MEDIUM)
    assert hop["from"]["basis"].startswith("the address 10.0.0.21 dc-01 issued its Kerberos ticket to (4769)")
    assert lin.hop_tie(hop, "event:3") == STRONG
    assert lin.hosts["dc-01"]["coverage"]["kerberos"] == 2


def test_a_ticket_for_the_hosts_own_account_just_before_a_network_logon_is_its_ticket_by_time():
    fs = "FS-002.northstar.example"
    events = [
        # the logon's GUID is not the ticket's: the ticket for FS-002$ from its address 20 s before is, by time
        _net_logon(1, fs, 0, "lab.admin", "0x81", ip="10.0.0.22", guid=G % 2),
        ev(2, 5140, fs, 0.1, subjectUser="lab.admin", subjectLogonId="0x81", shareName="\\\\*\\C$"),
        _ticket(3, -20 / 60, "lab.admin@NORTHSTAR.EXAMPLE", "FS-002$", "10.0.0.22", G % 3),
        # a later logon that carries the same logon GUID came with the same ticket
        _net_logon(4, fs, 0.2, "lab.admin", "0x82", ip="10.0.0.22", guid=G % 2),
        # not another account's, another host's, one from another address, nor one two minutes before
        _ticket(5, -0.1, "carla.morel@NORTHSTAR.EXAMPLE", "FS-002$", "10.0.0.22", G % 4),
        _ticket(6, -0.1, "lab.admin@NORTHSTAR.EXAMPLE", "FS-003$", "10.0.0.22", G % 5),
        _ticket(7, -0.1, "lab.admin@NORTHSTAR.EXAMPLE", "FS-002$", "10.0.0.66", G % 6),
        _net_logon(8, fs, 10, "lab.admin", "0x83", ip="10.0.0.22", guid=G % 7),
        _ticket(9, 8, "lab.admin@NORTHSTAR.EXAMPLE", "FS-002$", "10.0.0.22", G % 8),
    ]
    lin = build_lineage(events)
    first, again, late = lin.session_of("event:1"), lin.session_of("event:4"), lin.session_of("event:8")
    assert [(a["ref"], a["confidence"], a["basis"]) for a in first["auth"]] == [("event:3", MEDIUM, "by account, service, address and time")]
    assert [a["ref"] for a in again["auth"]] == ["event:3"] and late["auth"] == []
    [hop] = lin.hops_of("event:1")
    assert "event:3" in hop["refs"] and lin.hop_tie(hop, "event:3") == MEDIUM
    assert all(not lin.hops_of(f"event:{n}") for n in (5, 6, 7, 9))


def test_an_ntlm_validation_names_the_workstation_of_a_network_logon_that_names_none():
    fs = "FS-001.northstar.example"
    events = [
        _net_logon(1, fs, 0, "carla.morel", "0x91", ip="10.0.0.23", pkg="NTLM"),
        ev(2, 5140, fs, 0.1, subjectUser="carla.morel", subjectLogonId="0x91", shareName="\\\\*\\ADMIN$"),
        ev(3, 4776, DC, -10 / 60, targetUser="carla.morel", workstation="WS-003", status="0x0"),
        # a failed validation names nothing
        ev(4, 4776, DC, -5 / 60, targetUser="carla.morel", workstation="WS-666", status="0xc000006a"),
        # two workstations in the same minute: which one was this logon's is not known
        _net_logon(5, fs, 60, "dave", "0x92", ip="10.0.0.24", pkg="NTLM"),
        ev(6, 5140, fs, 60.1, subjectUser="dave", subjectLogonId="0x92", shareName="\\\\*\\ADMIN$"),
        ev(7, 4776, DC, 60 - 10 / 60, targetUser="dave", workstation="WS-004", status="0x0"),
        ev(8, 4776, DC, 60 - 20 / 60, targetUser="dave", workstation="WS-005", status="0x0"),
        # a domain controller is a host that issues tickets
        _ticket(9, -300, "WS-009$", "krbtgt", "10.0.0.99", eid=4768),
    ]
    lin = build_lineage(events)
    carla, dave = lin.session_of("event:1"), lin.session_of("event:5")
    assert carla["from"] == "ws-003" and "NTLM validation of the account from WS-003" in carla["fromBasis"]
    assert [(a["kind"], a["ref"], a["confidence"]) for a in carla["auth"]] == [("ntlm", "event:3", MEDIUM)]
    [hop] = lin.hops_of("event:1")
    assert (hop["from"]["host"], hop["confidence"]) == ("ws-003", MEDIUM) and lin.hop_tie(hop, "event:3") == MEDIUM
    assert dave["from"] is None and dave["auth"] == []
    assert lin.hosts["dc-01"]["coverage"]["ntlm"] == 4


def test_a_new_credentials_logon_ties_the_account_it_used_on_the_network_to_its_session():
    ws, fs = "WS-004.northstar.example", "FS-001.northstar.example"
    netonly = {"targetUser": "daniel.roy", "targetDomain": "NORTHSTAR", "logonType": 9, "logonProcess": "seclogo"}
    events = [
        ev(1, 4624, ws, 0, **netonly, targetLogonId="0x9901", targetOutboundUser="admin.bob", targetOutboundDomain="NORTHSTAR"),
        # admin.bob logs on to FS-001 from WS-004 half an hour later, and opens ADMIN$
        _net_logon(2, fs, 30, "admin.bob", "0x77", ip="10.0.0.4", ws="WS-004", pkg="NTLM"),
        ev(3, 5140, fs, 30.1, subjectUser="admin.bob", subjectLogonId="0x77", shareName="\\\\*\\ADMIN$"),
        ev(4, 4634, ws, 60, targetUser="daniel.roy", targetLogonId="0x9901"),
        # after the session ended, and from another host, admin.bob's logons are not its
        _net_logon(5, fs, 90, "admin.bob", "0x78", ip="10.0.0.4", ws="WS-004", pkg="NTLM"),
        _net_logon(6, "FS-002", 31, "admin.bob", "0x79", ip="10.0.0.9", ws="WS-009", pkg="NTLM"),
        # runas /netonly as oneself sets no other account
        ev(7, 4624, ws, 0, **netonly, targetLogonId="0x9902", targetOutboundUser="daniel.roy", targetOutboundDomain="NORTHSTAR.EXAMPLE"),
    ]
    lin = build_lineage(events)
    s = lin.session_of("event:1")
    assert s["network"] == "NORTHSTAR\\admin.bob" and "used other credentials (NORTHSTAR\\admin.bob) for the network" in s["actions"]
    assert lin.session_of("event:7")["network"] is None
    [hop] = lin.hops_of("event:1")
    assert (hop["kind"], hop["from"]["host"], hop["to"], hop["account"], hop["confidence"]) == (
        "explicit-credentials",
        "ws-004",
        "fs-001",
        "NORTHSTAR\\admin.bob",
        MEDIUM,
    )
    assert "(4624 type 9)" in hop["basis"] and hop["refs"] == ["event:1", "event:2"]
    # the logon on FS-001 is part of that way in, as surely as account, source and time tie it
    assert hop in lin.hops_of("event:2") and lin.hop_tie(hop, "event:2") == MEDIUM
    assert all(hop not in lin.hops_of(f"event:{n}") for n in (5, 6))


def test_a_hosts_clock_against_the_domain_controllers_is_noted_and_the_ties_by_time_allow_for_it():
    fs = "FS-005.northstar.example"
    skew = 7  # minutes the member server's clock is ahead
    events = [
        # three logons matched to their tickets by logon GUID, each 7 minutes after its ticket
        *[_net_logon(n, fs, 60 * n + skew, "lab.admin", hex(0x100 + n), ip="10.0.0.21", guid=G % n) for n in (1, 2, 3)],
        *[_ticket(10 + n, 60 * n - 0.01, "lab.admin@NORTHSTAR.EXAMPLE", "FS-005$", "10.0.0.21", G % n) for n in (1, 2, 3)],
        # a logon whose GUID is not its ticket's: 7 minutes after the ticket is just after it on the domain controller's clock
        _net_logon(4, fs, 300 + skew, "carla.morel", "0x200", ip="10.0.0.23", guid=G % 40),
        _ticket(14, 300 - 0.1, "carla.morel@NORTHSTAR.EXAMPLE", "FS-005$", "10.0.0.23", G % 41),
        # a host whose logons follow their tickets by a second has no skew to note
        _net_logon(5, "FS-006", 1, "lab.admin", "0x300", ip="10.0.0.21", guid=G % 50),
        _net_logon(6, "FS-006", 2, "lab.admin", "0x301", ip="10.0.0.21", guid=G % 51),
        _ticket(15, 1 - 1 / 60, "lab.admin@NORTHSTAR.EXAMPLE", "FS-006$", "10.0.0.21", G % 50),
        _ticket(16, 2 - 1 / 60, "lab.admin@NORTHSTAR.EXAMPLE", "FS-006$", "10.0.0.21", G % 51),
    ]
    lin = build_lineage(events)
    host = lin.hosts["fs-005"]
    assert host["clock"]["matches"] == 3 and abs(host["clock"]["offsetMs"] - skew * 60_000) < 1_000
    assert "FS-005.northstar.example's clock reads 7 min ahead of the domain controller's" in host["limits"][-1]
    assert [a["ref"] for a in lin.session_of("event:4")["auth"]] == ["event:14"]
    assert "clock" not in lin.hosts["fs-006"]
