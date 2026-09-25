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
        "service PSEXESVC installed 0 min after (7045)",
    ]
    assert set(hop["refs"]) == {"event:1", "event:4"} and lin.hops_of("event:4") == [hop]


def test_an_admin_share_without_its_logon_is_a_hop_from_the_address_the_share_record_names():
    host = "FS-001.northstar.example"
    events = [
        ev(1, 5140, host, 0, subjectUser="daniel.roy", subjectDomain="NORTHSTAR", ipAddress="203.0.113.69", shareName="\\\\*\\ADMIN$"),
        ev(2, 7045, host, 1, base=SCM, serviceName="NSLabUpdater-S04"),
    ]
    [hop] = build_lineage(events).hops.values()
    assert hop["kind"] == "remote-service" and hop["from"]["ip"] == "203.0.113.69" and hop["from"]["external"]
    assert hop["evidence"] == ["service NSLabUpdater-S04 installed 1 min after (7045)"] and hop["confidence"] == STRONG


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
