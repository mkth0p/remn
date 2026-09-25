"""The defects EVTX-ATTACK-SAMPLES exposed (docs/reviews/2026-09-23-evtx-attack-samples.md), each held
fixed here: the server store keeps every field the parser writes, both engines compare IPv6 ranges,
the parser names access rights and fills in what older logs leave out about a parent process, and the
Sigma converter reads classic Data, "-" placeholders and aliased empty checks the way the rules mean."""

from __future__ import annotations

import copy
import uuid

import pytest
import yaml

from services.parsers import evtx_parser
from services.rules import sigma
from services.store import rules as R
from services.store.casestore import EVENT_COLUMNS, PARSER_SOURCES, StoreRegistry
from services.store.writers import EventWriter


@pytest.fixture
def store(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    st = reg.get(str(uuid.uuid4()))
    yield st
    reg.close_all()


def _event(event_id: int, provider: str, channel: str, data: dict, ts: str = "2026-09-01T22:13:40.123456Z") -> dict:
    return {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": provider}},
                "EventID": event_id,
                "TimeCreated": {"#attributes": {"SystemTime": ts}},
                "EventRecordID": 1,
                "Channel": channel,
                "Computer": "WS01",
            },
            "EventData": data,
        }
    }


def _fired(store, rows: list[dict], rule: dict, settings: dict | None = None) -> list[dict]:
    w = EventWriter(store, 1)
    for r in rows:
        w.add(copy.deepcopy(r))
    w.flush()
    return R.run_rule(store, rule, settings or {})


# ---------------------------------------------------------------------------
# the server store and the SQL engine
# ---------------------------------------------------------------------------
def test_every_field_the_parser_writes_has_a_column():
    cols = {n for n, _ in EVENT_COLUMNS}
    assert set(evtx_parser.FIELD_MAP.values()) - {"dataList"} <= cols


def test_a_rule_on_a_parser_field_matches_on_the_server_as_in_the_browser(store):
    """Password Policy Enumerated reads accessList and objectServer; the store used to drop both."""
    row = evtx_parser.flatten(
        _event(
            4661,
            "Microsoft-Windows-Security-Auditing",
            "Security",
            {"ObjectServer": "Security Account Manager", "ObjectType": "SAM_DOMAIN", "AccessList": "%%5392\r\n\t\t\t\t%%5393"},
        )
    )
    rule = {
        "id": "t",
        "title": "t",
        "severity": "medium",
        "source": "events",
        "where": {"eventId": 4661, "accessList|contains": "%%5392", "objectServer": "Security Account Manager"},
    }
    assert len(_fired(store, [row], rule)) == 1
    # and a `not` on a parser field no longer passes everything: startModule '' is false when it has a value
    thread = evtx_parser.flatten(
        _event(
            8,
            "Microsoft-Windows-Sysmon",
            "Microsoft-Windows-Sysmon/Operational",
            {"SourceImage": "C:\\x.exe", "TargetImage": "C:\\Windows\\System32\\lsass.exe", "StartModule": "C:\\Windows\\System32\\ntdll.dll"},
        )
    )
    rule2 = {"id": "t2", "title": "t", "severity": "high", "source": "events", "where": {"eventId": 8, "targetImage|endswith": "lsass.exe", "startModule": ""}}
    assert _fired(store, [thread], rule2) == []


def test_a_store_written_before_the_columns_gets_them_filled_from_the_event_data(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    key = str(uuid.uuid4())
    st = reg.get(key)
    row = evtx_parser.flatten(_event(5136, "Microsoft-Windows-Security-Auditing", "Security", {"ObjectClass": "groupPolicyContainer", "AccessList": "-"}))
    w = EventWriter(st, 1)
    w.add(row)
    w.flush()
    # as an older store: the column does not exist yet
    st._con.execute('ALTER TABLE events DROP COLUMN "objectClass"')
    reg.close_all()
    reg2 = StoreRegistry()
    reg2.configure(tmp_path / "cases")
    st2 = reg2.get(key)
    assert st2.cursor().execute('SELECT "objectClass", "accessList" FROM events').fetchone() == ("groupPolicyContainer", None)
    assert PARSER_SOURCES["objectClass"] == ["ObjectClass"]
    reg2.close_all()


@pytest.mark.parametrize(
    ("ip", "internal"),
    [
        ("fe80::80ac:4126:fa58:1b81%10", True),
        ("fc00:1::5", True),
        ("::1", True),
        ("2001:db8::1", False),
        ("10.1.2.3", True),
        ("203.0.113.9", False),
    ],
)
def test_the_sql_engine_compares_ipv6_ranges_from_the_case_settings(store, ip, internal):
    row = {"eventId": 4624, "ts": 1, "ipAddress": ip, "logonType": 10, "channel": "Security"}
    rule = {"id": "t", "title": "t", "severity": "high", "source": "events", "where": {"eventId": 4624, "ipAddress|nin_setting": "internal_ips"}}
    settings = {"internal_ips": ["10.0.0.0/8", "::1", "fe80::/10", "fc00::/7"]}
    assert (len(_fired(store, [row], rule, settings)) == 0) is internal


# ---------------------------------------------------------------------------
# the parser
# ---------------------------------------------------------------------------
def test_access_rights_are_named_after_their_codes():
    row = evtx_parser.flatten(
        _event(
            5145,
            "Microsoft-Windows-Security-Auditing",
            "Security",
            {"ShareName": "\\\\*\\IPC$", "RelativeTargetName": "svcctl", "AccessList": "%%1538\r\n\t\t\t\t%%4416\r\n\t\t\t\t%%4417"},
        )
    )
    assert row["accessList"].startswith("%%1538") and "WriteData (or AddFile)" in row["accessList"] and "READ_CONTROL" in row["accessList"]
    assert evtx_parser.render_access_list("-") == "-" and evtx_parser.render_access_list("%%9999") == "%%9999"


def test_sysmon_25_keeps_its_type():
    row = evtx_parser.flatten(
        _event(25, "Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", {"Image": "C:\\x.exe", "Type": "Image is replaced"})
    )
    assert row["typeName"] == "Image is replaced" and row.get("type") is None


def test_an_older_log_gets_the_parent_filled_in_from_the_parents_own_event():
    lineage = evtx_parser.Lineage()
    sysmon = "Microsoft-Windows-Sysmon"
    chan = "Microsoft-Windows-Sysmon/Operational"
    parent = evtx_parser.flatten(_event(1, sysmon, chan, {"ProcessGuid": "{A}", "Image": "C:\\RogueWinRM.exe", "User": "NT AUTHORITY\\LOCAL SERVICE"}))
    child = evtx_parser.flatten(
        _event(1, sysmon, chan, {"ProcessGuid": "{B}", "ParentProcessGuid": "{A}", "Image": "C:\\Windows\\System32\\cmd.exe", "User": "NT AUTHORITY\\SYSTEM"})
    )
    for r in (parent, child):
        lineage.apply(r)
    assert child["data"]["ParentUser"] == "NT AUTHORITY\\LOCAL SERVICE" and "ParentUser" in child["enriched"]
    # a log that carries ParentUser keeps its own value
    own = evtx_parser.flatten(_event(1, sysmon, chan, {"ProcessGuid": "{C}", "ParentProcessGuid": "{A}", "ParentUser": "CORP\\bob", "User": "CORP\\bob"}))
    lineage.apply(own)
    assert own["data"]["ParentUser"] == "CORP\\bob" and "enriched" not in own

    sec = "Microsoft-Windows-Security-Auditing"
    wmi = evtx_parser.flatten(
        _event(
            4688,
            sec,
            "Security",
            {"NewProcessName": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "NewProcessId": "0xAE8", "ProcessId": "0x2f0"},
            "2026-09-01T22:15:49.645Z",
        )
    )
    calc = evtx_parser.flatten(
        _event(
            4688,
            sec,
            "Security",
            {"NewProcessName": "C:\\Windows\\System32\\calc.exe", "NewProcessId": "0xb10", "ProcessId": "0xae8"},
            "2026-09-01T22:15:49.676Z",
        )
    )
    for r in (wmi, calc):
        lineage.apply(r)
    assert calc["parentProcessName"].endswith("WmiPrvSE.exe") and "4688" in calc["enriched"]


def test_a_process_access_carries_the_signer_of_its_source_from_the_same_log():
    lineage = evtx_parser.Lineage()
    sysmon, chan = "Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational"
    exe = "C:\\Users\\u\\AppData\\Local\\Temp\\setup.exe"

    def load(guid, image, loaded, signed, signature="", status="Valid"):
        return evtx_parser.flatten(
            _event(
                7,
                sysmon,
                chan,
                {"ProcessGuid": guid, "Image": image, "ImageLoaded": loaded, "Signed": signed, "Signature": signature, "SignatureStatus": status},
            )
        )

    def access(guid, image):
        return evtx_parser.flatten(
            _event(
                10,
                sysmon,
                chan,
                {"SourceProcessGUID": guid, "SourceImage": image, "TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": "0x1410"},
            )
        )

    rows = [
        # an installer validly signed by its vendor, whose DLLs are signed too
        load("{A}", exe, exe, "true", "Avira Operations GmbH & Co. KG"),
        load("{A}", exe, "C:\\Windows\\System32\\kernel32.dll", "true", "Microsoft Windows"),
        access("{A}", exe),
        # a signed program that loaded an unsigned DLL first is vouched for by nothing
        load("{B}", exe, exe, "true", "Avast Software s.r.o."),
        load("{B}", exe, "C:\\Users\\u\\AppData\\Local\\Temp\\version.dll", "false", status="Unavailable"),
        access("{B}", exe),
        # an executable whose signature Sysmon could not verify, and one never seen loading
        load("{C}", exe, exe, "false", status="Unavailable"),
        access("{C}", exe),
        access("{D}", exe),
    ]
    for r in rows:
        lineage.apply(r)
    assert rows[2]["sourceSigner"] == "Avira Operations GmbH & Co. KG" and "sourceSigner" in rows[2]["enriched"]
    assert [r.get("sourceSigner") for r in (rows[5], rows[7], rows[8])] == [None, None, None]


# ---------------------------------------------------------------------------
# the Sigma converter and the packs it wrote before
# ---------------------------------------------------------------------------
def _convert(detection: dict, logsource: dict) -> dict:
    doc = {
        "title": "t",
        "id": "11111111-1111-1111-1111-111111111111",
        "level": "high",
        "logsource": {"product": "windows", **logsource},
        "detection": detection,
    }
    out = sigma.convert_text(yaml.safe_dump(doc))[0]
    assert out["ok"], out
    return out["rule"]["where"]


def test_the_converter_reads_classic_data_dashes_and_aliased_empty_checks_as_meant():
    assert (
        _convert({"sel": {"EventID": 15457, "Data|contains": "xp_cmdshell"}, "condition": "sel"}, {"service": "application"})["message|contains"]
        == "xp_cmdshell"
    )
    rotten = _convert({"sel": {"EventID": 4624, "WorkstationName": "-"}, "condition": "sel"}, {"service": "security"})
    assert rotten["data.WorkstationName"] == "-" and "workstation" not in rotten
    conhost = _convert(
        {"sel": {"ParentImage|endswith": "\\conhost.exe"}, "filter": {"Image": None}, "condition": "sel and not filter"}, {"category": "process_creation"}
    )
    assert conhost["not"] == {"image|exists": False, "processName|exists": False}
    parent = _convert({"sel": {"ParentImage": ["-", ""]}, "condition": "sel"}, {"category": "process_creation"})
    assert {"data.ParentImage": "-"} in parent["any_of_2"] and {"parentImage": "", "parentProcessName": ""} in parent["any_of_2"]
    assert _convert({"sel": {"Type": "Image is replaced"}, "condition": "sel"}, {"category": "process_tampering"})["typeName"] == "Image is replaced"


def test_the_shipped_packs_are_already_migrated():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "tools" / "migrate_community_packs.py"
    spec = importlib.util.spec_from_file_location("migrate_community_packs", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.main(["--check"]) == 0
    # and the migration writes what the converter now writes
    old = {"any_of": [{"parentImage|exists": False}, {"parentProcessName|exists": False}, {"parentImage|in": ["-", ""]}, {"parentProcessName|in": ["-", ""]}]}
    new = mod.migrate(old)["any_of"]
    assert {"parentImage|exists": False, "parentProcessName|exists": False} in new and {"parentImage": "", "parentProcessName": ""} in new
    assert {"data.ParentImage": "-"} in new and {"data.ParentProcessName": "-"} in new
    assert mod.migrate({"dataList|contains": "x", "type": "Image is replaced"}) == {"message|contains": "x", "typeName": "Image is replaced"}
