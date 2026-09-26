"""Disk artifacts on the case timeline, each time with what it means.

The $MFT, the USN journal, prefetch run history and exported event logs used to arrive as thin rows
with one time or none. Every fixture here is synthetic and shaped like the documented output of the
tool named (MFTECmd, PECmd, EvtxECmd, Velociraptor, dissect); nothing was collected from a real
machine.
"""

from __future__ import annotations

import csv
import io
import json
import zipfile

from services.ingest.package import PackageSource
from services.parsers import collection, evtx_parser, triage
from services.parsers.collection import normalize, normalize_rows, records, timestamp_utc
from services.parsers.mail.common import ParseContext

CTX = {"host": "WS01"}

MFT_HEADER = (
    "EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentSequenceNumber,ParentPath,FileName,Extension,FileSize,ReferenceCount,"
    "ReparseTarget,IsDirectory,HasAds,IsAds,SI<FN,uSecZeros,Copied,SiFlags,NameType,Created0x10,Created0x30,LastModified0x10,"
    "LastModified0x30,LastRecordChange0x10,LastRecordChange0x30,LastAccess0x10,LastAccess0x30,UpdateSequenceNumber,"
    "LogfileSequenceNumber,SecurityId,ObjectIdFileDroid,LoggedUtilStream,ZoneIdContents\n"
)
USN_HEADER = "Name,Extension,EntryNumber,SequenceNumber,ParentEntryNumber,ParentSequenceNumber,ParentPath,UpdateSequenceNumber,UpdateTimestamp,UpdateReasons,FileAttributes,OffsetToData,SourceFile\n"
PECMD_HEADER = (
    "Note,SourceFilename,SourceCreated,SourceModified,SourceAccessed,ExecutableName,Hash,Size,Version,RunCount,LastRun,"
    "PreviousRun0,PreviousRun1,PreviousRun2,PreviousRun3,PreviousRun4,PreviousRun5,PreviousRun6,"
    "Volume0Name,Volume0Serial,Volume0Created,Directories,FilesLoaded,ParsingError\n"
)
EVTXECMD_HEADER = (
    "RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,ProcessId,ThreadId,Computer,UserId,MapDescription,"
    "ChunkNumber,UserName,RemoteHost,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,"
    "ExecutableInfo,HiddenRecord,SourceFile,Keywords,ExtraDataOffset,Payload\n"
)


def mft_line(entry: int, name: str, si: tuple[str, str, str, str], fn: tuple[str, str, str, str] = ("", "", "", ""), flags=("False", "False")) -> str:
    """One MFTECmd $MFT row. si and fn are (created, modified, record changed, accessed)."""
    cells = [str(entry), "1", "True", "5", "5", ".\\Users\\jdoe\\Downloads", name, "." + name.rsplit(".", 1)[-1], "1024", "1", "", "False", "False", "False"]
    cells += [flags[0], flags[1], "False", "Archive", "Windows"]
    cells += [si[0], fn[0], si[1], fn[1], si[2], fn[2], si[3], fn[3]]
    cells += ["0", "0", "256", "", "", ""]
    return ",".join(cells) + "\n"


def parse(tmp_path, body: str, name: str) -> list[dict]:
    path = tmp_path / "member.csv"
    path.write_text(body, encoding="utf-8")
    return [row for i, raw in enumerate(records(str(path), name, {})) for row in normalize_rows(raw, name, i, CTX)]


def ms(text: str) -> int:
    value = timestamp_utc(text)
    assert value is not None
    return value


# ---- 1. MFTECmd $J: the USN change journal ------------------------------------------------------
def test_usn_rows_have_their_time_their_path_and_what_changed(tmp_path):
    body = USN_HEADER + (
        "upd.exe,.exe,42,3,5,5,.\\Users\\jdoe\\Downloads,1000,2026-09-01 10:00:00.1234567,FileCreate|Close,Archive,0,C:\\$Extend\\$J\n"
        "notes.txt,.txt,77,1,9,1,,1048,2026-09-01 10:05:00.0000001,DataExtend|DataOverwrite|Close,Archive,64,C:\\$Extend\\$J\n"
    )
    created, changed = parse(tmp_path, body, "FileSystem/20260905_MFTECmd_$J_Output.csv")

    # before: recordKind observation, ts None, path None
    assert created["artifactType"] == "usn" and created["recordKind"] == "event"
    assert created["ts"] == ms("2026-09-01 10:00:00.1234567")
    assert created["path"] == ".\\Users\\jdoe\\Downloads\\upd.exe" and created["name"] == "upd.exe"
    assert created["operation"] == "FileCreate|Close", "the reasons are what a rule reads"
    assert created["description"] == "USN FileCreate|Close"
    assert created["summary"] == "usn: .\\Users\\jdoe\\Downloads\\upd.exe (FileCreate|Close)"
    # a $J parsed without the $MFT has no parent path: the name alone is still the path
    assert changed["path"] == "notes.txt" and changed["operation"] == "DataExtend|DataOverwrite|Close"


# ---- 2. MFTECmd $MFT: every MACB time, $SI and $FN, and timestomping leads ----------------------
def test_an_mft_entry_is_one_row_per_distinct_time_saying_which_time_it_is(tmp_path):
    body = MFT_HEADER + mft_line(
        42,
        "upd.exe",
        si=("2026-09-01 10:00:00.1234567", "2026-09-01 10:00:00.1234567", "2026-09-02 08:00:00.5555555", "2026-09-03 09:00:00.7777777"),
    )
    rows = parse(tmp_path, body, "FileSystem/20260905_MFTECmd_$MFT_Output.csv")

    # before: a single row, ts = Created0x10, nothing saying it was the creation time
    assert [(r["ts"], r["description"]) for r in rows] == [
        (ms("2026-09-01 10:00:00.1234567"), "SI created, modified"),
        (ms("2026-09-02 08:00:00.5555555"), "SI changed"),
        (ms("2026-09-03 09:00:00.7777777"), "SI accessed"),
    ], "$FN columns left empty (the same as $SI) add no rows"
    assert rows[0]["summary"] == "mft: .\\Users\\jdoe\\Downloads\\upd.exe (SI M..B)"
    assert rows[1]["summary"].endswith("(SI ..C.)") and rows[2]["summary"].endswith("(SI .A..)")
    assert all(r["artifactType"] == "mft" and r["recordKind"] == "event" and r["sourceIndex"] == 0 for r in rows)
    assert all(r["path"] == ".\\Users\\jdoe\\Downloads\\upd.exe" for r in rows)
    assert "_timestompHints" not in rows[0]["data"]
    # the single-row reader keeps giving the creation time, as it did
    raw = next(records(str(tmp_path / "member.csv"), "FileSystem/20260905_MFTECmd_$MFT_Output.csv", {}))
    assert normalize(raw, "FileSystem/20260905_MFTECmd_$MFT_Output.csv", 0, CTX)["ts"] == ms("2026-09-01 10:00:00.1234567")


def test_fn_times_that_differ_from_si_are_rows_and_a_backdated_si_is_a_lead(tmp_path):
    # $SI says 2019 with no sub-second part; $FN, which the timestomping API cannot reach, says 2026
    body = MFT_HEADER + mft_line(
        43,
        "svc.dll",
        si=("2019-03-02 08:00:00.0000000", "2019-03-02 08:00:00.0000000", "2026-09-01 10:00:07.2222222", "2026-09-01 10:00:07.2222222"),
        fn=("2026-09-01 10:00:05.1111111", "2026-09-01 10:00:05.1111111", "2026-09-01 10:00:05.1111111", ""),
    )
    rows = parse(tmp_path, body, "FileSystem/20260905_MFTECmd_$MFT_Output.csv")

    assert [(r["ts"], r["description"]) for r in rows] == [
        (ms("2019-03-02 08:00:00"), "SI created, modified"),
        (ms("2026-09-01 10:00:07.2222222"), "SI changed, accessed"),
        (ms("2026-09-01 10:00:05.1111111"), "FN created, modified, changed"),
    ]
    assert rows[2]["summary"].startswith("mft: .\\Users\\jdoe\\Downloads\\svc.dll (FN M.CB)")
    hint = "$SI created is earlier than $FN created; $SI times have no sub-second part"
    assert rows[0]["data"]["_timestompHints"] == hint
    assert all(r["summary"].endswith("possible timestomping: " + hint) for r in rows)


def test_mftecmd_own_timestomp_flags_are_honoured(tmp_path):
    body = MFT_HEADER + mft_line(44, "a.txt", si=("2026-09-01 10:00:00.1234567",) * 4, flags=("True", "False"))
    (row,) = parse(tmp_path, body, "FileSystem/20260905_MFTECmd_$MFT_Output.csv")
    assert row["description"] == "SI created, modified, changed, accessed" and row["summary"].endswith(
        "(SI MACB); possible timestomping: $SI created is earlier than $FN created"
    )


def test_the_macb_helper_orders_and_merges():
    t = 1_000
    values = {"SI": {"M": t + 5, "A": t + 9, "C": t + 5, "B": t}, "FN": {"M": t + 5, "A": None, "C": t + 1, "B": t + 1}}
    assert collection.macb_times(values) == [
        (t, "SI created", "SI ...B"),
        (t + 5, "SI modified, changed", "SI M.C."),
        (t + 9, "SI accessed", "SI .A.."),
        (t + 1, "FN created, changed", "FN ..CB"),
    ]


# ---- 3. PECmd: the earlier runs as well as the last -----------------------------------------------
def test_pecmd_previous_runs_are_execution_rows(tmp_path):
    body = PECMD_HEADER + (
        ",C:\\Windows\\Prefetch\\UPD.EXE-1A2B3C4D.pf,2026-09-01 10:00:00.0000000,2026-09-03 08:00:00.0000000,2026-09-03 08:00:00.0000000,"
        "UPD.EXE,1A2B3C4D,12345,Windows 10 or 11,4,2026-09-03 08:00:00.1234567,"
        "2026-09-02 07:00:00.0000000,2026-09-01 12:00:00.0000000,2026-09-01 10:00:01.0000000,,,,,"
        '\\VOLUME{01d9},01D9,2025-01-01 00:00:00.0000000,"\\VOLUME{01d9}\\USERS\\JDOE\\DOWNLOADS",'
        '"\\VOLUME{01d9}\\WINDOWS\\SYSTEM32\\NTDLL.DLL, \\VOLUME{01d9}\\USERS\\JDOE\\DOWNLOADS\\UPD.EXE",False\n'
    )
    rows = parse(tmp_path, body, "ProgramExecution/20260905_PECmd_Output.csv")

    # before: one row, LastRun only
    assert [(r["ts"], r["description"]) for r in rows] == [
        (ms("2026-09-03 08:00:00.1234567"), "prefetch last run"),
        (ms("2026-09-02 07:00:00"), "prefetch earlier run"),
        (ms("2026-09-01 12:00:00"), "prefetch earlier run"),
        (ms("2026-09-01 10:00:01"), "prefetch earlier run"),
    ]
    assert all(r["artifactType"] == "prefetch" and r["recordKind"] == "event" for r in rows)
    assert {r["image"] for r in rows} == {"\\VOLUME{01d9}\\USERS\\JDOE\\DOWNLOADS\\UPD.EXE"}
    assert {r["processName"] for r in rows} == {"UPD.EXE"}


# ---- 4. EvtxECmd: the Payload read like the native parser reads EventData -------------------------
def _payload(pairs: dict[str, str | None]) -> str:
    data = [{"@Name": k, "#text": v} if v is not None else {"@Name": k} for k, v in pairs.items()]
    return json.dumps({"EventData": {"Data": data}})


def _evtxecmd(tmp_path, record_id: int, event_id: int, provider: str, channel: str, payload: str) -> dict:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(
        [
            record_id,
            record_id,
            "2026-08-19 01:35:00.0000000",
            event_id,
            "Info",
            provider,
            channel,
            4,
            8,
            "WS01",
            "S-1-5-18",
            "mapped",
            1,
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]
        + ["", "False", "C:\\Windows\\System32\\winevt\\Logs\\x.evtx", "", 0, payload]
    )
    (row,) = parse(tmp_path, EVTXECMD_HEADER + out.getvalue(), "EventLogs/20260905_EvtxECmd_Output.csv")
    return row


def _native(event_id: int, provider: str, pairs: dict[str, str | None]) -> dict:
    event = {"Event": {"System": {"EventID": event_id, "Provider": {"#attributes": {"Name": provider}}}, "EventData": pairs}}
    return evtx_parser.flatten(event, include_raw=False)


def test_evtxecmd_payload_fills_the_columns_the_native_parser_fills(tmp_path):
    security = "Microsoft-Windows-Security-Auditing"
    logon = {
        "SubjectUserSid": "S-1-5-18",
        "SubjectUserName": "WS01$",
        "TargetUserName": "jdoe",
        "TargetDomainName": "CORP",
        "TargetLogonId": "0x3e7abc",
        "LogonType": "10",
        "LogonProcessName": "User32",
        "AuthenticationPackageName": "Negotiate",
        "WorkstationName": "ATTACKER",
        "IpAddress": "203.0.113.9",
        "IpPort": "50123",
        "ProcessName": "C:\\Windows\\System32\\svchost.exe",
    }
    row = _evtxecmd(tmp_path, 7, 4624, security, "Security", _payload(logon))
    native = _native(4624, security, logon)
    # before: none of these were filled from an EvtxECmd row
    for field in ("targetUser", "targetDomain", "targetLogonId", "logonType", "logonTypeName", "authPackage", "workstation", "ipAddress", "ipPort"):
        assert row[field] == native[field], field
    assert row["logonType"] == 10 and row["ipAddress"] == "203.0.113.9"
    assert row["category"] == native["category"] and row["description"] == native["description"]
    assert row["summary"] == native["summary"]
    assert row["artifactType"] == "event-export" and row["recordId"] == 7 and row["processId"] == 4 and row["userSid"] == "S-1-5-18"
    assert row["data"]["IpAddress"] == "203.0.113.9" and row["data"]["Payload"], "EventData by name, the export's own columns beside it"

    process = {
        "NewProcessName": "C:\\Users\\jdoe\\Downloads\\upd.exe",
        "CommandLine": "upd.exe -enc SQBFAFgA",
        "ParentProcessName": "C:\\Windows\\explorer.exe",
        "SubjectUserName": "jdoe",
        "TokenElevationType": None,
    }
    row = _evtxecmd(tmp_path, 8, 4688, security, "Security", _payload(process))
    native = _native(4688, security, process)
    assert row["commandLine"] == native["commandLine"] == "upd.exe -enc SQBFAFgA"
    assert row["processName"] == native["processName"] and row["parentProcessName"] == native["parentProcessName"]
    assert row["message"] == "mapped", "the export's map description stays the message"

    sysmon = "Microsoft-Windows-Sysmon"
    net = {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "DestinationIp": "198.51.100.7",
        "DestinationPort": "443",
        "Protocol": "tcp",
    }
    row = _evtxecmd(tmp_path, 9, 3, sysmon, "Microsoft-Windows-Sysmon/Operational", _payload(net))
    native = _native(3, sysmon, net)
    assert (row["image"], row["destinationIp"], row["destinationPort"]) == (native["image"], native["destinationIp"], native["destinationPort"])


def test_evtxecmd_userdata_and_unreadable_payloads(tmp_path):
    cleared = json.dumps(
        {
            "UserData": {
                "LogFileCleared": {
                    "@xmlns": "http://manifests.microsoft.com/win/2004/08/windows/eventlog",
                    "SubjectUserName": "jdoe",
                    "SubjectDomainName": "CORP",
                }
            }
        }
    )
    row = _evtxecmd(tmp_path, 10, 1102, "Microsoft-Windows-Eventlog", "Security", cleared)
    assert row["subjectUser"] == "jdoe" and row["subjectDomain"] == "CORP"
    assert "@xmlns" not in row["data"]

    broken = _evtxecmd(tmp_path, 11, 4688, "Microsoft-Windows-Security-Auditing", "Security", "{not json")
    assert broken["eventId"] == 4688 and broken["category"] == "collection:event-export" and broken.get("commandLine") is None


def test_velociraptor_event_data_is_mapped_the_same_way():
    raw = {
        "System": {
            "EventID": {"Value": 4624},
            "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
            "TimeCreated": {"SystemTime": "2026-08-19T01:35:00Z"},
            "Channel": "Security",
            "Computer": "WS01",
            "EventRecordID": 12,
            "Execution": {"ProcessID": 4, "ThreadID": 8},
        },
        "EventData": {"TargetUserName": "jdoe", "LogonType": "3", "IpAddress": "203.0.113.9"},
    }
    row = normalize(raw, "results/Windows.EventLogs.Evtx.json", 0, CTX)
    assert row["logonType"] == 3 and row["ipAddress"] == "203.0.113.9" and row["targetUser"] == "jdoe" and row["processId"] == 4


# ---- 5. dissect's $MFT and USN journal: an explicit option ----------------------------------------
def test_dissect_mft_and_usn_records_carry_their_meaning():
    std = triage.to_row(
        "mft.records", "mft", {"_type": "filesystem/ntfs/mft/std", "ts": "2026-09-01T10:00:00+00:00", "ts_type": "B", "path": "C:\\Users\\jdoe\\upd.exe"}, 0, {}
    )
    assert std["recordKind"] == "event" and std["description"] == "SI created" and std["summary"] == "mft: C:\\Users\\jdoe\\upd.exe (SI ...B)"
    fn = triage.to_row(
        "mft.records",
        "mft",
        {"_type": "filesystem/ntfs/mft/filename", "ts": "2026-09-01T10:00:00+00:00", "ts_type": "M", "path": "C:\\Users\\jdoe\\upd.exe"},
        1,
        {},
    )
    assert fn["description"] == "FN modified" and fn["summary"].endswith("(FN M...)")
    usn = triage.to_row(
        "usnjrnl",
        "usn",
        {"_type": "filesystem/ntfs/usnjrnl", "ts": "2026-09-01T10:00:00+00:00", "path": "C:\\Users\\jdoe\\upd.exe", "reason": "FILE_CREATE|CLOSE"},
        2,
        {},
    )
    assert usn["operation"] == "FILE_CREATE|CLOSE" and usn["description"] == "USN FILE_CREATE|CLOSE" and usn["ts"] is not None


def test_the_filesystem_pass_runs_only_when_asked(tmp_path, monkeypatch):
    seen: list[tuple[str, ...]] = []

    class Recorder(triage.TriagePass):
        def __iter__(self):
            seen.append(tuple(name for name, _artifact, _cap in self.functions))
            return iter(())

    monkeypatch.setattr(triage, "TriagePass", Recorder)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("C/Windows/System32/config/SYSTEM", b"regf" + bytes(64))
    blob = out.getvalue()
    for filesystem in (False, True):
        source = PackageSource("kape.zip", None, blob, str(tmp_path), ParseContext(analyze_attachments=False))
        source.filesystem = filesystem
        list(source)
    assert "mft.records" not in seen[0] and "usnjrnl" not in seen[0]
    assert seen[1][-2:] == ("usnjrnl", "mft.records"), "last, so they cannot take the other artifacts' allowance"


# ---- 6. the export ceiling: MFT and USN CSVs stream instead of being cut -------------------------
def test_a_large_mft_export_is_read_whole_in_a_package(tmp_path, monkeypatch):
    monkeypatch.setattr(collection, "MAX_PARSE_BYTES", 16 * 1024)
    body = MFT_HEADER + "".join(mft_line(i, f"f{i}.txt", si=("2026-09-01 10:00:00.1234567",) * 4) for i in range(400))
    assert len(body) > 4 * 16 * 1024
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("FileSystem/20260905_MFTECmd_$MFT_Output.csv", body)
    source = PackageSource("kape.zip", None, out.getvalue(), str(tmp_path), ParseContext(analyze_attachments=False))
    rows = list(source)
    member = next(f for f in source.files if f["name"].endswith("$MFT_Output.csv"))
    assert member["status"] == "parsed" and member["count"] == len(rows) == 400
    assert source.counts["events"] == 400 and source.ranges["eventRange"]["firstTs"] == ms("2026-09-01 10:00:00.1234567")


def test_a_json_export_still_stops_at_the_parse_limit_and_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(collection, "MAX_PARSE_BYTES", 16 * 1024)
    body = json.dumps([{"Name": f"proc{i}.exe", "Id": i, "Path": "C:\\Windows\\System32\\proc.exe"} for i in range(1000)])
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("Processes/processes.json", body)
    source = PackageSource("pkg.zip", None, out.getvalue(), str(tmp_path), ParseContext(analyze_attachments=False))
    list(source)
    member = next(f for f in source.files if f["name"].endswith("processes.json"))
    assert member["status"] == "error" and "parse limit" in member["reason"]
