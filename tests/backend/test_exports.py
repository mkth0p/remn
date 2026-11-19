"""Collections from KAPE, Velociraptor and DFIR-ORC land in the same rows as everything else.

Every fixture here is synthetic and shaped like the documented output of the tool named.
"""

from __future__ import annotations

import io
import json
import sys
import zipfile
from datetime import UTC
from pathlib import Path

import pytest

from services.ingest.package import PackageSource
from services.parsers.collection import category, normalize, records, timestamp_utc
from services.parsers.mail.common import ParseContext

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "samples" / "synthetic"))

CTX = {"host": "WS01"}


def parse(tmp_path, body: bytes, name):
    path = tmp_path / "member"
    path.write_bytes(body)
    return [normalize(raw, name, i, CTX) for i, raw in enumerate(records(str(path), name, {}))]


def test_utc_by_documentation_formats():
    from datetime import datetime

    moment = int(datetime(2026, 8, 19, 1, 34, 26, tzinfo=UTC).timestamp() * 1000)
    assert timestamp_utc("2026-08-19 01:34:26.1234567") == moment + 123, "seven fractional digits, the Zimmerman way"
    assert timestamp_utc("08/19/2026 01:34:26.000") == moment, "the DFIR-ORC way"
    assert timestamp_utc("2026-08-19T01:34:26Z") == moment, "a written zone still wins"
    assert timestamp_utc("20260819") is None, "a bare date is not a moment"


def test_numeric_dates_are_read_in_the_order_given_and_never_guessed():
    from datetime import datetime

    def at(*parts):
        return int(datetime(*parts, tzinfo=UTC).timestamp() * 1000)

    # before: day-first and minute-resolution values gave None, and 03/04 was read as 4 March
    assert timestamp_utc("13/04/2026 10:00:00") == at(2026, 4, 13, 10, 0), "a first number above 12 is the day"
    assert timestamp_utc("9/25/2026 10:00") == at(2026, 9, 25, 10, 0), "a second number above 12 is the day; seconds may be absent"
    assert timestamp_utc("03/04/2026 10:00:00") is None, "either order fits: no time rather than a guess"
    assert timestamp_utc("03/04/2026 10:00:00", day_first=True) == at(2026, 4, 3, 10, 0)
    assert timestamp_utc("03/04/2026 10:00:00", day_first=False) == at(2026, 3, 4, 10, 0)
    assert timestamp_utc("9/5/2026 1:34:26 PM", day_first=False) == at(2026, 9, 5, 13, 34, 26)
    assert timestamp_utc("03.04.2026 10:00") == at(2026, 4, 3, 10, 0), "a dotted date is always day-first"
    assert timestamp_utc("31/02/2026 10:00") is None, "not a date"


AMCACHE_HEADER = (
    "ApplicationName,ProgramId,FileKeyLastWriteTimestamp,SHA1,IsOsComponent,FullPath,Name,FileExtension,LinkDate,ProductName,Size,Version,"
    "ProductVersion,LongPathHash,BinaryType,IsPeFile,BinFileVersion,BinProductVersion,Usn,Language,Description\n"
)


def _amcache_package(tmp_path, times: list[str]) -> tuple[PackageSource, list[dict]]:
    lines = [f"Unassociated,000{i},{when},,False,C:\\Tools\\tool{i}.exe,tool{i}.exe,.exe,,,1,,,,pe64_amd64,True,,,1,0,\n" for i, when in enumerate(times)]
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("ProgramExecution/20260905_Amcache_UnassociatedFileEntries.csv", AMCACHE_HEADER + "".join(lines))
    source = PackageSource("kape.zip", None, out.getvalue(), str(tmp_path), ParseContext(analyze_attachments=False))
    return source, list(source)


def test_an_export_resaved_day_first_is_dated_in_the_order_its_own_dates_show(tmp_path):
    from datetime import datetime

    # the AmcacheParser output an analyst opened and saved again in a day-first locale
    source, rows = _amcache_package(tmp_path, ["19/08/2026 01:34", "03/04/2026 10:00", "9/5/2026 10:00"])
    assert [r["ts"] for r in rows] == [
        int(datetime(2026, 8, 19, 1, 34, tzinfo=UTC).timestamp() * 1000),
        int(datetime(2026, 4, 3, 10, 0, tzinfo=UTC).timestamp() * 1000),
        int(datetime(2026, 5, 9, 10, 0, tzinfo=UTC).timestamp() * 1000),
    ]
    assert all(r["recordKind"] == "event" for r in rows) and "note" not in source.files[0]


def test_dates_whose_order_the_export_cannot_settle_are_left_untimed_and_counted(tmp_path):
    source, rows = _amcache_package(tmp_path, ["03/04/2026 10:00", "05/06/2026 11:00", "2026-09-01 10:00:00"])
    assert [r["ts"] is None for r in rows] == [True, True, False]
    assert [r["recordKind"] for r in rows] == ["observation", "observation", "event"]
    assert rows[0]["data"]["FileKeyLastWriteTimestamp"] == "03/04/2026 10:00", "the value is kept as written"
    member = source.files[0]
    assert member["status"] == "parsed" and member["undated"] == 2
    assert "2 row(s) carry a date that reads as day-first and as month-first" in member["note"]


# ---- KAPE: Zimmerman parser CSVs, recognised by header wherever they sit -------------------
def test_pecmd_output_is_prefetch_with_the_executable_path(tmp_path):
    body = (
        b"Note,SourceFilename,SourceCreated,SourceModified,SourceAccessed,ExecutableName,Hash,Size,Version,RunCount,LastRun,PreviousRun0,Volume0Name,Volume0Serial,Volume0Created,Directories,FilesLoaded,ParsingError\n"
        b',C:\\Windows\\Prefetch\\UPD.EXE-1A2B3C4D.pf,2026-09-01 10:00:00.0000000,2026-09-02 08:00:00.0000000,2026-09-02 08:00:00.0000000,UPD.EXE,1A2B3C4D,12345,Windows 10 or 11,3,2026-09-02 08:00:00.1234567,,\\VOLUME{01d9},01D9,2025-01-01 00:00:00.0000000,"\\VOLUME{01d9}\\USERS\\JDOE\\DOWNLOADS","\\VOLUME{01d9}\\WINDOWS\\SYSTEM32\\NTDLL.DLL, \\VOLUME{01d9}\\USERS\\JDOE\\DOWNLOADS\\UPD.EXE",False\n'
    )
    rows = parse(tmp_path, body, "ProgramExecution/20260905_PECmd_Output.csv")

    row = rows[0]
    assert row["artifactType"] == "prefetch"
    assert row["processName"] == "UPD.EXE"
    assert row["image"] == "\\VOLUME{01d9}\\USERS\\JDOE\\DOWNLOADS\\UPD.EXE"
    assert row["ts"] == timestamp_utc("2026-09-02 08:00:00.1234567") and row["recordKind"] == "event"
    assert row["data"]["RunCount"] == "3"


def test_evtxecmd_output_is_events_not_observations(tmp_path):
    body = (
        b"RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,ProcessId,ThreadId,Computer,UserId,MapDescription,ChunkNumber,UserName,RemoteHost,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,ExecutableInfo,HiddenRecord,SourceFile,Keywords,ExtraDataOffset,Payload\n"
        b'7,7,2026-08-19 01:35:00.0000000,4688,Info,Microsoft-Windows-Security-Auditing,Security,4,8,WS01,S-1-5-18,A new process has been created,1,WS01\\jdoe,,NewProcessName: C:\\Users\\jdoe\\Downloads\\upd.exe,,,,,,,False,C:\\Windows\\System32\\winevt\\Logs\\Security.evtx,Audit success,0,"{}"\n'
    )
    rows = parse(tmp_path, body, "EventLogs/20260905_EvtxECmd_Output.csv")

    row = rows[0]
    assert row["recordKind"] == "event" and row["artifactType"] == "event-export"
    assert row["eventId"] == 4688 and row["channel"] == "Security" and row["recordId"] == 7
    assert row["provider"] == "Microsoft-Windows-Security-Auditing" and row["computer"] == "WS01"
    assert row["ts"] == timestamp_utc("2026-08-19 01:35:00")
    assert "upd.exe" in row["message"]


def test_amcache_shimcache_and_recmd_outputs_reach_image_and_registry_fields(tmp_path):
    amcache = (
        b"ApplicationName,ProgramId,FileKeyLastWriteTimestamp,SHA1,IsOsComponent,FullPath,Name,FileExtension,LinkDate,ProductName,Size,Version,ProductVersion,LongPathHash,BinaryType,IsPeFile,BinFileVersion,BinProductVersion,Usn,Language,Description\n"
        b"Unassociated,0006abc,2026-09-01 10:00:00,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,False,C:\\Users\\jdoe\\Downloads\\upd.exe,upd.exe,.exe,2026-08-01 00:00:00,Updater,12345,1.0,1.0,abc,pe64_amd64,True,1.0,1.0,1,0,\n"
    )
    row = parse(tmp_path, amcache, "ProgramExecution/20260905_Amcache_UnassociatedFileEntries.csv")[0]
    assert row["artifactType"] == "amcache" and row["image"] == "C:\\Users\\jdoe\\Downloads\\upd.exe"
    assert row["hashes"] == "SHA1=" + "a" * 40 and row["ts"] == timestamp_utc("2026-09-01 10:00:00")

    shimcache = (
        b"ControlSet,CacheEntryPosition,Path,LastModifiedTimeUTC,Executed,Duplicate,SourceFile\n"
        b"1,0,C:\\Users\\Public\\svc.exe,2026-08-30 12:00:00,Yes,False,SYSTEM\n"
    )
    row = parse(tmp_path, shimcache, "ProgramExecution/20260905_AppCompatCache.csv")[0]
    assert row["artifactType"] == "shimcache" and row["image"] == "C:\\Users\\Public\\svc.exe" and row["data"]["Executed"] == "Yes"

    recmd = (
        b"HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,ValueData,ValueData2,ValueData3,Comment,Recursive,Deleted,LastWriteTimestamp,PluginDetailFile\n"
        b'C:\\Windows\\System32\\config\\SOFTWARE,Software,Run keys,Autoruns,Microsoft\\Windows\\CurrentVersion\\Run,Dropper,RegSz,"""C:\\Users\\Public\\svc.exe"" -k",,,,,False,2026-08-30 12:00:00,\n'
    )
    row = parse(tmp_path, recmd, "Registry/20260905_RECmd_Batch_Kroll_Output.csv")[0]
    assert row["artifactType"] == "registry" and row["targetObject"] == "Microsoft\\Windows\\CurrentVersion\\Run"
    assert row["name"] == "Dropper" and row["image"] == '"C:\\Users\\Public\\svc.exe" -k'


def test_zimmerman_output_is_read_by_its_header_wherever_it_sits(tmp_path):
    mft = (
        "EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentSequenceNumber,ParentPath,FileName,Extension,FileSize,ReferenceCount,"
        "ReparseTarget,IsDirectory,HasAds,IsAds,SI<FN,uSecZeros,Copied,SiFlags,NameType,Created0x10,Created0x30,LastModified0x10,"
        "LastModified0x30,LastRecordChange0x10,LastRecordChange0x30,LastAccess0x10,LastAccess0x30,UpdateSequenceNumber,"
        "LogfileSequenceNumber,SecurityId,ObjectIdFileDroid,LoggedUtilStream,ZoneIdContents\n"
        "42,1,True,5,5,.\\Users\\jdoe\\Downloads,upd.exe,.exe,1024,1,,False,False,False,False,False,False,Archive,Windows,"
        "2026-09-01 10:00:00.1234567,,2026-09-01 10:00:00.1234567,,2026-09-01 10:00:00.1234567,,2026-09-01 10:00:00.1234567,,0,0,256,,,\n"
    )
    srum = "Id,Timestamp,ExeInfo,ExeInfoDescription,ExeTimestamp,SidType,Sid,UserName,UserId,AppId,BytesReceived,BytesSent,InterfaceLuid,InterfaceType,L2ProfileFlags,L2ProfileId,ProfileName\n"
    srum += "1,2026-09-02 08:00:00,\\device\\harddiskvolume3\\users\\jdoe\\downloads\\upd.exe,,,,S-1-5-21-1-2-3-1001,jdoe,7,9,1200,880000,1,IF_TYPE_ETHERNET_CSMACD,0,0,\n"
    evtxecmd = json.dumps(
        {
            "RecordNumber": 7,
            "EventRecordId": 7,
            "TimeCreated": "2026-08-19T01:35:00.0000000+00:00",
            "EventId": 4688,
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Channel": "Security",
            "Computer": "WS01",
            "MapDescription": "A new process has been created",
            "Payload": "{}",
        }
    )
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        # MFTECmd run by hand, a KAPE module folder outside the listed ones, EvtxECmd's --json output
        z.writestr("20260905_MFTECmd_$MFT_Output.csv", mft)
        z.writestr("SRUMDatabase/20260905_SrumECmd_NetworkUsages_Output.csv", srum)
        z.writestr("Output/20260905_EvtxECmd_Output.json", evtxecmd + "\n")
        z.writestr("hayabusa.csv", "Timestamp,RuleTitle,Level,Computer,Channel,EventID,RecordID,Details\n")
    source = PackageSource("kape-modules.zip", None, out.getvalue(), str(tmp_path), ParseContext(analyze_attachments=False))
    rows = list(source)
    files = {f["name"]: f for f in source.files}

    # before: each was "unsupported: no parser for this member"
    assert files["20260905_MFTECmd_$MFT_Output.csv"]["status"] == "parsed" and files["20260905_MFTECmd_$MFT_Output.csv"]["artifactType"] == "mft"
    assert any(r["artifactType"] == "mft" and r["path"] == ".\\Users\\jdoe\\Downloads\\upd.exe" for r in rows)
    assert files["SRUMDatabase/20260905_SrumECmd_NetworkUsages_Output.csv"]["status"] == "parsed"
    assert any(r["artifactType"] == "sru" and r["image"].endswith("upd.exe") for r in rows)
    assert files["Output/20260905_EvtxECmd_Output.json"]["status"] == "parsed"
    assert any(r["artifactType"] == "event-export" and r["eventId"] == 4688 and r["recordId"] == 7 for r in rows)
    # a header the parser does not know is still said to be unsupported, not read as something else
    assert files["hayabusa.csv"]["status"] == "unsupported"


# ---- Velociraptor offline collector -------------------------------------------------------
def test_velociraptor_results_are_named_after_their_artifact():
    assert category("results/Windows.System.Services.json") == "service"
    assert category("results/Windows.EventLogs.Evtx.json") == "event-export"
    assert category("results/Windows.Forensics.Prefetch.json") == "prefetch"
    assert category("results/Windows.Network.Netstat.json") == "connection"
    assert category("Collection-WS01-2026/results/Windows.Sysinternals.Autoruns.json") == "autorun"


def test_a_velociraptor_collector_zip_yields_results_and_triage_rows(tmp_path):
    from triage_fixture import write_triage

    root = write_triage(tmp_path / "drive")
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        uploads = []
        for path in sorted(root.rglob("*")):
            if path.is_file():
                rel = path.relative_to(root).as_posix().replace("C/", "C%3A/", 1)
                z.write(path, f"uploads/auto/{rel}")
                uploads.append({"vfs_path": f"auto/{rel}", "file_size": path.stat().st_size})
        z.writestr("uploads.json", "\n".join(json.dumps(u) for u in uploads) + "\n")
        # Velociraptor writes one object per line, so a real result file has many lines
        z.writestr(
            "results/Windows.System.Services.json",
            json.dumps(
                {"Name": "SyncHelper", "DisplayName": "Sync Helper", "PathName": "C:\\Users\\Public\\svc.exe -k", "StartMode": "Auto", "State": "Running"}
            )
            + "\n"
            + json.dumps(
                {"Name": "Spooler", "DisplayName": "Print Spooler", "PathName": "C:\\Windows\\System32\\spoolsv.exe", "StartMode": "Auto", "State": "Running"}
            )
            + "\n",
        )
        z.writestr(
            "results/Windows.EventLogs.Evtx.json",
            json.dumps(
                {
                    "System": {
                        "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
                        "EventID": {"Value": 4688},
                        "TimeCreated": {"SystemTime": "2026-08-19T01:35:00Z"},
                        "Channel": "Security",
                        "Computer": "WS01",
                        "EventRecordID": 7,
                    },
                    "EventData": {"NewProcessName": "C:\\Users\\jdoe\\Downloads\\upd.exe", "SubjectUserName": "jdoe"},
                    "Message": "A new process has been created",
                }
            )
            + "\n",
        )
        z.writestr(
            "results/Windows.Network.Netstat.json",
            json.dumps(
                {"Pid": 4242, "Name": "upd.exe", "Status": "ESTAB", "Laddr": {"IP": "10.0.0.5", "Port": 51000}, "Raddr": {"IP": "198.51.100.7", "Port": 443}}
            )
            + "\n",
        )

    source = PackageSource("Collection-WS01.zip", None, out.getvalue(), str(tmp_path), ParseContext(analyze_attachments=False))
    rows = list(source)
    by_type: dict[str, list] = {}
    for row in rows:
        by_type.setdefault(row.get("artifactType") or row["type"], []).append(row)

    assert source.triage is True, "the drive under uploads/ is read by dissect"
    assert any(r.get("serviceName") == "SyncHelper" and r["sourceFile"].startswith("results/") for r in by_type["service"])
    assert any(r.get("serviceName") == "Spooler" and r["sourceFile"].startswith("triage!/") for r in by_type["service"])
    velo = [r["serviceName"] for r in by_type["service"] if r["sourceFile"] == "results/Windows.System.Services.json"]
    assert velo == ["SyncHelper", "Spooler"], "a two-line result file gives two rows, not an error"
    event = by_type["event-export"][0]
    assert event["eventId"] == 4688 and event["recordId"] == 7 and event["targetUser"] == "jdoe" and event["recordKind"] == "event"
    net = by_type["connection"][0]
    assert net["destinationIp"] == "198.51.100.7" and net["destinationPort"] == 443 and net["sourceIp"] == "10.0.0.5"


# ---- DFIR-ORC -----------------------------------------------------------------------------
def test_an_orc_archive_is_read_through_its_csv_manifests(tmp_path):
    py7zr = pytest.importorskip("py7zr")

    getthis = (
        "ComputerName,VolumeID,ParentFRN,FRN,FullName,SampleName,SizeInBytes,MD5,SHA1,FindMatch,ContentType,CreationDate,LastModificationDate,LastAccessDate,LastAttrChangeDate,FileNameCreationDate,FileNameLastModificationDate,FileNameLastAccessDate,FileNameLastAttrModificationDate,AttrType,AttrName,AttrID,SnapshotID,SHA256,SSDeep,YaraRules\n"
        "WS01,0x1,0x5,0x26,\\Users\\jdoe\\Downloads\\upd.exe,0000000000000026_upd.exe_data,12345,"
        + "b" * 32
        + ","
        + "a" * 40
        + ",Name=*.exe,data,08/30/2026 12:00:00.000,09/02/2026 08:00:00.000,09/02/2026 08:00:00.000,09/02/2026 08:00:00.000,,,,,$DATA,,0,,{}"
        + "c" * 64
        + ",,\n"
    ).format("")
    ntfsinfo = (
        "ComputerName,VolumeID,FullName,File,ParentName,Extension,Attributes,SizeInBytes,CreationDate,LastModificationDate,LastAccessDate,LastAttrChangeDate,USN,FRN,ParentFRN,RecordInUse,MD5,SHA1,SHA256\n"
        "WS01,0x1,\\Users\\Public\\svc.exe,svc.exe,\\Users\\Public,.exe,A,4096,08/30/2026 12:00:00.000,08/30/2026 12:01:00.000,08/30/2026 12:01:00.000,08/30/2026 12:01:00.000,0x10,0x30,0x20,Y,,,\n"
    )
    inner = io.BytesIO()
    with py7zr.SevenZipFile(inner, "w") as z:
        z.writestr(getthis, "GetThis.csv")
        z.writestr(ntfsinfo, "NTFSInfo_C.csv")
    outer = io.BytesIO()
    with py7zr.SevenZipFile(outer, "w") as z:
        z.writestr(inner.getvalue(), "ORC_WS01_20260905_General.7z")
        z.writestr("Command,Status\nGetThis,0\n", "JobStatistics.csv")

    source = PackageSource("ORC_WS01_20260905.7z", None, outer.getvalue(), str(tmp_path), ParseContext(analyze_attachments=False))
    rows = list(source)
    files = [r for r in rows if r.get("artifactType") == "file"]

    assert {f["name"] for f in source.files} >= {
        "ORC_WS01_20260905_General.7z!/GetThis.csv",
        "ORC_WS01_20260905_General.7z!/NTFSInfo_C.csv",
        "JobStatistics.csv",
    }
    sample = next(r for r in files if "upd.exe" in str(r.get("path")))
    assert sample["hashes"] == "SHA256=" + "c" * 64 + ",SHA1=" + "a" * 40 + ",MD5=" + "b" * 32
    # 09/02 fits either order alone; the 08/30 beside it in the file says month first
    assert sample["ts"] == timestamp_utc("09/02/2026 08:00:00.000", day_first=False) and sample["recordKind"] == "event"
    listed = next(r for r in files if "svc.exe" in str(r.get("path")))
    assert listed["path"] == "\\Users\\Public\\svc.exe"
    assert not [p for p in Path(tmp_path).iterdir() if p.suffix == ".7z"], "the expanded archive is removed with the parse"
