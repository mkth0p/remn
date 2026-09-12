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

    shimcache = (b"ControlSet,CacheEntryPosition,Path,LastModifiedTimeUTC,Executed,Duplicate,SourceFile\n" b"1,0,C:\\Users\\Public\\svc.exe,2026-08-30 12:00:00,Yes,False,SYSTEM\n")
    row = parse(tmp_path, shimcache, "ProgramExecution/20260905_AppCompatCache.csv")[0]
    assert row["artifactType"] == "shimcache" and row["image"] == "C:\\Users\\Public\\svc.exe" and row["data"]["Executed"] == "Yes"

    recmd = (
        b"HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,ValueData,ValueData2,ValueData3,Comment,Recursive,Deleted,LastWriteTimestamp,PluginDetailFile\n"
        b"C:\\Windows\\System32\\config\\SOFTWARE,Software,Run keys,Autoruns,Microsoft\\Windows\\CurrentVersion\\Run,Dropper,RegSz,\"\"\"C:\\Users\\Public\\svc.exe\"\" -k\",,,,,False,2026-08-30 12:00:00,\n"
    )
    row = parse(tmp_path, recmd, "Registry/20260905_RECmd_Batch_Kroll_Output.csv")[0]
    assert row["artifactType"] == "registry" and row["targetObject"] == "Microsoft\\Windows\\CurrentVersion\\Run"
    assert row["name"] == "Dropper" and row["image"] == '"C:\\Users\\Public\\svc.exe" -k'


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
        z.writestr("results/Windows.System.Services.json", json.dumps({"Name": "SyncHelper", "DisplayName": "Sync Helper", "PathName": "C:\\Users\\Public\\svc.exe -k", "StartMode": "Auto", "State": "Running"}) + "\n")
        z.writestr(
            "results/Windows.EventLogs.Evtx.json",
            json.dumps({"System": {"Provider": {"Name": "Microsoft-Windows-Security-Auditing"}, "EventID": {"Value": 4688}, "TimeCreated": {"SystemTime": "2026-08-19T01:35:00Z"}, "Channel": "Security", "Computer": "WS01", "EventRecordID": 7}, "EventData": {"NewProcessName": "C:\\Users\\jdoe\\Downloads\\upd.exe", "SubjectUserName": "jdoe"}, "Message": "A new process has been created"}) + "\n",
        )
        z.writestr("results/Windows.Network.Netstat.json", json.dumps({"Pid": 4242, "Name": "upd.exe", "Status": "ESTAB", "Laddr": {"IP": "10.0.0.5", "Port": 51000}, "Raddr": {"IP": "198.51.100.7", "Port": 443}}) + "\n")

    source = PackageSource("Collection-WS01.zip", None, out.getvalue(), str(tmp_path), ParseContext(analyze_attachments=False))
    rows = list(source)
    by_type: dict[str, list] = {}
    for row in rows:
        by_type.setdefault(row.get("artifactType") or row["type"], []).append(row)

    assert source.triage is True, "the drive under uploads/ is read by dissect"
    assert any(r.get("serviceName") == "SyncHelper" and r["sourceFile"].startswith("results/") for r in by_type["service"])
    assert any(r.get("serviceName") == "Spooler" and r["sourceFile"].startswith("triage!/") for r in by_type["service"])
    event = by_type["event-export"][0]
    assert event["eventId"] == 4688 and event["recordId"] == 7 and event["targetUser"] == "jdoe" and event["recordKind"] == "event"
    net = by_type["connection"][0]
    assert net["destinationIp"] == "198.51.100.7" and net["destinationPort"] == 443 and net["sourceIp"] == "10.0.0.5"


# ---- DFIR-ORC -----------------------------------------------------------------------------
def test_an_orc_archive_is_read_through_its_csv_manifests(tmp_path):
    py7zr = pytest.importorskip("py7zr")

    getthis = (
        "ComputerName,VolumeID,ParentFRN,FRN,FullName,SampleName,SizeInBytes,MD5,SHA1,FindMatch,ContentType,CreationDate,LastModificationDate,LastAccessDate,LastAttrChangeDate,FileNameCreationDate,FileNameLastModificationDate,FileNameLastAccessDate,FileNameLastAttrModificationDate,AttrType,AttrName,AttrID,SnapshotID,SHA256,SSDeep,YaraRules\n"
        "WS01,0x1,0x5,0x26,\\Users\\jdoe\\Downloads\\upd.exe,0000000000000026_upd.exe_data,12345," + "b" * 32 + "," + "a" * 40 + ",Name=*.exe,data,08/30/2026 12:00:00.000,09/02/2026 08:00:00.000,09/02/2026 08:00:00.000,09/02/2026 08:00:00.000,,,,,$DATA,,0,,{}" + "c" * 64 + ",,\n"
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

    assert {f["name"] for f in source.files} >= {"ORC_WS01_20260905_General.7z!/GetThis.csv", "ORC_WS01_20260905_General.7z!/NTFSInfo_C.csv", "JobStatistics.csv"}
    sample = next(r for r in files if "upd.exe" in str(r.get("path")))
    assert sample["hashes"] == "SHA256=" + "c" * 64 + ",SHA1=" + "a" * 40 + ",MD5=" + "b" * 32
    assert sample["ts"] == timestamp_utc("09/02/2026 08:00:00.000") and sample["recordKind"] == "event"
    listed = next(r for r in files if "svc.exe" in str(r.get("path")))
    assert listed["path"] == "\\Users\\Public\\svc.exe"
    assert not [p for p in Path(tmp_path).iterdir() if p.suffix == ".7z"], "the expanded archive is removed with the parse"
