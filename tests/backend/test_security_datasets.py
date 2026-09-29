"""
tools/security_datasets.py: OTRF Security-Datasets' atomic Windows datasets read into the rows an
.evtx of the same events gives, on synthetic records of the three shapes the datasets were shipped in.
"""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import security_datasets as S  # noqa: E402

SYSMON_1 = {
    "SourceName": "Microsoft-Windows-Sysmon",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "Hostname": "WORKSTATION5.theshire.local",
    "EventID": 1,
    "Message": "Process Create:\r\nRuleName: -\r\nUtcTime: 2020-10-19 04:29:00.004\r\nProcessGuid: {1}\r\nProcessId: 42\r\n"
    "Image: C:\\Windows\\System32\\esentutl.exe\r\nCommandLine: esentutl.exe /y /vss C:\\Windows\\System32\\config\\SAM /d sam",
    "UtcTime": "2020-10-19 04:29:00.004",
    "ProcessGuid": "{1}",
    "ProcessId": "42",
    "Image": "C:\\Windows\\System32\\esentutl.exe",
    "CommandLine": "esentutl.exe /y /vss C:\\Windows\\System32\\config\\SAM /d sam",
}


def _zip(tmp: Path, name: str, records: list[dict], junk: bool = False) -> Path:
    path = tmp / f"{name}.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(f"{name}.json", "\n".join(json.dumps(r) for r in records) + "\n")
        if junk:
            zf.writestr(f"__MACOSX/._{name}.json", b"\x00\x05\x16\x07binary")
    return path


def test_later_nxlog_shape_takes_its_offset_from_sysmon(tmp_path: Path) -> None:
    # the lab's clock is 8 hours ahead of UTC, and says so nowhere but in Sysmon's own UtcTime
    security = {
        "SourceName": "Microsoft-Windows-Security-Auditing",
        "Channel": "Security",
        "Hostname": "WORKSTATION5.theshire.local",
        "EventID": 4688,
        "TimeCreated": "2020-10-19 12:29:01.500",
        "Level": "0",
        "Keywords": "0x8020000000000000",
        "Message": "A new process has been created.",
        "NewProcessName": "C:\\Windows\\System32\\esentutl.exe",
        "CommandLine": "esentutl.exe /y /vss C:\\Windows\\System32\\config\\SAM /d sam",
    }
    sysmon = {**SYSMON_1, "TimeCreated": "2020-10-19 12:29:00.013", "Level": "4", "Keywords": "0x8000000000000000"}
    path = _zip(tmp_path, "cmd_sam_copy_esentutl", [sysmon, security], junk=True)
    read = S.Read()
    rows = list(S.rows([path], include_raw=False, read=read))
    assert read.records == 2 and read.unread == 0 and read.offsets == {"cmd_sam_copy_esentutl.json": 8.0}
    by_id = {r["eventId"]: r for r in rows}
    assert by_id[4688]["ts"] - by_id[1]["ts"] == 1_496  # both in UTC: 12:29:01.500 - 8 h and Sysmon's 04:29:00.004
    assert by_id[4688]["computer"] == "WORKSTATION5.theshire.local"
    assert "esentutl" in json.dumps(by_id[4688]).lower()
    assert "TimeCreated" not in json.dumps(by_id[4688].get("data") or {})


def test_winlogbeat_shape(tmp_path: Path) -> None:
    rec = {
        "@timestamp": "2019-03-19T17:14:25.901Z",
        "event_id": 4104,
        "log_name": "Microsoft-Windows-PowerShell/Operational",
        "source_name": "Microsoft-Windows-PowerShell",
        "computer_name": "HR001.shire.com",
        "record_number": "1999",
        "level": "Verbose",
        "event_data": {"ScriptBlockText": "Invoke-Mimikatz -Command sekurlsa::pth", "MessageNumber": "1", "MessageTotal": "1"},
        "user": {"identifier": "S-1-5-21-1-2-3-1104"},
    }
    path = tmp_path / "empire_mimikatz_opth.json"
    path.write_text(json.dumps(rec) + "\n")
    read = S.Read()
    (row,) = list(S.rows([path], include_raw=False, read=read))
    assert read.shapes == {"winlogbeat": 1}
    assert row["eventId"] == 4104 and row["computer"] == "HR001.shire.com"
    assert "sekurlsa::pth" in json.dumps(row)


def test_datasets_read_labels_and_host_files(tmp_path: Path) -> None:
    meta = tmp_path / S.METADATA
    meta.mkdir(parents=True)
    host = tmp_path / "datasets/atomic/windows/credential_access/host"
    host.mkdir(parents=True)
    _zip(host, "cmd_sam_copy_esentutl", [SYSMON_1])
    link = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/"
    (meta / "SDWIN-201019002900.yaml").write_text(
        "id: SDWIN-201019002900\ntitle: SAM Copy via Esentutl VSS\n"
        "attack_mappings:\n  - technique: T1003\n    sub-technique: '002'\n    tactics:\n      - TA0006\n"
        f"files:\n  - type: Host\n    link: {link}cmd_sam_copy_esentutl.zip\n  - type: Host\n    link: {link}gone.zip\n"
    )
    (d,) = S.datasets(tmp_path)
    assert d.id == "SDWIN-201019002900" and d.techniques == frozenset({"T1003.002"}) and d.tactics == ("Credential Access",)
    assert [f.name for f in d.files] == ["cmd_sam_copy_esentutl.zip"]
    assert d.missing == ["datasets/atomic/windows/credential_access/host/gone.zip"]
