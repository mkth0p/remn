"""Prefetch files written by Windows, one for each format version, read as a collection reads them.

The files and where they come from are listed in tests/fixtures/real/prefetch/README.md. The
expected values are not REMN's output: they are those plaso's own tests give for the same files,
those Velociraptor's golden output gives for its sample, and, where neither names a value, the
bytes read by hand at the offsets the libscca format description documents.
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from datetime import datetime

import pytest
from real_samples import FIXTURES, download

from services.ingest.package import PackageSource
from services.parsers.mail.common import ParseContext

PREFETCH = FIXTURES / "prefetch"
VELOCIRAPTOR = "https://raw.githubusercontent.com/Velocidex/velociraptor/24fedbd423dad78098bc8a3bdb8d10f65741a305"


def ms(text: str) -> int:
    return int(datetime.fromisoformat(text).timestamp() * 1000)


def read(tmp_path, paths):
    """The rows of each file and the package's entry for it, as an uploaded collection gives them."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for path in paths:
            z.writestr(f"Prefetch Files/{path.name}", path.read_bytes())
    blob = out.getvalue()
    source = PackageSource("prefetch.zip", None, blob, str(tmp_path), ParseContext(analyze_attachments=False), package_id=hashlib.sha256(blob).hexdigest())
    rows = list(source)
    files = {f["name"].rsplit("/", 1)[-1]: f for f in source.stats()["files"]}
    return rows, files


@pytest.fixture(scope="module")
def collection(tmp_path_factory):
    return read(tmp_path_factory.mktemp("prefetch"), sorted(PREFETCH.glob("*.pf")))


def runs(rows, executable):
    return sorted((r for r in rows if r["processName"] == executable), key=lambda r: r["ts"])


def test_every_prefetch_version_from_23_on_is_read_and_version_17_is_reported_as_not_read(collection):
    _, files = collection
    assert {name: f["status"] for name, f in files.items()} == {
        "AM_DELTA_PATCH_1.443.990.0.EX-7037CF86.pf": "parsed",
        "BYTECODEGENERATOR.EXE-C1E9BCE6.pf": "parsed",
        "CMD.EXE-087B4001.pf": "error",
        "NOTEPAD.EXE-D8414F97.pf": "parsed",
        "ONEDRIVE.EXE-7E152375.pf": "parsed",
        "PING.EXE-B29F6629.pf": "parsed",
        "TASKHOST.EXE-3AE259FC.pf": "parsed",
    }
    # the version 17 layout of the run time and count is not read by the library REMN uses, so the
    # file is counted as not read, with the reason, rather than given a wrong time
    assert "v17" in files["CMD.EXE-087B4001.pf"]["reason"]
    assert files["CMD.EXE-087B4001.pf"]["count"] == 0


def test_a_windows_7_prefetch_file_gives_its_one_run_time_and_no_invented_earlier_runs(collection):
    rows, _ = collection
    ping = runs(rows, "PING.EXE")
    # plaso: last run 2012-04-06T19:00:55.9329556, run count 14; version 23 keeps one run time
    assert [r["ts"] for r in ping] == [ms("2012-04-06T19:00:55.932+00:00")]
    assert ping[0]["data"]["RunCount"] == 14
    assert ping[0]["image"] == "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\PING.EXE"


def test_a_windows_8_1_prefetch_file_gives_its_four_run_times(collection):
    rows, _ = collection
    taskhost = runs(rows, "TASKHOST.EXE")
    assert [r["ts"] for r in taskhost] == [
        ms("2013-10-04T06:11:13.642+00:00"),
        ms("2013-10-04T06:19:54.596+00:00"),
        ms("2013-10-04T15:28:09.010+00:00"),
        ms("2013-10-04T15:40:09.037+00:00"),
    ]
    assert {r["data"]["RunCount"] for r in taskhost} == {4}
    assert taskhost[0]["image"] == "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\SYSTEM32\\TASKHOST.EXE"


def test_a_compressed_windows_10_prefetch_file_gives_its_seven_run_times(collection):
    rows, _ = collection
    generator = runs(rows, "BYTECODEGENERATOR.EXE")
    assert [r["ts"] for r in generator] == [
        ms("2015-05-14T22:10:38.251+00:00"),
        ms("2015-05-14T22:11:05.906+00:00"),
        ms("2015-05-14T22:11:19.858+00:00"),
        ms("2015-05-14T22:11:25.842+00:00"),
        ms("2015-05-14T22:11:45.513+00:00"),
        ms("2015-05-14T22:11:55.357+00:00"),
        ms("2015-05-14T22:11:58.091+00:00"),
    ]
    assert {r["data"]["RunCount"] for r in generator} == {7}


def test_the_first_windows_10_layout_gives_its_run_count(collection):
    rows, _ = collection
    onedrive = runs(rows, "ONEDRIVE.EXE")
    assert [r["ts"] for r in onedrive] == [ms("2015-05-14T22:10:28.674+00:00"), ms("2015-05-14T22:11:05.485+00:00")]
    assert {r["data"]["RunCount"] for r in onedrive} == {2}


def test_the_windows_10_1903_layout_gives_its_run_count_from_its_own_offset(collection):
    rows, _ = collection
    notepad = runs(rows, "NOTEPAD.EXE")
    assert [r["ts"] for r in notepad] == [ms("2019-06-05T19:23:00.815+00:00"), ms("2019-06-05T19:55:04.877+00:00")]
    # plaso and libscca: this layout keeps the run count four bytes earlier than the first one
    assert {r["data"]["RunCount"] for r in notepad} == {2}
    assert notepad[0]["image"] == "\\VOLUME{01d3096ba3a46863-2ca3d1ae}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE"


def test_a_windows_11_prefetch_file_with_a_cut_executable_name_gives_its_run_and_full_path(collection):
    rows, _ = collection
    patch = runs(rows, "AM_DELTA_PATCH_1.443.990.0.EX")
    # the run time is not in plaso's test: it is the first FILETIME at offset 44 of the file
    # information, read by hand
    assert [r["ts"] for r in patch] == [ms("2026-02-04T13:43:44.668+00:00")]
    assert patch[0]["data"]["RunCount"] == 1
    # Windows cuts the executable's name in the header to 29 characters; plaso's path hint is the
    # full name, which the referenced files hold
    assert patch[0]["image"].endswith("\\WINDOWS\\SOFTWAREDISTRIBUTION\\DOWNLOAD\\INSTALL\\AM_DELTA_PATCH_1.443.990.0.EXE")


@pytest.mark.heavy
def test_velociraptor_s_prefetch_sample_gives_the_run_count_and_times_of_its_golden_output(tmp_path):
    path = download(f"{VELOCIRAPTOR}/artifacts/testdata/files/VELOCIRAPTOR.EXE-DB95245D.pf", "ff7436336f0151ccf0cc9db8be172ca781b86b017d566ee82291f93b74f3d0ca")
    rows, files = read(tmp_path, [path])
    assert files[path.name]["status"] == "parsed"
    # artifacts/testdata/server/testcases/prefetch.out.yaml at the same commit
    assert [r["ts"] // 1000 * 1000 for r in runs(rows, "VELOCIRAPTOR.EXE")] == [
        ms(t)
        for t in (
            "2022-02-18T01:40:35+00:00",
            "2022-02-18T05:18:52+00:00",
            "2022-02-18T05:41:13+00:00",
            "2022-02-18T05:43:21+00:00",
            "2022-02-18T06:55:37+00:00",
            "2022-02-21T00:12:14+00:00",
            "2022-02-21T00:45:24+00:00",
            "2022-02-21T01:03:45+00:00",
        )
    ]
    assert {r["data"]["RunCount"] for r in rows} == {30}
    assert {r["image"] for r in rows} == {"\\DEVICE\\MUP\\VMWARE-HOST\\SHARED FOLDERS\\SHARED\\VELOCIRAPTOR.EXE"}
