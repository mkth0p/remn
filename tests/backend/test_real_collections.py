"""Velociraptor's own test data and golden outputs, read as an uploaded collection is read.

Velociraptor (AGPL 3.0) keeps sample artifacts and, for each test query, the rows its artifacts
returned (artifacts/testdata/server/testcases/*.out.yaml). Neither is committed here: the tests
are marked heavy and download them by URL and SHA-256. A golden output's rows are what the real
collector writes to results/<Artifact>.json, one object a line, so they are put in a collection
as that file, and the expected values are read from the same rows, not from REMN.
"""

from __future__ import annotations

import io
import json
import re
import zipfile

import pytest
from real_samples import download

from services.ingest.package import PackageSource
from services.parsers.collection import THREAT_NAME, timestamp_utc
from services.parsers.mail.common import ParseContext

pytestmark = pytest.mark.heavy

VELOCIRAPTOR = "https://raw.githubusercontent.com/Velocidex/velociraptor/24fedbd423dad78098bc8a3bdb8d10f65741a305/artifacts/testdata"


def golden(name: str, sha256: str) -> list[list[dict]]:
    """Each query's rows in a golden output: the JSON after "Output:" in each query's block."""
    text = download(f"{VELOCIRAPTOR}/server/testcases/{name}", sha256).read_text(encoding="utf-8")
    out = []
    for block in re.split(r"^Query: ", text, flags=re.M)[1:]:
        if "\nOutput: " in block:
            out.append(json.JSONDecoder().raw_decode(block.split("\nOutput: ", 1)[1])[0])
    return out


def collection(tmp_path, members: dict[str, bytes]):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    source = PackageSource("Collection-velociraptor.zip", None, out.getvalue(), str(tmp_path), ParseContext(analyze_attachments=False))
    rows = list(source)
    return rows, {f["name"]: f for f in source.files}


def results(artifact: str, rows: list[dict]) -> dict[str, bytes]:
    return {f"results/{artifact}.json": "".join(json.dumps(r) + "\n" for r in rows).encode()}


def test_a_defender_log_written_in_utf_16_with_windows_line_ends_is_read_line_for_line(tmp_path):
    path = download(f"{VELOCIRAPTOR}/files/mplog/MPLog-20210722-153000.log", "febecfba200124815f211ddc2ae2da7f91c9cc3258fdce002713d185ac1f1a1b")
    data = path.read_bytes()
    assert data[:2] == b"\xff\xfe" and "\r\n".encode("utf-16-le") in data
    lines = [line for line in data.decode("utf-16").splitlines() if line.strip()]
    rows, files = collection(tmp_path, {f"WdSupportLogs/{path.name}": data})
    member = files[f"WdSupportLogs/{path.name}"]
    # a log this short is kept whole
    assert (member["status"], member["count"]) == ("parsed", len(lines))
    assert [r["message"] for r in rows] == [line.strip() for line in lines]
    # the threats Velociraptor's MPLog artifact finds in the same file
    found = golden("mplog.out.yaml", "7b7d07e8b431491d8c173ee80f08315ac7bc5d4aa686dfe5aee69231ad36767c")[0]
    expected = {r["Details"]["ThreatName"] for r in found if isinstance(r.get("Details"), dict) and r["Details"].get("ThreatName")}
    assert expected
    named = {r["threatName"] for r in rows if r.get("threatName")}
    assert expected <= named
    # and nothing named that the line itself does not hold
    assert all(THREAT_NAME.search(r["message"]).group(1) == r["threatName"] for r in rows if r.get("threatName"))


def test_velociraptor_s_mft_rows_give_every_time_of_the_entry_and_its_path(tmp_path):
    entry = golden("mft.out.yaml", "764a928f17d31201bbbf93b922a19bbb146e77443efa5b6d509d03da879cdfa9")[1][0]
    assert entry["_Source"] == "Windows.NTFS.MFT"
    rows, files = collection(tmp_path, results("Windows.NTFS.MFT", [entry]))
    assert files["results/Windows.NTFS.MFT.json"]["status"] == "parsed"
    assert {r["artifactType"] for r in rows} == {"mft"}
    assert {r["path"] for r in rows} == {entry["OSPath"]}
    columns = [f"{stem}{code}" for stem in ("Created", "LastModified", "LastRecordChange", "LastAccess") for code in ("0x10", "0x30")]
    # every one of the eight times is on a row, and no row has a time the entry does not hold
    assert {r["ts"] for r in rows} == {timestamp_utc(entry[c]) for c in columns}
    for c in columns[::2]:
        assert timestamp_utc(entry[c]) in {r["ts"] for r in rows if r["summary"].startswith(f"mft: {entry['OSPath']} (SI")}


def test_velociraptor_s_kerberoasting_rows_reach_the_fields_the_kerberoasting_rule_reads(tmp_path):
    found = golden("kerberoasting.out.yaml", "f9664cd782d37aa170c0eafe5c0c294fb78e1f76dc59edd32a4b585f85acd551")[0]
    assert len(found) == 2
    rows, files = collection(tmp_path, results("Windows.EventLogs.Kerberoasting", found))
    assert (files["results/Windows.EventLogs.Kerberoasting.json"]["status"], len(rows)) == ("parsed", 2)
    got = sorted((r["ts"], r["eventId"], r["computer"], r["targetUser"], r["serviceName"], r["ticketEncryption"]) for r in rows)
    want = sorted((timestamp_utc(f["EventTime"]), f["EventID"], f["Computer"], f["TargetUserName"], f["ServiceName"], f["TicketEncryptionType"]) for f in found)
    assert got == want
    assert {r["ipAddress"] for r in rows} <= {f["IpAddress"] for f in found} | {f["IpAddress"].removeprefix("::ffff:") for f in found}
