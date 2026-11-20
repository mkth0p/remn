"""What one anonymous request may hold, spend and leave behind.

The public instance stages into a tmpfs that is RAM, inside a container memory limit, and serves
strangers. Every case here is an attack an adversarial review measured against this parser: the
numbers in the assertions are the ceilings, not incidental behaviour.
"""

from __future__ import annotations

import io
import os
import time
import zipfile

import pytest

from services.ingest import package as P
from services.ingest.package import PackageSource
from services.parsers.mail.common import ParseContext


def prefetch_zip(count, size):
    """Members that look like prefetch to the dispatcher, padded to a chosen staged size."""
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "samples" / "synthetic"))
    from native_artifacts import prefetch_bytes

    body = prefetch_bytes()
    body = body + b"\x00" * max(0, size - len(body))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for i in range(count):
            z.writestr(f"Prefetch Files/p{i:04d}.pf", body)
    return out.getvalue()


def staged_bytes(directory):
    """What the staging folder holds now; a file the parse deletes while it is counted holds nothing."""
    total = 0
    for e in os.scandir(directory):
        try:
            if e.is_file():
                total += e.stat().st_size
        except FileNotFoundError:
            pass
    return total


SEVEN_ZIP = b"7z\xbc\xaf\x27\x1c\x00\x04"


class FakeSevenZip:
    """Stands in for py7zr where it is not installed, as in this suite's default run: the archive
    is a list of (name, declared size, content) and extraction writes the content. Like py7zr it
    writes no more than a member declares and stops once more than max_extract_size has been
    decompressed in total. The optional parser run of the continuous integration has the real one."""

    members: list[tuple[str, int, bytes]] = []
    extracted: list[str] = []

    def __init__(self, src, mode="r", max_extract_size=None):
        self.limit = max_extract_size

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def list(self):
        from types import SimpleNamespace

        return [SimpleNamespace(filename=name, uncompressed=size, is_directory=False) for name, size, _ in self.members]

    def extract(self, path=None, targets=None):
        total = 0
        last = max((i for i, (name, _, _) in enumerate(self.members) if targets is None or name in targets), default=-1)
        for name, size, content in self.members[: last + 1]:
            total += min(len(content), size)
            if self.limit is not None and total > self.limit:
                raise RuntimeError(f"decompressed size {total} exceeds limit of {self.limit} bytes")
            if targets is not None and name not in targets:
                continue
            out = os.path.join(path, name)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "wb") as fh:
                fh.write(content[:size])
            FakeSevenZip.extracted.append(name)

    def extractall(self, path=None):
        self.extract(path)


@pytest.fixture
def fake_py7zr(monkeypatch):
    import sys
    from types import SimpleNamespace

    FakeSevenZip.members, FakeSevenZip.extracted = [], []
    monkeypatch.setitem(sys.modules, "py7zr", SimpleNamespace(SevenZipFile=FakeSevenZip))
    return FakeSevenZip


def test_an_expanded_7z_still_being_read_is_not_swept_as_stale(tmp_path, fake_py7zr):
    """The sweep removes staging directories by age, and a 7z is expanded once when its parse
    starts. A parse that runs past the retention window takes its members from the expansion until
    the end, so it must not look abandoned while it does."""
    from django.test import override_settings

    from api.views.upload import cleanup_stale

    fake_py7zr.members = [
        ("Processes/processes.csv", 24, b"Name,PID\nupdater.exe,42\n"),
        ("Services/services.csv", 29, b"Name,PathName\nSvc,C:\\svc.exe\n"),
    ]
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_UPLOAD_MAX_AGE_S=60):
        source = PackageSource("ORC_WS01.7z", None, SEVEN_ZIP, str(tmp_path), ParseContext(analyze_attachments=False))
        rows = iter(source)
        next(rows)
        expanded = source._extracted
        old = time.time() - 3600
        os.utime(expanded, (old, old))  # the parse has been running for an hour
        next(rows)  # and takes its next member
        assert cleanup_stale() == 0
        assert os.path.isdir(expanded)
        list(rows)
    assert not os.path.exists(expanded), "the parse removes its expansion when it ends"


def test_a_client_that_disconnects_mid_group_strands_nothing(tmp_path):
    """A streaming response that is abandoned closes the generator part-way. The group being
    decoded had been taken off the instance, so nothing could reclaim it, and the staging area is
    RAM that only a restart gave back."""
    blob = prefetch_zip(40, 4096)
    source = PackageSource("pkg.zip", None, blob, str(tmp_path), ParseContext(analyze_attachments=False))

    rows = iter(source)
    next(rows)  # one row delivered, then the client goes away
    assert staged_bytes(tmp_path) > 0, "the fixture must actually stage something to be a test"
    rows.close()

    assert staged_bytes(tmp_path) == 0, [e.name for e in os.scandir(tmp_path)]
    assert source.budget["deferredBytes"] == 0


def test_the_hold_allowance_is_per_request_not_per_nesting_level(tmp_path, monkeypatch):
    """Held-back bytes lived on the instance, and a nested package got a fresh instance. Four
    permitted depths therefore held four times what the tmpfs was sized for."""
    monkeypatch.setattr(P, "MAX_DEFERRED_BYTES", 64 * 1024)

    inner = prefetch_zip(20, 4096)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("Prefetch Files/top.pf", prefetch_zip(1, 4096)[:0] or b"")
        for level in range(3):
            z.writestr(f"nested{level}.zip", inner)
    blob = out.getvalue()

    # What is staged only grows between two deletions, so measuring the folder just before each one,
    # in the parse's own thread, sees every peak. A thread that sampled it every few milliseconds
    # could miss one, and raced with the deletions it measured.
    peak = {"bytes": 0}
    unlink = os.unlink

    def measured_unlink(path, *args, **kwargs):
        peak["bytes"] = max(peak["bytes"], staged_bytes(tmp_path))
        return unlink(path, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(os, "unlink", measured_unlink)
        m.setattr(os, "remove", measured_unlink)
        source = PackageSource("pkg.zip", None, blob, str(tmp_path), ParseContext(analyze_attachments=False))
        list(source)

    assert peak["bytes"] > 0, "the parse must stage and delete something for the measure to mean anything"
    # one member is staged at a time on top of the held-back set, so allow a member of headroom
    assert peak["bytes"] <= P.MAX_DEFERRED_BYTES + 256 * 1024, f"peak {peak['bytes']} exceeded the per-request ceiling"
    assert staged_bytes(tmp_path) == 0


def test_a_decode_that_fails_is_charged_for_the_time_it_took(tmp_path):
    """Elapsed time was added only on the success path, so a package of artifacts that all fail
    spent the time budget without ever charging it, and only the artifact count stopped it."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for i in range(3):
            z.writestr(f"Registry/hive{i}.dat", b"regf" + bytes(4096))
    source = PackageSource("pkg.zip", None, out.getvalue(), str(tmp_path), ParseContext(analyze_attachments=False))
    list(source)

    assert all(f["status"] == "error" for f in source.files), [f["status"] for f in source.files]
    assert source.budget["decodes"] == 3
    assert source.budget["decodeSeconds"] > 0, "a failing decode costs real time and must be charged for it"


def test_a_cabinet_that_claims_far_more_than_it_holds_is_refused(tmp_path):
    """Many CAB entries may point at one range of folder data, so the expanded total counts bytes
    written rather than bytes allocated. Without a ratio, kilobytes manufacture the whole ceiling."""
    from services.parsers.native_worker import MAX_CAB_RATIO, cabinet

    cab = pytest.importorskip("cabarchive")
    archive = cab.CabArchive()
    for i in range(64):
        archive[f"f{i:04d}.bin"] = cab.CabFile(bytes(256 * 1024))
    blob = archive.save(compress=True)

    src = tmp_path / "bomb.cab"
    src.write_bytes(blob)
    ratio = (64 * 256 * 1024) / len(blob)
    assert ratio > MAX_CAB_RATIO, f"the fixture must be a bomb: {ratio:.0f}:1 against a {MAX_CAB_RATIO}:1 limit"

    with pytest.raises(ValueError, match=r"past the \d+:1 limit"):
        cabinet(str(src), str(tmp_path / "out.zip"))


def test_a_cabinet_with_a_realistic_ratio_is_still_accepted(tmp_path):
    """The Defender support cab this parser exists to read expands about ten to one. The ratio
    guard must refuse bombs without refusing evidence."""
    from services.parsers.native_worker import cabinet

    cab = pytest.importorskip("cabarchive")
    archive = cab.CabArchive()
    for i in range(8):
        # incompressible content, so the cabinet stays near its expanded size
        archive[f"f{i:04d}.bin"] = cab.CabFile(os.urandom(64 * 1024))
    src = tmp_path / "real.cab"
    src.write_bytes(archive.save(compress=True))

    out = tmp_path / "out.zip"
    cabinet(str(src), str(out))
    with zipfile.ZipFile(out) as z:
        assert len(z.namelist()) == 8


def test_a_cabinet_is_charged_against_the_native_decoding_allowance(tmp_path, monkeypatch):
    """Cabinets spawned the same bounded worker and manufactured a whole nested package, but were
    counted against neither the artifact allowance nor the time one."""
    monkeypatch.setattr(P, "MAX_NATIVE_DECODES", 0)
    cab = pytest.importorskip("cabarchive")
    archive = cab.CabArchive()
    archive["MPLog.txt"] = cab.CabFile(b"threat detected: synthetic\n")

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("WdSupportLogs/support.cab", archive.save())
    source = PackageSource("pkg.zip", None, out.getvalue(), str(tmp_path), ParseContext(analyze_attachments=False))
    list(source)

    entry = source.files[0]
    assert entry["status"] == "error"
    assert "budget for this package is spent" in entry["reason"], entry["reason"]


def test_the_sweeper_reclaims_what_a_killed_parse_could_not(tmp_path):
    """A parse releases its own staging, but a process killed mid-parse cannot, and these suffixes
    were not in the sweep list, so the bytes stayed until the container restarted."""
    from django.test import override_settings

    from api.views.upload import cleanup_stale, upload_dir

    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_UPLOAD_MAX_AGE_S=60):
        upload_dir()
        stranded = []
        for suffix in (".member", ".decoded", ".manifest"):
            p = tmp_path / f"orphan{suffix}"
            p.write_bytes(b"evidence a killed parse left behind")
            old = time.time() - 3600
            os.utime(p, (old, old))
            stranded.append(p)

        assert cleanup_stale() >= len(stranded)
        assert not [p for p in stranded if p.exists()]


# ---------------------------------------------------------------------------
# what an archive may expand to: the staging area, the ratio, the walk
# ---------------------------------------------------------------------------
KIB, MIB = 1024, 1024**2
CSV = b"Name,PID\nupdater.exe,42\n"


def ctx():
    return ParseContext(analyze_attachments=False)


@pytest.fixture
def small_staging(tmp_path, monkeypatch):
    """A staging area that can hold 1 MiB: an invented 10 MiB disk with 2 MiB free, a tenth of it
    kept in reserve. Nothing is written beyond what the fixtures stage."""
    import shutil

    from django.test import override_settings

    usage = shutil._ntuple_diskusage(10 * MIB, 8 * MIB, 2 * MIB)
    monkeypatch.setattr(shutil, "disk_usage", lambda path: usage)
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_TMP_MAX_GB=0):
        yield tmp_path


def stored_zip(members: dict[str, bytes], method=zipfile.ZIP_STORED) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", method) as z:
        for name, body in members.items():
            z.writestr(name, body)
    return out.getvalue()


def bz2_tar(members: list[tuple[str, int, bytes]]) -> bytes:
    """A bz2 tar of (name, size, content); a member with no content is that many MiB of zeros.
    Made of concatenated bz2 streams, which decompress as one, so gigabytes cost nothing to build."""
    import bz2
    import tarfile

    zero_mib = bz2.compress(bytes(MIB))
    parts = []
    for name, size, content in members:
        info = tarfile.TarInfo(name)
        info.size = size if not content else len(content)
        parts.append(bz2.compress(info.tobuf(format=tarfile.USTAR_FORMAT)))
        if content:
            parts.append(bz2.compress(content + bytes(-len(content) % 512)))
        else:
            parts.append(zero_mib * (size // MIB))
    parts.append(bz2.compress(bytes(1024)))
    return b"".join(parts)


def by_name(source):
    return {f["name"]: f for f in source.files}


def test_a_package_member_may_take_at_most_half_the_staging_area(small_staging):
    """The member ceiling was a fixed 4 GiB and the package total a fixed 16 GiB, whatever the
    staging area could hold; on the public instance that area is a 1 GiB RAM disk."""
    blob = stored_zip({"Processes/processes.csv": CSV, "memory/dump.bin": os.urandom(600 * KIB)})
    source = PackageSource("pkg.zip", None, blob, str(small_staging), ctx())
    rows = list(source)

    dump = by_name(source)["memory/dump.bin"]
    assert dump["status"] == "skipped" and "half the staging area" in dump["reason"], dump
    assert by_name(source)["Processes/processes.csv"]["status"] == "parsed" and len(rows) == 1


def test_nested_archives_share_the_room_the_staging_area_had(small_staging):
    """Each nesting level keeps its archive member on disk while that archive's members are read,
    so members just under the ceiling at three levels held three times what one may take."""
    innermost = stored_zip({"logs/big.bin": os.urandom(400 * KIB)})
    outer = stored_zip({"middle.zip": stored_zip({"inner.zip": innermost})})
    source = PackageSource("pkg.zip", None, outer, str(small_staging), ctx())
    list(source)

    deepest = by_name(source)["middle.zip!/inner.zip!/logs/big.bin"]
    assert deepest["status"] == "skipped" and "staging area" in deepest["reason"], deepest
    assert source.budget["held"] == 0, "everything the parse held is given back"
    assert not list(small_staging.iterdir())


def test_a_zip_that_expands_past_its_ratio_is_read_only_to_that_point(tmp_path):
    """Three members of 40 MiB of zeros in a zip of about 120 KiB: a ratio near a thousand to one.
    The archive may expand to 200 times its size, and never less than 64 MiB, so the first member is
    read and the other two are listed with the reason."""
    from services.ingest.pipeline import MAX_RATIO, RATIO_FLOOR

    blob = stored_zip({"Processes/processes.csv": CSV, **{f"dump{i}.bin": bytes(40 * MIB) for i in range(3)}}, zipfile.ZIP_DEFLATED)
    assert len(blob) * MAX_RATIO < RATIO_FLOOR, "the fixture must be judged by the floor"
    source = PackageSource("pkg.zip", None, blob, str(tmp_path), ctx())
    list(source)

    files = by_name(source)
    assert files["dump0.bin"]["status"] == "unsupported" and files["dump0.bin"]["sha256"]
    for name in ("dump1.bin", "dump2.bin"):
        assert files[name]["status"] == "skipped" and f"{MAX_RATIO} times its own size" in files[name]["reason"], files[name]
    assert files["Processes/processes.csv"]["status"] == "parsed"


def test_a_compressed_tar_is_walked_only_as_far_as_its_ratio_allows(tmp_path):
    """A member too large to read is still decompressed to reach the next header. 5 GiB of zeros in
    a bz2 tar of about 230 KB took the walk fifteen seconds of one core, and the ratio of bz2 makes
    hours reachable."""
    blob = bz2_tar([("filler.bin", 5 * 1024 * MIB, b""), ("Processes/processes.csv", 0, CSV)])
    source = PackageSource("collection.tar.bz2", None, blob, str(tmp_path), ctx())
    started = time.monotonic()
    rows = list(source)
    elapsed = time.monotonic() - started

    assert elapsed < 3, f"{elapsed:.1f}s"
    files = by_name(source)
    assert files["filler.bin"]["status"] == "skipped"
    rest = files["(rest of archive)"]
    assert rest["status"] == "skipped" and "200 times its own size" in rest["reason"] and "not listed" in rest["reason"], rest
    assert rows == [] and source.stats()["inventoryComplete"] is False


def test_an_event_log_archive_is_walked_and_read_within_its_ratio():
    from services.ingest.pipeline import iter_archive

    skipped: list = []
    started = time.monotonic()
    names = [m.name for m in iter_archive(None, bz2_tar([("filler.evtx", 5 * 1024 * MIB, b""), ("Security.evtx", 0, b"ElfFile\x00")]), "tar", skipped)]
    assert time.monotonic() - started < 3
    assert names == [] and [s["name"] for s in skipped] == ["filler.evtx", "(rest of archive)"], skipped
    assert "not listed" in skipped[-1]["reason"]

    skipped = []
    blob = stored_zip({f"dump{i}.evtx": bytes(40 * MIB) for i in range(3)}, zipfile.ZIP_DEFLATED)
    names = [m.name for m in iter_archive(None, blob, "zip", skipped)]
    assert names == ["dump0.evtx"]
    assert [s["name"] for s in skipped] == ["dump1.evtx", "dump2.evtx"] and all("200 times" in s["reason"] for s in skipped)


def test_a_7z_is_expanded_only_as_far_as_its_ratio_allows(tmp_path, fake_py7zr):
    """The 7z reader summed the sizes the archive declares and expanded all of it, up to 16 GiB,
    into the staging area before anything was checked."""
    fake_py7zr.members = [("Processes/processes.csv", len(CSV), CSV), ("dump.bin", 100 * MIB, b"")]
    source = PackageSource("ORC_WS01.7z", None, SEVEN_ZIP, str(tmp_path), ctx())
    rows = list(source)

    dump = by_name(source)["dump.bin"]
    assert dump["status"] == "skipped" and "200 times its own size" in dump["reason"], dump
    assert fake_py7zr.extracted == ["Processes/processes.csv"] and len(rows) == 1


def test_a_7z_member_larger_than_the_staging_ceiling_is_not_expanded(small_staging, fake_py7zr):
    fake_py7zr.members = [("Processes/processes.csv", len(CSV), CSV), ("memory/dump.bin", 600 * KIB, os.urandom(600 * KIB))]
    source = PackageSource("ORC_WS01.7z", None, SEVEN_ZIP, str(small_staging), ctx())
    list(source)

    dump = by_name(source)["memory/dump.bin"]
    assert dump["status"] == "skipped" and "half the staging area" in dump["reason"], dump
    assert fake_py7zr.extracted == ["Processes/processes.csv"]
    assert source.budget["held"] == 0 and not list(small_staging.iterdir())


def test_a_7z_keeps_room_to_copy_out_what_it_expanded(small_staging, fake_py7zr):
    """The expanded members stay on disk while each is copied out to be read, so a 7z is expanded
    only as far as leaves room for that copy too."""
    fake_py7zr.members = [(f"dumps/part{i}.bin", 300 * KIB, os.urandom(300 * KIB)) for i in range(3)]
    source = PackageSource("ORC_WS01.7z", None, SEVEN_ZIP, str(small_staging), ctx())
    list(source)

    files = by_name(source)
    assert fake_py7zr.extracted == ["dumps/part0.bin", "dumps/part1.bin"]
    assert [files[f"dumps/part{i}.bin"]["status"] for i in range(3)] == ["unsupported", "unsupported", "skipped"]
    assert "staging area" in files["dumps/part2.bin"]["reason"], files["dumps/part2.bin"]
    assert source.budget["held"] == 0 and not list(small_staging.iterdir())


def test_a_7z_stops_once_what_it_decompresses_passes_the_ratio(tmp_path, fake_py7zr):
    """py7zr writes no more than a member declares, but in a solid archive the members before the
    one wanted are decompressed to reach it. What stops those is the limit on the total."""
    fake_py7zr.members = [("zeros.bin", 100 * MIB, bytes(70 * MIB)), ("Processes/processes.csv", len(CSV), CSV)]
    source = PackageSource("ORC_WS01.7z", None, SEVEN_ZIP, str(tmp_path), ctx())
    list(source)

    files = by_name(source)
    assert "exceeds limit" in files["ORC_WS01.7z"]["reason"], files
    assert source.stats()["inventoryComplete"] is False
    assert not [p for p in tmp_path.iterdir() if p.suffix == ".7z"], "nothing half-expanded is left or read"


def real_7z(members: list[tuple[str, bytes]]) -> bytes:
    py7zr = pytest.importorskip("py7zr")
    out = io.BytesIO()
    with py7zr.SevenZipFile(out, "w") as z:  # solid, as 7-Zip writes by default
        for name, body in members:
            z.writestr(body, name)
    return out.getvalue()


def test_a_real_7z_bomb_is_stopped_by_the_limit_on_what_it_decompresses(tmp_path):
    blob = real_7z([("zeros.bin", bytes(70 * MIB)), ("Processes/processes.csv", CSV)])
    assert len(blob) < 64 * KIB
    source = PackageSource("ORC_WS01.7z", None, blob, str(tmp_path), ctx())
    rows = list(source)

    files = by_name(source)
    assert files["zeros.bin"]["status"] == "skipped" and "200 times its own size" in files["zeros.bin"]["reason"]
    assert "DecompressionBombError" in files["ORC_WS01.7z"]["reason"], files
    assert rows == [] and not list(tmp_path.iterdir())


def test_a_real_7z_is_read_up_to_its_ratio_and_lists_the_rest(tmp_path):
    blob = real_7z([("Processes/processes.csv", CSV), ("zeros.bin", bytes(70 * MIB))])
    source = PackageSource("ORC_WS01.7z", None, blob, str(tmp_path), ctx())
    rows = list(source)

    files = by_name(source)
    assert files["Processes/processes.csv"]["status"] == "parsed" and len(rows) == 1
    assert files["zeros.bin"]["status"] == "skipped" and "200 times its own size" in files["zeros.bin"]["reason"]
    assert not list(tmp_path.iterdir())
