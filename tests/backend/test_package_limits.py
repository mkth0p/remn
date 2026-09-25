"""What one anonymous request may hold, spend and leave behind.

The public instance stages into a tmpfs that is RAM, inside a container memory limit, and serves
strangers. Every case here is an attack an adversarial review measured against this parser: the
numbers in the assertions are the ceilings, not incidental behaviour.
"""

from __future__ import annotations

import io
import os
import threading
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
    return sum(e.stat().st_size for e in os.scandir(directory) if e.is_file())


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

    peak = {"bytes": 0}
    stop = threading.Event()

    def watch():
        while not stop.is_set():
            peak["bytes"] = max(peak["bytes"], staged_bytes(tmp_path))
            time.sleep(0.005)

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    source = PackageSource("pkg.zip", None, blob, str(tmp_path), ParseContext(analyze_attachments=False))
    list(source)
    stop.set()
    watcher.join()

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
