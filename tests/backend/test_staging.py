"""The staging area holds evidence only while it is parsed.

A public instance takes files from people it does not know, so what matters is not only that a
completed parse cleans up, but that an abandoned upload cannot sit there, cannot accumulate, and
is not readable by anyone else on the host.
"""

from __future__ import annotations

import json
import os
import shutil
import threading
import time
from pathlib import Path

from django.test import Client, override_settings

from api.views.upload import cleanup_stale, start_sweeper, upload_dir
from services.ingest import staging
from services.ingest.staging import staged_bytes

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
GIB = 1024**3


def _init(client, size=1024, name="evidence.evtx"):
    return client.post("/api/upload/init", json.dumps({"name": name, "size": size}), content_type="application/json", **HDR)


def _disk(monkeypatch, total_gib: int, free_gib: int) -> None:
    """The disk under the staging area, as the server sees it: invented sizes, nothing is written."""
    usage = shutil._ntuple_diskusage(total_gib * GIB, (total_gib - free_gib) * GIB, free_gib * GIB)
    monkeypatch.setattr(shutil, "disk_usage", lambda path: usage)


def test_a_default_install_takes_a_file_above_four_gib_when_its_disk_has_room(tmp_path, monkeypatch):
    """The chunked-upload limit is 64 GiB, and a staging total fixed at 4 GiB refused every larger
    mailbox or collection with 507, ten lines after the limit had let it through."""
    _disk(monkeypatch, total_gib=500, free_gib=200)
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_BROWSER_ONLY=False):
        response = _init(Client(), size=5 * GIB, name="mailbox.pst")
        assert response.status_code == 200, response.content[:300]


def test_a_file_the_configured_total_can_never_hold_is_told_so_rather_than_to_retry(tmp_path, monkeypatch):
    _disk(monkeypatch, total_gib=500, free_gib=200)
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_TMP_MAX_GB=4, FORENSIC_MAX_CHUNKED_GB=64, FORENSIC_BROWSER_ONLY=False):
        response = _init(Client(), size=5 * GIB, name="mailbox.pst")
        body = response.json()
        assert response.status_code == 413 and body["code"] == "staging-too-small", body
        # the reason names the setting that decides it, and does not promise that waiting helps
        assert "FORENSIC_TMP_MAX_GB" in body["error"] and "5.0 GiB" in body["error"] and "4.0 GiB" in body["error"]
        assert "try again" not in body["error"]


def test_without_a_configured_total_the_disk_decides_and_the_refusal_says_so(tmp_path, monkeypatch):
    """30 GiB free on a 100 GiB disk, a tenth of which stays free for the case stores: 20 GiB can
    be staged. A 25 GiB file is refused with the disk named as the reason, a 15 GiB one is taken."""
    _disk(monkeypatch, total_gib=100, free_gib=30)
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_TMP_MAX_GB=0, FORENSIC_MAX_CHUNKED_GB=64, FORENSIC_BROWSER_ONLY=False):
        refused = _init(Client(), size=25 * GIB)
        assert refused.status_code == 413 and refused.json()["code"] == "staging-too-small"
        assert "30.0 GiB free" in refused.json()["error"] and "10.0 GiB" in refused.json()["error"]
        assert _init(Client(), size=15 * GIB).status_code == 200


def test_a_staging_area_full_for_now_says_what_holds_it_and_when_it_frees(tmp_path, monkeypatch):
    _disk(monkeypatch, total_gib=500, free_gib=200)
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_TMP_MAX_GB=8, FORENSIC_MAX_CHUNKED_GB=64, FORENSIC_BROWSER_ONLY=False):
        c = Client()
        assert _init(c, size=5 * GIB).status_code == 200
        second = _init(c, size=5 * GIB)
        body = second.json()
        assert second.status_code == 507 and body["code"] == "staging-full", body
        # 5 GiB announced by the first upload is held; 3 GiB is left, this one needs 5
        assert "5.0 GiB" in body["error"] and "3.0 GiB" in body["error"], body["error"]


def test_health_gives_the_chunked_ceiling_the_staging_area_can_really_take(tmp_path, monkeypatch):
    """Health said 64 GB whatever the staging area could hold, so the client offered uploads that
    init then refused with 413."""

    def ceiling(**configured):
        with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_BROWSER_ONLY=False, **configured):
            return Client().get("/api/health", **HDR).json()["limits"]["maxChunkedGb"]

    _disk(monkeypatch, total_gib=100, free_gib=30)
    # a tenth of the disk stays free for the case stores: 20 GiB can be staged
    assert ceiling(FORENSIC_TMP_MAX_GB=0, FORENSIC_MAX_CHUNKED_GB=64) == 20
    assert ceiling(FORENSIC_TMP_MAX_GB=4, FORENSIC_MAX_CHUNKED_GB=64) == 4
    assert ceiling(FORENSIC_TMP_MAX_GB=0, FORENSIC_MAX_CHUNKED_GB=8) == 8
    # what health gives is what init takes
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_TMP_MAX_GB=4, FORENSIC_MAX_CHUNKED_GB=64, FORENSIC_BROWSER_ONLY=False):
        assert _init(Client(), size=4 * GIB).status_code == 200
        assert _init(Client(), size=4 * GIB + 1).status_code == 413


def test_an_upload_is_not_promised_the_room_a_running_parse_has_set_aside(tmp_path, monkeypatch):
    _disk(monkeypatch, total_gib=500, free_gib=200)
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_TMP_MAX_GB=8, FORENSIC_MAX_CHUNKED_GB=64, FORENSIC_BROWSER_ONLY=False):
        room, claim = staging.parse_room(claim=True)
        try:
            # the parse holds half the 8 GiB area, so 4 GiB is left
            assert room == 4 * GIB
            refused = _init(Client(), size=5 * GIB)
            assert refused.status_code == 507 and refused.json()["code"] == "staging-full", refused.content[:300]
            assert "4.0 GiB" in refused.json()["error"]
            assert _init(Client(), size=4 * GIB).status_code == 200
        finally:
            staging.release(claim)


def test_a_parse_is_not_given_the_room_an_unfinished_upload_has_announced(tmp_path, monkeypatch):
    _disk(monkeypatch, total_gib=500, free_gib=200)
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_TMP_MAX_GB=8, FORENSIC_MAX_CHUNKED_GB=64, FORENSIC_BROWSER_ONLY=False):
        assert _init(Client(), size=6 * GIB).status_code == 200
        room, claim = staging.parse_room(claim=True)
        staging.release(claim)
        # 6 GiB of the 8 is announced and not yet sent; the upload's small record is on disk
        assert room == 2 * GIB - staged_bytes()


def test_an_upload_and_a_parse_that_ask_together_are_not_promised_the_same_room(tmp_path, monkeypatch):
    """Upload init and a parse's claim each read the free room under a lock of its own, so one could
    be promised the room the other was being promised at the same moment."""
    _disk(monkeypatch, total_gib=500, free_gib=200)
    real = staging.staged_bytes
    # each of the two waits here, on its first look at the area, for the other to look too: when they
    # decide one after the other, the first stops waiting after half a second and the second does not wait
    together = threading.Barrier(2, timeout=0.5)
    waited: set[int] = set()

    def staged() -> int:
        if threading.get_ident() not in waited:
            waited.add(threading.get_ident())
            try:
                together.wait()
            except threading.BrokenBarrierError:
                pass
        return real()

    monkeypatch.setattr(staging, "staged_bytes", staged)
    promised: dict[str, int] = {}

    def upload() -> None:
        promised["upload"] = 6 * GIB if _init(Client(), size=6 * GIB).status_code == 200 else 0

    def parse() -> None:
        promised["parse"], promised["claim"] = staging.parse_room(claim=True)

    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_TMP_MAX_GB=8, FORENSIC_MAX_CHUNKED_GB=64, FORENSIC_BROWSER_ONLY=False):
        threads = [threading.Thread(target=upload), threading.Thread(target=parse)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        staging.release(promised.get("claim"))
    assert set(promised) == {"upload", "parse", "claim"}
    assert promised["upload"] + promised["parse"] <= 8 * GIB, promised


def test_an_abandoned_upload_is_removed_without_waiting_for_a_restart(tmp_path):
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_UPLOAD_MAX_AGE_S=60):
        c = Client()
        upload_id = _init(c).json()["uploadId"]
        c.put(f"/api/upload/{upload_id}/chunk?offset=0", b"abandoned", content_type="application/octet-stream", **HDR)

        staged = list(upload_dir().iterdir())
        assert staged, "the chunk should be on disk"
        assert cleanup_stale() == 0, "a fresh upload must not be swept out from under its client"

        # age it past the window
        old = time.time() - 3600
        for p in staged:
            os.utime(p, (old, old))
        assert cleanup_stale() == len(staged)
        assert not list(upload_dir().iterdir())


def test_the_sweep_also_clears_a_half_finished_single_request_upload(tmp_path):
    """Django spools a large multipart body to its own temp directory. A request that dies part-way
    leaves that file behind, and the original sweep never looked there."""
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_UPLOAD_MAX_AGE_S=60):
        upload_dir()  # ensure the tree exists
        orphan = Path(tmp_path) / "tmp12345.upload"
        orphan.write_bytes(b"half a mailbox")
        old = time.time() - 3600
        os.utime(orphan, (old, old))

        assert cleanup_stale() >= 1
        assert not orphan.exists()


def test_a_stream_of_abandoned_uploads_cannot_fill_the_disk(tmp_path):
    """However short the lifetime, uploads inside the window still accumulate. The staging area has
    a total budget and refuses rather than accepting what it cannot hold."""
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_TMP_MAX_GB=1, FORENSIC_MAX_CHUNKED_GB=64, FORENSIC_BROWSER_ONLY=False):
        c = Client()
        # something already occupies most of the budget
        upload_dir()
        (Path(tmp_path) / "uploads" / "bulk.part").write_bytes(b"x" * (900 * 1024))
        assert staged_bytes() >= 900 * 1024

        with override_settings(FORENSIC_TMP_MAX_GB=1):
            # under the budget: accepted
            assert _init(c, size=1024).status_code == 200

        # a request the staging area cannot hold is refused, with a reason a client can act on:
        # larger than the whole area, so it is not one to retry
        big = c.post("/api/upload/init", json.dumps({"name": "huge.evtx", "size": 2 * 1024**3}), content_type="application/json", **HDR)
        assert big.status_code == 413 and big.json()["code"] == "staging-too-small", big.content[:200]


def test_a_full_staging_area_sweeps_before_refusing(tmp_path):
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_TMP_MAX_GB=1, FORENSIC_UPLOAD_MAX_AGE_S=60, FORENSIC_BROWSER_ONLY=False):
        upload_dir()
        stale = Path(tmp_path) / "uploads" / "old.part"
        stale.write_bytes(b"x" * (1024**3 - 1024))
        old = time.time() - 3600
        os.utime(stale, (old, old))

        # the budget is spent by a file nothing will collect; the sweep runs and the upload proceeds
        assert _init(Client(), size=4096).status_code == 200
        assert not stale.exists()


def _aged(path: Path, seconds: int = 3600) -> None:
    old = time.time() - seconds
    os.utime(path, (old, old))


def _left_behind(tmp_path: Path) -> tuple[Path, Path]:
    """What a parse killed mid-way leaves: a 7z expanded to be read, and event logs staged for an
    engine run, both directories named the way the parsers name them. The contents are invented."""
    expanded = tmp_path / "tmpa1b2c3d4.7z"
    (expanded / "ORC" / "General").mkdir(parents=True)
    (expanded / "ORC" / "General" / "GetThis.csv").write_bytes(b"x" * 4096)
    staged = tmp_path / "tmpe5f6g7h8.evtx"
    staged.mkdir()
    (staged / "0000-Security.evtx").write_bytes(b"ElfFile\x00" + bytes(4088))
    return expanded, staged


def test_the_sweep_removes_the_directories_a_killed_parse_left_behind(tmp_path):
    """An expanded 7z and the event logs staged for Hayabusa are directories, and the sweep only
    ever looked at files: a parse killed in the middle of either left them on disk for good."""
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_UPLOAD_MAX_AGE_S=60):
        upload_dir()
        expanded, staged = _left_behind(tmp_path)
        in_use = tmp_path / "tmpi9j0k1l2.evtx"
        in_use.mkdir()
        for directory in (expanded, staged, upload_dir()):
            _aged(directory)
        # while they exist they count against the staging budget
        assert staged_bytes() >= 2 * 4096

        assert cleanup_stale() == 2
        assert not expanded.exists() and not staged.exists()
        assert in_use.exists(), "a directory a parse may still be using is left alone"
        assert upload_dir().exists(), "the chunked staging area itself is not a parse's leftover"


def test_a_restart_clears_what_a_stopped_process_staged_and_keeps_resumable_uploads(tmp_path):
    from api.views.upload import clear_leftovers

    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path):
        part = upload_dir() / ("a" * 32 + ".part")
        part.write_bytes(b"half an upload a client can resume")
        expanded, staged = _left_behind(tmp_path)
        # Django's spool keeps the uploaded file's extension after ".upload"
        spool = tmp_path / "tmpm3n4o5p6.upload.pst"
        spool.write_bytes(b"part of a mailbox")

        assert clear_leftovers() == 3
        assert not expanded.exists() and not staged.exists() and not spool.exists()
        assert part.exists(), "a chunked upload can be resumed after a restart"


def test_the_sweep_finds_the_spool_of_an_upload_whose_name_has_an_extension(tmp_path):
    """The spool file is named tmpXXXX.upload.<extension>, so matching on the last suffix only
    found uploads that had no extension at all."""
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_UPLOAD_MAX_AGE_S=60):
        upload_dir()
        spool = tmp_path / "tmpq7r8s9t0.upload.evtx"
        spool.write_bytes(b"half an event log")
        _aged(spool)
        assert cleanup_stale() == 1
        assert not spool.exists()


def test_staged_evidence_is_private_to_the_server_account(tmp_path):
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path):
        upload_id = _init(Client()).json()["uploadId"]
        part = Path(tmp_path) / "uploads" / f"{upload_id}.part"
        assert part.exists()
        if os.name != "nt":  # POSIX permission bits are meaningless on Windows
            assert part.stat().st_mode & 0o077 == 0, "no group or other access to evidence in transit"
            assert upload_dir().stat().st_mode & 0o077 == 0


def test_there_is_never_more_than_one_sweeper_and_it_can_be_switched_off():
    import threading

    def alive():
        return [t for t in threading.enumerate() if t.name == "remn-upload-sweeper" and t.is_alive()]

    with override_settings(FORENSIC_UPLOAD_SWEEP_S=0):
        before = len(alive())
        assert start_sweeper() is False, "0 means no periodic sweep"
        assert len(alive()) == before

    with override_settings(FORENSIC_UPLOAD_SWEEP_S=3600):
        # the app already started one at boot; calling again from another worker must not add a second
        for _ in range(3):
            start_sweeper()
        assert len(alive()) == 1, "one sweeper, not one per caller"


@override_settings(FORENSIC_BROWSER_ONLY=True)
def test_a_public_instance_keeps_a_short_retention_window():
    """The default is the point: an operator can lengthen it, a stranger-facing instance should not
    hold someone's evidence for a day because nobody set a variable."""
    from django.conf import settings

    assert settings.FORENSIC_UPLOAD_MAX_AGE_S <= 6 * 3600
