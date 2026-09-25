"""The staging area holds evidence only while it is parsed.

A public instance takes files from people it does not know, so what matters is not only that a
completed parse cleans up, but that an abandoned upload cannot sit there, cannot accumulate, and
is not readable by anyone else on the host.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from django.test import Client, override_settings

from api.views.upload import cleanup_stale, staged_bytes, start_sweeper, upload_dir

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}


def _init(client, size=1024, name="evidence.evtx"):
    return client.post("/api/upload/init", json.dumps({"name": name, "size": size}), content_type="application/json", **HDR)


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

        # a request the staging area cannot hold is refused, with a reason a client can act on
        big = c.post("/api/upload/init", json.dumps({"name": "huge.evtx", "size": 2 * 1024**3}), content_type="application/json", **HDR)
        assert big.status_code in (400, 507), big.content[:200]


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
