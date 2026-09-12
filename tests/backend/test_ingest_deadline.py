"""One ingest request may not hold a worker thread for as long as it likes.

The rate limiter shapes arrivals, not concurrent work, and the server cannot reap a request once
it is running. The deadline ends the stream with what was parsed, says why, and releases what the
parse was holding.
"""

from __future__ import annotations

import io
import itertools
import json
import os
import sys
import zipfile
from pathlib import Path

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings

from api.views import ingest

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}


def prefetch_package(count):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "samples" / "synthetic"))
    from native_artifacts import prefetch_bytes

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for i in range(count):
            z.writestr(f"Prefetch Files/p{i:04d}.pf", prefetch_bytes())
    return out.getvalue()


def post_package(blob):
    response = Client().post("/api/ingest/package", {"file": SimpleUploadedFile("pkg.zip", blob)}, **HDR)
    assert response.status_code == 200
    return [json.loads(line) for line in b"".join(response.streaming_content).splitlines() if line.strip()]


def test_a_parse_past_the_deadline_ends_with_what_it_has(tmp_path, monkeypatch):
    # the second check is the one that fires: one row goes out, then the stream is ended
    calls = itertools.count()
    monkeypatch.setattr(ingest, "_expired", lambda deadline: next(calls) >= 1)

    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path):
        lines = post_package(prefetch_package(6))

    kinds = [line["type"] for line in lines]
    assert kinds[0] == "meta" and kinds[-1] == "done"
    assert kinds.count("event") == 2, "the rows sent before the limit are kept"
    assert any(line["type"] == "error" and "FORENSIC_INGEST_MAX_S" in line["error"] for line in lines)
    assert lines[-1]["stats"]["inventoryComplete"] is False
    assert not [p for p in os.scandir(tmp_path) if p.is_file()], "everything the parse was holding is released"


def test_no_limit_means_no_limit(tmp_path):
    with override_settings(FILE_UPLOAD_TEMP_DIR=tmp_path, FORENSIC_INGEST_MAX_S=0):
        lines = post_package(prefetch_package(3))

    assert sum(1 for line in lines if line["type"] == "event") == 6
    assert not any(line["type"] == "error" for line in lines)
    assert lines[-1]["stats"]["inventoryComplete"] is True


def test_the_deadline_comes_from_the_setting():
    with override_settings(FORENSIC_INGEST_MAX_S=0):
        assert ingest._deadline() is None
        assert ingest._expired(None) is False
    with override_settings(FORENSIC_INGEST_MAX_S=3600):
        deadline = ingest._deadline()
        assert deadline is not None and not ingest._expired(deadline)
        assert ingest._expired(deadline - 7200), "a deadline in the past has expired"


def test_the_public_deployment_sets_a_limit():
    """The default is computed at import from FORENSIC_BROWSER_ONLY, so the public compose file
    is where a stranger-facing instance actually gets its ceiling."""
    compose = (Path(__file__).resolve().parents[2] / "docker-compose.public.yml").read_text(encoding="utf-8")
    assert "FORENSIC_INGEST_MAX_S" in compose
    assert "REMN_INGEST_MAX_S:-1800" in compose
