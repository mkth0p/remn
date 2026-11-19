"""A job belongs to one case: it is listed, read, followed and cancelled only by a request that
presents that case's key, and no answer about a job carries the key."""

from __future__ import annotations

import json
import threading
import uuid

import pytest
from django.test import Client

from api.jobs import manager
from services.store.casestore import registry

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}


@pytest.fixture
def running_job():
    """A job of an invented case that runs until the test ends."""
    release = threading.Event()
    key = str(uuid.uuid4())
    job = manager.submit("rules", key, lambda j: release.wait(30), label="evidence-name.evtx")
    yield key, job
    release.set()


def test_the_job_listing_needs_a_case_key_and_lists_that_case_only(running_job):
    key, job = running_job
    other = manager.submit("rules", str(uuid.uuid4()), lambda j: None, label="another-case.evtx")
    c = Client()
    for query in ("", "?case=", "?case=not-a-key"):
        r = c.get(f"/api/jobs{query}", **HDR)
        assert r.status_code == 400 and "case is required" in r.json()["error"]
    ids = [j["id"] for j in c.get(f"/api/jobs?case={key}", **HDR).json()["jobs"]]
    assert ids == [job.id] and other.id not in ids


def test_no_job_answer_carries_a_case_key(running_job):
    key, job = running_job
    c = Client()
    listed = c.get(f"/api/jobs?case={key}", **HDR)
    read = c.get(f"/api/jobs/{job.id}?case={key}", **HDR)
    assert listed.status_code == 200 and read.status_code == 200
    for body in (listed.content, read.content):
        assert key not in body.decode() and "caseKey" not in body.decode()


def test_a_job_is_read_only_with_the_key_of_its_case(running_job):
    key, job = running_job
    c = Client()
    unknown = c.get(f"/api/jobs/{uuid.uuid4().hex}?case={key}", **HDR)
    assert unknown.status_code == 404
    # no key and a wrong key are answered as an unknown id is, so a key cannot be tried against a job
    for query in ("", f"?case={uuid.uuid4()}", "?case=caf%C3%A9"):
        r = c.get(f"/api/jobs/{job.id}{query}", **HDR)
        assert r.status_code == 404 and r.content == unknown.content, query
    r = c.get(f"/api/jobs/{job.id}?case={key}", **HDR)
    assert r.status_code == 200 and r.json()["id"] == job.id


def test_a_job_is_cancelled_only_with_the_key_of_its_case(running_job):
    key, job = running_job
    c = Client()
    assert c.delete(f"/api/jobs/{job.id}", **HDR).status_code == 404
    assert c.delete(f"/api/jobs/{job.id}?case={uuid.uuid4()}", **HDR).status_code == 404
    assert not job.cancelled
    r = c.delete(f"/api/jobs/{job.id}?case={key}", **HDR)
    assert r.status_code == 200 and r.json() == {"cancelled": True} and job.cancelled


def test_the_progress_stream_of_a_job_needs_the_key_of_its_case(running_job):
    key, job = running_job
    c = Client()
    assert c.get(f"/api/jobs/{job.id}/events", **HDR).status_code == 404
    assert c.get(f"/api/jobs/{job.id}/events?case={uuid.uuid4()}", **HDR).status_code == 404
    r = c.get(f"/api/jobs/{job.id}/events?case={key}", **HDR)
    assert r.status_code == 200 and r["Content-Type"].startswith("text/event-stream")
    first = next(iter(r.streaming_content)).decode()
    assert first.startswith("data: ") and json.loads(first[6:])["id"] == job.id and key not in first
    r.close()


def test_an_export_of_an_unknown_key_is_a_404_and_creates_no_store(tmp_path):
    old = registry.root
    registry.configure(tmp_path / "cases")
    try:
        key = str(uuid.uuid4())
        r = Client().get(f"/api/store/{key}/export", **HDR)
        assert r.status_code == 404
        assert list((tmp_path / "cases").iterdir()) == []
    finally:
        if old:
            registry.configure(old)
