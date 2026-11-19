"""A numeric request parameter that is not a number is the client's mistake: it is answered with a
400 that names the parameter, never with a 500."""

from __future__ import annotations

import json
import uuid

import pytest
from django.test import Client

from api.params import BadParameter, seconds, whole_number
from services.store.casestore import registry

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}


def _post(c: Client, path: str, body: dict):
    return c.post(path, data=json.dumps(body), content_type="application/json", **HDR)


@pytest.fixture
def store_key(tmp_path):
    old = registry.root
    registry.configure(tmp_path / "cases")
    key = str(uuid.uuid4())
    registry.get(key, create=True)
    yield key
    registry.close_all()
    if old:
        registry.configure(old)


def test_a_whole_number_is_read_and_anything_else_is_refused_by_name():
    assert whole_number(None, "limit", 25) == 25 and whole_number("", "limit", 25) == 25
    assert whole_number("40", "limit", 25) == 40 and whole_number(40, "limit", 25) == 40
    for bad in ("ten", "1.5", "1e3", [1], {"n": 1}, True, float("nan"), float("inf")):
        with pytest.raises(BadParameter, match="^limit must be a whole number"):
            whole_number(bad, "limit", 25)
    with pytest.raises(BadParameter, match="offset must be a whole number, 0 or more"):
        whole_number(-1, "offset", 0, minimum=0)


def test_a_duration_is_read_and_anything_else_is_refused_by_name():
    assert seconds(None, "deadline", 60) == 60 and seconds("2.5", "deadline", 60) == 2.5
    for bad in ("soon", -1, "nan", "inf", [5], True):
        with pytest.raises(BadParameter, match="deadline must be a number of seconds above 0"):
            seconds(bad, "deadline", 60)


def test_an_upload_size_that_is_not_a_number_is_a_400():
    c = Client()
    for size in ("big", "1.5", [10], True):
        r = _post(c, "/api/upload/init", {"name": "e.evtx", "size": size})
        assert r.status_code == 400 and "size must be a whole number" in r.json()["error"], size


def test_store_limits_and_offsets_that_are_not_numbers_are_a_400(store_key):
    c = Client()
    base = f"/api/store/{store_key}"
    posts = [
        ("search", {"limit": "many"}, "limit"),
        ("search", {"offset": "x"}, "offset"),
        ("search", {"offset": -10}, "offset"),
        ("aggregate", {"limit": "x"}, "limit"),
        ("stack", {"limit": [1]}, "limit"),
        ("sql", {"sql": "SELECT 1", "limit": "x"}, "limit"),
    ]
    for route, body, name in posts:
        r = _post(c, f"{base}/{route}", body)
        assert r.status_code == 400 and r.json()["error"].startswith(f"{name} must be"), (route, body, r.content)
    for query, name in (("facets?limit=x", "limit"), ("iocs?limit=x", "limit"), ("iocs?offset=-5", "offset")):
        r = c.get(f"{base}/{query}", **HDR)
        assert r.status_code == 400 and r.json()["error"].startswith(f"{name} must be"), (query, r.content)
    # and a number is still a number
    assert _post(c, f"{base}/search", {"limit": "5", "offset": 0}).status_code == 200
    assert c.get(f"{base}/facets?limit=3", **HDR).status_code == 200


def test_a_lookup_deadline_that_is_not_a_number_of_seconds_is_a_400():
    c = Client()
    for deadline in ("soon", -1, "nan"):
        r = _post(c, "/api/reputation/lookup", {"items": [], "deadline": deadline})
        assert r.status_code == 400 and "deadline must be" in r.json()["error"], deadline
