"""A reputation lookup sends the indicator to the provider, which is the analyst's choice per case.
The server cannot read that choice, so a request that would reach an external provider has to
state it (networkAllowed: true) and is refused before any provider is asked when it does not."""

from __future__ import annotations

import json

import pytest
from django.test import Client

from services.reputation import offline, providers, spamhaus
from services.reputation.base import Provider, TTLCache, Verdict, registry

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
ITEMS = [{"kind": "domain", "value": "invented-lookup.example"}]


class _Counting(Provider):
    kinds = ("domain",)

    def __init__(self, name: str, external: bool) -> None:
        super().__init__({})
        self.name = name
        self.external = external
        self.calls = 0

    def lookup(self, kind: str, value: str) -> Verdict:
        self.calls += 1
        return Verdict(self.name, kind, value, "clean")


@pytest.fixture
def fake_providers(monkeypatch):
    remote, local = _Counting("remote", True), _Counting("local", False)
    monkeypatch.setattr(registry, "providers", {"remote": remote, "local": local})
    monkeypatch.setattr(registry, "cache", TTLCache(60))
    return remote, local


def _lookup(body: dict):
    return Client().post("/api/reputation/lookup", data=json.dumps(body), content_type="application/json", **HDR)


def test_a_lookup_that_would_leave_the_machine_is_refused_without_the_case_choice(fake_providers):
    remote, local = fake_providers
    r = _lookup({"items": ITEMS})
    assert r.status_code == 403
    body = r.json()
    assert body["code"] == "lookupsNotAllowed" and body["external"] == ["remote"] and "networkAllowed" in body["error"]
    assert remote.calls == 0 and local.calls == 0


def test_only_a_true_choice_allows_it(fake_providers):
    remote, _ = fake_providers
    for said in (False, "true", 1, "yes", None, [True]):
        assert _lookup({"items": ITEMS, "networkAllowed": said}).status_code == 403, said
    assert remote.calls == 0


def test_a_lookup_the_case_allows_is_made(fake_providers):
    remote, local = fake_providers
    r = _lookup({"items": ITEMS, "networkAllowed": True})
    assert r.status_code == 200 and {v["provider"] for v in r.json()["results"]} == {"remote", "local"}
    assert remote.calls == 1 and local.calls == 1


def test_a_lookup_that_names_only_local_providers_needs_no_choice(fake_providers):
    remote, local = fake_providers
    r = _lookup({"items": ITEMS, "providers": ["local"]})
    assert r.status_code == 200 and [v["provider"] for v in r.json()["results"]] == ["local"]
    assert remote.calls == 0 and local.calls == 1


def test_naming_one_external_provider_among_local_ones_is_refused(fake_providers):
    remote, local = fake_providers
    r = _lookup({"items": ITEMS, "providers": ["local", "remote"]})
    assert r.status_code == 403 and r.json()["external"] == ["remote"]
    assert remote.calls == 0 and local.calls == 0


def test_a_lookup_of_nothing_needs_no_choice(fake_providers):
    r = _lookup({"items": []})
    assert r.status_code == 200 and r.json()["results"] == []


def test_the_provider_list_says_which_providers_leave_the_machine(fake_providers):
    listed = {p["name"]: p["external"] for p in Client().get("/api/reputation/providers", **HDR).json()["providers"]}
    assert listed == {"remote": True, "local": False}


def test_the_offline_lists_and_geoip_are_local_and_every_network_provider_is_external():
    assert offline.OfflineLists.external is False and offline.GeoIP.external is False
    assert spamhaus.Spamhaus.external is True
    assert all(cls.external for cls in providers.ALL)
