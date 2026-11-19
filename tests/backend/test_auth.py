from __future__ import annotations

import pytest
from django.test import Client, override_settings

from forensic.middleware import ApiClientHeaderMiddleware


@pytest.fixture(autouse=True)
def _fresh_allowance():
    # wrong tokens are counted per client address across requests; each test starts with none
    ApiClientHeaderMiddleware.reset()
    yield
    ApiClientHeaderMiddleware.reset()


def test_no_token_mode_presence_only():
    c = Client()
    assert c.get("/api/meta").status_code == 403
    # a health probe without the header learns that the server is up, and nothing more
    assert c.get("/api/health").json() == {"ok": True}
    assert c.get("/api/health", HTTP_X_FORENSIC_CLIENT="anything").status_code == 200
    assert c.options("/api/health").status_code == 403


@override_settings(FORENSIC_AUTH_TOKEN="s3cret-token")
def test_token_mode_requires_exact_value():
    c = Client()
    # missing header stays 403 (not 401) so scanners learn nothing
    assert c.get("/api/meta").status_code == 403
    assert c.get("/api/health").json() == {"ok": True}
    r = c.get("/api/health", HTTP_X_FORENSIC_CLIENT="remn")
    assert r.status_code == 401
    assert r.json()["code"] == "auth"
    assert c.get("/api/health", HTTP_X_FORENSIC_CLIENT="s3cret-token").status_code == 200
    # OPTIONS rejected even with the right token (no preflights ever)
    assert c.options("/api/health", HTTP_X_FORENSIC_CLIENT="s3cret-token").status_code == 403


@override_settings(FORENSIC_AUTH_TOKEN="s3cret-token")
def test_token_mode_covers_store_and_upload_routes():
    c = Client()
    assert c.get("/api/meta", HTTP_X_FORENSIC_CLIENT="wrong").status_code == 401
    assert c.post("/api/upload/init", HTTP_X_FORENSIC_CLIENT="wrong").status_code == 401


@override_settings(FORENSIC_AUTH_TOKEN="s3cret-token")
def test_a_non_ascii_token_is_refused_not_an_error():
    r = Client().get("/api/health", HTTP_X_FORENSIC_CLIENT="s3cret-tokén")
    assert r.status_code == 401


def _wrong(c: Client, n: int, **meta) -> list[int]:
    return [c.get("/api/meta", HTTP_X_FORENSIC_CLIENT="wrong", **meta).status_code for _ in range(n)]


@override_settings(FORENSIC_AUTH_TOKEN="s3cret-token", FORENSIC_AUTH_FAILURES_PER_MIN=10)
def test_wrong_tokens_past_the_allowance_get_429_with_a_retry_after():
    c = Client()
    assert _wrong(c, 10) == [401] * 10
    r = c.get("/api/meta", HTTP_X_FORENSIC_CLIENT="wrong")
    assert r.status_code == 429 and r.json()["code"] == "rate" and int(r["Retry-After"]) >= 1


@override_settings(FORENSIC_AUTH_TOKEN="s3cret-token", FORENSIC_AUTH_FAILURES_PER_MIN=3)
def test_a_limited_address_is_refused_the_right_token_too():
    # were the right token let through, every guess would still be answered
    c = Client()
    assert _wrong(c, 3) == [401] * 3
    assert c.get("/api/meta", HTTP_X_FORENSIC_CLIENT="s3cret-token").status_code == 429


@override_settings(FORENSIC_AUTH_TOKEN="s3cret-token", FORENSIC_AUTH_FAILURES_PER_MIN=3)
def test_the_right_token_does_not_count_against_the_allowance():
    c = Client()
    for _ in range(20):
        assert c.get("/api/meta", HTTP_X_FORENSIC_CLIENT="s3cret-token").status_code == 200
    assert _wrong(c, 3) == [401] * 3


@override_settings(FORENSIC_AUTH_TOKEN="s3cret-token", FORENSIC_AUTH_FAILURES_PER_MIN=2)
def test_the_placeholder_the_page_sends_before_it_has_a_token_is_refused_but_not_counted():
    c = Client()
    for placeholder in ("remn", "1") * 5:
        assert c.get("/api/meta", HTTP_X_FORENSIC_CLIENT=placeholder).status_code == 401
    # the allowance is untouched: two real wrong tokens are still answered 401 before the limit
    assert _wrong(c, 3) == [401, 401, 429]


@override_settings(FORENSIC_AUTH_TOKEN="s3cret-token", FORENSIC_AUTH_FAILURES_PER_MIN=2)
def test_the_allowance_is_kept_per_client_address_and_per_64_for_ipv6():
    c = Client()
    assert _wrong(c, 3, REMOTE_ADDR="198.51.100.7") == [401, 401, 429]
    assert _wrong(c, 2, REMOTE_ADDR="198.51.100.8") == [401, 401]
    assert _wrong(c, 2, REMOTE_ADDR="2001:db8:1:1::1") == [401, 401]
    # another address of the same /64 shares the allowance
    assert _wrong(c, 1, REMOTE_ADDR="2001:db8:1:1::ffff") == [429]
    assert _wrong(c, 1, REMOTE_ADDR="2001:db8:1:2::1") == [401]


@override_settings(FORENSIC_AUTH_TOKEN="s3cret-token", FORENSIC_AUTH_FAILURES_PER_MIN=0)
def test_zero_turns_the_limit_off():
    assert set(_wrong(Client(), 30)) == {401}


@override_settings(FORENSIC_AUTH_TOKEN="s3cret-token", FORENSIC_AUTH_FAILURES_PER_MIN=2)
def test_a_probe_without_the_header_is_not_counted_and_stays_answered():
    c = Client()
    for _ in range(5):
        assert c.get("/api/health").json() == {"ok": True}
    assert _wrong(c, 2) == [401, 401]
    # a limited address is still told the server is up: the probe presents no token at all
    assert c.get("/api/health").json() == {"ok": True}
