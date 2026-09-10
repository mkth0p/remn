"""Browser-only mode closes every stateful or costly path; the request budget is per client address;
the store listing is an operator action that needs a token."""

from __future__ import annotations

import json

from django.test import Client, override_settings

from forensic.middleware import RateLimitMiddleware

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
CLOSED = [
    ("get", "/api/store"),
    ("post", "/api/store/abc/search"),
    ("delete", "/api/store/abc"),
    ("get", "/api/jobs"),
    # collection packages are an operator workflow: reconciliation is quadratic in
    # attacker-controlled input and each native member spawns a decoder subprocess
    ("post", "/api/ingest/package"),
    ("get", "/api/reputation/providers"),
    ("post", "/api/reputation/lookup"),
    ("post", "/api/ai/chat"),
    ("post", "/api/ai/query"),
    ("get", "/api/ai/models"),
    ("get", "/api/ai/claude/status"),
]


@override_settings(FORENSIC_BROWSER_ONLY=True)
def test_browser_only_closes_the_stateful_and_costly_paths():
    c = Client()
    for method, path in CLOSED:
        r = getattr(c, method)(path, **HDR)
        assert r.status_code == 403 and r.json()["code"] == "browserOnly", (path, r.status_code)
    h = c.get("/api/health", **HDR).json()
    assert h["mode"] == "browser-only"
    assert "store" not in h and "casesDir" not in json.dumps(h) and "platform" not in h
    assert h["providers"] == [] and h["ollama"]["reachable"] is False and h["optional"]["claudeCode"] is False
    # what the browser needs stays open: prompts for its own model, rule packs, the meta tables
    assert c.get("/api/ai/meta", **HDR).status_code == 200
    assert c.get("/api/rules/packs", **HDR).status_code == 200
    assert c.get("/api/meta", **HDR).status_code == 200


def test_full_mode_says_so_and_keeps_the_store():
    h = Client().get("/api/health", **HDR).json()
    assert h["mode"] == "full" and "store" in h


def test_store_listing_is_an_operator_action():
    r = Client().get("/api/store", **HDR)
    assert r.status_code == 403 and r.json()["code"] == "listing"
    with override_settings(FORENSIC_AUTH_TOKEN="operator-token"):
        assert Client().get("/api/store", HTTP_X_FORENSIC_CLIENT="operator-token").status_code == 200


def _build(c: Client, **meta):
    return c.post("/api/chains/build", json.dumps({"mails": [], "events": []}), content_type="application/json", **HDR, **meta)


@override_settings(FORENSIC_RATE_LIMIT_PER_MIN=3)
def test_the_budget_is_per_client_and_only_on_heavy_paths():
    RateLimitMiddleware.reset()
    c = Client()
    codes = [_build(c).status_code for _ in range(4)]
    assert codes[:3] == [200, 200, 200] and codes[3] == 429, codes
    r = _build(c)
    assert r.status_code == 429 and r.json()["code"] == "rate" and int(r["Retry-After"]) >= 1
    assert c.get("/api/health", **HDR).status_code == 200  # not budgeted
    assert _build(c, REMOTE_ADDR="10.0.0.9").status_code == 200  # another client, its own budget


@override_settings(FORENSIC_RATE_LIMIT_PER_MIN=2)
def test_forwarded_addresses_count_only_behind_a_trusted_proxy():
    RateLimitMiddleware.reset()
    c = Client()
    for _ in range(2):
        assert _build(c, HTTP_X_FORWARDED_FOR="203.0.113.5").status_code == 200
    # the header is ignored: every request came from the same peer, whose budget is spent
    assert _build(c, HTTP_X_FORWARDED_FOR="203.0.113.6").status_code == 429
    RateLimitMiddleware.reset()
    with override_settings(FORENSIC_TRUST_PROXY=True):
        for _ in range(2):
            assert _build(c, HTTP_X_FORWARDED_FOR="203.0.113.5, 10.0.0.1").status_code == 200
        assert _build(c, HTTP_X_FORWARDED_FOR="203.0.113.5, 10.0.0.1").status_code == 429
        assert _build(c, HTTP_X_FORWARDED_FOR="203.0.113.6").status_code == 200


def test_budget_off_by_default():
    RateLimitMiddleware.reset()
    c = Client()
    assert all(_build(c).status_code == 200 for _ in range(5))


@override_settings(FORENSIC_BROWSER_ONLY=True)
def test_browser_only_keeps_the_ordinary_ingestion_paths_open():
    """Closing the package endpoint must not close the paths the browser store depends on."""
    c = Client()
    for path in ("/api/ingest/evtx", "/api/ingest/mail"):
        assert c.post(path, **HDR).status_code != 403, path


@override_settings(FORENSIC_BROWSER_ONLY=True, FORENSIC_MAX_UPLOAD_MB=64, FORENSIC_MAX_CHUNKED_GB=64)
def test_browser_only_allows_chunked_upload_but_caps_it_at_the_single_request_ceiling():
    """A browser-store case has to get its evidence to the parser, and one request carrying the
    whole file is what proxies refuse. The chunked path stays open, bounded by the same ceiling."""
    c = Client()
    ok = c.post("/api/upload/init", json.dumps({"name": "big.evtx", "size": 32 * 1024**2}), content_type="application/json", **HDR)
    assert ok.status_code == 200 and ok.json()["uploadId"]

    # beyond what this instance accepts in one request, an unfinished upload would just hold disk
    too_big = c.post("/api/upload/init", json.dumps({"name": "huge.evtx", "size": 128 * 1024**2}), content_type="application/json", **HDR)
    assert too_big.status_code == 400


@override_settings(FORENSIC_BROWSER_ONLY=False, FORENSIC_MAX_UPLOAD_MB=64, FORENSIC_MAX_CHUNKED_GB=64)
def test_full_mode_keeps_the_operator_scale_chunked_ceiling():
    r = Client().post("/api/upload/init", json.dumps({"name": "huge.evtx", "size": 128 * 1024**2}), content_type="application/json", **HDR)
    assert r.status_code == 200


@override_settings(FORENSIC_RATE_LIMIT_PER_MIN=2, FORENSIC_TRUST_PROXY=True)
def test_a_forged_forwarded_header_cannot_buy_a_fresh_budget():
    """The budget must read the address the trusted proxy observed, which it appends on the right,
    not the leftmost entry, which is whatever the client sent."""
    RateLimitMiddleware.reset()
    c = Client()
    # a proxy that appends leaves the client's own value first and the real address last
    for _ in range(2):
        assert _build(c, HTTP_X_FORWARDED_FOR="10.9.9.9, 203.0.113.5").status_code == 200
    # rotating the forgeable half must not reset anything
    assert _build(c, HTTP_X_FORWARDED_FOR="10.9.9.8, 203.0.113.5").status_code == 429
    assert _build(c, HTTP_X_FORWARDED_FOR="totally-made-up, 203.0.113.5").status_code == 429
    # a genuinely different client, as the proxy reports it, has its own budget
    assert _build(c, HTTP_X_FORWARDED_FOR="10.9.9.9, 203.0.113.6").status_code == 200


@override_settings(FORENSIC_BROWSER_ONLY=True)
def test_browser_only_withholds_the_version_and_the_compiled_parsers():
    """Version plus which native parsers are compiled in is exactly what picks a CVE off a shelf."""
    body = Client().get("/api/health", **HDR).json()
    assert "version" not in body and "python" not in body and "platform" not in body
    assert body["optional"] == {"claudeCode": False}
    assert body["mode"] == "browser-only"


def test_full_mode_still_reports_the_version_and_capabilities_to_its_operator():
    body = Client().get("/api/health", **HDR).json()
    assert body["version"] and "pst" in body["optional"] and "yara" in body["optional"]


@override_settings(FORENSIC_BROWSER_ONLY=True)
def test_browser_only_narrows_the_exfiltration_channel():
    """An open connect-src would let any script injection post the evidence anywhere. A page on
    HTTPS can only reach loopback in any case, so narrowing costs that deployment nothing."""
    from forensic.middleware import CSP, CSP_BROWSER_ONLY

    assert "connect-src 'self' http://localhost:*" in CSP_BROWSER_ONLY
    assert " http: https:" not in CSP_BROWSER_ONLY.split("connect-src")[1].split(";")[0]
    assert "connect-src 'self' http: https:" in CSP  # an operator keeps their own network


def test_the_static_fallback_refuses_methods_it_cannot_serve(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><body>REMN</body>", encoding="utf-8")
    with override_settings(FRONTEND_DIST=dist):
        c = Client()
        assert c.get("/some/spa/route").status_code == 200
        for method in ("put", "delete", "patch"):
            r = getattr(c, method)("/some/spa/route")
            assert r.status_code == 405, (method, r.status_code)
