"""Security headers: the API gets the closed policy, the app pages and their scripts get the app policy.

A web worker takes its Content Security Policy from the response that served its script, so the
hashing and ingest workers must be served with the page's policy (wasm, connect-src); the closed
policy on a script asset breaks every upload when Django serves the built frontend.
"""

from __future__ import annotations

from django.test import Client, override_settings

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
CLOSED = "default-src 'none'; frame-ancestors 'none'; sandbox"


def test_api_responses_get_the_closed_policy():
    r = Client().get("/api/health", **HDR)
    assert r.status_code == 200
    assert r["Content-Security-Policy"] == CLOSED
    assert r["X-Content-Type-Options"] == "nosniff"
    assert r["Cross-Origin-Resource-Policy"] == "same-origin"


def test_scripts_and_pages_get_the_app_policy(tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "assets" / "ingest.worker-abc123.js").write_text("self.postMessage('ok')", encoding="utf-8")
    (dist / "assets" / "index-abc123.css").write_text("body{}", encoding="utf-8")
    (dist / "index.html").write_text("<!doctype html><html><body>REMN</body></html>", encoding="utf-8")
    with override_settings(FRONTEND_DIST=dist):
        c = Client()
        script = c.get("/assets/ingest.worker-abc123.js")
        assert script.status_code == 200
        csp = script["Content-Security-Policy"]
        assert "'wasm-unsafe-eval'" in csp and "connect-src 'self'" in csp and "sandbox" not in csp
        page = c.get("/")
        assert page.status_code == 200
        assert page["Content-Security-Policy"] == csp
        style = c.get("/assets/index-abc123.css")
        assert style.status_code == 200
        assert not style.has_header("Content-Security-Policy")
