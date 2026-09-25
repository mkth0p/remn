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


def test_root_files_are_served_as_files_and_missing_ones_are_404(tmp_path):
    """A browser asking for an icon must get the icon or a 404, never the page: HTML shown as an icon is blank."""
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><html><body>REMN</body></html>", encoding="utf-8")
    (dist / "favicon-32.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    with override_settings(FRONTEND_DIST=dist):
        c = Client()
        icon = c.get("/favicon-32.png")
        assert icon.status_code == 200
        assert icon["Content-Type"] == "image/png"
        assert c.get("/favicon.ico").status_code == 404
        assert c.get("/robots.txt").status_code == 404
        page = c.get("/cases/12/findings")
        assert page.status_code == 200
        assert page["Content-Type"].startswith("text/html")


def _block(text: str, opener: str) -> str:
    """The body of the Caddyfile block that opens with `opener` (a line ending in "{")."""
    start = text.index(opener)
    depth, i = 0, text.index("{", start)
    for j in range(i, len(text)):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        if depth == 0:
            return text[i + 1 : j]
    raise AssertionError(f"unclosed block {opener}")


def test_the_public_proxy_serves_the_page_with_djangos_headers_and_sends_only_the_api_on():
    """On the public profile Caddy serves the app from its own image and the parser answers /api/*
    only. The page headers are written twice, in the middleware and in the Caddyfile: they must agree."""
    import re
    from pathlib import Path

    from django.conf import settings

    from forensic.middleware import CSP_BROWSER_ONLY

    root = Path(__file__).resolve().parents[2]
    caddy = (root / "deploy" / "Caddyfile").read_text(encoding="utf-8")
    api = _block(caddy, "handle /api/* {")
    assert "reverse_proxy remn:8000" in api and caddy.count("reverse_proxy") == 1
    app = _block(caddy, "\thandle {")
    assert "root * /srv/remn" in app and "file_server" in app and "reverse_proxy" not in app
    headers = dict(re.findall(r'^\t\t\t([A-Za-z-]+) "(.*)"$', _block(app, "header {"), re.M))
    r = Client().get("/api/health", **HDR)  # the middleware's values, as it sets them
    expected = {
        k: r[k] for k in ("X-Content-Type-Options", "Referrer-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Permissions-Policy")
    }
    assert headers == {"Content-Security-Policy": CSP_BROWSER_ONLY, "X-Frame-Options": settings.X_FRAME_OPTIONS, **expected}
    # the image Caddy runs holds the build, from the same commit as the parser
    docker = (root / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^FROM caddy:[^\s]+@sha256:[0-9a-f]{64} AS static\nCOPY --from=frontend /src/frontend/dist /srv/remn$", docker, re.M)
    compose = (root / "docker-compose.public.yml").read_text(encoding="utf-8")
    service = compose[compose.index("  caddy:") :]
    assert "target: static" in service and "REMN_BUILD_ID: ${REMN_BUILD_ID:-}" in service
    update = (root / "deploy" / "update.sh").read_text(encoding="utf-8")
    assert update.index("caddy validate") < update.index('"${compose[@]}" up -d')
