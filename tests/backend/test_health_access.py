"""A health probe without the client header (a container health check, a load balancer) learns that
the server is up and nothing about the server; the page, which sends the header, gets the detail.
Ollama is asked at most every fifteen seconds, however many pages ask for health."""

from __future__ import annotations

import http.server
import os
import subprocess
import sys
import threading
from pathlib import Path

from django.test import Client, override_settings

from api.views import health

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
ROOT = Path(__file__).resolve().parents[2]


def test_a_probe_without_the_header_learns_only_that_the_server_is_up():
    r = Client().get("/api/health")
    assert r.status_code == 200 and r.json() == {"ok": True}


def test_a_caller_with_the_header_gets_the_detail():
    body = Client().get("/api/health", **HDR).json()
    assert body["ok"] is True and "platform" in body and "store" in body and "optional" in body


@override_settings(FORENSIC_AUTH_TOKEN="invented-token")
def test_with_a_token_the_probe_still_gets_liveness_and_the_detail_still_needs_the_token():
    c = Client()
    assert c.get("/api/health").json() == {"ok": True}
    wrong = c.get("/api/health", HTTP_X_FORENSIC_CLIENT="remn")
    assert wrong.status_code == 401 and wrong.json()["code"] == "auth"
    assert "platform" in c.get("/api/health", HTTP_X_FORENSIC_CLIENT="invented-token").json()


def test_only_a_get_of_the_health_route_is_answered_without_the_header():
    c = Client()
    assert c.post("/api/health").status_code == 403
    assert c.options("/api/health").status_code == 403
    for path in ("/api/health/", "/api/healthz", "/api/meta", "/api/store"):
        assert c.get(path).status_code == 403, path


def test_ollama_is_asked_at_most_every_fifteen_seconds(monkeypatch):
    asked: list[str] = []

    class Ollama:
        def ping(self):
            asked.append("ping")
            return {"reachable": True, "host": "", "models": [], "defaultModel": ""}

        def capabilities(self, model):
            asked.append("capabilities")
            return ["tools"]

    monkeypatch.setattr(health, "ollama_service", Ollama)
    monkeypatch.setattr(health, "_probe", None)
    c = Client()
    for _ in range(3):
        assert c.get("/api/health", **HDR).json()["ollama"]["capabilities"] == ["tools"]
    assert asked == ["ping", "capabilities"]
    # sixteen seconds later
    monkeypatch.setattr(health, "_probe", (health._probe[0] - 16, *health._probe[1:]))
    c.get("/api/health", **HDR)
    assert asked == ["ping", "capabilities"] * 2


class _Recorder(http.server.BaseHTTPRequestHandler):
    seen: list[dict[str, str]] = []

    def do_GET(self):  # noqa: N802 - the name http.server calls
        self.seen.append({"path": self.path, **{k.lower(): v for k, v in self.headers.items()}})
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_the_container_health_check_probes_without_the_header_or_the_token():
    # it needs no token, and a probe that presents none can never present a wrong one
    server = http.server.HTTPServer(("127.0.0.1", 0), _Recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # no proxy: the probe goes to this machine, as it does inside the container
        env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
        env = {**env, "REMN_HEALTH_PORT": str(server.server_address[1]), "FORENSIC_AUTH_TOKEN": "invented-token"}
        done = subprocess.run([sys.executable, str(ROOT / "tools" / "healthcheck.py")], env=env, timeout=30, check=False)
    finally:
        server.shutdown()
        server.server_close()
    assert done.returncode == 0
    (request,) = _Recorder.seen
    assert request["path"] == "/api/health" and "x-forensic-client" not in request
