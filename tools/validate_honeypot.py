"""Local Docker integration check; creates only a disposable project and loopback listeners.

Build remn-archive first: docker build -t remn-archive honeypot
Uses the existing remn:latest image for routing checks. It never deploys a public site.
"""

import json
import os
import secrets
import socket
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs).stdout


def available_port():
    with socket.socket() as conn:
        conn.bind(("127.0.0.1", 0))
        return conn.getsockname()[1]


def main():
    project = "remn-archive-verify-" + secrets.token_hex(4)
    env = {**os.environ, "REMN_DOMAIN": "app.remn.test", "REMN_ARCHIVE_DOMAIN": "vault.remn.test"}
    base = ["docker", "compose", "-p", project, "-f", str(ROOT / "docker-compose.public.yml"), "-f", str(ROOT / "docker-compose.honeypot.yml")]
    config = json.loads(run(base + ["config", "--format", "json"], env=env))
    app, archive, proxy = (config["services"][name] for name in ("remn", "archive", "caddy"))
    assert archive["network_mode"] == "none" and archive["read_only"] and archive["cap_drop"] == ["ALL"]
    assert archive["user"] == "10001:10001" and not archive.get("ports") and not archive.get("networks")
    assert "no-new-privileges:true" in archive["security_opt"]
    assert {v["target"] for v in archive["volumes"]} == {"/run/archive", "/var/lib/archive"}
    assert next(v for v in proxy["volumes"] if v["target"] == "/run/archive")["read_only"]
    assert app["environment"]["FORENSIC_BROWSER_ONLY"] == "1"
    assert not app.get("ports")
    port = available_port()
    (ROOT / "backend" / "tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="archive-verify-", dir=ROOT / "backend" / "tmp") as directory:
        temp = Path(directory)
        caddy = (ROOT / "deploy" / "Caddyfile.honeypot").read_text()
        # Same route definitions, plain local HTTP and no ACME/network certificate request.
        caddy = caddy.replace("{\n", "{\n\tauto_https off\n", 1)
        caddy = caddy.replace("{$REMN_DOMAIN} {", "http://app.remn.test:8080 {").replace("{$REMN_ARCHIVE_DOMAIN} {", "http://vault.remn.test:8080 {")
        caddy_path = temp / "Caddyfile"
        caddy_path.write_text(caddy)
        # Work from the resolved configuration so inherited ports cannot accidentally remain.
        proxy["ports"] = [{"target": 8080, "published": str(port), "host_ip": "127.0.0.1", "protocol": "tcp"}]
        for volume in proxy["volumes"]:
            if volume["target"] == "/etc/caddy/Caddyfile":
                volume["source"] = str(caddy_path)
        for service in config["services"].values():
            service.pop("build", None)
            service["restart"] = "no"
        config_path = temp / "compose.json"
        config_path.write_text(json.dumps(config))
        cmd = ["docker", "compose", "-p", project, "-f", str(config_path)]

        def get(path, host="vault.remn.test", headers=None):
            request = urllib.request.Request(f"http://127.0.0.1:{port}" + path, headers={"Host": host, **(headers or {})})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            try:
                with opener.open(request, timeout=8) as response:
                    return response.status, response.headers, response.read(65537)
            except urllib.error.HTTPError as error:
                return error.code, error.headers, error.read(65537)

        try:
            run(cmd + ["up", "-d", "--wait", "--wait-timeout", "60"], timeout=75)
            checked = json.loads(run(cmd + ["exec", "-T", "archive", "python", "-m", "honeypot.verify", "boundary"]))
            seed = get("/.env.bak", "app.remn.test", {"Cookie": "must-not-be-logged=SECRET", "Authorization": "Bearer SECRET"})
            assert seed[0] == 200 and seed[1].get_content_type() == "text/plain"
            assert "sandbox" in seed[1]["Content-Security-Policy"]
            assert not seed[1].get("Set-Cookie") and not seed[1].get("Access-Control-Allow-Origin")
            url = seed[2].decode().split("RETENTION_COMPAT_MANIFEST=")[1].strip()

            def follow(url):
                parsed = urlsplit(url)
                response = get(parsed.path + "?" + parsed.query)
                assert response[0] == 200, response
                return json.loads(response[2])

            release = follow(url)
            current = follow(release["replacementIndex"])
            copy = follow(current["records"][1]["compatibilityReference"])
            assert copy["contentSha256"] == current["records"][1]["contentSha256"]
            receipt = urlsplit(copy["references"]["currentReceipt"])
            assert b"External reference request" in get(receipt.path + "?" + receipt.query)[2]
            for path in ("/operator", "/healthz", "/discovery/env", "/.env", "/api/store", "/records/unknown"):
                assert get(path)[0] == 404, path
            assert get("/api/store", "app.remn.test", {"X-Forensic-Client": "1"})[0] == 403
            assert get("/", "app.remn.test")[0] == 200
            assert get("/.env", "app.remn.test")[0] == 404
            episodes = json.loads(run(cmd + ["exec", "-T", "archive", "python", "-m", "honeypot.operator", "list"]))
            assert "SECRET" not in json.dumps(episodes)
            episode = episodes["episodes"][0]["episodeId"]
            exported = run(cmd + ["exec", "-T", "archive", "python", "-m", "honeypot.operator", "export", "--episode", episode])
            assert exported.startswith(b"PK") and len(exported) <= 128 * 1024
            # Preserve reviewable local artifacts, but never service keys or raw request data.
            result = ROOT / "backend" / "tmp" / "archive-smoke-export.zip"
            result.write_bytes(exported)
            stats = run(cmd + ["stats", "--no-stream", "--format", "json", "archive"]).decode().strip()
            # Exercise proxy errors too: Caddy must not log URL handles or headers.
            run(cmd + ["stop", "archive"], timeout=20)
            assert get("/compat/release.json?r=DO-NOT-LOG-QUERY", headers={"User-Agent": "DO-NOT-LOG-HEADER"})[0] == 502
            proxy_logs = run(cmd + ["logs", "--no-color", "caddy"]).decode()
            assert "DO-NOT-LOG" not in proxy_logs and '"request":' not in proxy_logs
            print(
                json.dumps(
                    {
                        "boundary": checked,
                        "routing": "production unchanged; two passive lures; deep routes isolated",
                        "trail": "manifest, retained copy, current receipt",
                        "export": str(result),
                        "containerStats": stats,
                    },
                    indent=2,
                )
            )
        finally:
            # Only the random disposable project created above; never the user's running stack.
            run(cmd + ["down", "--volumes", "--remove-orphans"], timeout=30)


if __name__ == "__main__":
    main()
