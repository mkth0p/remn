"""
Production-style local launcher: serves the API and the built frontend on
one port with waitress (no debug mode, threaded, streaming responses).

    .venv\\Scripts\\python.exe backend\\run.py [--port 8000]
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "forensic.settings")


def _loopback(address: str) -> bool:
    """True for an address that only this machine can reach."""
    name = address.strip().strip("[]").lower()
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def refusal(host: str) -> str | None:
    """Why the server must not start listening on `host`, or None when it may.

    Without a token, anyone who can reach the port can read and delete every case in the server
    store, so the server starts without one only where other machines cannot reach it, or where the
    operator has said that this is intended (FORENSIC_ALLOW_NO_TOKEN). In a container the server
    listens on every interface and who can reach it is decided by how the port is published, which
    the container cannot see: FORENSIC_PUBLISHED_ON carries that address in, and is what is judged."""
    from django.conf import settings

    reachable_on = settings.FORENSIC_PUBLISHED_ON or host
    if settings.FORENSIC_AUTH_TOKEN or settings.FORENSIC_ALLOW_NO_TOKEN or _loopback(reachable_on):
        return None
    at_stake = (
        "    A browser-only instance keeps no cases, and still has to say that it is open on purpose."
        if settings.FORENSIC_BROWSER_ONLY
        else "    Anyone who can reach that address could read and delete every case in the server store."
    )
    return "\n".join(
        [
            f"[!] Not starting: the server would be reachable on {reachable_on or 'every interface'} without an access token.",
            at_stake,
            "    Choose one of:",
            "      - FORENSIC_AUTH_TOKEN=<long random string>: every request must carry it (REMN_TOKEN with docker compose);",
            "      - listen on 127.0.0.1, or publish the container's port on 127.0.0.1 and tell the server so with",
            "        FORENSIC_PUBLISHED_ON=127.0.0.1 (docker-compose.yml does both by default);",
            "      - FORENSIC_ALLOW_NO_TOKEN=1: something in front of the server decides who gets in, or the instance is",
            "        browser-only and open by design (REMN_NO_TOKEN=1 with docker compose).",
            '    See docs/setup.md, "Remote access".',
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Forensic mail + EVTX analyzer")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--threads", type=int, default=8)
    args = parser.parse_args()
    # settings size the heavy-request cap from the thread count
    os.environ.setdefault("FORENSIC_THREADS", str(args.threads))

    import django

    django.setup()
    from django.conf import settings
    from waitress import serve

    from forensic.wsgi import application

    # waitress spools a request body over 512 KiB to a temporary file. Put those next to the other
    # staged evidence, on the volume sized for it, rather than in the system /tmp, which a hardened
    # container keeps small (64 MiB in docker-compose.public.yml) and where a large single-request
    # upload failed with a reset connection.
    tempfile.tempdir = str(settings.FILE_UPLOAD_TEMP_DIR)

    if not (settings.FRONTEND_DIST / "index.html").exists():
        print("[!] frontend/dist/index.html not found. Run `npm run build` in frontend/ first.")

    if (said := refusal(args.host)) is not None:
        print(said, file=sys.stderr)
        sys.exit(2)
    if not settings.FORENSIC_AUTH_TOKEN and not _loopback(settings.FORENSIC_PUBLISHED_ON or args.host):
        print("[!] Listening beyond loopback without an access token, as FORENSIC_ALLOW_NO_TOKEN says is intended.")
        if not settings.FORENSIC_BROWSER_ONLY:
            print("    Anyone who can reach this port can read and delete every case store.")
    print(f"[*] Forensic analyzer listening on http://{args.host}:{args.port}")
    serve(
        application,
        host=args.host,
        port=args.port,
        threads=args.threads,
        channel_timeout=3600,
        max_request_body_size=settings.FORENSIC_MAX_UPLOAD_MB * 1024 * 1024 + 1024 * 1024,
    )


if __name__ == "__main__":
    main()
