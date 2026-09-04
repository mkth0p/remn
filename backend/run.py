"""
Production-style local launcher: serves the API and the built frontend on
one port with waitress (no debug mode, threaded, streaming responses).

    .venv\\Scripts\\python.exe backend\\run.py [--port 8000]
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "forensic.settings")


def main() -> None:
    parser = argparse.ArgumentParser(description="Forensic mail + EVTX analyzer")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--threads", type=int, default=8)
    args = parser.parse_args()

    import django

    django.setup()
    from django.conf import settings
    from waitress import serve

    from forensic.wsgi import application

    if not (settings.FRONTEND_DIST / "index.html").exists():
        print("[!] frontend/dist/index.html not found. Run `npm run build` in frontend/ first.")

    if args.host not in ("127.0.0.1", "localhost", "::1") and not settings.FORENSIC_AUTH_TOKEN:
        print("[!] WARNING: binding a non-loopback interface WITHOUT an access token.")
        print("    Anyone who can reach this port can read and delete every case store.")
        print("    Set FORENSIC_AUTH_TOKEN=<long-random-string> (and FORENSIC_ALLOWED_HOSTS) before exposing it.")
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
