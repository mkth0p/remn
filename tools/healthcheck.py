"""Exit 0 when the server in this container answers its health route, 1 when it does not.

The image's HEALTHCHECK runs it: the runtime image has no curl. The request carries neither the
X-Forensic-Client header nor the access token: the server answers a GET of /api/health without the
header with {"ok": true} and nothing about itself, and a probe that presents no token can never be
taken for a wrong one. The result depends on the status line only.
"""

import os
import sys
import urllib.request

port = os.environ.get("REMN_HEALTH_PORT", "8000")
try:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=4) as response:
        sys.exit(0 if response.status == 200 else 1)
except Exception:
    sys.exit(1)
