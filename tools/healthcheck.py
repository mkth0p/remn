"""Exit 0 when the server in this container answers its health route, 1 when it does not.

The image's HEALTHCHECK runs it: the runtime image has no curl. The request carries the header
every API call needs, with the access token when the container was given one, and the result
depends on the status line only.
"""

import os
import sys
import urllib.request

port = os.environ.get("REMN_HEALTH_PORT", "8000")
request = urllib.request.Request(f"http://127.0.0.1:{port}/api/health", headers={"X-Forensic-Client": os.environ.get("FORENSIC_AUTH_TOKEN") or "1"})
try:
    with urllib.request.urlopen(request, timeout=4) as response:
        sys.exit(0 if response.status == 200 else 1)
except Exception:
    sys.exit(1)
