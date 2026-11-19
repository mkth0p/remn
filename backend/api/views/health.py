from __future__ import annotations

import platform
import sys
import threading
import time

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_GET

from api.services import ollama_service
from forensic.build import VERSION, build_id, source_url
from services.ai import claude_code
from services.analysis import hayabusa
from services.analysis.attachments import yara_scan
from services.parsers.mail import pst
from services.reputation.base import registry

# how long an answer from Ollama is reused
PROBE_TTL_S = 15.0
_probe_lock = threading.Lock()
# when Ollama was last asked, and what it answered
_probe: tuple[float, dict, list] | None = None


def _ollama() -> tuple[dict, list]:
    """Whether Ollama answers and what its default model can do, asked at most every PROBE_TTL_S.

    Every open page asks for health twice a minute, and each answer used to be a call to Ollama,
    two when it is up. Requests that arrive while it is being asked wait for that one answer."""
    global _probe
    with _probe_lock:
        if _probe is None or time.monotonic() - _probe[0] > PROBE_TTL_S:
            ai = ollama_service().ping()
            caps = ollama_service().capabilities(settings.OLLAMA_MODEL) if ai.get("reachable") else []
            _probe = (time.monotonic(), ai, caps)
        return _probe[1], _probe[2]


@require_GET
def health(request):
    if not getattr(request, "forensic_client", False):
        # A caller that did not send the client header: a health check, a load balancer, anyone who
        # can reach the port. It learns that the server answers, and nothing about the server.
        return JsonResponse({"ok": True})
    browser_only = settings.FORENSIC_BROWSER_ONLY
    if browser_only:
        # no server-side model in this mode, and nothing about the machine that a stranger needs
        ai: dict = {"reachable": False, "host": "", "models": [], "defaultModel": "", "error": "browser-only mode: no server-side model"}
        caps: list = []
    else:
        ai, caps = _ollama()
    payload = {
        "ok": True,
        "name": "REMN forensic analyzer",
        "version": VERSION,
        # the exact source this server runs, so anyone can read and check it; kept in every mode
        "build": build_id(),
        "source": source_url(),
        "stateless": True,
        "mode": "browser-only" if browser_only else "full",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "limits": {
            "maxUploadMb": settings.FORENSIC_MAX_UPLOAD_MB,
            "inMemoryMb": settings.FORENSIC_IN_MEMORY_MB,
            "maxChunkedGb": settings.FORENSIC_MAX_CHUNKED_GB,
            "chunkMb": settings.FORENSIC_CHUNK_MB,
            "uploadMaxAgeS": settings.FORENSIC_UPLOAD_MAX_AGE_S,
        },
        "profile": settings.FORENSIC_PROFILE or None,
        "store": {"thresholdMb": settings.FORENSIC_STORE_THRESHOLD_MB, "casesDir": str(settings.CASES_DIR)},
        "ollama": {**ai, "capabilities": caps, "numCtx": settings.OLLAMA_NUM_CTX},
        "optional": {
            "pst": pst.available(),
            "yara": yara_scan.available(),
            "yaraRules": yara_scan.rule_count(),
            "claudeCode": claude_code.available() and not browser_only,
            "hayabusa": hayabusa.available(),
        },
        "providers": [] if browser_only else registry.list(),
        "rulesDir": str(settings.RULES_DIR),
        "dataDir": str(settings.DATA_DIR),
        "engines": hayabusa.engines(),
    }
    if browser_only:
        # An instance open to strangers keeps the machine's paths, platform and interpreter to
        # itself. It does say which commit it runs: the source is public, and a visitor trusting
        # the server with evidence should be able to read exactly what parses it. What the parser
        # can read is given as coarse formats, not as the native libraries behind them.
        for k in ("python", "platform", "store", "rulesDir", "dataDir"):
            payload.pop(k, None)
        payload["optional"] = {"claudeCode": False}
        payload["formats"] = {"pst": pst.available()}
    return JsonResponse(payload)
