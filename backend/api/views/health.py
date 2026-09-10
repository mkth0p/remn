from __future__ import annotations

import platform
import sys

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_GET

from api.services import ollama_service
from services.ai import claude_code
from services.analysis.attachments import yara_scan
from services.parsers.mail import pst
from services.reputation.base import registry

VERSION = "0.1.1"


@require_GET
def health(request):
    browser_only = settings.FORENSIC_BROWSER_ONLY
    if browser_only:
        # no server-side model in this mode, and nothing about the machine that a stranger needs
        ai: dict = {"reachable": False, "host": "", "models": [], "defaultModel": "", "error": "browser-only mode: no server-side model"}
        caps: list = []
    else:
        ai = ollama_service().ping()
        caps = ollama_service().capabilities(settings.OLLAMA_MODEL) if ai.get("reachable") else []
    payload = {
        "ok": True,
        "name": "REMN forensic analyzer",
        "version": VERSION,
        "stateless": True,
        "mode": "browser-only" if browser_only else "full",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "limits": {
            "maxUploadMb": settings.FORENSIC_MAX_UPLOAD_MB,
            "inMemoryMb": settings.FORENSIC_IN_MEMORY_MB,
            "maxChunkedGb": settings.FORENSIC_MAX_CHUNKED_GB,
            "chunkMb": settings.FORENSIC_CHUNK_MB,
        },
        "store": {"thresholdMb": settings.FORENSIC_STORE_THRESHOLD_MB, "casesDir": str(settings.CASES_DIR)},
        "ollama": {**ai, "capabilities": caps, "numCtx": settings.OLLAMA_NUM_CTX},
        "optional": {
            "pst": pst.available(),
            "yara": yara_scan.available(),
            "yaraRules": yara_scan.rule_count(),
            "claudeCode": claude_code.available() and not browser_only,
        },
        "providers": [] if browser_only else registry.list(),
        "rulesDir": str(settings.RULES_DIR),
        "dataDir": str(settings.DATA_DIR),
    }
    if browser_only:
        # The same reasoning as the paths and platform: an instance open to strangers should not
        # hand out its exact version and which native parsers are compiled in. libpff and
        # yara-python are the most CVE-prone parts of the stack, and the browser needs to know
        # only whether a capability exists, which it learns when a file needs it.
        for k in ("python", "platform", "store", "rulesDir", "dataDir", "version"):
            payload.pop(k, None)
        payload["optional"] = {"claudeCode": False}
    return JsonResponse(payload)
