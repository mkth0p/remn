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

VERSION = "0.1.0"


@require_GET
def health(request):
    ai = ollama_service().ping()
    caps = ollama_service().capabilities(settings.OLLAMA_MODEL) if ai.get("reachable") else []
    return JsonResponse({
        "ok": True,
        "name": "REMN forensic analyzer",
        "version": VERSION,
        "stateless": True,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "limits": {"maxUploadMb": settings.FORENSIC_MAX_UPLOAD_MB, "inMemoryMb": settings.FORENSIC_IN_MEMORY_MB, "maxChunkedGb": settings.FORENSIC_MAX_CHUNKED_GB, "chunkMb": settings.FORENSIC_CHUNK_MB},
        "store": {"thresholdMb": settings.FORENSIC_STORE_THRESHOLD_MB, "casesDir": str(settings.CASES_DIR)},
        "ollama": {**ai, "capabilities": caps, "numCtx": settings.OLLAMA_NUM_CTX},
        "optional": {
            "pst": pst.available(),
            "yara": yara_scan.available(),
            "yaraRules": yara_scan.rule_count(),
            "claudeCode": claude_code.available(),
        },
        "providers": registry.list(),
        "rulesDir": str(settings.RULES_DIR),
        "dataDir": str(settings.DATA_DIR),
    })
