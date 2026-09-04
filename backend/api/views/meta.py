"""Static reference data for the UI: event descriptions, flag descriptions, bundled rules."""
from __future__ import annotations

import logging
from pathlib import Path

import yaml
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_GET

from services.analysis.attachments.magic import DANGEROUS_EXT
from services.parsers.mail.common import MAIL_WEIGHTS, STRONG_FLAGS
from services.reference import eventids, flags

log = logging.getLogger(__name__)


def load_rules(rules_dir: Path) -> list[dict]:
    out: list[dict] = []
    if not rules_dir.is_dir():
        return out
    for path in sorted(rules_dir.rglob("*.y*ml")):
        try:
            text = path.read_text(encoding="utf-8")
            docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
        except Exception as exc:  # noqa: BLE001
            log.warning("rule file %s invalid: %s", path, exc)
            out.append({"file": str(path.relative_to(rules_dir)), "error": str(exc)[:200], "yaml": ""})
            continue
        if len(docs) == 1:
            out.append({"file": str(path.relative_to(rules_dir)).replace("\\", "/"), "yaml": text, "rule": docs[0]})
        else:
            for i, d in enumerate(docs):
                out.append({"file": f"{str(path.relative_to(rules_dir)).replace(chr(92), '/')}#{i}", "yaml": yaml.safe_dump(d, sort_keys=False, allow_unicode=True), "rule": d})
    return out


@require_GET
def meta(request):
    events = [{"provider": prov, "eventId": eid, "description": desc, "category": cat} for (prov, eid), (desc, cat) in eventids._EVENTS.items()]
    return JsonResponse({
        "events": events,
        "notes": {str(k): v for k, v in eventids.NOTES.items()},
        "logonTypes": {str(k): v for k, v in eventids.LOGON_TYPES.items()},
        "statusCodes": eventids.STATUS_CODES,
        "kerberosFailures": eventids.KERBEROS_FAILURES,
        "ticketEncryption": eventids.TICKET_ENCRYPTION,
        "flags": flags.FLAGS,
        "mailWeights": MAIL_WEIGHTS,
        "mailStrongFlags": sorted(STRONG_FLAGS),
        "dangerousExtensions": DANGEROUS_EXT,
        "rules": load_rules(settings.RULES_DIR),
    })
