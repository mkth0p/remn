"""Static reference data for the UI: event descriptions, flag descriptions, bundled rules."""

from __future__ import annotations

import logging
import threading
from pathlib import Path

import yaml
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_GET

from services.analysis.attachments.magic import DANGEROUS_EXT
from services.parsers.mail.common import MAIL_WEIGHTS, STRONG_FLAGS
from services.reference import eventids, flags
from services.rules import measures, packs

log = logging.getLogger(__name__)

_lock = threading.Lock()
# the signature the rules were parsed under, and the rules
_parsed: tuple[str, list[dict]] | None = None


def load_rules(rules_dir: Path) -> list[dict]:
    out: list[dict] = []
    if not rules_dir.is_dir():
        return out
    for path in sorted(rules_dir.rglob("*.y*ml")):
        if packs.is_pack_path(path, rules_dir):
            continue  # community packs are served lazily by /api/rules/packs/<id>
        try:
            text = path.read_text(encoding="utf-8")
            docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
        except Exception as exc:  # noqa: BLE001
            log.warning("rule file %s invalid: %s", path, exc)
            # what is wrong with the YAML is for the reader of the rule list; any other failure
            # (the file cannot be read) carries the server's full path in its text
            said = str(exc)[:200] if isinstance(exc, yaml.YAMLError) else f"the file could not be read ({type(exc).__name__})"
            out.append({"file": str(path.relative_to(rules_dir)), "error": said, "yaml": ""})
            continue
        if len(docs) == 1:
            out.append({"file": str(path.relative_to(rules_dir)).replace("\\", "/"), "yaml": text, "rule": docs[0]})
        else:
            for i, d in enumerate(docs):
                out.append(
                    {
                        "file": f"{str(path.relative_to(rules_dir)).replace(chr(92), '/')}#{i}",
                        "yaml": yaml.safe_dump(d, sort_keys=False, allow_unicode=True),
                        "rule": d,
                    }
                )
    for entry in out:
        measured = measures.for_rule(entry.get("rule"))
        if measured is not None:
            entry["measured"] = measured
    return out


def _signature(rules_dir: Path) -> str:
    """Changes when a bundled rule file is added, removed or edited, and when the measures file is."""
    files = []
    if rules_dir.is_dir():
        for path in sorted(rules_dir.rglob("*.y*ml")):
            if packs.is_pack_path(path, rules_dir):
                continue
            try:
                st = path.stat()
            except OSError:
                continue
            files.append(f"{path.relative_to(rules_dir)}:{st.st_size}:{st.st_mtime_ns}")
    return "\n".join([str(rules_dir), measures.signature(), *files])


def bundled_rules(rules_dir: Path) -> list[dict]:
    """load_rules, parsed once and kept until a rule file or the measures file changes.

    Parsing the bundled rules takes about a second, and every page load asks for them. Looking at
    the files' sizes and modification times takes a few milliseconds."""
    global _parsed
    signature = _signature(rules_dir)
    with _lock:
        if _parsed and _parsed[0] == signature:
            return _parsed[1]
    rules = load_rules(rules_dir)
    with _lock:
        _parsed = (signature, rules)
    return rules


@require_GET
def meta(request):
    events = [{"provider": prov, "eventId": eid, "description": desc, "category": cat} for (prov, eid), (desc, cat) in eventids._EVENTS.items()]
    return JsonResponse(
        {
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
            "rules": bundled_rules(settings.RULES_DIR),
            "packs": packs.list_packs(),
            "measures": measures.summary(),
        }
    )
