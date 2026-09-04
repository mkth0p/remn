from __future__ import annotations

import logging

from django.apps import AppConfig
from django.conf import settings

log = logging.getLogger(__name__)


class ApiConfig(AppConfig):
    name = "api"

    def ready(self) -> None:
        # Wire the Django-independent services with the settings.
        from services.analysis.attachments import yara_scan
        from services.reputation.base import registry

        from api.views.upload import cleanup_stale
        from services.store.casestore import registry as store_registry

        yara_scan.configure(settings.YARA_RULES_DIR)
        store_registry.configure(settings.CASES_DIR)
        try:
            removed_uploads = cleanup_stale()
            if removed_uploads:
                log.info("removed %d stale chunked upload file(s)", removed_uploads)
        except Exception as exc:  # noqa: BLE001
            log.warning("upload cleanup failed: %s", exc)
        registry.configure(
            keys=settings.REPUTATION_KEYS,
            timeout=settings.REPUTATION_TIMEOUT,
            cache_ttl=settings.REPUTATION_CACHE_TTL,
            offline_dir=str(settings.OFFLINE_LISTS_DIR),
            geoip_dir=str(settings.DATA_DIR / "geoip"),
        )
        # Remove any upload temp file left over by a previous crashed run.
        tmp = settings.FILE_UPLOAD_TEMP_DIR
        try:
            tmp.mkdir(parents=True, exist_ok=True)
            removed = 0
            for child in tmp.iterdir():
                if child.is_file() and child.suffix not in (".part", ".json"):
                    try:
                        child.unlink()
                        removed += 1
                    except OSError:
                        pass
            if removed:
                log.info("cleaned %d leftover upload temp file(s)", removed)
        except OSError as exc:  # pragma: no cover
            log.warning("could not clean temp dir %s: %s", tmp, exc)
