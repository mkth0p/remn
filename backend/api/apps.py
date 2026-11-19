from __future__ import annotations

import logging

from django.apps import AppConfig
from django.conf import settings

log = logging.getLogger(__name__)


class ApiConfig(AppConfig):
    name = "api"

    def ready(self) -> None:
        # Wire the Django-independent services with the settings.
        from api.views.upload import cleanup_stale, clear_leftovers, start_sweeper
        from services.analysis.attachments import yara_scan
        from services.reputation.base import registry
        from services.store.casestore import registry as store_registry

        yara_scan.configure(settings.YARA_RULES_DIR)
        store_registry.configure(settings.CASES_DIR)
        try:
            removed_uploads = cleanup_stale()
            if removed_uploads:
                log.info("removed %d stale chunked upload file(s)", removed_uploads)
            # and again on a timer, so an abandoned upload does not wait for the next restart
            if start_sweeper():
                log.info("staged evidence swept every %ds, removed after %ds", settings.FORENSIC_UPLOAD_SWEEP_S, settings.FORENSIC_UPLOAD_MAX_AGE_S)
        except Exception as exc:  # noqa: BLE001
            log.warning("upload cleanup failed: %s", exc)
        registry.configure(
            keys=settings.REPUTATION_KEYS,
            timeout=settings.REPUTATION_TIMEOUT,
            cache_ttl=settings.REPUTATION_CACHE_TTL,
            offline_dir=str(settings.OFFLINE_LISTS_DIR),
            geoip_dir=str(settings.DATA_DIR / "geoip"),
        )
        # Remove whatever a previous run stopped mid-parse left in the staging area: files, and the
        # directories an expanded 7z or the logs staged for an engine run occupy.
        try:
            removed = clear_leftovers()
            if removed:
                log.info("cleaned %d leftover staging file(s) and folder(s)", removed)
        except OSError as exc:  # pragma: no cover
            log.warning("could not clean temp dir %s: %s", settings.FILE_UPLOAD_TEMP_DIR, exc)
