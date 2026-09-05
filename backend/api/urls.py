from django.urls import path

from api.views import ai, chains, enrich, health, ingest, meta, reputation, rules, store, upload

urlpatterns = [
    path("health", health.health),
    path("meta", meta.meta),
    # browser-stored cases: streamed NDJSON ingestion
    path("ingest/evtx", ingest.ingest_evtx),
    path("ingest/mail", ingest.ingest_mail),
    path("analyze/attachment", ingest.analyze_single_attachment),
    # rule-format converters (Sigma -> REMN DSL)
    path("rules/convert/sigma", rules.convert_sigma),
    path("rules/convert/sublime", rules.convert_sublime),
    # community rule packs (SigmaHQ, Sublime) served on demand
    path("rules/packs", rules.list_packs),
    path("rules/packs/<str:pack_id>", rules.pack),
    path("rules/packs/<str:pack_id>/license", rules.pack_license),
    # cross-source attack chains
    path("chains/build", chains.build),
    # enrichment passes (sender baseline, campaigns)
    path("enrich/mails", enrich.mails),
    path("enrich/mails/rescore", enrich.rescore),
    # chunked uploads (large files)
    path("upload/init", upload.init),
    path("upload/<str:upload_id>/chunk", upload.chunk),
    path("upload/<str:upload_id>/complete", upload.complete),
    path("upload/<str:upload_id>", upload.status),
    # server case stores (DuckDB)
    path("store", store.list_stores),
    path("store/<str:key>", store.store_root),
    path("store/<str:key>/evidence/<int:evidence_id>", store.delete_evidence),
    path("store/<str:key>/ingest", store.ingest),
    path("store/<str:key>/import", store.import_rows),
    path("store/<str:key>/export", store.export_rows),
    path("store/<str:key>/search", store.search),
    path("store/<str:key>/count", store.count),
    path("store/<str:key>/aggregate", store.aggregate),
    path("store/<str:key>/timeline", store.timeline),
    path("store/<str:key>/facets", store.facets),
    path("store/<str:key>/row", store.row),
    path("store/<str:key>/pivot", store.pivot),
    path("store/<str:key>/iocs", store.iocs),
    path("store/<str:key>/reputation", store.reputation),
    path("store/<str:key>/rules/run", store.rules_run),
    path("store/<str:key>/sql", store.sql),
    path("store/<str:key>/schema", store.schema),
    # jobs
    path("jobs", store.jobs_list),
    path("jobs/<str:job_id>", store.job_detail),
    path("jobs/<str:job_id>/events", store.job_events),
    # reputation providers
    path("reputation/providers", reputation.providers),
    path("reputation/lookup", reputation.lookup),
    # AI
    path("ai/meta", ai.ai_meta),
    path("ai/models", ai.models),
    path("ai/query", ai.query),
    path("ai/chat", ai.chat),
]
