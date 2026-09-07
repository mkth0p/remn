# Storage modes

_Browser store, server store (DuckDB), uploads, jobs, the checklist before real exports._

## Gigabyte-scale cases (server store)

Measured on a laptop with 200k synthetic events (55 Windows rules, `samples/synthetic/scale_test.py`):

| Operation | Time |
|---|---|
| ingestion (parse + DuckDB write) | ~10k events/s |
| count / aggregate / timeline | 1-30 ms |
| regex over the raw JSON of every event | ~70 ms |
| full-text search across 20 columns | ~0.5 s |
| 55 rules (bursts, spraying, out-of-hours, LOLBins, …) | ~20 s |

Ingestion of a 1 GB Security.evtx (~3.5M events) therefore takes a few minutes;
queries stay interactive. Settings in `.env`: `FORENSIC_CASES_DIR`,
`FORENSIC_STORE_THRESHOLD_MB` (UI suggestion threshold, default 150),
`FORENSIC_MAX_CHUNKED_GB` (default 64), `FORENSIC_CHUNK_MB` (default 16).
Per-row rules that match more than 200 rows are collapsed into one finding per
entity (user, host, IP…) with a count, instead of thousands of identical alerts.

### Before ingesting real case exports (checklist)

1. **PST/OST first**: `pip install libpff-python`, then a smoke test with ONE
   .pst before the big export. `/api/health` -> `optional.pst` must say `true`.
   The PST path was validated against a real-world Outlook export (mail, meeting
   requests, appointments, RTF-only notifications).
   That run also calibrated the scoring on real Exchange Online mail:
   `X-MS-Exchange-Organization-AuthAs: Internal` marks intra-tenant mail as
   authenticated (flag `exchange_internal`; Exchange neither signs nor
   DMARC-evaluates it), the gateway's own verdicts surface as
   `gateway_spam_verdict` (SCL >= 5) / `gateway_bulk_verdict` (BCL >= 4),
   calendar objects get `calendar_item`, and brand-owned domains (`.microsoft`
   TLD, onmicrosoft.com, service-now.com…) are never lookalikes. Links that stay
   on an authenticated sender's own domain, ESP click-tracker redirects and
   file-name anchor text no longer count as lures, hidden text is only "content
   salting" when the sender or a link is already suspect, and the medium content
   rules (hidden/obfuscated content, suspicious links, link-text mismatch) fire
   only when the score corroborates (`risk|gte: 40`). The regression set is
   `tests/backend/test_mail_calibration.py`.
2. **Disk**: the DuckDB store plus temp files need roughly **2x the input
   size** free (store ~= input, plus the upload copy until ingestion ends).
3. **deepAttachments**: for a first look at a huge mailbox, turn OFF
   "deep attachment analysis" in Settings (macro/PDF analyzers dominate the
   cost); re-ingest with it ON once the interesting time range is known.
4. **Expected throughput** (laptop, one core): EVTX ~10k events/s; mail
   ~150-300 msg/s with deep analysis off (a 300k-mail export ~= 20-35 min).
   The heavy validation suite (`pytest -m heavy -s`) reproduces these numbers
   with synthetic data (`samples/synthetic/make_big.py`).
5. **If an ingest job fails**: the store stays consistent - check the job
   error in the console (or `GET /api/jobs`), cancel leftovers, fix the cause
   (usually disk or a corrupt member file), delete the evidence and re-ingest.
   Interrupted chunked uploads resume automatically when the same file is
   dropped again.
