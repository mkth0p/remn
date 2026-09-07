# Storage modes

Every case chooses where its rows live. The choice decides what the server ever sees of
the evidence and how large a case can get. This page describes the two stores, how a case
moves from one to the other, how uploads and ingestion jobs work, what removing evidence
does, and what to check before dropping real, multi-gigabyte exports for the first time.

## Browser store

Rows live only in the browser's IndexedDB. The server parses each dropped file in a
temporary location, streams the rows back, and keeps nothing. This is the default and
the mode for evidence that may not be persisted on a shared machine: nothing about the
case exists outside that browser profile. It is comfortable up to a few hundred megabytes
of evidence; beyond that, queries and rule runs slow down and the server store is the
better fit. In both modes the browser keeps the case itself, its findings, notes, chains,
decisions and AI sessions, so a case can be exported as a bundle and imported elsewhere.

## Server store

Rows live in a DuckDB file per case under `backend/data/cases/<uuid>/` on the REMN host.
Search, facets, rules and the AI's `sql` tool run inside DuckDB. Files arrive through
chunked uploads with resumable offsets and are ingested by background jobs, so a
multi-gigabyte export does not depend on a browser tab staying open.

A browser-store case converts to the server store from Settings, and the app suggests
the conversion when a file above the threshold is dropped. Settings in `.env`:
`FORENSIC_CASES_DIR`, `FORENSIC_STORE_THRESHOLD_MB` (the suggestion threshold, default
150), `FORENSIC_MAX_CHUNKED_GB` (default 64), `FORENSIC_CHUNK_MB` (default 16).

Measured on a laptop with 200,000 synthetic events and 55 Windows rules
(`samples/synthetic/scale_test.py`):

| Operation | Time |
|---|---|
| ingestion (parse and DuckDB write) | about 10,000 events per second |
| count, aggregate, timeline | 1 to 30 ms |
| regex over the raw JSON of every event | about 70 ms |
| full-text search across 20 columns | about 0.5 s |
| 55 rules (bursts, spraying, out-of-hours, LOLBins, …) | about 20 s |

A 1 GB Security.evtx (about 3.5 million events) therefore ingests in a few minutes and
queries stay interactive. Per-row rules that match more than 200 rows are collapsed into
one finding per entity (user, host, IP, …) with a count, instead of thousands of identical
alerts.

## Uploads and jobs

Browser-store ingestion streams from the browser to the server and back in one request.
Server-store ingestion uploads the file in chunks (`POST /api/upload/init`, then one
request per chunk, then `complete`, which checks the size and the SHA-256), and a
background job parses it; the Evidence page shows the job's progress and its errors,
and `GET /api/jobs` lists them. An interrupted upload resumes from the last received
offset when the same file is dropped again.

## Removing evidence

Removing an evidence file deletes everything derived from it at once: its events, mails,
bodies, attachments and URLs, the case's findings, chain snapshot and last-run
diagnostics (they reference rows that no longer exist), the upload-resume record and any
server-side partial. Browser cases recompute facets and indicators from the rows that
remain (reputation results of surviving indicators are kept); server cases delete the
rows from DuckDB and checkpoint the file so the space is released. Analyst decisions are
archived and reattached when the same findings reappear on the next rule run.

## Before ingesting real exports

1. **PST and OST first**: `pip install libpff-python`, then a smoke test with one `.pst`
   before the big export. `/api/health` must report `optional.pst` as `true`. The PST
   path was validated against a real Outlook export (mail, meeting requests,
   appointments, RTF-only notifications). That run also calibrated the scoring on real
   Exchange Online mail: `X-MS-Exchange-Organization-AuthAs: Internal` marks
   intra-tenant mail as authenticated (flag `exchange_internal`; Exchange neither signs
   nor DMARC-evaluates it), the gateway's own verdicts surface as
   `gateway_spam_verdict` (SCL 5 or more) and `gateway_bulk_verdict` (BCL 4 or more),
   calendar objects get `calendar_item`, and brand-owned domains (the `.microsoft` TLD,
   onmicrosoft.com, service-now.com, …) are never lookalikes. Links that stay on an
   authenticated sender's own domain, ESP click-tracker redirects and file-name anchor
   text do not count as lures, hidden text is only "content salting" when the sender or
   a link is already suspect, and the medium content rules (hidden or obfuscated content,
   suspicious links, link-text mismatch) fire only when the score corroborates
   (`risk|gte: 40`). The regression set is `tests/backend/test_mail_calibration.py`.
2. **Disk**: the DuckDB store plus temporary files need roughly twice the input size
   free (the store is about the size of the input, plus the upload copy until ingestion
   ends).
3. **Deep attachment analysis**: for a first look at a huge mailbox, turn it off in
   Settings (the macro and PDF analysers dominate the cost); re-ingest with it on once
   the interesting time range is known.
4. **Expected throughput** (laptop, one core): EVTX about 10,000 events per second; mail
   150 to 300 messages per second with deep analysis off, so a 300,000-mail export takes
   20 to 35 minutes. The heavy validation suite (`pytest -m heavy -s`) reproduces these
   numbers with synthetic data from `samples/synthetic/make_big.py`.
5. **If an ingest job fails**: the store stays consistent. Read the job's error in the
   console or in `GET /api/jobs`, cancel leftovers, fix the cause (usually disk space or
   a corrupt member file), delete the evidence and re-ingest.
