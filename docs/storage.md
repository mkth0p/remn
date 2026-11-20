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
better fit. Searches, counts, aggregations, timelines and the global pivot run in query
workers, a few at a time, so the page stays responsive while they scan; a query whose
answer is no longer wanted (the filter changed, the view or panel closed, a new pivot) is
stopped where it stands rather than left to finish. In both modes the browser keeps the case itself, its findings, notes, chains,
decisions and AI sessions, so a case can be exported as a bundle and imported elsewhere.
When evidence is first added, the app asks the browser to keep the site's storage
(`navigator.storage.persist()`); without that grant a browser short of space may clear a
site's IndexedDB, and the Dashboard says which applies. Export a case bundle to keep a copy
either way. The bundle also carries the custom rules its findings came from (a custom rule is global
in the browser that made it; it arrives as a rule of the imported case), the pack and
disabled-rule choices in force at export, and the decisions on relationship hypotheses.
An imported case starts with external reputation lookups switched off, whatever the bundle
had: lookups send the case's indicators to third parties, so the analyst who imports the
case decides, and the import message says so.
A finding the analyst decided is never pruned because its rule is missing from the
importing browser: it is a conclusion, not an orphan. Removing one evidence file removes
the findings built on it and keeps the engine (Hayabusa) findings of the other files.

## Server store

Rows live in a DuckDB file per case under `backend/data/cases/<uuid>/` on the REMN host.
REMN does not encrypt these files: on a server they belong on an encrypted volume, as the
[security model](security.md#where-evidence-lives) requires.
Search, facets, rules and the AI's `sql` tool run inside DuckDB. Files arrive through
chunked uploads with resumable offsets and are ingested by background jobs, so a
multi-gigabyte export does not depend on a browser tab staying open.

A browser-store case converts to the server store from Settings, and the app suggests
the conversion when a file above the threshold is dropped. Settings in `.env`:
`FORENSIC_CASES_DIR`, `FORENSIC_STORE_THRESHOLD_MB` (the suggestion threshold, default
150), `FORENSIC_MAX_CHUNKED_GB` (default 64), `FORENSIC_CHUNK_MB` (default 16).

Each store records the schema version it is written in (`schema-version` in its `meta`
table). When the server opens a store written by an older version, it brings it up to date
in one transaction: the upgrade step of each later version, then the tables and columns the
store lacks. The store keeps a record of what was done (`schema-history`: from which version
to which, when, and which columns were added), and the server log says it. An upgrade that
fails part-way is rolled back and leaves the store as it was. A store written by a newer
version of REMN is not opened and nothing in it is changed: the store routes answer 409 with
the code `storeVersion` and a message that names both versions. Run the version that wrote
it, or restore the backup taken before that version was installed (see
[Backup and upgrade](setup.md#backup-and-upgrade)).

What one store may take from the server is bounded, and each bound is a setting in `.env`:

- **Memory and threads.** Each open store gets its own DuckDB memory limit
  (`FORENSIC_STORE_MEMORY_MB`, 2048 MiB) and worker threads (`FORENSIC_STORE_THREADS`; the
  default 0 is one fewer than the processors, between 2 and 8). The stores open at once add
  up, so keep their sum under what the machine or container gives REMN.
- **Closing idle stores.** A store nobody has used for `FORENSIC_STORE_IDLE_S` seconds (600)
  is closed and its memory released, as soon as no request or job still holds it; its next
  query opens it again. 0 keeps every store open until the server stops.
- **Query time.** One query on a store (search, count, aggregate, stack, timeline, facets,
  pivot, a row, the summary, the indicator list, SQL from the SQL view or the analyst's
  `sql` tool, and the reads of a story, relationship or mail enrichment build, which count
  together as one) runs at most `FORENSIC_STORE_QUERY_MAX_S` seconds (60). A query past it is
  stopped and answered with 504, the code `queryStopped` and a message that names the limit;
  narrow the filter or the time range, or raise the limit. The export of a whole case reads
  in pages and has no overall limit.
- **Rule time.** One rule of a server-store rule run runs at most `FORENSIC_STORE_RULE_MAX_S`
  seconds (300). A rule past it is stopped, listed among the run's errors with a message that
  names the limit and says it has no findings in that run, and the run goes on with the next
  rule.

0 turns a time limit off.

Migration transfers bounded pages to a new server store, preserves event and mail IDs,
and retains findings, reviews, narratives and links. Only a completed transfer switches
the case's storage and removes browser evidence. A failed transfer leaves the browser
case available. Finish ingestion before migrating.

## Portable case backups

Report exports a `.remn.ndjson` backup to a selected file, or through temporary browser
file storage. Rows are streamed and checksummed without collecting the whole dataset in
memory. The backup includes chain snapshots, review decisions, report settings, notes and
AI undo history. Import verifies the entire checksum before creating a case, remaps row
IDs and links, and removes partial imports on failure. Keep ingestion and analysis idle
while exporting to obtain a consistent snapshot.

Legacy `.remn.json` browser backups remain supported and require memory for their JSON
document. Older server backups omitted row IDs, so their investigation links cannot be
recovered reliably; import rejects those explicitly. Original evidence files are separate
from these parsed-data backups and should be retained separately.

The server's operator backs up the server stores themselves, every case at once, with
`tools/store_backup.py`: a byte copy of each store with its digests and row counts, checked
before it counts, and a restore that checks the backup first and never writes over a case.
A backup skips a case the server holds open, and while the tool copies a case the server
answers that case with 503 (`storeBusy`). [Backup and upgrade](setup.md#backup-and-upgrade)
gives the commands, and the upgrade and rollback procedure.

Measured on a laptop with 200,000 synthetic events and 55 Windows rules
(`samples/synthetic/scale_test.py`):

| Operation | Time |
|---|---|
| ingestion (parse and DuckDB write) | about 10,000 events per second |
| count, aggregate, timeline | 1 to 30 ms |
| regex over the raw JSON of every event | about 70 ms |
| full-text search across 20 columns | about 0.5 s |
| 55 rules (bursts, spraying, out-of-hours, LOLBins, …) | about 20 s |

Those timings are measurements of that synthetic case, not a throughput guarantee for
multi-gigabyte real evidence. Per-row rules that match more than 200 rows are collapsed into
one finding per entity (user, host, IP, …) with a count, instead of thousands of identical
alerts.

## Uploads and jobs

Browser-store ingestion streams from the browser to the server and back in one request.
Server-store ingestion uploads the file in chunks (`POST /api/upload/init`, then one
request per chunk, then `complete`, which checks the size and the SHA-256), and a
background job parses it; the Evidence page shows the job's progress and its errors,
and `GET /api/jobs?case=<key>` lists the jobs of that case. A job is read, followed and
cancelled only with its case's key (`/api/jobs/<id>?case=<key>`); without it, or with
another key, the answer is the 404 of an unknown job, and no answer about a job carries
the key. An interrupted upload resumes from the last received offset when the same file
is dropped again.

A running import can be cancelled from its line in the jobs list, in either store. The file
stops being read and sent; a server job is asked to stop and, once it has, what the import
had written is removed as removing the evidence would remove it (rows, the findings, facets
and indicators that count them, the staged upload), and the evidence entry goes. An import
cancelled before it wrote a row only loses its entry. In a drop of several files, the files
after the cancelled one are not imported, and the console says how many.

A browser-store import writes its rows as they arrive and completes the evidence (status,
count, facets, indicators) at the end, so a tab closed, reloaded or crashed part-way would
leave rows nothing counts and a file that, added again, doubles them. Each import holds a
Web Lock while it runs, which the browser releases with the tab. When the app starts, an
evidence still importing whose lock is free is stopped: its partial rows are removed, the
case's derived state is rebuilt as for a removed file, and the evidence stays listed as an
import that stopped, with the reason, until it is removed or the file is added again. The
browser asks for confirmation before leaving the page while an import runs. Without Web
Locks (an old browser, a page not served over HTTPS or from localhost) a stopped import
cannot be told from one running in another tab, and nothing is removed.

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
4. **Expected throughput** (laptop, one core, synthetic data): EVTX about 10,000 events
   per second; mail 150 to 300 messages per second with deep analysis off, so a
   300,000-mail export takes 20 to 35 minutes. The heavy validation suite
   (`pytest -m heavy -s`) reproduces these numbers with synthetic data from
   `samples/synthetic/make_big.py`. Real logs can read far slower: the public attack
   recordings measured on 2026-09-28 loaded at about 1,560 events per second (2,377,981
   events in 1,522.8 s, `throughput` in `frontend/src/data/libraryMeasures.json`).
5. **If an ingest job fails**: the store stays consistent. Read the job's error in the
   console or in `GET /api/jobs?case=<key>`, cancel leftovers, fix the cause (usually disk space or
   a corrupt member file), delete the evidence and re-ingest.
