# API reference

The browser application talks to the server through the routes under `/api/`. This page lists
every one of them: its method, what it does, what an account needs to call it when the server
has accounts, whether it is open on a browser-only instance, and its main request and response
fields. The routes are declared in `backend/api/urls.py`, the views in `backend/api/views/`.
`tests/backend/test_api_reference.py` reads the route index below and fails when a route of the
server is missing from it, when it names a route that no longer exists, or when a method, a
role or a mode in it differs from the code.

The API is made for REMN's own page. It has no version number and may change with any
release; a script that calls it should pin the commit it was written against (`/api/health`
gives it).

## Calling the API

- **Header.** Every request carries `X-Forensic-Client`. On a server without a token any
  value will do (the page sends `remn`): a page of another site cannot add the header without
  a preflight, which the server refuses, so the header is the protection against requests
  forged from another origin. With `FORENSIC_AUTH_TOKEN` set the value is that token, and on
  a server with accounts it is the account's personal token. The one request answered without
  the header is `GET /api/health`, which then answers `{"ok": true}` and nothing else.
- **Bodies.** JSON unless the route says otherwise. Evidence goes up as `multipart/form-data`
  (field `file`) or through a chunked upload. A JSON body may be up to 64 MiB.
- **Streams.** The parse routes answer with NDJSON (`application/x-ndjson`, one JSON object a
  line) written as the parse goes; the model routes and the job progress route answer with
  server-sent events (`text/event-stream`, one `data:` line of JSON per event).
- **Case keys.** A server-store case is named by its key, a UUID the page makes when the case
  is created. On a server without accounts the key is the only thing that opens a case, so it
  is a secret: keep it out of logs and tickets.
- **Errors.** An error answers with a JSON object holding `error` (a sentence for the analyst)
  and often `code`. A failure inside the server answers 500 with a reference that ties it to
  the server log, never with the exception's text.

| Status | `code` | When |
|---|---|---|
| 400 | | a missing or malformed field; the message names it |
| 401 | `auth` | no token, or a wrong one, on a server with a token or accounts |
| 403 | `browserOnly` | a route closed on a browser-only instance |
| 403 | `role` | the account's role does not allow the request; the message says why |
| 403 | `undeclared` | with accounts on, a route that declares no permission (none does today) |
| 403 | `lookupsNotAllowed` | a reputation lookup that would reach an external provider without `networkAllowed: true` |
| 404 | `caseAccess` | a case nobody uses, or one the account is not a member of (the same answer for both) |
| 409 | `storeVersion`, `evidenceId` | a store written by a newer version; an evidence number another file of the case already has |
| 413 | `tooLarge`, `staging-too-small` | a body over the server's limit; a file larger than the staging area could ever hold |
| 429 | `rate` | the per-address request budget or the wrong-token allowance is spent; `Retry-After` says when to retry |
| 503 | `busy`, `storeBusy` | too many heavy requests in flight, or the store is held by a backup; `Retry-After` is set |
| 504 | `queryStopped` | a store query ran past `FORENSIC_STORE_QUERY_MAX_S` |
| 507 | `staging-full` | the staging area has no room for this upload now |

### What a request needs

With accounts on, each route declares what the request's account needs
(`backend/forensic/access.py`), and the server refuses a request that lacks it before the view
runs. Without accounts every request that passes the header check is answered. The levels:

| Level | Who has it |
|---|---|
| `signed-in` | any account |
| `work` | an analyst or an admin: brings evidence in, sends indicators to providers |
| `admin` | an admin |
| `read` | a member of the case (any role), its owner, or an admin |
| `write` | an analyst who owns the case or is a member of it, or an admin |
| `own` | the case's owner while an analyst, or an admin |

The case is named in the path (`<key>`), in the query (`?case=<key>`, the job routes) or in
the JSON body (`storeKey`). A route that reads its case from the body and gets a body without
one reads no case, and then needs `signed-in` only. What the roles mean for a team is on the
[security page](security.md#accounts-roles-and-the-audit-log).

### Browser-only mode and budgets

On an instance started with `FORENSIC_BROWSER_ONLY=1` the routes marked `closed` below answer
403 with the code `browserOnly`: the server store, the jobs, reputation and the server-side
model transports. The story, relationship and enrichment routes stay open for rows the page
posts and refuse a body that names a server case.

`FORENSIC_RATE_LIMIT_PER_MIN` budgets the heavy routes per client address: parsing, attachment
analysis, chains, stories, relationships, enrichment, rule conversion, reputation, the model
routes, `upload/init`, and the store's ingest, import, export, rule run, SQL and reputation.
`FORENSIC_MAX_HEAVY_REQUESTS` and `FORENSIC_MAX_HEAVY_PER_CLIENT` cap how many of those run at
once. Both are off on a private server and on in browser-only mode; see
[Security model](security.md#browser-only-mode-and-request-budgets).

## Route index

| Method | Route | Needs | Browser-only |
|---|---|---|---|
| GET | `/api/health` | signed-in | open |
| GET | `/api/meta` | signed-in | open |
| POST | `/api/ingest/evtx` | work | open |
| POST | `/api/ingest/mail` | work | open |
| POST | `/api/ingest/package` | work | open |
| POST | `/api/analyze/attachment` | work | open |
| POST | `/api/upload/init` | work | open |
| PUT | `/api/upload/<upload_id>/chunk` | work | open |
| POST | `/api/upload/<upload_id>/chunk` | work | open |
| POST | `/api/upload/<upload_id>/complete` | work | open |
| GET | `/api/upload/<upload_id>` | work | open |
| DELETE | `/api/upload/<upload_id>` | work | open |
| POST | `/api/rules/convert/sigma` | signed-in | open |
| POST | `/api/rules/convert/sublime` | signed-in | open |
| GET | `/api/rules/packs` | signed-in | open |
| GET | `/api/rules/packs/<pack_id>` | signed-in | open |
| GET | `/api/rules/packs/<pack_id>/license` | signed-in | open |
| POST | `/api/chains/build` | signed-in | open |
| POST | `/api/stories/build` | read | open |
| POST | `/api/relationships/build` | read | open |
| POST | `/api/enrich/mails` | write | open |
| POST | `/api/enrich/mails/rescore` | write | open |
| GET | `/api/store` | signed-in | closed |
| GET | `/api/store/<key>` | read | closed |
| DELETE | `/api/store/<key>` | own | closed |
| DELETE | `/api/store/<key>/evidence/<evidence_id>` | write | closed |
| POST | `/api/store/<key>/ingest` | write | closed |
| POST | `/api/store/<key>/import` | write | closed |
| GET | `/api/store/<key>/export` | read | closed |
| POST | `/api/store/<key>/search` | read | closed |
| POST | `/api/store/<key>/count` | read | closed |
| POST | `/api/store/<key>/aggregate` | read | closed |
| POST | `/api/store/<key>/stack` | read | closed |
| POST | `/api/store/<key>/timeline` | read | closed |
| GET | `/api/store/<key>/facets` | read | closed |
| GET | `/api/store/<key>/row` | read | closed |
| POST | `/api/store/<key>/pivot` | read | closed |
| GET | `/api/store/<key>/iocs` | read | closed |
| POST | `/api/store/<key>/reputation` | write | closed |
| POST | `/api/store/<key>/rules/run` | read | closed |
| POST | `/api/store/<key>/sql` | read | closed |
| GET | `/api/store/<key>/schema` | read | closed |
| GET | `/api/store/<key>/access` | read | closed |
| POST | `/api/store/<key>/access` | own | closed |
| GET | `/api/jobs` | read | closed |
| GET | `/api/jobs/<job_id>` | read | closed |
| DELETE | `/api/jobs/<job_id>` | read | closed |
| GET | `/api/jobs/<job_id>/events` | read | closed |
| GET | `/api/reputation/providers` | signed-in | closed |
| POST | `/api/reputation/lookup` | work | closed |
| GET | `/api/ai/meta` | signed-in | open |
| GET | `/api/ai/models` | signed-in | closed |
| POST | `/api/ai/query` | signed-in | closed |
| POST | `/api/ai/chat` | signed-in | closed |
| GET | `/api/ai/claude/status` | signed-in | closed |
| POST | `/api/ai/claude/chat` | signed-in | closed |
| POST | `/api/ai/claude/query` | signed-in | closed |
| GET | `/api/audit` | admin | open |
| GET | `/api/audit/verify` | admin | open |

## Server and reference data

**`GET /api/health`.** Whether the server answers, and what it is. Without the header:
`{"ok": true}`. With it: `version`, `build` (version and commit), `source` (a link to that
commit), `mode` (`full` or `browser-only`), `limits` (`maxUploadMb`, `inMemoryMb`,
`maxChunkedGb`, `chunkMb`, `uploadMaxAgeS`), `optional` (whether PST, YARA, Claude Code and
Hayabusa are available), `engines`, `providers`, `ollama` (reachable, models, default model),
`accounts` (whether accounts are on) and `account` (the name and role of the caller). A full
server also gives its paths, platform and Python version; a browser-only one leaves them out.

**`GET /api/meta`.** Reference data for the page: event id descriptions, logon types, status
codes, flag descriptions, the mail score weights, the bundled rules (`rules`, each with its
file, YAML text and measure), the community pack manifests (`packs`) and a summary of the rule
measure (`measures`).

## Evidence for a browser-store case

These routes parse a file and stream its rows back; the server keeps nothing. Each parse runs
in a process of its own ([Architecture](architecture.md#processes)).

**`POST /api/ingest/evtx`.** An event log, an archive of them, event records exported as XML,
or a Microsoft 365 or Entra export. Multipart fields: `file`, or `uploadId` of a completed
chunked upload; `raw` (`0` leaves the raw record out of each row); `engines` (`0` skips
Hayabusa); `dates`, JSON `{"order": "day-first" | "month-first", "zone": "UTC" | "+02:00" |
"Europe/Paris"}` for exports whose dates carry neither. Response, NDJSON: one `meta` line
(`format`, `name`, `size`, `sha256`, `parser`), one `event` line per record, `finding` and
`engine` lines from Hayabusa, an `error` line when the parse stopped early (a limit, the
deadline, a damaged file), and a `done` line with `stats`, `emitted` and `sha256`.

**`POST /api/ingest/mail`.** A mailbox: `.eml`, `.msg`, `.mbox`, `.pst` or `.ost`, or an
archive of them. Fields: `file` or `uploadId`; `format` to force one; `settings`, JSON with the
case's `internalDomains`, `brands`, `vipNames`, `trustedSenders`, `trustedArcSealers`,
`includeHtml`, `includeHeaders` and `analyzeAttachments`. Response, NDJSON: `meta`, one `mail`
line per message, `error` when stopped early, `done` with `stats` (for an archive also
`members`, `membersTotal` and `memberCounts`). A PST without `libpff-python` installed gets 501.

**`POST /api/ingest/package`.** An investigation package or triage collection (a zip, a tar or
a 7z of mixed mail, event logs and host exports). Fields: `file` or `uploadId`, `sourceName`,
`settings`, `raw`, `engines`, `filesystem` (`1` reads the file system records), `dates`.
Response, NDJSON: `meta`, the rows of every member (`event`, `mail` and the package's own
lines), `error` when stopped early, Hayabusa's lines, then `done`. See
[Investigation packages](packages.md).

**`POST /api/analyze/attachment`.** One file analysed as a mail attachment would be (macros,
PDF actions, archives, YARA). Multipart `file`, at most 200 MB. Response:
`{"type": "attachment", "result": {...}}`; 422 when the analysis stopped at a limit.

### Chunked uploads

A file too large for one request goes up in chunks, then a parse route or the store's ingest
route reads it by its `uploadId`. An unfinished upload is removed after
`FORENSIC_UPLOAD_MAX_AGE_S` (six hours, thirty minutes in browser-only mode).

**`POST /api/upload/init`.** Body `{"name", "size"}`. Reserves room in the staging area.
Response `{"uploadId", "chunkSize"}`. Refused with 413 (`staging-too-small`) when the file is
larger than the staging area could hold even empty, and with 507 (`staging-full`) when other
uploads and running parses hold or have set aside too much of it now; both messages give the sizes.

**`PUT /api/upload/<upload_id>/chunk?offset=<n>`** (or `POST`). The raw bytes of the next
chunk, at most 64 MiB, at the offset the server has received so far. Response
`{"received", "size"}`; 409 with `received` when the offset is not the server's.

**`POST /api/upload/<upload_id>/complete`.** Checks that every byte arrived and computes the
SHA-256. Response `{"uploadId", "sha256", "size", "name"}`.

**`GET /api/upload/<upload_id>`.** How far an upload got (`received`, `size`, `complete`), so
an interrupted one resumes. **`DELETE`** discards it.

## Rules

**`POST /api/rules/convert/sigma`**, **`POST /api/rules/convert/sublime`.** Convert Sigma
rules (Windows log sources) or Sublime MQL rules to REMN's rule language. Body: multipart
`file` (a `.yml`, `.yaml` or a `.zip` of them), or JSON `{"text"}` or `{"files": [{"name",
"text"}]}`; at most 6,000 rules. Response `{"rules": [...], "summary": {"total", "converted",
"skipped", "reasons"}}`, one entry per upstream rule with `ok`, the converted `rule` or the
`error`, and `warnings`. Nothing is stored: the page keeps the result as custom rules. See
[Writing rules](rules.md#importing-sigma-and-sublime-rules).

**`GET /api/rules/packs`.** The manifests of the community packs: id, name, upstream
repository and commit, licence, counts, whether a new case enables it.

**`GET /api/rules/packs/<pack_id>`.** One pack: `{"pack": manifest, "rules": [{"file",
"rule"}]}`, each rule with its measure. 404 for an unknown pack.

**`GET /api/rules/packs/<pack_id>/license`.** The pack's upstream licence, as plain text.

## Correlation

**`POST /api/chains/build`.** Attack chains from rows the page posts: `{"mails", "events",
"findings", "settings"}` and the options `seedMinRisk`, `windowHours`, `beforeMinutes`,
`collapseMinutes`, `minScore`, `maxChains`. Response `{"chains": [...], "stats": {...}}`. A
server case's chains come with its stories, so a body with `storeKey` gets 400 (`storyBuild`).
See [Attack chains](chains.md).

**`POST /api/stories/build`.** The stories of a case: `{"storeKey", "settings", "findings"}` for
a server case, whose rows the server selects, or `{"events", "mails", "findings", "settings"}`
for rows the page posts; options `gapHours`, `maxStories`, `maxSteps`, `seedMinRisk`, held to
bounds. Response: `stories`, `incidents`, `campaigns`, `chains`, `identities`, `hosts`,
`unstoried` and `stats`. See [Stories](stories.md).

**`POST /api/relationships/build`.** The relationship graph Explore draws: `{"storeKey",
"evidenceId", "cursor", "pageSize", "options"}` for a server case, read a page at a time, or
`{"events", "mails", "processContext", "options"}`. Response `{"nodes", "edges", "stats",
"cursor"}`; `cursor` is set while more rows remain. See
[Explore](relationship-intelligence.md).

**`POST /api/enrich/mails`.** The sender baseline and campaign clusters: `{"storeKey",
"settings"}` writes the columns into a server case and answers `{"summary"}`; `{"mails",
"settings"}` answers `{"rows": [{"id", "senderPrevalence", ...}], "summary"}` for the page to
write back.

**`POST /api/enrich/mails/rescore`.** Scores mails again with the current calibration:
`{"storeKey", "settings"}` starts a job on a server case (202 with `jobId`; 409 while another
job of the case runs); each read of the case runs at most `FORENSIC_STORE_QUERY_MAX_S` seconds,
and a read past it ends the job with an error naming the limit and no score changed.
`{"mails", "settings"}` scores at most 200 posted rows and answers them.

## Server store

A server-store case keeps its rows in a DuckDB file on the server
([Storage modes](storage.md#server-store)). Every route names the case by `<key>`. A store
query runs at most `FORENSIC_STORE_QUERY_MAX_S` seconds and answers 504 (`queryStopped`) past
it. The filter that `search`, `count`, `aggregate`, `stack` and `timeline` take is the one
the Events and Mails pages build: `{"text", "conditions": [{"field", "op", "value"}], "logic":
"and" | "or", "timeRange": {"from", "to"}, "hourRange": {"from", "to", "tz", "outside"},
"regex": {"field", "pattern"}}`, with the operators of the [rule language](rules.md#operators).

**`GET /api/store`.** The cases the caller may open. With accounts: each case the account may
read, with its name, owner, members, size and what the account may do with it. Without
accounts it is answered only on a server with a token (an operator's listing); otherwise 403
(`listing`).

**`GET /api/store/<key>`.** The case summary: row counts, size, time ranges, top event ids,
computers, senders and flags, and the evidence list. **`DELETE`** removes the store;
`?keepAccess=1` keeps its owner and members for a case emptied to be filled again. Response
`{"deleted": true | false}`.

**`DELETE /api/store/<key>/evidence/<evidence_id>`.** Removes one evidence file and every row
derived from it. Response `{"deleted": {...counts per table}}`.

**`POST /api/store/<key>/ingest`.** Parses a completed chunked upload into the store as a
background job: `{"uploadId", "kind": "evtx" | "mail" | "package", "evidence": {"id", "name",
"sha256Client", "addedAt"}, "options": {"settings", "includeRaw", "keepBodies",
"fileSystem", "dates"}}`. Response `{"jobId"}`. The job's result holds `count`, `stats`,
`sha256Server`, `integrity` (`verified` when the browser's and the server's digests agree,
`mismatch` when they differ), Hayabusa's `findings` and `engineSummaries`. 409 (`evidenceId`)
when the case already holds another file under that evidence number.

**`POST /api/store/<key>/import`.** Rows already parsed, as NDJSON lines `{"type": "evidence"
| "event" | "mail", ...}`: how a browser case moves to the server store, and how a bundle is
restored. Query: `evidenceId`, `raw=0`, `preserveIds=1`. Response `{"events", "mails",
"eventStats", "mailStats"}`.

**`GET /api/store/<key>/export`.** Every row of the case as NDJSON, in the form `import`
takes. Recorded in the audit log, as evidence leaving the server.

**`POST /api/store/<key>/search`.** Rows: `{"source": "events" | "mails", "filter", "limit"
(2,000 by default, 20,000 at most), "offset", "sort", "settings", "full"}`. Response
`{"rows", "truncated", "offset", "limit"}`.

**`POST /api/store/<key>/count`.** `{"source", "filter", "settings"}`, response `{"count"}`.

**`POST /api/store/<key>/aggregate`.** Counts by one field: `{"source", "filter", "field",
"limit"}`. Response `{"field", "groups": [{"value", "count"}], "total", "distinct"}`.

**`POST /api/store/<key>/stack`.** Every value of one event field, rarest first by hosts then
events: `{"filter", "field", "order": "rare" | "common", "limit"}`. Response `{"rows":
[{"value", "count", "hosts", "hostList", "first", "last"}], "events", "blank", "distinct",
"hosts", "truncated"}`.

**`POST /api/store/<key>/timeline`.** Counts per time bucket: `{"source", "filter", "bucket":
"minute" | "hour" | "day"}`. Response `[{"t", "count"}]`.

**`GET /api/store/<key>/facets?source=&field=&limit=`.** The most frequent values of a field,
`[{"value", "count"}]`.

**`GET /api/store/<key>/row?source=&id=`.** One row with every column: an event with its
parsed EventData (`data`), a mail with its `attachments`, `urls` and `body`.

**`POST /api/store/<key>/pivot`.** Where one value (an address, a hash, an account) appears:
`{"value"}`. Response: for events and for mails, the count, first and last time, and the count
per field.

**`GET /api/store/<key>/iocs?kind=&q=&bad=&unchecked=&limit=&offset=&sort=`.** The indicators
of the case (addresses, domains, URLs, hashes) with their reputation. Response `{"rows",
"total", "kinds", "offset", "limit"}`.

**`POST /api/store/<key>/reputation`.** Stores reputation results the page obtained:
`{"items": [{"kind", "value", "verdict", ...}]}`. Response `{"stored", "mailsFlagged"}`.

**`POST /api/store/<key>/rules/run`.** Runs rules on the store as a background job: `{"rules":
[rule objects], "settings"}`. Response `{"jobId"}`. The job's result: `findings`, `byRule`,
`errors`, `diagnostics` (why a rule found nothing, or that it was cut at its finding cap),
`total` and `notRun` (the enabled rules a cancel kept from running, 0 for a run that finished). A
rule past `FORENSIC_STORE_RULE_MAX_S` is stopped and named in `errors`. It writes nothing to the
store, so a viewer may run it.

**`POST /api/store/<key>/sql`.** One read-only SELECT on the case's tables: `{"sql", "limit"}`
(200 by default, 2,000 at most). Response `{"rows", "truncated", "columns"}`. Statements that
write, read files or call other table functions are refused with 400.

**`GET /api/store/<key>/schema`.** The tables and columns the SQL view and the model's `sql`
tool may use, as text.

**`GET /api/store/<key>/access`.** On a server with accounts: the case's `name`, `owner`,
`members`, and `may` (what the caller may do). **`POST`** with `{"members": [names]}`, `{"name"}`
or, for an admin, `{"owner"}` changes them. Without accounts, 404 (`noAccounts`).

## Jobs

Server-store ingests, rule runs and rescores run as jobs in the server process, at most two at a
time ([Architecture](architecture.md#processes)). A job is read only with its case's key in the
query, and no answer about a job carries the key. Jobs are kept in memory: a restart forgets
them, and the last 200 finished ones are kept.

**`GET /api/jobs?case=<key>`.** The case's jobs, newest first: `id`, `kind`, `label`,
`status` (`queued`, `running`, `done`, `error`, `cancelled`), `progress`, `error`, times and the
last lines of its log.

**`GET /api/jobs/<job_id>?case=<key>`.** One job; a finished one with its `result`.
**`DELETE`** cancels it. With accounts, only the account that started the job or one that may
write to the case cancels it.

**`GET /api/jobs/<job_id>/events?case=<key>`.** The job's progress as server-sent events, one
event per change, ending when the job ends.

## Reputation

**`GET /api/reputation/providers`.** The providers the server knows (`name`, `kinds`,
`configured`, `needsKey`, `external`, `description`), with the size of the server's cache.

**`POST /api/reputation/lookup`.** `{"items": [{"kind": "ip" | "domain" | "url" | "hash",
"value"}], "providers", "deadline", "networkAllowed"}`, at most 200 items. A lookup that would
send an indicator to an external provider is refused (403, `lookupsNotAllowed`) unless the body
says `"networkAllowed": true`, which the page sends only when the case allows external lookups.
Response `{"results", "summary"}`.

## AI analyst

What each transport sends where is on the [AI page](ai.md#transports).

**`GET /api/ai/meta`.** The prompts, tool schemas, query schema, store schema text, context
size and default model, for the browser-direct transport, which calls the analyst's own Ollama
from the page.

**`GET /api/ai/models`.** The models of the Ollama the server is configured with, and what each
can do (tools, thinking).

**`POST /api/ai/query`.** A question in words turned into a filter: `{"question", "context",
"model"}`. Response `{"query", "raw", "model"}`; 502 when Ollama fails.

**`POST /api/ai/chat`.** One model turn through the server's Ollama, as server-sent events:
`{"messages", "mode", "tools", "toolNames", "think", "model", "options", "context"}`. Events,
by `type`: `token` and `thinking` (text as it comes), `tool_calls`, `error`, and a final
`done` with the model and its statistics.

**`GET /api/ai/claude/status`.** Whether the Claude Code connector is on, the `claude` command
line found and signed in, and the models it offers. `?refresh=1` asks again rather than
reusing the last answer of the minute.

**`POST /api/ai/claude/chat`**, **`POST /api/ai/claude/query`.** The same contracts as
`/api/ai/chat` and `/api/ai/query`, through the `claude` command line on the server under its
account's sign-in. 403 while `CLAUDE_CODE_ENABLED` is off, as it is by default.

## Audit log

Both routes answer 404 (`noAccounts`) on a server without accounts.

**`GET /api/audit?after=&limit=&case=&account=`.** Entries of the audit log, oldest first:
`seq`, time, account and role, address, method, route, path, case, status, outcome. At most
1,000 per call; `next` is the `seq` to pass as `after` for the next page.

**`GET /api/audit/verify?head=<code>`.** Checks the chain of the log, and that each code given
as `head` (noted from an earlier check) is still in it. Response `{"ok", "entries", "problems",
"problemCount", "head": {"seq", "time", "mac"}}`; `head.mac` is the code to note for the next
check.
