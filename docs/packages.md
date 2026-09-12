# Investigation packages

Import a ZIP or TAR from Evidence and choose **Investigation package**. Members
are detected independently, so one archive can contain EVTX, Microsoft 365 exports,
mailboxes and structured host collections. The same parser feeds browser storage
and DuckDB. Browser storage still uses the API to parse files and build relationships.

**Import folder contents** and folder drag-and-drop preserve relative paths, with
one evidence item per file. Files import sequentially. Use a ZIP for one package
hash, inventory and shared manifest.

## Coverage and provenance

Open an evidence item to see **Package coverage**. Members record their path, size,
index, SHA-256 when readable, parser, row count and outcome:

- **parsed**: a recognized parser finished; this does not mean the evidence is benign.
- **metadata**: a collection manifest was read.
- **unsupported**: inventoried and hashed, without searchable records.
- **error**: reading or parsing failed; any emitted rows are explicitly partial.
- **skipped**: path, link, encryption or size restrictions prevented processing.

Rows retain their package hash, source path/hash, member/record index and parser
version. Original fields remain in `data`. Original archive bytes and unsupported
member contents are not retained by either store; keep the acquisition separately.
Case migration, export/import and deletion include normalized rows and provenance.

A structured export is parsed under a 64 MiB budget counted while reading, not checked against
the file size. An export past it contributes every record read before the ceiling and is reported
as an error member with the reason, rather than contributing nothing but a hash. The member and
package byte budgets are unchanged.

## Collection adapters

CSV (comma, semicolon or tab), TSV, JSON objects/arrays, JSON `records` arrays and
JSONL/NDJSON are supported under these directory names or matching file stems:

| Directory | Artifact |
|---|---|
| Autoruns | autorun configuration |
| Installed Programs | installed program |
| Network Connections | connection observation |
| Prefetch Files | native Prefetch and structured execution exports |
| Processes | process observation |
| Scheduled Tasks | task configuration |
| Services | service configuration |
| SMB Session | SMB observation |
| System Information | system observation |
| Temp Directories | file inventory |
| Users and Groups | account/group observation |
| WdSupportLogs | Defender text/structured exports and supported CAB members |
| Registry | native hive keys/values; service and Run/RunOnce configurations |
| Forensics Collection Summary.csv | collection summary |

Column matching ignores capitalization, spaces and punctuation. Aliases include
`ComputerName`/`HostName`, `PID`/`ProcessId`/`OwningProcess`,
`ExecutablePath`/`ImagePath`, `RemoteAddress`/`DestinationIp`, and
`UserName`/`AccountName`. UTF-8, BOM-marked UTF-16 and PowerShell CSV `#TYPE`
preambles are supported. Unknown columns remain in the original record.

Additional adapters handle scheduled-task XML `Exec` actions, scalar PowerShell
CLIXML, `Field : value` command output and TCP/UDP `netstat -ano` rows. Unrecognized
text lines remain searchable observations with their original line numbers.
Other XML schemas/actions produce an explicit parser error.

Text encoding is determined from the bytes, not from a byte order mark. Several
Windows Defender support logs are UTF-16 with nothing declaring it; read as UTF-8
some of them decode without error into text carrying a NUL after every character.
An export whose encoding cannot be identified is read as Windows-1252 rather than
discarded. The chosen encoding is reported on the member when it is not UTF-8.

A row that does not match its header no longer ends the file. Where an exporter has
quoted a run of columns as one cell, `'True','Auto'`, the cell is split back apart
when doing so reproduces the header exactly. Otherwise the row is kept as it is:
surplus values go to `_unmappedValues`, a short row is padded and marked in
`_partialRow`, and the counts appear on the member. A well-formed export is never
altered by this.

Defender engine logs above 500 lines are reduced to the lines naming a detection,
threat, quarantine, remediation, exclusion or change of protection state, each with
the four lines either side. The context is the point: in a resource-scan block it is
the neighbouring lines that carry the path of the file and the name of the process,
so a filter that kept the threat name alone would report that something was found
while discarding what it was. Files that are state dumps rather than engine logs,
such as MPRegistry, MPStateInfo and MPDetection, are kept whole however long they
are. The member records how many lines were read and how many were kept; the file
itself is inventoried and hashed in full either way.

Collected artifacts are mapped into the fields the rules read, and a few export shapes
needed specific handling before any rule could reach them. `schtasks /fo csv` writes
its headers in the host's language and carries the command under "Task To Run", so
that column and its French form become `commandLine`, with `image` taken from the
quoted first token and the run-as account becoming `targetUser`. A prefetch entry
names its own executable among the files it references, so `image` and `path` now
carry that full path rather than the bare file name. Installed programs expose their
install location or source as `path`. A Defender log line naming a threat has it
lifted into `threatName`, whatever the surrounding text, so detections can be grouped
by name. An autoruns member that is concatenated `reg query /s` output becomes one
row per registry value, with the key in `targetObject`, the value name in `name` and
launch strings in `image`; flags and resource references get no `image`, and the
collector's own error lines are kept as messages.

A row the parser reassembled says so on the row, not only in the count on the
member, so it stays distinguishable from a clean one wherever it is read. A repair
is accepted only when a single grouped cell was split and that split alone accounts
for the whole shortfall; reaching the header width by combining several splits is a
coincidence rather than a repair.

Native decoders use Dissect for Prefetch v23/30/31 (including MAM compression) and
REGF registry hives. Prefetch emits each recorded execution time, run count and
referenced filenames; these filenames are not automatically resolved to host drive
letters. Prefetch v17/26 is unsupported. Registry last-write times remain metadata;
no transaction-log replay or deleted-key recovery is performed. In-transaction hives
are identified in the original fields. Services and Run/RunOnce values become
configuration observations. Memory/disk images and arbitrary collector schemas
still require exported records or additional adapters.

CAB supports uncompressed and MSZIP members; LZX/Quantum and duplicate-name CABs
produce explicit errors. A CAB expands to at most 256 MiB across at most 20,000
members, sized for a genuine Defender support cab rather than for record output,
and at a ratio of at most 200 to its own size: several entries may point at the
same folder data, so the expanded total counts bytes written rather than bytes
allocated and would otherwise put no limit on what a few kilobytes can produce. ZIP/TAR/CAB can nest up to three container levels, sharing
the outer package's budgets. Provenance uses `container.zip!/member` paths and
retains container hashes. A nested manifest can override inherited host/time defaults.

Collection summaries compare `Artifact,Count` against parsed **record** counts;
counts of files/bytes need a corresponding manifest field, not `Count`. A manifest
may include `expectedFiles: [{"path":"Processes/processes.csv","count":1,
"sha256":"…","size":123}]`. Coverage shows matched, missing, incomplete, mismatched
and unresolved expectations, including nested packages. A verified, completed
import with the same case, name, kind and SHA-256 is skipped on repeat; failed or
incomplete imports can be retried. Removing existing evidence allows a fresh parse.

## Context and timestamps

An optional, unique `collection-manifest.json` at the archive root supplies
defaults where rows do not identify a host or collection time:

```json
{
  "host": "WS01",
  "collectedAt": "2026-09-09T10:00:00Z",
  "collector": "Example collector"
}
```

Omit the default host for multi-machine packages unless every row identifies its
own host. Duplicate or misplaced manifests are errors. Folder imports do not share
a manifest between individually uploaded files.

Collection rows have `recordKind: observation`, an `artifactType`, and `observedAt`.
No Windows event ID or historical timestamp is fabricated. The Events page labels
snapshots and offers type/artifact filters; snapshots do not create historical
timeline activity. Only timestamps with an explicit timezone are normalized;
ambiguous originals remain in `data`. Prefetch exports with explicit
`LastRunTime`/`LastExecutionTime` become timestamped activity records.

Observations share the existing event record store and query interface with an
explicit record type, keeping migration, rules and deletion compatible. They are
not classified as Windows/Sysmon events. New rules can target `recordKind`,
`artifactType`, `category` (for example `collection:process`) and `data.*`.

## Relationships

Open **Relationships**, select the whole case or one evidence item, and build.
Search hosts, accounts, programs, configurations, files, hashes, addresses, domains,
processes or records. The diagram shows neighbors. Expand a relationship for its
rationale, confidence and source references; **Open** displays the underlying row.

Examples include service → executable → digest ← mail attachment, and source
record → process instance → observed endpoint. Instances require a host plus a GUID
or PID with explicit start time. A PID-only connection can resolve contextually to
one process when host, package and explicit collection time all agree and process
start is no later than collection. Multiple candidates remain unresolved. Full Windows
paths are host-scoped; bare filenames do not join files. Accounts retain explicit
domains/UPNs; unqualified names are host- or record-scoped. UPN/NetBIOS and hostname
aliases are not inferred. Enter known mappings in **Explicit host and account aliases**
and rebuild; cycles are rejected. A path may have multiple historical digests; this does not
establish which version a process executed.

High confidence means the relationship is explicitly reported, not that the source
is truthful or activity is malicious. Contextual links are weaker associations.
Shared entities do not establish causation. Existing scored attack chains and their
review workflow remain separate; this explorer does not require a mail seed.

**Build relationships** scans successive pages of 1,000 events and 1,000 mails,
with progress and a **Stop after this page** control. **Continue scanning** resumes
a stopped scan. Resource limits still apply and incomplete scans remain labeled.
**Cross-source links** highlights entities supported by multiple source files or
evidence items, prioritizing hashes, files and process instances over general hubs.
Each entry names its sources and opens supporting records. Repeated rows from one
source do not count as independent support; overlap does not establish maliciousness.
Browser queries use case/ID indexes; both stores use an independent process context
index/query so page boundaries do not prevent snapshot matching. Process context
caps at 20,000 records; exceeding it disables snapshot inference and marks the graph
partial. Each page caps at 20,000 nodes/40,000 edges; the merged view caps at
100,000 nodes/200,000 edges, with 30 sample references per edge. Server attachment
and URL joins cap at 100,000 rows each per page. Narrow the evidence scope when a
limit is reached. A cached graph and its cursor resume on return and are invalidated
by changed evidence. Graphs above the cache budget must be rebuilt after leaving
the view; saved analyst reviews remain available. They are rebuildable analysis,
not authoritative evidence.

The related-evidence timeline follows two connections from any entity, up to 200
source records, and distinguishes event time from collection time. Save accepted or
rejected links with analyst notes. Check **Include accepted link in report** and save
to include the relationship, rationale, aliases and source references in the report.
Decisions survive rebuilds and case backup/restore using content provenance. Removed
evidence is excluded from reports; reviews remain archived. Existing links without
member hashes fall back to database identity and may need review again after restore.

Six collection rules cover user-writable persistence paths, encoded execution,
script-host connections, remote execution service names, Defender alert text and
Prefetch script/admin tool execution. They are triage leads, not malicious verdicts,
and have the same tested behavior in the browser and SQL engines.

## Limits and synthetic verification

Packages allow 20,000 archive entries, 4 GiB per member and 16 GiB expanded data.
Structured exports cap at 64 MiB per member, manifests at 64 KiB. Members stream to
temporary files; archive paths are never used as extraction destinations. Links,
encrypted members and traversal paths are skipped. Temporary files are cleaned up.
An inventory cut short is marked incomplete.

Native decoders run in subprocesses, monitored at 50 ms intervals with 30-second,
512 MiB RSS and 64 MiB input/output limits; CAB output is allowed 512 MiB because it
is an archive rather than records. These are sampled limits, not an OS sandbox.
Prefetch is decoded in groups of up to 64 artifacts per process, since a collection
carries hundreds of them and an interpreter start each cost more than the decoding.
An artifact a group does not reach is decoded on its own, so one damaged artifact
costs only itself, and only artifacts the single-artifact path would accept are held
back. A package may decode 5,000 native artifacts or spend 300 seconds decoding,
whichever comes first, counting cabinets and counting decodes that fail; past that,
members are inventoried and hashed with the reason recorded. Held-back artifacts
occupy at most 256 MiB of staging per request rather than per archive. Text exports keep their first 100,000 lines and are marked
truncated rather than discarded; registry traversal caps at 100,000 keys and depth
128. No evidence command or executable is run. Native decoder dependencies
include AGPL-licensed Dissect and LGPL-licensed cabarchive; see `THIRD_PARTY_NOTICES.md`.

Generate a synthetic package with mail, EVTX, host exports, native Prefetch, a REGF
hive, a Defender CAB, a matching attachment digest and unsupported placeholders:

```
python samples/synthetic/make_package.py --out samples/generated/investigation-package.zip
```

Backend tests cover coverage, limits, parser failures, timestamps, identity isolation
and storage parity. Worker tests cover interleaved mail/observation ingestion;
Playwright exercises package import and relationship exploration in the built app.
These fixtures are invented. Compatibility with a real acquisition from your
collector still needs a representative package; the screenshot alone cannot establish it.
