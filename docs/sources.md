# Data sources

Mixed host investigation collections are described in [Investigation packages](packages.md),
including structured artifact adapters, snapshots and member coverage.

REMN reads three kinds of evidence and turns them into two tables, events and mails, so
that search, facets, the timeline, the rules, the attack chains and the AI tools work
the same way whatever the file came from. Every dropped file is hashed with SHA-256 in
the browser before it leaves, and again on the server, and the Evidence page keeps that
chain of custody. This page says what each source is, which formats are accepted, and
what the rows carry.

A loose file is taken by its name. One whose name is none of the formats below is read by
its start: a mailbox file without an extension, as mail clients keep them, or a saved message
goes on as mail; anything else is not imported, and the drop says which files were turned
away. Inside a dropped folder or an archive, each file is recognised by its content instead
(see [packages](packages.md)).

## Windows event logs

Drop `.evtx` files, or a `.zip` or `.tar` archive of them; the archive is walked and
every event is tagged with its source file. Records are flattened into the events table:
the standard fields (time, event id, channel, provider, computer, level) and the
event-specific ones under their own names (`targetUser`, `subjectUser`, `ipAddress`,
`logonType`, `processName`, `commandLine`, `serviceName`, `taskName`, …), with every
EventData field also reachable as `data.<Name>`. A column keeps at most 4,000 characters and
ends in `…` where it is cut, except the text rules search whole, which keep 65,536: the command
line, the script block, the task definition, and `message`, the unnamed Data of a classic event
(a PowerShell 400's `HostApplication`) joined; `data` keeps every value whole. Access rights in
object-access events (4656, 4663, 5145 …) keep their codes and are followed by their names (`%%4417` then
`WriteData (or AddFile)`), as the event viewer shows them, so rules written against either
spelling match. Where an older log leaves out what a newer one records about a parent
process, the parser fills it in from the parent's own event in the same log: `ParentUser`
on a Sysmon 1 from before Sysmon logged it, the parent's image on a 4688 from before
Windows logged it; the row's `enriched` field says what was filled in, and the raw record
is unchanged. Security, System, PowerShell, Sysmon and Defender logs are the ones the
bundled rules target. On the machine under
investigation, `wevtutil epl Security C:\evidence\Security.evtx` (as administrator)
exports a channel.

Event records exported as XML are read into the same rows: `wevtutil qe Security /f:xml`,
Event Viewer's "Save All Events As" XML, `Get-WinEvent | ForEach-Object { $_.ToXml() }`, and a
SIEM's XmlWinEventLog export (Splunk keeps one record a line), as `.xml`, `.log` or `.txt`,
alone or in an archive, in UTF-8 or UTF-16. Each `<Event>` is read into the shape the EVTX
parser gives the same record, so every rule reads it as it reads the `.evtx`: on the 50,176
records of EVTX-ATTACK-SAMPLES and EVTX-to-MITRE-Attack read both ways, the rows agree except
that XML reads a Windows line break (`\r\n`) as one line feed, a value the event types as a
boolean is the text Windows writes (`true`), and a control character XML does not allow is
replaced. Some exports write a value as it is, an ampersand or markup inside it unescaped; such a
record is read with those escaped, and the file says how many were. An export holds what its
query selected, not a file's own record numbering, so no statement about missing records is made
for it, and its rendered message (`RenderingInfo`) is not read.

A record the decoder cannot read is counted as an error and passed over. Should the decoder
itself stop part-way through a file, in the browser or on the server, the rows read before that
point are kept and the file is reported as cut there.

Each file also says what it cannot show about itself, in its parser statistics
(`sequences`, one entry per file, archive or package member):

- **Holes in its numbering.** The record header's id is the file's own sequence, so an id
  that is missing between two others is a record no longer in the file: deleted, or in a
  part that could not be read. The header id is used rather than the event's
  EventRecordID, which a forwarded log copies from the machine that wrote the event.
- **Write times that step back** by more than a second between consecutive records
  (EvtxECmd's `--tdt` default), each with both times, and the clock changes (Kernel-General
  1, Security 4616) and event log service starts (System 6005) the file holds. Most steps
  are how Windows logs: records made while it starts are written once the log service runs,
  and a clock set back makes every log step back at once. The report explains a step by a
  clock change or service start on the same machine in any file of the case, and takes a
  step that three or more logs of one machine make at the same moment for its clock; a step
  that one log makes alone, by a minute or more, is named as a record put in later or a
  clock change no log collected records. On the seven machines of `evtx-baseline` (6.6
  million records) that leaves no such step, and eight clocks set back by hours during
  setup. A zero write time (1601-01-01), which filtered exports write, counts as none.
- **Chunks that fail their checksum.** The file header, each chunk header and each chunk's
  records carry a CRC32. The parser reads a changed record without complaint, so the check
  is what says it was changed after Windows wrote it. None of the 2,239 files of
  NextronSystems' `evtx-baseline`, 707 of them copied from running machines, fails it.

The Evidence page and the report turn these into sentences; see "Where it stops" on the
[interface page](interface.md#report).

## Mailboxes

Accepted: `.pst` and `.ost` (with `libpff-python` installed), `.mbox`, `.eml`, `.msg`,
and a `.zip` of `.eml` files. Each message becomes a row of the mails table with its
addresses, subject, date, headers, authentication results (SPF, DKIM, DMARC, ARC),
URLs, attachments and the risk score described on the [detection page](detection.md).
Bodies and raw headers are kept for previews and body rules unless the case says
otherwise. Attachments are analysed statically at ingest (structure, macros, PDF
content, archives, YARA when installed); the analysis summary is kept, the bytes are
not. Deep attachment analysis can be switched off for a first pass over a very large
mailbox. A body is kept to 200,000 characters of text and 400,000 of HTML, and a longer one
is flagged `body_truncated`. The first 60 attachments of a message are analysed and listed,
and a message with more is flagged `attachments_truncated` while its attachment count stays
the real one. An attachment over 60 MiB in a PST or OST is not read: it is listed with the
size the mailbox declares, no hash, and the flag `not_read`.

A message attached to another (a `message/rfc822` part of an `.eml` or `.mbox` message, also
when a client wrote it in base64 as GroupWise does, or an Outlook item inside a `.msg`) is one
of its attachments, flagged `nested_mail`. Its text and links stay out of the outer message's
body: the attachment analysis reads it as a mail and keeps its subject, sender, date, flags and
own score in the attachment's details.

A `.msg` saved in 8-bit strings rather than Unicode is read in the code page it names. Outlook
does not always write the message code page; when only the internet code page is there (a
message in Chinese saved as Big5, for example), that one is used, rather than the Western
European default that turned such a subject and sender into unreadable characters.

A display name that holds an address without quotes is read as a name, and the sender's
address is the one in angle brackets: Outlook keeps an address as the name of a contact who has
none and writes a contact as "Name (address)", and a lure shows a trusted address there, which
is flagged `display_name_email_mismatch`. A list in which one entry cannot be read is read entry
by entry, so a `.msg` without transport headers, whose recipients are joined by semicolons,
keeps them.

### Deleted and orphaned mail (PST and OST)

Messages inside Deleted Items and the Exchange Recoverable Items dumpster (Purges,
Deletions, Versions, DiscoveryHolds, in the common Outlook locales) are flagged
`deleted_item`. Messages that were deleted and detached from every folder are recovered
from the PST or OST item tree as libpff orphan items, listed under a synthetic
"(orphaned)" folder and flagged `deleted_item` and `orphan_item`. The rule
`mail-deleted-message-with-indicators` reports the ones that also score 45 or more,
since a cleaned mailbox is itself evidence. Outlook *exports* rarely contain orphans;
original PST and OST files do.

A message, folder or orphan item that libpff cannot read, as in a damaged PST or a partly
synchronised OST, becomes a row of its own in its folder, with the subject "(unreadable
message)", "(unreadable folder)", "(unreadable folder contents)" or "(unreadable orphan item)",
the flag `parse_error` and libpff's error, and the import counts it among its errors.

## Microsoft 365 and Entra exports

Business email compromise investigations rest on the tenant's own logs. Drop the exports
the acquisition tools produce next to the mailbox export and they become rows of the
events table:

- the Unified Audit Log as CSV (Purview export, Invictus Microsoft-Extractor-Suite,
  Office-365-Extractor: any CSV with an `AuditData` column) or JSON (an array or NDJSON
  of AuditData objects, Untitled Goose Tool output, or the records of the Graph audit log
  query, whose record sits under `auditData`, as Microsoft-Extractor-Suite's `Get-UALGraph`
  writes them);
- Entra ID sign-ins as Graph JSON (`Get-EntraSignInLogs`, Goose), the portal's CSV
  export, or the Azure Monitor records Entra's diagnostic settings write to Log Analytics,
  an Event Hub or a storage account (the sign-in under `properties`, categories
  `SignInLogs`, `NonInteractiveUserSignInLogs`, `ServicePrincipalSignInLogs` and
  `ManagedIdentitySignInLogs`; a record of another category, such as `AuditLogs`, is
  counted as not read);
- Entra ID directory audits as Graph JSON (`auditLogs/directoryAudits`,
  `Get-MgAuditLogDirectoryAudit`, a page or an array of records), the Entra admin
  centre's audit log download as JSON or CSV, or the Azure Monitor records of the
  `AuditLogs` category;
- Entra ID Protection risk detections and risky users as Graph JSON
  (`identityProtection/riskDetections`, `identityProtection/riskyUsers`), their properties
  as CSV columns (`Get-MgRiskDetection | Export-Csv`, `Get-MgRiskyUser | Export-Csv`,
  Microsoft-Extractor-Suite's `Get-RiskyDetections` and `Get-RiskyUsers`), or the Azure
  Monitor records of the `UserRiskEvents` and `RiskyUsers` categories;
- the Exchange Online message trace as `Get-MessageTrace` or `Get-MessageTraceV2` output
  written with `Export-Csv` (Microsoft-Extractor-Suite's `Get-MessageTraceLog`), or the
  Exchange admin centre's downloadable enhanced summary and extended reports.

A `.zip` of a whole acquisition folder is walked.

An Azure Monitor record holds the record under `properties`, with the names of the Graph
record, and its category says what it is: it gives the row its Graph form gives, the record's
time taken from the envelope's `time` when it has none. A file of them is of the category of
its first record, as a JSON file is of the kind of its first record, except that a file whose
first records include a sign-in is read as sign-ins; a record of another category in it is
counted as not read. The
risks of service principals (`ServicePrincipalRiskEvents`, `RiskyServicePrincipals`) are not
read.

Not read, each for the reason given further down: ID Protection reports downloaded from the admin
centre whose fields are not the Graph property names; the Exchange admin centre's "Export
results" of the message trace shown on screen; a UTF-16 file without a byte order mark. A
Graph page that ends with `@odata.nextLink` is one page of a longer list: REMN reads the
records it holds and does not say that more pages exist.

Each export may be written in UTF-8, or in UTF-16 or UTF-32 with a byte order mark, as
Windows PowerShell's `Export-Csv -Encoding Unicode` and `Out-File` write it. The `#TYPE`
line `Export-Csv` writes above the header without `-NoTypeInformation` is passed over, and a
date `ConvertTo-Json` wrote as `\/Date(milliseconds)\/` is read. A UTF-16 file without a
byte order mark is not recognised.

Outside the Azure Monitor records, whose category says what they are, a record is read as a
sign-in only when it carries a time (`createdDateTime`), a client address (`ipAddress`) and
the user or the application signed in to. Directory audits, risk detections, risky users
and user lists name a `userPrincipalName` too, but they are not sign-ins: a file of
directory audits, risk detections or risky users is read as such (below), and a user list is
listed as a member REMN has no parser for (in the event-log import, as "not a recognised
Microsoft 365 or Entra export"). A JSON file is of the kind of its first record, and a record
of another kind inside it is counted as not read: the evidence's statistics (`notRead`) and
its member list say how many, and the member is marked failed. Field names are read in any case, so the
PascalCase columns of `Get-MgAuditLogSignIn | Export-Csv` land on the same names as the
Graph JSON; a column that export wrote as a .NET type name (`Status`, `Location`,
`DeviceDetail`) is left out. A sign-in whose export gives neither a status nor an error code
has no `status`, and its summary says the outcome is not in the export: it is not counted as
a successful sign-in.

A directory audit becomes a row with the provider `Microsoft Entra ID Audit`, the channel
`Entra Audit` and the category `Entra audit`. Its `operation` is the activity as the Unified
Audit Log names it, with a closing period (`Consent to application.`, `Add member to
role.`), so the rules, stories and chains that know an audit log record know the same
activity in a directory audit; `description` and `data.activityDisplayName` keep Entra's own
spelling, and Privileged Identity Management activities keep theirs. The initiator, a user
or an application, is `subjectUser`, and its address `ipAddress`; the first target with a
user principal name is `targetUser`, and the first named target that is not a user
`objectName`. Each modified property is `data.<name>` with its new value and
`data.<name>.old` with its old one (`data.Role.DisplayName`, `data.ConsentAction.Permissions`),
each additional detail `data.<key>` (`data.User-Agent`), and the initiator and the targets
`data.initiatedBy.*` and `data.Target.*`. A field REMN does not know is kept under its own
name in `data`. A record whose id holds a GUID is kept once, as an audit log record is.

The admin centre's CSV download writes the date, service, category, activity and result
columns in the language of the portal, so those five are read by their place, first and third
to sixth; the other columns are named in English in every language. It holds at most three
targets with five modified properties each and six additional details, which is all REMN can
read of a record from it, and no record id, so a record downloaded twice is in the case twice.
`Get-MgAuditLogDirectoryAudit | Export-Csv` writes the initiator, the targets and the details
as .NET type names, so its rows say what was done and when but not by whom; the JSON from
the same cmdlet holds them. The admin centre downloads at most 250,000 audit records a file:
a CSV or JSON download of exactly that many carries a "gaps" badge on the Evidence page, since
the records after it in its time window are probably missing.

A risk detection becomes a row with the provider `Microsoft Entra ID Protection`, the channel
`Entra RiskDetection`, the category `Entra risk` and the operation `RiskDetection`, at the time
of the activity it rates (`activityDateTime`; `detectedDateTime` when it has none, and an
offline detection is often hours later). Its `description` is the `riskEventType`, its
`status` the `riskState` and `statusText` the `riskDetail`; the user is `subjectUser` and
`targetUser`, the address `ipAddress`, and the place `data.country`, `data.city` and
`data.state`, as on a sign-in. `data.correlationId` and `data.requestId` are those of the
sign-in it rates, and each key of `additionalInfo` is `data.additionalInfo.<key>` (the
`userAgent` is also `workstation`). A risky user becomes a row of the channel `Entra
RiskyUser` and the operation `RiskyUser` at `riskLastUpdatedDateTime`: the state of that
user's risk when the list was taken, so the same user listed again after the risk changed is
a second row. Both are a warning when the risk is medium or high or the compromise was
confirmed. A risk detection is kept once by its id. The ID Protection reports in the admin
centre can be downloaded as CSV or JSON, but Microsoft does not document what those files
hold: a download whose fields are the Graph property names is read, any other is not
recognised.

A message trace becomes rows with the provider `Exchange Online Message Trace`, the channel
`Exchange MessageTrace`, the category `Exchange message trace` and the operation
`MessageTrace`, one for each recipient of a message: the sender is `subjectUser`, the
recipient `targetUser`, the subject `objectName`, the delivery status `status` (a message
that failed, was quarantined or filtered as spam is a warning), the address that sent it to
the service `ipAddress` and the one the service sent it to `destinationIp`. Every column is
kept under its own name in `data`, with `data.SenderDomain`, `data.RecipientDomain` and
`data.InternetMessageId`, which opens the mailbox message and the audit records that name the
same message. The cmdlets write their times in UTC, Microsoft says, so a zone set for the
evidence does not move them, but `Export-Csv` writes them in the session's date order. A row
of `Get-MessageTrace` is kept once by its `MessageTraceId`, recipient and status;
`Get-MessageTraceV2`'s output properties are not documented, and its export is read by the
same column names (`Received`, `SenderAddress`, `RecipientAddress` and the others its
parameters are named after), any other column kept as it is. Both cmdlets return 1,000
rows unless told otherwise, and `Get-MessageTraceV2` 5,000 at most: an export of exactly
1,000 or 5,000 rows carries a "gaps" badge, as an audit log export cut at its limit does.
The enhanced summary report
gives a row for each `<address>##<status>` of `Recipient_status` (Microsoft does not say what
separates two recipients; a `;` before another `<address>##` is taken as the separator) and
its `directionality` as `direction`; the extended report gives a row for each recipient of
each event, its `event_id` as the status and its `source` (`MAILBOXRULE` for a message an
inbox rule sent) in `data.source`. A report writes its times in the zone of the admin who
asked for it, so a time without a zone, in a column whose name does not say UTC, is counted
(`zoneAssumed`) and read in the zone set for the evidence. A report has no id for its rows,
so a report downloaded twice is in the case twice. The admin centre's "Export results" of the
summary shown on screen is not recognised: Microsoft does not document its columns.

Rows carry `provider`, `channel` (the workload), `category` (`M365 Exchange`,
`M365 Entra`, `Entra sign-in`, …), `operation`, `subjectUser` and `targetUser`,
`ipAddress`, `status`, `objectName`, and every AuditData field under `data.<Name>`
(Parameters, ModifiedProperties and OperationProperties flattened; Entra
`data.country`, `data.clientAppUsed`, `data.riskState`, …). A value nested deeper is kept as
JSON up to 4,000 characters (`Target` and `Actor` ids, `Folders` paths and the applied
conditional access policies up to 2,000), and the whole record in `raw` up to 200,000. A
value cut at its limit ends with `…`, and the evidence's statistics (`cut`) and its member
list say how many records hold one.

A record that cannot be read is counted in the evidence's parse errors, and the records after
it are still read. A CSV field may hold up to 16 MiB, so an AuditData column longer than the
131,072 characters Python's CSV reader stops at by default no longer ends the file; a row
the reader cannot take (a longer field, a stray quote) is one such error. JSON exports are
read one record at a time whatever their size, so a large array no longer has to fit in the
server's memory: an array, a Graph page (`{"value": [...]}`), several of them one after the
other, or one object per line. A record longer than 16 MiB on a line of its own is one
error; inside an array it stops the file there, the records before it kept and the file
marked failed with the record number. So does JSON that is broken part-way.

A time written with a zone or an offset keeps it; one written without is read as UTC, the
zone the audit log's `CreationTime`, Graph and the portal's `Date (UTC)` use. Dates a
culture or a spreadsheet wrote are read too (`9/1/2026 10:00 AM`, `01.09.2026 10:00`,
`2026/09/01 10:00:00`, with or without seconds or an offset). Such a time without a zone, in
a column whose name does not say UTC, is counted (`zoneAssumed`): `Export-Csv` writes a time
in whatever zone it held, so UTC is an assumption there. A sign-in CSV that writes its
dates as numbers is read in the order its own dates show: one day above 12 anywhere in the
file settles it for the whole file. When no date shows it, the dates are read month-first,
the portal's order, and the evidence's statistics (`dateOrderGuessed`) and its member list
say how many records were dated that way: in a day-first export those dates are wrong. A
record whose date is missing or cannot be read is kept without a time and counted the same
way (`undated`), since it is not on the timeline.

The date order and the time zone can be set for an evidence file where its exports cannot
say. The detail of such a file on the Evidence page says how its dates were read and what was
guessed or assumed, and sets an order and a zone for it: the original file is dropped again,
checked against the SHA-256 recorded when it was imported, and the evidence is removed and
the file imported again with the setting (its analyst note is kept; its findings are cleared
until the rules run again). The console says which setting each import used. The import
request takes it as the `dates` field: `{"order": "day-first" | "month-first", "zone": "UTC"
| "+02:00" | "Europe/Paris"}`. The order set is used for every numeric date of the file's
Entra and message trace exports in place of the order the file shows; a date that cannot be
read in it but can the other way is counted (`dateOrderContradicted`) and left without a
time. The zone set
is used for each time a culture wrote without a zone, and never for an ISO 8601 time, a time
with an offset, or a column whose name says UTC; a zone given by name follows daylight
saving time. The evidence's statistics keep the setting (`dates`) and count the records it
was used for (`dateOrderSet`, `zoneSet`), and each member of an archive or a package says
the same in its note. The audit log's times are ISO 8601 in UTC, so the setting does not
change them, and the other tables of a collection package still leave a date that reads
both ways without a time.

A record is in the case once. Search-UnifiedAuditLog's large-set pages repeat records,
and exports cut into time slices overlap, so a UAL record whose `AuditData.Id` was already
read, and a Graph sign-in whose `id` was, is not added again: not from the same file, not
from another file of the upload, not from evidence added earlier. The evidence detail and
the archive or package member list say how many repeats were left out. A record without a
GUID for an id is never dropped. The ids of the first 6,291,456 records of an upload are
held to find repeats, in 64 MiB of the server's memory at most; a record read after that is
still compared with them and with the case, but not with the others read after it, and the
evidence's statistics (`repeatsUnchecked`) and its member list say how many there were.

Sign-ins keep what ties them to the token and session they gave: `data.sessionId` and
`data.uniqueTokenIdentifier` (the audit records the token made carry them as
`data.AppAccessContext.AADSessionId` and `data.AppAccessContext.UniqueTokenId`),
`authenticationProtocol` and `originalTransferMethod` (a device-code sign-in says
`[device code]` in its summary), `incomingTokenType`, `authenticationMethods`,
`appliedConditionalAccessPolicies` (as `name=result`), `autonomousSystemNumber` and
`ipAddressFromResourceProvider`, from the Graph JSON or the portal CSV alike.

MailItemsAccessed names each message it read, and a delete or move each message it
touched: `data.InternetMessageId` keeps those ids (the first 1,000; beyond that
`data["InternetMessageId.total"]` gives the number), written the way the mailbox stores
`messageId`. An audit record opens the messages it names in the mailbox evidence, and a
message opens the audit records that name it.

`rules/m365/bec.yaml` ships 37 rules for this data: inbox rules that forward or hide
mail, mailbox and transport-rule forwarding, delegate permissions, MailItemsAccessed
bursts and delegate syncs, OAuth consent, privileged role assignment, MFA and
security-info changes, conditional-access and audit tampering, legacy protocols,
eDiscovery, mass download and anonymous sharing, risky sign-ins, legacy-auth sign-ins,
sign-ins outside the expected countries (a case setting), two countries within 24 hours,
password spray, brute force followed by success, MFA fatigue. The rules that read a
directory activity (consent, roles, security info, applications) find it in a directory
audit export as in the audit log, since both name it the same way.

Eight rules read the directory audits, ID Protection and message trace exports:

- `m365-risk-detection` and `m365-risky-user`: a risk detection, or a user in the risky
  users list, at medium or high risk or confirmed compromised;
- `m365-risk-then-inbox-rule`: a sign-in or risk detection at medium or high risk, raised
  to critical when the same account creates or changes an inbox rule within 24 hours;
- `m365-auth-method-added`: a passkey, a passwordless phone sign-in or a Windows Hello for
  Business credential added, or security info updated by the user;
- `m365-device-registered`: a device registered in the directory;
- `m365-app-permission-granted`: an application permission given to a service principal;
- `m365-trace-external-relay`: a message from outside the internal domains sent on to an
  address outside them (an inbox rule's redirect, mailbox forwarding, a transport rule);
- `m365-trace-mailbox-rule-message`: a message the extended report marks as made by an
  inbox rule (source `MAILBOXRULE`), sent outside the internal domains.

The two message trace rules do not run until the internal domains are set. A forward made
by an inbox rule's ForwardTo is a new message from the mailbox and shows in the message
trace as that user's own mail; only the extended report marks it. These eight rules have
not been measured: `rules/measures.json` has no entry for them, and the Rules view shows
them as unmeasured.
`samples/synthetic/make_m365.py` writes a complete scenario in all four formats.
