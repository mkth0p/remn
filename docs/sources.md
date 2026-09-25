# Data sources

Mixed host investigation collections are described in [Investigation packages](packages.md),
including structured artifact adapters, snapshots and member coverage.

REMN reads three kinds of evidence and turns them into two tables, events and mails, so
that search, facets, the timeline, the rules, the attack chains and the AI tools work
the same way whatever the file came from. Every dropped file is hashed with SHA-256 in
the browser before it leaves, and again on the server, and the Evidence page keeps that
chain of custody. This page says what each source is, which formats are accepted, and
what the rows carry.

## Windows event logs

Drop `.evtx` files, or a `.zip` or `.tar` archive of them; the archive is walked and
every event is tagged with its source file. Records are flattened into the events table:
the standard fields (time, event id, channel, provider, computer, level) and the
event-specific ones under their own names (`targetUser`, `subjectUser`, `ipAddress`,
`logonType`, `processName`, `commandLine`, `serviceName`, `taskName`, …), with every
EventData field also reachable as `data.<Name>`. Access rights in object-access events
(4656, 4663, 5145 …) keep their codes and are followed by their names (`%%4417` then
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
mailbox.

### Deleted and orphaned mail (PST and OST)

Messages inside Deleted Items and the Exchange Recoverable Items dumpster (Purges,
Deletions, Versions, DiscoveryHolds, in the common Outlook locales) are flagged
`deleted_item`. Messages that were deleted and detached from every folder are recovered
from the PST or OST item tree as libpff orphan items, listed under a synthetic
"(orphaned)" folder and flagged `deleted_item` and `orphan_item`. The rule
`mail-deleted-message-with-indicators` reports the ones that also score 45 or more,
since a cleaned mailbox is itself evidence. Outlook *exports* rarely contain orphans;
original PST and OST files do.

## Microsoft 365 audit and Entra sign-in exports

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
  counted as not read); a `.zip` of a whole acquisition folder is walked.

Rows carry `provider`, `channel` (the workload), `category` (`M365 Exchange`,
`M365 Entra`, `Entra sign-in`, …), `operation`, `subjectUser` and `targetUser`,
`ipAddress`, `status`, `objectName`, and every AuditData field under `data.<Name>`
(Parameters, ModifiedProperties and OperationProperties flattened; Entra
`data.country`, `data.clientAppUsed`, `data.riskState`, …).

A record is in the case once. Search-UnifiedAuditLog's large-set pages repeat records,
and exports cut into time slices overlap, so a UAL record whose `AuditData.Id` was already
read, and a Graph sign-in whose `id` was, is not added again: not from the same file, not
from another file of the upload, not from evidence added earlier. The evidence detail and
the archive or package member list say how many repeats were left out. A record without a
GUID for an id is never dropped.

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

`rules/m365/bec.yaml` ships 28 rules for this data: inbox rules that forward or hide
mail, mailbox and transport-rule forwarding, delegate permissions, MailItemsAccessed
bursts and delegate syncs, OAuth consent, privileged role assignment, MFA and
security-info changes, conditional-access and audit tampering, legacy protocols,
eDiscovery, mass download and anonymous sharing, risky sign-ins, legacy-auth sign-ins,
sign-ins outside the expected countries (a case setting), two countries within 24 hours,
password spray, brute force followed by success, MFA fatigue.
`samples/synthetic/make_m365.py` writes a complete scenario in all four formats.
