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
EventData field also reachable as `data.<Name>`. Security, System, PowerShell, Sysmon
and Defender logs are the ones the bundled rules target. On the machine under
investigation, `wevtutil epl Security C:\evidence\Security.evtx` (as administrator)
exports a channel.

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
  of AuditData objects, Untitled Goose Tool output);
- Entra ID sign-ins as Graph JSON (`Get-EntraSignInLogs`, Goose) or the portal's CSV
  export; a `.zip` of a whole acquisition folder is walked.

Rows carry `provider`, `channel` (the workload), `category` (`M365 Exchange`,
`M365 Entra`, `Entra sign-in`, …), `operation`, `subjectUser` and `targetUser`,
`ipAddress`, `status`, `objectName`, and every AuditData field under `data.<Name>`
(Parameters, ModifiedProperties and OperationProperties flattened; Entra
`data.country`, `data.clientAppUsed`, `data.riskState`, …).

`rules/m365/bec.yaml` ships 28 rules for this data: inbox rules that forward or hide
mail, mailbox and transport-rule forwarding, delegate permissions, MailItemsAccessed
bursts and delegate syncs, OAuth consent, privileged role assignment, MFA and
security-info changes, conditional-access and audit tampering, legacy protocols,
eDiscovery, mass download and anonymous sharing, risky sign-ins, legacy-auth sign-ins,
sign-ins outside the expected countries (a case setting), two countries within 24 hours,
password spray, brute force followed by success, MFA fatigue.
`samples/synthetic/make_m365.py` writes a complete scenario in all four formats.
