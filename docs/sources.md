# Data sources

_Windows event logs, mailboxes, Microsoft 365 and Entra exports, deleted mail._

## Microsoft 365 audit and Entra sign-in exports (BEC investigations)

Drop the exports the acquisition tools produce next to the mailbox export and
they become rows of the events table, so the timeline, facets, rules, AI tools
and pivots work on them unchanged:

* Unified Audit Log as CSV (Purview export, Invictus Microsoft-Extractor-Suite,
  Office-365-Extractor: any CSV with an `AuditData` column) or JSON (array or
  NDJSON of AuditData objects, Untitled Goose Tool output);
* Entra ID sign-ins as Graph JSON (`Get-EntraSignInLogs`, Goose) or the portal
  CSV export; a `.zip` of a whole acquisition folder is walked.

Rows carry `provider`, `channel` (the workload), `category` (`M365 Exchange`,
`M365 Entra`, `Entra sign-in`, ...), `operation`, `subjectUser` / `targetUser`,
`ipAddress`, `status`, `objectName`, and every AuditData field under
`data.<Name>` (Parameters, ModifiedProperties, OperationProperties flattened;
Entra `data.country`, `data.clientAppUsed`, `data.riskState` ...).
`rules/m365/bec.yaml` ships 28 rules: inbox rules that forward or hide mail,
mailbox and transport-rule forwarding, delegate permissions, MailItemsAccessed
bursts and delegate syncs, OAuth consent, privileged role assignment, MFA and
security-info changes, conditional-access and audit tampering, legacy
protocols, eDiscovery, mass download and anonymous sharing, risky sign-ins,
legacy-auth sign-ins, sign-ins outside the expected countries (Settings), two
countries within 24 h, password spray, brute force followed by success, MFA
fatigue. `samples/synthetic/make_m365.py` writes a complete BEC scenario in all
four formats.

## Deleted and orphaned mail (PST / OST)

Messages inside Deleted Items and the Exchange Recoverable Items dumpster
(Purges, Deletions, Versions, DiscoveryHolds, in the common Outlook locales)
are flagged `deleted_item`. Messages that were deleted and detached from every
folder are recovered from the PST/OST item tree as libpff orphan items, listed
under a synthetic "(orphaned)" folder and flagged `deleted_item` +
`orphan_item`. The rule `mail-deleted-message-with-indicators` reports the
ones that also score 45 or more, since a cleaned mailbox is itself evidence.
Outlook *exports* rarely contain orphans; original PST/OST files do.
