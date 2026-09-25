# REMN's rules, measured (2026-09-24)

> **Update, 2026-09-25.** The rules are measured on EVTX-to-MITRE-Attack too: 279 recorded attacks,
> each labelled with its technique, from a library no rule was written against (the two rules
> written since for the gaps it showed are not measured on it). The credential-dumping rule was
> split, and those two rules added ([head-to-head](2026-09-25-head-to-head.md)).
>
> | | 2026-09-24 | 2026-09-25 |
> |---|---:|---:|
> | Event rules measured | 2,998 | 3,002 |
> | Detect a recorded attack | 830 | 885 |
> | REMN's own Windows rules that do | 112 of 133 | 119 of 137 |
> | Fire on the clean machines | 167 | 168 |
>
> The new library gave 53 leads their first recorded attack, five of them REMN's own (AS-REP
> roasting, Kerberos pre-authentication brute force, audit policy and firewall changes, the system
> time changed); no rule lost one. The critical credential-dumping rule, which fired 2,504 times
> on six of the clean machines, no longer fires on them; the LSASS memory reads it caught are a
> rule of their own (high, one finding per program): 2,400 events there in nine findings, 2,379 of
> the events one antivirus installer run from a temporary folder. The rest of this page is the
> measure of 2026-09-24.

Every event rule REMN ships, its own and the three SigmaHQ packs', was run by
`tools/measure_rules.py` on recorded attacks and on the logs of clean machines, and the result
ships as `rules/measures.json`. The Rules page, the finding panel and the report read it (see
[measured rules](../detection.md#measured-rules)); this page says what it found.

**Recorded attacks**: the 459 SigmaHQ regression samples (SigmaHQ/sigma `272daf82`, the commit
the packs were converted from), the 278 files of EVTX-ATTACK-SAMPLES (`4ceed2f`) and 67
Office 365 and Entra ID datasets of Splunk attack_data (`7a5e9d5`). **Clean machines**: the seven
Windows installations of NextronSystems/evtx-baseline `v0.8.4`, 6,611,184 events.

## The answer

| Rules | Measured | Detect a recorded attack | Leads | Fire on clean machines |
|---|---:|---:|---:|---:|
| REMN Windows | 133 | 112 | 21 | 52 |
| REMN Microsoft 365 and Entra | 28 | 15 | 13 | not measured |
| REMN collection artifacts | 13 | 0 | 13 | not measured |
| SigmaHQ Windows | 2,387 | 652 | 1,735 | 86 |
| SigmaHQ emerging threats | 320 | 19 | 301 | 3 |
| SigmaHQ threat hunting | 117 | 32 | 85 | 26 |
| **All** | **2,998** | **830** | **2,168** | **167** |

A rule detects when it fires on a recording of what it looks for: its own SigmaHQ sample, an
EVTX-ATTACK-SAMPLES file reviewed as identifying it, or a recording it can read labelled with
one of its ATT&CK techniques. The other rules are leads: most SigmaHQ rules have no recording of their own,
and a technique label is coarse (a rule for one PowerShell cmdlet is "of" every PowerShell
recording without being expected to fire on them). A lead is not a bad rule; its finding is a
place to look rather than a detection shown to work. The one rule not measured needs a case
setting a recording does not have (`m365-signin-unexpected-country`, expected countries).

All 457 SigmaHQ rules with a regression sample fire on it, as converted, on the SQL engine.

## What measuring found, and fixed

- **SigmaHQ rules that could never fire.** The 10 AppX deployment rules read a channel named
  after the provider (`appxdeployment-server`) where Windows writes
  `Microsoft-Windows-AppXDeploymentServer/Operational`, and the 4 rules comparing a field with
  `true` compared it with `1` where Windows writes "true". A first trial on five SigmaHQ
  samples found two of them missing their own; after the fixes, every sample's rule fires on it.
- **PowerShell 7 was invisible to the 212 SigmaHQ PowerShell rules**: they read
  `Microsoft-Windows-PowerShell/Operational` and not `PowerShellCore/Operational`, which one of
  the clean machines logs to. The 6 DNS client rules also match the channel's display name,
  as SigmaHQ's own regression config names it.
- **Office 365 audit records with their keys in alphabetical order** (Splunk's add-on writes
  them so) were taken for event logs, because the format was told from the first 512 bytes.
  13 of attack_data's Office 365 datasets were unreadable for it.

## Rules that fire on the clean machines

167 rules fire at least once on the seven clean machines. Some are meant to (a service
installed, an audit policy changed, a log cleared: the clean images were prepared, and their
logs cleared, before they were exported); the others are the first candidates for tuning. The
twenty that fire most:

| Rule | Findings | Machines | Events matched, of those it reads |
|---|---:|---:|---|
| Successful MSIX/AppX Package Installation (`sigma-289dfa9e-e378-4a56-a9d4-7ed5ee218029`) | 437 | 6 of 6 | 926 of 926 (100%) |
| Potential Raspberry Robin Registry Set Internet Settings ZoneMap (`sigma-16a4c7b3-4681-49d0-8d58-3e9b796dcb43`) | 420 | 4 of 7 | 420 of 1,151,505 (3.6 per 10,000) |
| Process executed from a temp / download / public folder (`win-process-from-suspicious-path`) | 398 | 6 of 7 | 522 of 27,399 (2%) |
| Firewall Rule Modified In The Windows Firewall Exception List (`sigma-5570c4d9-8fdd-4622-965b-403a5a101aa0`) | 261 | 6 of 6 | 261 of 261 (100%) |
| Run / RunOnce registry persistence (Sysmon 13 / 4657) (`win-registry-run-key`) | 258 | 7 of 7 | 529 of 1,151,765 (4.6 per 10,000) |
| System Drawing DLL Load (`sigma-666ecfc7-229d-42b8-821e-1a8f8cb7057c`) | 252 | 7 of 7 | 1,038 of 727,396 (14 per 10,000) |
| Modification of IE Registry Settings (`sigma-d88d0ab2-e696-4d40-a2ed-9790064e66b3`) | 231 | 5 of 7 | 231 of 1,151,505 (2 per 10,000) |
| New service installed (inventory) (`win-service-installed-any`) | 218 | 7 of 7 | 218 of 218 (100%) |
| Signed DLL Loaded With Missing PE Version Metadata (`sigma-2a297820-04ce-41f2-b60d-5afe139aaab3`) | 200 | 5 of 7 | 200 of 727,383 (2.7 per 10,000) |
| System time changed (4616 / Kernel-General 1) (`win-time-changed`) | 196 | 7 of 7 | 196 of 18,887 (1%) |
| Removal of Potential COM Hijacking Registry Keys (`sigma-96f697b0-b499-4e5d-9908-a67bec11cdb6`) | 191 | 5 of 7 | 1,438 of 1,714,224 (8.4 per 10,000) |
| WMI Module Loaded By Uncommon Process (`sigma-671bb7e3-a020-4824-a00e-2ee5b55f385e`) | 186 | 5 of 7 | 186 of 727,396 (2.6 per 10,000) |
| Scheduled Task Created - FileCreation (`sigma-a762e74f-4dce-477c-b023-4ed81df600f9`) | 140 | 7 of 7 | 140 of 542,441 (2.6 per 10,000) |
| Process opened with full rights by a binary that has no reason to (Sysmon 10) (`win-process-access-hollowing`) | 139 | 7 of 7 | 1,685 of 1,619,360 (10 per 10,000) |
| Net.EXE Execution (`sigma-183e7ea8-ac4b-4c23-9aec-b3dac4e401ac`) | 134 | 3 of 7 | 134 of 20,994 (64 per 10,000) |
| Stop Windows Service Via Net.EXE (`sigma-88872991-7445-4a22-90b2-a3adadb0e827`) | 134 | 3 of 7 | 134 of 20,994 (64 per 10,000) |
| Creation of an Executable by an Executable (`sigma-297afac9-5d02-4138-8c58-b977bac60556`) | 131 | 4 of 7 | 131 of 542,441 (2.4 per 10,000) |
| Suspicious DNS query (Sysmon 22) (`win-suspicious-dns-sysmon`) | 124 | 3 of 6 | 124 of 7,251 (2%) |
| Memory of TeamViewer or KeePass read or written by another program (credential theft) (`win-credential-app-memory-read`) | 120 | 2 of 7 | 120 of 1,619,360 (0.74 per 10,000) |
| Remote thread injection or process tampering (Sysmon 8 / 25) (`win-remote-thread-injection`) | 117 | 7 of 7 | 117 of 823 (14%) |

## REMN's own rules that are leads

47 of REMN's 174 own event rules have not been seen to detect what they look for:

- `collection-defender-alert-text` (Defender support log contains a threat or protection alert): no recording of what it looks for
- `collection-defender-detection` (Defender recorded a threat detection): no recording of what it looks for
- `collection-defender-exclusions` (Defender exclusions listed in a support log): no recording of what it looks for
- `collection-defender-pua` (Defender recorded a potentially unwanted application): no recording of what it looks for
- `collection-encoded-execution` (Encoded or download-and-execute command in collected artifacts): no recording of what it looks for
- `collection-execution-user-path` (Executable ran from, or sat in, a temporary or user profile location): no recording of what it looks for
- `collection-persistence-script-host` (Persistence entry launches a script host or system utility): no recording of what it looks for
- `collection-persistence-user-path` (Collected persistence configuration launches from a user-writable location): no recording of what it looks for
- `collection-prefetch-script-execution` (Prefetch records execution of a script host or administration utility): no recording of what it looks for
- `collection-program-user-location` (Installed program lives in a user-writable location): no recording of what it looks for
- `collection-remote-service` (Remote execution service present in collection): no recording of what it looks for
- `collection-script-host-connection` (Collected script interpreter with a network endpoint): no recording of what it looks for
- `collection-service-unquoted-path` (Service binary path with spaces is not quoted): no recording of what it looks for
- `m365-anonymous-sharing` (Anonymous or company-wide sharing link created): does not fire on the one recording of what it looks for
- `m365-audit-disabled` (Mailbox or organisation auditing disabled): fires on none of the 3 recordings of what it looks for
- `m365-conditional-access-change` (Conditional access policy changed or deleted): does not fire on the one recording of what it looks for; fires on 4 other recordings
- `m365-inbox-rule-hiding` (Inbox rule hides messages (delete / move / mark read) with financial or security keywords): does not fire on the one recording of what it looks for
- `m365-junk-config-changed` (Junk mail configuration changed (safe senders / blocked senders)): fires on none of the 3 recordings of what it looks for
- `m365-legacy-protocol-enabled` (IMAP / POP / SMTP AUTH enabled on a mailbox): fires on none of the 3 recordings of what it looks for
- `m365-mailitemsaccessed-burst` (Mailbox enumeration - burst of MailItemsAccessed from one client): fires on none of the 7 recordings of what it looks for
- `m365-mailitemsaccessed-sync-delegate` (Mailbox synced by a delegate or admin logon): fires on none of the 7 recordings of what it looks for
- `m365-mass-download` (Mass file download (SharePoint / OneDrive)): no recording of what it looks for; fires on 1 other recording
- `m365-signin-legacy-auth` (Successful sign-in with a legacy authentication protocol): fires on none of the 11 recordings of what it looks for
- `m365-signin-mfa-failed-then-success` (MFA denied, then a successful sign-in): fires on none of the 4 recordings of what it looks for
- `m365-signin-risky` (Entra risky sign-in (identity protection)): fires on none of the 3 recordings of what it looks for
- `m365-signin-two-countries-24h` (One account signed in from two countries within 24 hours): fires on none of the 3 recordings of what it looks for
- `win-account-lockouts` (Account lockouts (4740)): no recording of what it looks for
- `win-applocker-codeintegrity-block` (AppLocker / Code Integrity / SmartScreen block): fires on none of the 3 recordings of what it looks for
- `win-asrep-roasting` (AS-REP roasting - TGT without pre-authentication in RC4): no recording of what it looks for
- `win-audit-policy-changed` (Audit policy changed (4719)): no recording of what it looks for; fires on 1 other recording
- `win-bruteforce-4625-by-account` (Brute force - repeated failed logons against one account): no recording of what it looks for
- `win-bruteforce-4625-by-ip` (Brute force - burst of failed logons from one source IP): no recording of what it looks for
- `win-event-log-service-stopped` (Event log service stopped or logging shut down): no recording of what it looks for
- `win-kerberoasting` (Kerberoasting - many RC4 service tickets requested by one account): no recording of what it looks for
- `win-kerberos-preauth-bruteforce` (Kerberos pre-authentication failures burst (4771)): no recording of what it looks for
- `win-logon-outside-business-hours` (Interactive / remote logon outside business hours): fires on none of the 2 recordings of what it looks for
- `win-logon-weekend` (Interactive / remote logon during the weekend): fires on none of the 2 recordings of what it looks for
- `win-new-firewall-rule` (Firewall rules added for an application, or all rules deleted): no recording of what it looks for
- `win-ntlm-bruteforce-4776` (NTLM validation failures burst (4776)): no recording of what it looks for
- `win-office-spawns-shell` (Office / PDF reader spawned a shell or script host): fires on none of the 9 recordings of what it looks for; fires on 1 other recording
- `win-password-spraying` (Password spraying - one source, many accounts): no recording of what it looks for
- `win-rdp-bruteforce-rdpcorets` (RDP brute force without Security log (RdpCoreTS 140 / 131)): no recording of what it looks for
- `win-rdp-logon-external` (RDP logon from a non-internal address): fires on none of the 3 recordings of what it looks for
- `win-suspicious-dns-sysmon` (Suspicious DNS query (Sysmon 22)): no recording of what it looks for
- `win-time-changed` (System time changed (4616 / Kernel-General 1)): fires on none of the 3 recordings of what it looks for
- `win-usb-mass-storage` (USB / removable device connected): does not fire on the one recording of what it looks for
- `win-username-enumeration` (Username enumeration (unknown user names)): no recording of what it looks for

## What the measure does not say

- **Precision on real networks.** Seven lab installations, 91% of their events Sysmon, are a
  floor: a rule quiet on them can be noisy on a busy domain controller or a developer's laptop.
- **Benign Microsoft 365 activity.** No clean tenant's audit log is public; the Microsoft 365
  and Entra rules have no clean-machine measure.
- **Recall.** "Detects 2 of 12 recordings of its technique" says the rule caught those two, not
  that it misses the ten: they may record another variant of the technique.
- **Rules as they change.** A measure holds for the rule it was taken on. Re-run the tool after
  changing a rule or re-importing a pack (about an hour on four cores, with 9 GB of downloads);
  a backend test warns while a rule has changed since it was measured.

## The same clean machines, for what the evidence cannot show

The clean machines also checked the report's "where it stops" statements: across their 2,239
event logs (6.6 million records) no record number is missing, and no chunk fails its checksum.
Write times step back in 200 files; the clock changes and event log service starts in the
machines' own System and Security logs explain all but 49 steps, and those 49 are 48 logs of one
machine stepping back together when its clock was set back during setup, which no log
recorded, and one step of a second in one log. What the report names is the eight clocks set back
during setup, by seven hours to thirty days: true, and a limit on reading those machines' times.
