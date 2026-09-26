# Detection

## External engines

Hayabusa runs Sigma over Windows event logs with thousands of curated rules and tuned levels,
and it does that better than a converted rule set can. When the binary is present (`hayabusa`
on PATH or `HAYABUSA_PATH`, rules beside it or at `HAYABUSA_RULES`; the container image ships
it pinned by version and by the SHA-256 of the release archive) every ingested event log is
also handed to it, and its detections come back as findings with rule ids under
`engine:hayabusa:`, the level mapped to a severity, the MITRE techniques it tags, and refs to
the rows REMN parsed from the same records, linked by computer, channel and record id. The
rules run in REMN's own engines are untouched; they cover mail, cloud and collected artifacts,
which Hayabusa does not.

It runs the way the native decoders do: a separate process, watched for memory, time and
output, killed rather than trusted past a limit, with whatever it wrote before that kept and
the stop stated in the ingest log. `HAYABUSA_ENABLED=0` keeps it out of ingest;
`HAYABUSA_MIN_LEVEL` and `HAYABUSA_MAX_S` set the floor and the time bound; `HAYABUSA_ARGS`
replaces the option set for a release whose flags have moved. Engine findings are stored per
piece of evidence and replaced when that evidence is ingested again; analyst decisions on a
finding whose key survives are kept, and orphan pruning leaves them alone.


Findings come from three places: the rules bundled with REMN (Windows, mail, Microsoft
365), the community rule packs converted from SigmaHQ and Sublime Security, and the mail
risk score computed at ingest. All rules are written in one YAML language and run on two
engines that are held to identical output: one in the browser, so evidence never has to
reach the server, and one in SQL, for gigabyte cases. This page describes the language,
the rule sets, the scoring, the sender baseline that enriches mails after ingest, and
the parity between the engines.

## The rule language

A rule is a YAML document with a `where` block over the fields of one source, optional
grouping over a sliding window, an optional follow-up that escalates the finding, and
exclusions that read the case settings:

```yaml
id: win-bruteforce-4625-by-ip
title: Brute force - burst of failed logons from one source IP
severity: high                # info | low | medium | high | critical
source: events                # events | mails
attack: [T1110.001]
where:                        # field: value  /  field|op: value  /  any_of / all_of / not
  eventId: 4625
  ipAddress|exists: true
group_by: [ipAddress]         # aggregate per group
window: 5m                    # sliding window
threshold: ">= 5"             # count (or distinct count with `distinct: field`)
then:                         # follow-up that escalates the finding
  where: { eventId: 4624 }
  join: [ipAddress]
  within: 15m
  severity: critical
time: { outside_business_hours: true, weekend: true }   # uses case settings
exclude: { targetUser|in_setting: service_accounts }
```

Operators: `eq ne in nin contains not_contains contains_any contains_all startswith
not_startswith endswith not_endswith re not_re gt gte lt lte exists empty in_setting
nin_setting levenshtein length contains_cs startswith_cs endswith_cs`. The `_cs`
variants match case exactly; everything else is case-insensitive. Dotted paths reach
nested values (`attachments.flags`, `data.LogonType`). `field|length: "< 500"` counts the
characters of a text or the items of a list, with the same threshold syntax as
`threshold`. The derived URL fields `urls.subdomain` (host minus the registrable domain)
and `urls.fragment` are available in both engines.

`in_setting` and `nin_setting` read the lists in the case settings (internal domains,
VIP and organisation display names, trusted senders, internal IP ranges, admin and
service accounts, expected countries) and fall back to a bundled list when the settings
define none of that name. Today that is `tranco_10k`, the top 10,000 of the
[Tranco](https://tranco-list.eu) ranking (list id and fetch date in
`backend/services/reference/tranco.json`; Le Pochat et al., NDSS 2019). A case setting
named `tranco_10k` overrides it; `tools/import_community_rules.py tranco --download`
refreshes it.

Rules are edited in the Rules page, and a custom rule with the same id as a bundled or
pack rule overrides it.

## Bundled rules

`rules/windows/`, `rules/mail/` and `rules/m365/` hold the rules REMN ships and
maintains: brute force and password spraying, out-of-hours logons, RDP from outside,
PsExec and admin shares, persistence, log clearing, Defender tampering, PowerShell
cradles and credential dumping on the Windows side; display-name spoofing, lookalike
domains, macro, PDF and HTML-smuggling attachments, the BEC lexicon, forged headers,
score bands and the sender-baseline rules on the mail side; and the 28 business email
compromise rules over Microsoft 365 and Entra rows listed on the [data sources
page](sources.md). Every rule carries MITRE ATT&CK technique ids, as of ATT&CK v19 (April
2026), which split Defense Evasion into Stealth and Defense Impairment and moved Impair
Defenses and event-log clearing to T1685 to T1690 (`T1562.001` is now `T1685`, `T1070.001` is
`T1685.005`, `T1656` is `T1684.001`); the SigmaHQ packs carry the same ids. The report's
threat profile counts both the old and the new ids under defense evasion.

The Windows set was extended against EVTX-ATTACK-SAMPLES, a public library of one attack
technique per log (see `docs/reviews/2026-09-23-evtx-attack-samples.md`). The techniques
the packs left undetected are covered by six files of their own: `security-audit.yaml`
(Security channel: Zerologon traces, machine-account resets, browser credential stores,
boot configuration, hive copies and executables written to drive shares, privileged group
enumeration, token and logon tricks), `other-channels.yaml` (the channels no rule read: RPC
ETW, Netlogon, ProcessExitMonitor, MSSQL, RdpCoreTS, DistributedCOM, Program Compatibility,
Application Experience, Winsock, classic PowerShell, BITS), `correlation.yaml` (what only a
burst or a sequence shows: share and pipe enumeration, SMB sweeps, Kerberos spraying,
process listing), `registry.yaml` (persistence and defence-evasion keys), `image-load.yaml`
(DLL hijacks, unsigned loads into service hosts, pipes of known tools, timestomping) and
`process-lineage.yaml` (parent-child pairs that should not happen, renamed binaries,
accessibility-binary backdoors). Each rule was written for a sample the packs missed, then
reviewed for false positives against the rest of the library and the benign background of
the linked lab, and runs the same in both engines. `tools/evtx_attack_samples.py` and a CI
job hold the detections in place: the job fails when a rule that identifies a sample's
attack stops firing on it, or when the engines disagree on any sample.

PowerShell module logging (4103) and pipeline execution details (800) record each command a
session runs, with its parameters, as `CommandInvocation` and `ParameterBinding` lines. The parser
writes them back as the command (`Get-ADGroupMember -Identity 'Domain Admins'`) into
`commandLine`, taking 800's command as typed when it has one and leaving out what the host adds
to every interactive pipeline (Out-Default, PSConsoleHostReadline). It also takes the user into
`subjectUser` and the script into `path`. `powershell-commands.yaml` reads those commands:
privileged group members listed, Kerberos tickets requested from PowerShell (Kerberoasting),
SPN accounts searched, forest and trust enumeration, a service's ImagePath or FailureCommand
rewritten, New-Service, BITS transfers, permanent WMI subscriptions, printer ports pointing at a
file (PrintDemon), AMSI bypasses, named pipe shells and the OpenSSH server enabled. These are
commands that ran, as opposed to script text that 4104 logs when a module is loaded. The pack
was written for the PowerShell files the default rules missed in EVTX-to-MITRE-Attack, so that
library does not count as held out for it (`WRITTEN_AGAINST`). None of its rules fires on the
4103 and 800 events of the evtx-baseline machines.

The rules that flooded the clean machines were cut down without losing a recorded detection
(measured in [the noise review](reviews/2026-09-25-noise-and-held-out.md)). A rule a busy
machine matches over and over raises one finding per program per machine: a program reading
TeamViewer's or KeePass's memory, a thread started in another process, a LOLBin command line,
a suspicious script block, a Run key. A rule whose matches split by how sure they are is two
rules: a Run or RunOnce value, a hijack value or a print monitor pointing into a user folder, at
a script or a LOLBin (high) apart from one naming a program under Program Files or Windows
(low); an unsigned DLL a Windows system process loads from outside the system folder, or under a
phantom DLL's name (high), apart from one in the system folder itself (medium); a thread started
in another process at no module or at a loader routine (high) apart from one at a Windows
routine (low); msiexec installing from a URL, installing a file that is not an installer
package or registering a DLL from outside Program Files (the LOLBin rule, high) apart from a
quiet install of a local package (low); a program outside Windows reading LSASS
memory (high) apart from one Sysmon saw validly signed by a vendor other than Microsoft
(medium). The signer is the parser's: a Sysmon 8 or 10 carries `sourceSigner`, the signature
Sysmon recorded on its source process's own executable when that process started (Sysmon 7,
valid), as long as every image the log shows it loading before was signed as well. A log
without Sysmon 7 gives no signer, and the high rule applies.

## Community rule packs

The public collections ship with REMN as packs under `rules/community/`, already
converted to the rule language so both engines run them without a converter round-trip:

| pack | upstream | rules | default |
|---|---|---|---|
| `sigma-windows` | SigmaHQ `rules/` (Windows, stable and test) | 2,387 of 2,410 | on |
| `sigma-emerging-threats` | SigmaHQ `rules-emerging-threats/` (Windows) | 320 of 323 | on |
| `sigma-threat-hunting` | SigmaHQ `rules-threat-hunting/` (Windows) | 117 of 128 | off (noisy by design) |
| `sublime` | sublime-security `detection-rules/` | 189 of 1,227 | on |

Each pack directory holds the rules grouped by log source (`process_creation.yaml`,
`registry_set.yaml`, …) or by Sublime rule family, a `pack.json` manifest with the
upstream repository, the exact commit, the licence and the counts, the upstream
`LICENSE` verbatim, and `skipped.json` naming every upstream rule that was not converted
and why. A rule is skipped rather than weakened: `fieldref`, `expand` and the time-part
modifiers, any modifier outside the Sigma 2.1 list, `file_access` sources, Sublime ML
classifiers, `file.explode`, link analysis, and so on. What translates exactly is
translated: `base64`, `base64offset` and `utf16`/`wide` values become the literal strings
the encoded value can appear as (all three alignments), matched case-sensitively; `neq`
becomes a negated equality; `cased` selects the case-sensitive operators; the regex flags
`m` and `s` travel as an inline group; IPv6 CIDRs translate when they name one address or
a prefix within the first group (`::1/128`, `fe80::/10`, `fc00::/7`). The SigmaHQ rules are
redistributed under the Detection Rule License 1.1, the Sublime rules under MIT.

The Rules page lists the packs with a toggle each. `/api/meta` only carries the
manifests; a pack's rules are fetched once per session from
`GET /api/rules/packs/<id>` when it is on, so the app does not pay for 3,000 rules it
does not use. Single rules can still be switched off in the table. Analysts' pack
choices are kept in the browser.

Running 3,000 rules stays practical on both engines. The browser worker groups rules
by the event ids they pin and reads each event subset from IndexedDB once (the roughly
1,500 process-creation rules share one read of the Sysmon 1 and 4688 rows; 2,987 rules
over a 972-event PowerShell log ran in 10 s). The SQL engine runs the same set in about
90 s as a background job, 35 ms per rule including the zero-finding diagnostics. Two
DuckDB pitfalls are handled in the engine: a parameter-binding probe for pandas that
rescanned `sys.path` on every bound value when pandas is absent (50 ms per rule,
short-circuited in `casestore.py`), and list operators such as a 179-item
`contains_any` on script blocks, which are compiled to one regex alternation instead of
a chain of `lower(col) LIKE ?` (5.6 s per rule down to 0.04 s).

**Refreshing the packs**: `tools/import_community_rules.py all --download` resolves the
branch heads on GitHub, fetches those exact commits, converts them with the same code as
the import buttons and rewrites the pack directories in place (stable order, no YAML
aliases), so an update is one reviewable commit. `--zip <archive> --sha <commit>` works
offline from a downloaded archive.

**Importing other collections** ("import Sigma" and "import Sublime" in the Rules page)
converts one `.yml` or a `.zip` through `POST /api/rules/convert/sigma` and
`POST /api/rules/convert/sublime` and stores the result as custom rules. Sigma: Windows
log sources map to channel and event id (Sysmon 1 and Security 4688 for
`process_creation`, …), fields map to the parser's flattened columns (`Image` matches
both Sysmon and 4688, and "Image has no value" means neither has one), the `Data` list of
classic events (MSSQL, MsiInstaller, Windows PowerShell 800) is read from `message`, a
comparison with `-`, the Windows placeholder for "no value", is made against the EventData
value (the parser leaves the column empty for `-`), unmapped EventData fields are reachable
as `data.<Field>`, globs
become the right operator or an anchored regex, `1 of x*` and `all of them` become
`any_of` and `all_of`. Sublime: the structural subset of MQL translates (sender, subject
and header comparisons, `strings.*` and `regex.*` matchers,
`any(body.links | attachments | recipients.* | headers.reply_to)`, `length()` counts,
`$org_domains` and `$org_vips` from the case settings, the common `$lists`,
`strings.ilevenshtein` through the `levenshtein` operator, `1 of (...)`, `all()` with
negated predicates, `profile.by_sender()` through the sender-baseline columns,
`$tenant_domains`, `$org_display_names` and `$recipient_emails` through the case
settings, `$tranco_10k` through the bundled list; `$tranco_1m` is approximated with the
10,000 list, which only makes those rules fire more often, never less).

## Measured rules

A finding is only as good as the rule behind it, so every event rule, the core ones and the
packs', is measured on recorded attacks and on the logs of clean machines, and the pages say
what the measure shows. `tools/measure_rules.py` runs the rules on the SQL engine and writes
`rules/measures.json`; the server attaches each measure to the rule it was taken on. A measure
carries a hash of the rule's logic (everything but its title, description, severity,
techniques and other metadata, `backend/services/rules/measures.py`), so a rule changed since
it was measured is shown as changed rather than with a measure that is not its own.

Recorded attacks, at the versions measured:

- the SigmaHQ regression samples (SigmaHQ/sigma at `272daf82`, the commit the packs were
  converted from): 459 recordings, each made by a rule's author for that rule;
- EVTX-ATTACK-SAMPLES (`4ceed2f`): 278 recordings, with the rules reviewed as
  identifying each (`tests/fixtures/evtx-attack-samples/expected.json`);
- the Office 365 and Entra ID datasets of Splunk attack_data (`7a5e9d5`): 67
  recordings, each labelled with its ATT&CK technique. 25 more are Entra directory
  audit logs, other Azure Monitor records and Splunk search exports, which REMN does not read;
- EVTX-to-MITRE-Attack (`4748560`): 279 recordings, each labelled with the ATT&CK technique of
  the folder it is filed in. No rule was written against it before it was first measured
  ([the head-to-head](reviews/2026-09-25-head-to-head.md)); the two rules written since for
  the gaps it showed are not measured on it (`WRITTEN_AGAINST` in the tool);
- the Windows datasets of Splunk attack_data (`7a5e9d5`): 535 recordings of the event logs of
  its attack range, kept as XmlWinEventLog, each labelled with the techniques its author tested.
  No rule was written against them before they were first measured
  ([the noise review](reviews/2026-09-25-noise-and-held-out.md)); the 36 datasets larger than
  20 MB, and the 14 whose files are not at the pinned commit, are not measured.

Clean machines: the seven Windows installations of NextronSystems/evtx-baseline `v0.8.4`
(6.6 million events, 91% of them Sysmon), which SigmaHQ runs its own rules against for false
positives.

A recording is of what a rule looks for when it is the rule's own sample, a file reviewed as
identifying it, or one the rule can read (it holds the event ids, channels and fields the rule
needs) labelled with one of its techniques (the same ATT&CK v19 id, its parent or a
sub-technique). The measure of a rule says whether it fires on its own SigmaHQ sample, on
how many of the recordings of what it looks for it fires, and, on the clean machines, how many
findings it raised, how many events they cover, on how many machines, out of how many events
it reads (those of its channels and event ids with a value in every field its conditions
need, so a Microsoft 365 rule reads no Windows event). The pages read it as:

- **detects**: it fires on at least one recording of what it looks for;
- **lead**: it never did, or no recording of it was available. Its finding says where to
  look, not what happened, and the findings list, the finding panel and the report mark it;
- **misses its sample**: a SigmaHQ rule that does not fire on the sample its author recorded,
  so, as converted, it may not match what it looks for;
- **fires on clean machines**: benign activity matches it too; the finding panel gives the
  share of the events it reads that it matched;
- **changed** or **needs settings**: not measured in its current form, or it cannot run
  without a case setting a recording does not have (expected countries, internal domains).

Mail rules are calibrated on mail corpora instead (below).

At this commit, 1,023 of the 3,008 event rules fire on a recording of what they look
for and 1,985 are leads; 457 of the 457 SigmaHQ rules with a sample fire on it; on the
clean machines 170 of the 2,794 rules whose log sources they have fired at least once.
Measuring found SigmaHQ rules that could never fire (the AppX deployment channel, comparisons
with true) and PowerShell rules blind to PowerShell 7's log, since fixed in the converter.
EVTX-to-MITRE-Attack, added as a source on 2026-09-25, gave 53 leads their first recorded
attack, five of them REMN's own (AS-REP roasting, Kerberos pre-authentication brute force, audit
policy and firewall changes, the system time changed); attack_data's Windows datasets, added the
same day, gave 137, four of them REMN's own (Kerberoasting, password spraying, a suspicious DNS
query, a member added to a security group).

**Re-measuring** takes the downloads listed in the tool's docstring (about 10 GB unpacked;
`--datasets DIR --fetch` fetches them at their pinned versions) and about two hours on four cores;
re-run it after changing a rule or re-importing a pack, with `--detail rules/measures-detail.json`,
and commit both files. A backend test warns while a rule has changed since it was measured.

**The gate**: `--gate rules/measures-detail.json` measures again and fails when a rule no longer
detects a recording it detected when the committed detail was taken, a SigmaHQ rule no longer
fires on its own sample, a recording is no longer read, or a high or critical rule raises more
findings on a clean machine (all of its findings, when it was lower when measured).
`.github/workflows/measure-rules.yml` runs it weekly, on demand, and on a pull request that
touches the rules, the rule engine, the parsers or the tool, and uploads the measures it took. A
change meant to lose a detection or add noise commits those measures, so the diff of the two files
says what it changed. The weekly run also catches a new release of a dependency (the EVTX parser,
DuckDB) that changes what the rules match.

## Mail risk scoring

The 0 to 100 risk score on every mail is an investigation priority, not a probability of
compromise. The current calibration, mail-2, groups correlated observations before
scoring:

- **Strong indicators** (domain spoofing and lookalikes, display-name tricks, hidden
  text, IP-literal or credential-harvest URLs, risky attachments, gated BEC and
  credential-phishing patterns, the receiving gateway's own spam verdict) set the score
  on their own.
- **Weak signals** (urgency and finance wording, trackers, shorteners, bulk-mail headers)
  only amplify a strong indicator. Without one the score is capped at 45, and
  authenticated senders are capped lower: internal with aligned authentication at 12,
  authenticated newsletters at 20.
- Links wrapped by mail gateways (Microsoft Safe Links, Proofpoint v2 and v3,
  Mimecast, …) are unwrapped and the real destination is analysed, so protected
  corporate links do not trip text-destination-mismatch or redirect flags.
- "login", "account" or "invoice" in a URL is only a signal on an already suspicious URL;
  on a normal one it becomes the informational `login_link` flag. Microsoft Forms and
  Google Forms count as `form_saas`, not free hosting.
- The BEC and credential-phishing composite flags require sender or URL suspicion on top
  of the wording, so IT password-expiry notices and CEO newsletters stay quiet.
- Hidden marketing preheaders count as informational, not as hidden-text salting;
  click-tracker link mismatches are expected in newsletters; `.msg` and `.pst` exports
  without transport headers are not treated as forged mail.
- **Only the receiver's own verdict is believed.** That is the topmost
  `Authentication-Results`, read without its RFC 8601 comments. Lower result headers,
  `ARC-Authentication-Results` and claims in comments ("arc=pass (i=1 spf=pass dmarc=pass)")
  can all be written by the sender, and they are shown but never counted. SPF or DKIM
  passing counts as authentication only for a domain aligned with the From address: a
  pass for the attacker's own envelope domain authenticates that domain. A mail claiming
  one of the organisation's domains whose only pass is for another domain is an
  `internal_spoof`. `X-MS-Exchange-Organization-AuthAs: Internal` is ignored when the
  receiver failed the sender, since on a mailbox Exchange did not receive anyone can add it.
- **ARC forgives failures only from a sealer you trust.** arc=pass says the ARC chain is
  intact, and anyone can seal their own chain. Mailing-list forwarding is restored when the
  receiver verified the seal and the sealer is in the case's *trusted ARC sealers* (the
  internal domains always are), or when the receiver's composite verdict passed
  (`compauth=pass`, Microsoft's ARC override). The flag `arc_trusted_sealer` marks it.
- Static HTML in an archive, a normal CSV-export button, PDF JavaScript, encrypted
  content and bank-change wording remain review signals. Stronger findings require
  payload behaviour or corroborating identity, link or authentication evidence. Related
  attachment flags contribute once per family.

Mail details show the calibration version, the evidence confidence, the grouped score
drivers, the attachment risk and the analysis limitations. Findings display priority
separately from a rule's declared confidence; flags use neutral observation badges.
Confidence is qualitative and does not change with a priority escalation; rules without
declared confidence show `unspecified`.

The score bands are mirrored by rules (`mail-high-risk-score` from 60, and
`mail-critical-risk-score` from 80), so a mail the Mails page paints high or critical
always has at least one finding.

### Rescoring an existing case

After upgrading REMN, open **Mails → rescore + refresh findings** on each existing case.
It updates the chronological sender history, recalculates mail and attachment scores from
the retained facts, refreshes the score and flag facets, and reruns the enabled mail rules
with the current settings. It works on browser and server cases, preserves evidence ids
and original mail bodies, and keeps analyst status and notes for stable finding keys even
when a finding disappears and later reappears. Completed rule results replace previous
findings atomically; a failed rule keeps its previous findings. An interrupted refresh
is marked incomplete and can be retried. Server score updates roll back on failure or
cancellation; browser score updates commit in batches and may need a retry to finish.

Original attachment bytes are not stored with the analysis summaries, so rescoring reuses
retained observations: old HTML facts can be reclassified when available, missing or
skipped analysis is marked incomplete, and uncertain previous high attachment scores are
kept. Changes to parser extraction or to internal-domain lookalike detection need
re-ingestion. Custom rule overrides and enabled community packs keep their own
priorities. Analyst false-positive decisions do not train the scorer or whitelist a
sender.

### Measuring the calibration

`tools/calibrate_mail.py` runs the labelled calibration benchmark without touching a
case:

```powershell
.\.venv\Scripts\python.exe tools/calibrate_mail.py --synthetic --output calibration-results.json
.\.venv\Scripts\python.exe tools/calibrate_mail.py --manifest corpus.json --output corpus-results.json
```

The manifest supplies local EML files and reviewed labels, with paths relative to the
manifest; originals are read-only and there are no network lookups:

```json
{"settings":{"internal_domains":["company.example"]},"messages":[
  {"path":"mail/invoice.eml","label":"benign","name":"Reviewed supplier invoice"},
  {"path":"mail/phishing.eml","label":"malicious","name":"Confirmed phishing"}
]}
```

The report ranks high and critical false positives by rule and counts unique message
references separately for the core rules and the Sublime pack. Large grouped findings
cap references, so those counts can understate coverage on a large corpus. The eight
synthetic controls yield 0 of 5 benign messages at high or critical, in scores and in
core findings, while the 3 malicious controls stay high or critical. Sublime matches
none of these eight; that says nothing about that pack on a real mailbox. The browser
engine's regression fixture is generated from the same pipeline with
`--synthetic --export-fixture samples/synthetic/mail-calibration.json`. The rates
measured on public corpora are on the [validation page](validation.md).

## Sender baseline and campaigns

"Baseline senders" on the Mails page runs one pass over the case's mails, in time order,
and writes history columns that every rule and the rule language can use:
`senderPrevalence` (new, rare or common: earlier mails from the address),
`senderPriorCount`, `senderFirstSeen`, `senderDaysKnown`, `senderSolicited` (an internal
sender wrote to that address first, so its reply is expected), `senderAuthRegression`
(the domain passed SPF, DKIM or DMARC at least three times before and fails now), and
`campaignId`, `campaignSize` and `campaignSenders` (mails sharing a subject skeleton plus
link domains or attachment hashes, with the number of distinct senders behind them).
`rules/mail/baseline.yaml` uses them: first contact with a lure, unsolicited first-contact
attachment, authentication regression, campaign clusters (one finding per campaign).
Server cases are updated inside DuckDB; browser cases post the minimal rows and write
the columns back to IndexedDB (`POST /api/enrich/mails`). Sublime rules that use
`profile.by_sender().prevalence`, `.solicited` and `.days_known` translate onto these
columns.

An inbox-only export leaves prior solicitation unknown until outbound contact has been
observed. The rescore action also runs this history pass and uses established,
authenticated relationships to reduce weak anomaly scores; strong payload and deceptive
identity evidence still applies.

## Two engines, one behaviour

The browser engine lets confidential evidence be analysed without a row ever reaching
the server; the SQL engine handles gigabyte cases. They are held to the same output by a
fixture: `tools/parity_fixture.py` builds a mixed scenario (Windows events, Microsoft 365
rows, mails), runs every bundled rule on the SQL engine and records the rows and finding
keys under `tests/fixtures/parity/`; `frontend/src/rules/parity.test.ts` runs the
browser engine on the same rows and fails on any difference. Regenerate the fixture after
changing an engine or a rule, and review the diff.

The server store keeps every field the parser writes on a row (a guard test checks the
parser's field map against the store's columns; a store written before a column existed
gets it filled from the stored EventData when it is opened), and both engines compare IPv6
ranges from the case settings by prefix. Before this, 65 converted rules read a field the
store had dropped and gave other answers on the server than in the browser. Run over all
278 EVTX-ATTACK-SAMPLES files with every default and hunting rule, the two engines now
give the same findings (see `docs/reviews/2026-09-23-evtx-attack-samples.md`).

The community packs in the repository were converted before three converter fixes (`Data`,
`-`, empty checks on aliased fields) and Sysmon 25's `Type` moving to `typeName`;
`tools/migrate_community_packs.py` applied the same changes to them in place, and a test
fails if a pack still needs it. A new import makes it unnecessary.

## When a rule finds nothing

Rules pinned to event ids or channels the evidence does not contain (most of the Sigma
packs on a mail-only or Security-only case) are skipped before they run and reported as
"not applicable" on the Rules page, on both engines. After a run, the Rules page says
why every other silent rule found nothing: event ids absent from the case, empty
settings lists disarming it, everything whitelisted, below threshold. "No findings" is
always explainable.
