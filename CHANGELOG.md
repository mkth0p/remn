# Changelog

Versions follow semantic versioning; the number lives in `backend/forensic/build.py`
and a `vX.Y.Z` tag on `main` makes a GitHub release with a built archive.

## Unreleased

- An .evtx file can be parsed in the browser and never uploaded: a case kept in the browser has a
  setting, "parse .evtx files in this browser", off by default. The file is read 64 KiB chunk by
  chunk by the server's own decoder, the Rust `evtx` crate, compiled to a 259 KB WebAssembly module
  (`frontend/wasm/evtx`, rebuilt byte for byte in CI from a pinned toolchain), and flattened by a
  TypeScript port of the server's flattening that makes the same rows: every row of the golden
  corpus's five event logs and all 37,364 rows of EVTX-ATTACK-SAMPLES are identical, and so is each
  file's ledger (record ranges and holes, clock steps, chunk checksums). The evidence says "parsed
  in this browser", no size cap of the server applies, the upload notice is not shown, and the
  digest of the bytes the parser read is checked against the file's SHA-256. Hayabusa does not run
  on such a file; the rules run in the browser as for any other.
- REMN's own rules raise 200 high and critical findings on the seven clean machines of
  evtx-baseline instead of 895, and detect every recording they detected before (342 recordings,
  435 rule detections, up from 340 and 433). A rule a busy machine matches over and over raises
  one finding per program per machine (TeamViewer or KeePass memory read, remote threads, LOLBin
  command lines, suspicious script blocks, Run keys). Rules whose matches split by how sure they
  are became two: a Run or RunOnce value naming a program under Program Files or Windows is a low
  rule of its own, an unsigned DLL in System32 itself is medium, a thread started at a Windows
  routine is low while one started in no module or at a loader routine stays high (Sysmon 8's
  start module and function are read), and a quiet install of a local MSI package is low. The WMI
  persistence rule no longer fires on the SCM Event Log consumer Windows registers itself, and the
  LOLBin rule no longer takes wmic's own output formats (`/format:list`) for XSL script
  processing. See `docs/reviews/2026-09-25-noise-and-held-out.md`.
- A Sysmon 8 or 10 carries the signer of its source process (`sourceSigner`): the valid signature
  Sysmon recorded on the process's own executable when it started (Sysmon 7), as long as every
  image the log shows it loading before was signed. A program signed by a vendor other than
  Microsoft reading LSASS memory is a medium finding of its own (security products' installers
  and updaters do it); an unsigned one, one signed by Microsoft, or one whose signer the log does
  not show stays high.
- Event records exported as XML are read as event logs, into the rows the same records give from
  an `.evtx`: `wevtutil qe /f:xml`, Event Viewer's "Save All Events As" XML, Get-WinEvent's
  `ToXml()` and a SIEM's XmlWinEventLog export (Splunk's one record a line), as `.xml`, `.log` or
  `.txt`, in UTF-8 or UTF-16, alone, in an archive of event logs or in a package. They used to be
  refused as an unsupported XML schema or left unread. The 50,176 records of EVTX-ATTACK-SAMPLES
  and EVTX-to-MITRE-Attack read both ways give the same rows but for line breaks, boolean text
  and control characters XML does not allow; "where the evidence stops" says an export cannot
  show records deleted before it was made.
- Host lineage reads WMI and WinRM lateral movement (a program started by WmiPrvSE or the WinRM
  plug-in host tied to the network logon before it, WinRM 91 on the target, `wmic /node:`,
  `Invoke-Command -ComputerName`, `Enter-PSSession`, `winrs -r:` and WinRM 6 on the source, WMI
  queries a remote host refused), attributes addresses to hosts from DNS answers (Sysmon 22) and
  DHCP leases with the time span of each, and places an Entra sign-in on the host of its device's
  name. The DHCP server's audit log (`DhcpSrvLog-*.log`) is read as a collection artifact, its
  local times kept without a zone.
- The rules are measured on a second library they were not written for: the 535 Windows datasets
  of Splunk attack_data (785,361 events, 226 ATT&CK techniques), which REMN reads now. By default
  REMN detects 227 of them (42%) at medium level and above, 33 of those through its own rules
  alone; a finding its technique and level do not explain is not counted. 137 rules that no
  recording showed detecting before, four of them REMN's own, have their first.
- `tools/measure_rules.py --gate rules/measures-detail.json` fails when a rule stops detecting a
  recording it detected, a SigmaHQ rule stops firing on its own sample, a recording is no longer
  read, or a high or critical rule raises more findings on a clean machine;
  `.github/workflows/measure-rules.yml` runs it weekly, on demand and on a pull request that
  changes the rules, the rule engine or the parsers. `--datasets DIR --fetch` fetches every
  dataset at its pinned version, and `--detail` writes what each rule detects, recording by
  recording (`rules/measures-detail.json`, committed with `rules/measures.json`).

- Stories replace the Chains and Relationships pages: the case reads as one story per person,
  or per host when its records name no one, and per incident, along ATT&CK's phases. A story
  starts from a finding of medium severity or more or a phishing chain; a mail received or a
  failed logon joins its person's story, or its campaign. Each step says why it belongs and how
  surely (flagged, phishing chain, same session, same way in, process tree, same source, same
  person), each finding carries its rule's measure, routine runs fold, and each story lists what
  its hosts' evidence cannot show. A phishing chain starts a story only when its recipient acted
  on the mail (the link resolved, the attachment saved, a reply). An identity resolver joins the forms an account goes by
  (address, NetBIOS form, SID, Entra object id, distinguished name, bare name) with a confidence
  per join, never across organisations, and names namesakes, renamed machine accounts and bare
  names several accounts share. Host lineage reads logon sessions, hops (RDP, admin shares and
  execution pipes, the service installed after them, explicit credentials, connections to
  remote-access ports) and process trees from Sysmon and 4688. Campaigns group the stories that
  share an attacker's addresses, sender and link domains, attachments, forwarding addresses or
  consented applications, with the other accounts the same sources reached. An analyst's note on
  a story is checked against the story's records, and the report prints the stories above its
  floor, with their notes, before the chains. Explore keeps the relationship graph and its
  link reviews, and a story step shows the links of its own records. On the synthetic lab each
  of the five planted attacks is one story holding all its planted records, and the controls stay
  out. Server cases select their rows by SQL, browser cases post them to `POST /api/stories/build`.
  See `docs/stories.md`.
- A domain whose suffix is not on the public suffix list (`.example`, `.local`, `.lan`,
  `.internal`) keeps its last two labels as its registrable domain instead of the bare suffix:
  every `.example` sender used to count as the organisation's own, reply-to and Message-ID
  mismatches between two such domains went unnoticed, and a phishing chain matched the link
  domain "example" in every host name. The lab's golden corpus is frozen again with the fix.
- A phishing chain no longer takes a visit to the recipient's own organisation (the intranet
  portal a supplier invoice links to) for a click on the mail when the case settings name no
  internal domain: the domains of the mail's own recipients are not artifacts either. On the
  lab read without internal domains, 38 chains of benign mails whose reply-to goes to a
  supplier were made of such visits.
- A report or note sentence that ends with an IP address ("…from 198.51.100.77.") has that
  address checked against the rows, as one in the middle of a sentence was.

- The AI analyst is an investigator: it plans, runs up to 40 rounds of tools on its own
  (24 by default), keeps a hypothesis board, runs seven playbooks from one click (phishing
  to compromise, password guessing, lateral movement, persistence, Microsoft 365 account
  takeover, ransomware precursors, credential theft), and answers with citations checked
  against the rows its tools returned, as chips that open them. New tools read exact
  counts, a finding with its rows, process trees, logon sessions, indicators, case notes,
  field values, the rule library, and test a draft rule on the case without saving it.
  Everything it would change (review decisions, notes and timeline entries, row marks,
  rules, the executive summary) waits in an approval inbox until the analyst accepts it,
  and an accepted proposal can be undone. Every run, tool call, proposal and decision goes
  to a hash-chained AI ledger that travels with the case, and the report says how AI was
  used. Evidence text addressed to a model is flagged before the model reads it and marks
  what the run proposes afterwards. A long investigation keeps the question and its newest
  turns, compacting older results, where the transports used to drop the newest messages.
  LM Studio, llama.cpp, vLLM and Jan work as local model servers through their
  OpenAI-compatible API, and only local addresses are accepted. A chain decision word on
  an incident ("confirmed") is now applied as its meaning (escalated) instead of
  "reviewed"; chain narratives and relationship reviews get their own prompts; a drafted
  executive summary records that a model wrote it and when; the model's regular
  expressions run off the page's thread with a time limit. See `docs/ai.md`.
- A public instance that can take real cases: bounded decompression (bz2, xz, zip members),
  message size, YAML aliases, JSON bodies and heavy requests in flight (overall, per client,
  per IPv6 /64); cleanup when a client disconnects; logs without evidence text, rotated; every
  archive member listed as read, skipped or failed; the build commit and its source link in
  health, in every parse and in the app; a notice before the first upload that says where the
  file goes and what the server keeps. See `docs/security.md` and the review in
  `docs/reviews/2026-09-22-browser-only-analysis.md`.
- Evidence read as it is: collections over 32 MiB, Velociraptor results, raw 8-bit mail
  headers, the Sysmon PE description, command lines and script blocks up to 64 KiB, artifact
  times that mean activity, Microsoft 365 IPv6 addresses, culture dates, Graph pages, Outlook
  inbox rules, MFA prompts that are not failures, and mail authentication that believes only
  the receiver (trusted ARC sealers are a case setting).
- Microsoft 365 records once and joined: a UAL record or Graph sign-in exported twice (large-set
  pages, overlapping slices, an earlier export) is added once and the repeat is counted; sign-ins
  keep their session, token, protocol, method and conditional-access fields; the messages
  MailItemsAccessed read, or a delete moved, are named and open in the mailbox evidence.
- An import cut short by a closed or crashed tab no longer leaves rows that count twice: the
  next start removes them and the evidence says the import stopped; leaving the page while an
  import runs asks first.
- A password-guessing campaign against the person a phish reached joins that person's chain,
  whichever spelling the logs use for the account, before the rules run as after: the linked
  lab reads to its five planted chains either way.
- The public profile serves the app from Caddy's own image and sends only `/api/*` to the
  parser, and an update validates the new proxy before it replaces the running one.
- Browser-store searches, counts, timelines and pivots run in query workers and stop when
  their answer is no longer wanted, so a large case no longer freezes the page.
- A file dropped before the server has answered no longer goes out without the notice: a page
  on another host asks first until it knows what an upload there means.
- A demo case: the synthetic lab as the app reads it, with its findings and five chains,
  opens from the Dashboard in the visitor's browser without uploading anything.
- A golden corpus: what the parsers make of the synthetic lab is frozen row by row, so a parser
  change that alters rows fails with the rows it changed.
- The two rule engines agree on real attack logs: the server store keeps every field the
  parser writes (65 converted rules read one it used to drop), both engines compare IPv6
  ranges by prefix, access rights are named after their codes, an older log gets its
  parent's user or image from the parent's own event, and the converted Sigma rules read
  classic `Data`, `-` placeholders and aliased empty checks as their authors meant.
- Core Windows rules that could not fire now do: four process rules read Sysmon's `image`,
  the BITS rule no longer excludes every record, credential dumping covers PowerShell and
  other script hosts, service keys are no longer Run-key persistence but a rule of their
  own, process access by a LOLBin has a rule, and the print spooler DLL tricks are caught.
- Windows detection measured and extended on EVTX-ATTACK-SAMPLES (278 logs, one attack each):
  75 new core rules for what the packs missed (Security-channel tricks, the channels no rule
  read, bursts and sequences, registry keys, DLL loads, parent-child pairs), taking the samples
  detected from 171 to 269; a CI job fails when a sample's detection stops firing or the two
  engines disagree on any sample.
- A report and a case that hold: times in UTC, a verdict over the whole case, confidence that
  falls when a file was not read in full or the rules are behind, a valid STIX export, AI
  triage that proposes rather than decides, bundles that carry their rules, and search that
  agrees with the SQL engine.

- Optional Records Continuity honeypot: isolated Unix-socket service, signed ARG
  reference trail, consented exercise, bounded private telemetry/replay and REMN
  package import with episode/exhibit relationships. Includes deployment and
  network/routing verification; see `docs/honeypot.md`.

- Native Prefetch/REGF/CAB adapters, task XML, CLIXML and text exports; nested packages
  share import limits, collection counts/hashes reconcile, and duplicate sources skip.
- Collection detection rules, explicit entity aliases, conservative process snapshot
  resolution, paginated relationship graphs, related evidence timelines and saved
  link decisions/notes included in reports and case backups.

- Mixed investigation-package ingestion in browser and server storage, with member
  hashes, explicit partial coverage and CSV/JSON host collection adapters. Folder
  imports preserve relative paths; snapshots retain their own record type and time.
- Relationships explores entities across the evidence without requiring a mail seed,
  with source references and explicit graph limits. See `docs/packages.md` for coverage.

- Browser-only mode (`FORENSIC_BROWSER_ONLY=1`) for an instance open to strangers: the
  server parses and returns rows and keeps nothing; server stores, jobs, chunked uploads,
  reputation lookups and the server-side model transports answer 403, health reports the
  mode without paths or platform details, and the interface hides what is not there. A
  per-address budget on the heavy paths (`FORENSIC_RATE_LIMIT_PER_MIN`, off by default) and
  `FORENSIC_TRUST_PROXY` for the client address behind a proxy. `docker-compose.public.yml`
  runs it behind Caddy with automatic HTTPS. Listing every server store now needs a
  configured access token; a case reaches its store by its key.
- Mail-led chains keep full recipient identities through deduplication; foreign bare aliases
  cannot bypass realm checks and duplicate account fields no longer duplicate event steps.
- Authentication campaigns can start from Windows or Entra events alone: ten failures in
  thirty minutes, medium without a later success and high with one. Event navigation and
  reports retain the seed's source. Analysis-limit warnings persist in results and reports.
- Case backups stream to disk as checksummed `.remn.ndjson`, include case-owned review,
  chain, report and AI state, verify before import, remap row references and roll back failed
  restores. Legacy browser JSON bundles remain readable. Legacy server bundles without row
  IDs are rejected explicitly because their investigation links cannot be recovered safely.
- Browser-to-server migration stages rows with original IDs, keeps findings and reviews,
  and switches storage only after transfer completes. Failed transfers retain the browser case.
- Added modern synthetic mail holdout checks for scores and rule packs, and a production
  browser upload/review/export/restore regression. Releases now require the full CI workflow.
- Settings has a "delete this case" button next to "delete all case data". The first removes
  the case itself (server store, browser records, custom rules, settings) and switches to the
  most recently updated remaining case, or a fresh one; the second empties the case and keeps it.
- Fixed: on the development server a fresh browser got two "Case 1" cases, because React
  runs the boot effect twice there and both runs saw an empty case table. The default case
  is now created inside one transaction.
- Compose takes `REMN_BIND`, `REMN_HOSTS` and `REMN_TOKEN` to publish the container on a
  network; `REMN_HOSTS='*'` switches the host check off. `docker-compose.open.yml` is the
  behind-a-proxy configuration in one file (full build, no checks, port 8300 on loopback),
  with `deploy/apache-remn.conf` as the matching virtual host.
- Fixed: a mail tied to both a malicious and a suspicious indicator was marked `suspicious`
  in server cases, because the worst verdict was the alphabetical maximum of the labels.
  Verdicts are now ranked malicious, suspicious, clean.
- Reputation lookups honour their deadline: calls still queued when it passes are cancelled
  and reported with the verdict `timeout`, instead of running on after the answer was sent.
- Fixed: Unified Audit Log records from the Graph audit log query (Microsoft-Extractor-Suite
  `Get-UALGraph`), which carry the record under `auditData`, were recognised and then gave no
  row. They are read, and a record that omits its time, operation, user, IP or workload takes
  them from the Graph envelope.
- REMN's own rules use ATT&CK v19 technique ids, as the SigmaHQ packs already did: v19 (April
  2026) revoked `T1562.x`, `T1070.001` and `T1656` for `T1685` to `T1690` and `T1684.x`, and 22
  core rules still carried the old ones. Fixed with it: the report's defense-evasion badge knew
  only the old ids, so the 137 SigmaHQ rules tagged `T1685` lit no badge.
- Fixed: the Sigma converter, used for the SigmaHQ packs and for rules imported in the Rules
  view, turned `|neq` into its opposite and ignored `|cased` and the regex flags `m` and `s`.
  They now keep their meaning. A rule with a modifier outside the Sigma 2.1 list, or with
  `fieldref`, `expand` or a time-part modifier, is skipped instead of converted without it.
  `base64`, `base64offset`, `utf16`, `utf16le`, `utf16be` and `wide` are translated into the
  strings the encoded value can appear as, and IPv6 CIDRs of one address or of a first-group
  prefix (`fe80::/10`) into text conditions. The SigmaHQ packs, re-imported at the same
  upstream commit, gain 28 rules; no existing rule changes. The `smbserver-connectivity` log
  source maps to its channel, so the one new rule on it can fire.
- Fixed: behind the public profile's Caddy, a path naming a file that is not there got the app
  page. `robots.txt` answered 200 with the page, and a missing script under `/assets/`, such as
  a chunk of an earlier build, came back as the page with a one-year immutable cache header.
  Those are 404s now; a path that names no file still gets the page. CI checks both.
- Fixed: in Relationships, an open link could turn into another link under the analyst's hands.
  Saving a review, or new findings, rebuilds the stories, and a rebuild can list a story's links
  in another order; the open panel, with its form, stayed at its place in the list and showed
  whichever link moved there. It now stays with its link.
- The report says what the evidence cannot show, first under "Where it stops": records
  missing from an event log's numbering, write times that step back where no clock change or
  restart explains it, clocks set back, chunks that fail
  the EVTX checksum (a record changed after Windows wrote it), record numbers in none of the
  files of one log, logs that start after the first finding, Unified Audit Log exports cut
  at 5,000 or 50,000 records, throttled MailItemsAccessed, and Entra sign-ins that start
  after the first finding. The parser records each file's numbering and checksums; the
  Evidence page marks a file with such a gap and lists what it cannot show.
- Fixed: an event with no TimeCreated took no time from its record header, because the
  header's time ends in " UTC", which the time parser did not read.
- Entra sign-ins exported through Azure Monitor (the diagnostic settings' Log Analytics,
  Event Hub or storage account records, the sign-in under `properties`) are read. Such a file
  was taken for an event log and failed; a record of another category, such as `AuditLogs`,
  is counted as not read.
- Fixed: SigmaHQ rules that could never fire. The 10 AppX deployment rules read a channel
  named after the provider (`appxdeployment-server`), where Windows writes
  `Microsoft-Windows-AppXDeploymentServer/Operational`; the 4 rules that compare a field with
  `true` compared it with `1`, where Windows writes "true" (Sysmon's `Signed` and
  `Initiated`, the AppX `HasFullTrust`). The 212 PowerShell rules now read PowerShell 7's
  `PowerShellCore/Operational` as well as Windows PowerShell's log, and the 6 DNS client
  rules also match the channel's display name. Each log source now maps to the channel
  SigmaHQ's own regression tests use (`tests/thor.yml`); measuring the rules on their SigmaHQ
  samples found the gaps.
- Fixed: a Unified Audit Log export whose records have their keys in alphabetical order, as
  Splunk's Microsoft 365 add-on and some exporters write them, was taken for an event log and
  failed: the format was told from the first 512 bytes, and such a record names its Operation
  past them. The first 64 KB are read, alone, in an archive or in a package. 13 of Splunk
  attack_data's Office 365 datasets were unreadable for it.
- Every event rule is measured on recorded attacks and on the logs of clean machines, and the
  pages say what the measure shows. `tools/measure_rules.py` runs the rules on the SigmaHQ
  regression samples, EVTX-ATTACK-SAMPLES and Splunk attack_data's Office 365 and Entra ID
  datasets, and on the seven Windows machines of NextronSystems' evtx-baseline, and writes
  `rules/measures.json`, which the server attaches to the rule it was taken on (a rule changed
  since is shown as changed). A rule that fires on a recording of what it looks for detects
  it; one never seen to is a lead, and its findings are marked "lead" in the findings list,
  the finding panel and the report. The Rules page has a "measured" column and filters the
  leads, the rules that miss their own SigmaHQ sample and those that fire on clean machines;
  the finding panel says what the rule's measure shows; the report's method says how many of
  the rules behind its findings detect recorded attacks. At this commit 830 of the
  2,998 event rules detect a recorded attack of what they look for (REMN's own Windows
  rules: 112 of 133), all 457 SigmaHQ rules with a regression sample fire on
  it, and 167 fire on the clean machines. See `docs/reviews/2026-09-24-measured-rules.md`.
- What the report says about rows is read back against the rows before it prints. Each
  printed finding's rows (the first 50) must still be in the case, match its rule as the
  rule is now, hold the values it names and begin at its time; a chain narrative or an
  incident note must name only addresses, accounts and hashes its own rows hold; the
  executive summary only values the evidence holds. Each rule's line in the report says "rows
  checked", "rows missing" or "rows disagree" and names its first row by its place in its own
  file (an event log's record number with its computer and channel, a mailbox's message
  number, a cloud record's id), which stays the same when evidence is removed and added again
  or the case is imported elsewhere, where REMN's row ids do not. A claim that does not hold
  is listed under "Where it stops" and on the Report page, and a new preflight check keeps
  the report a draft until they all hold or the analyst waives it. The 129 findings of the
  demo case all hold, and a tampered copy of its rows does not. The AI analyst's answers are
  read the same way: each sentence that cites rows is checked against those rows, not only
  against what the tools returned, and one that names what they do not hold is listed under
  the answer.
- `tools/head_to_head.py` scores REMN, Hayabusa and Chainsaw on a library of recorded
  attacks by the ATT&CK technique each file records, at the same level cut for all three,
  and counts their false alarms on clean machines. On EVTX-to-MITRE-Attack, which REMN's
  rules were not written against (8 of Hayabusa's rules and 2 of SigmaHQ's cite it), REMN
  detects 109 of 279 recorded attacks at medium level and above (39%, where it detects 97%
  of EVTX-ATTACK-SAMPLES), Hayabusa 86 and Chainsaw 52; on seven clean machines it raises
  about four times as many high and critical alerts as either, most from its own rules. See
  `docs/reviews/2026-09-25-head-to-head.md`.
- The critical credential-dumping rule keeps only near-certain evidence (dumping tools and
  commands, ntds.dit and SAM copies): a program reading LSASS memory is its own high rule,
  one finding per program per machine, which leaves out the query-only access that cannot
  read memory and treats SysWOW64 as System32, and an LSA package that is not signed as
  expected its own medium rule, with Windows' own packages left out. On the seven clean
  machines the critical rule went from 2,504 matches to none and REMN's critical events from
  2,589 to 85, while every attack sample the old rule identified is still found.
- Two rules close the gaps the head-to-head found: a member added to a security group other
  than the privileged ones (medium), and a logon with explicit credentials from PowerShell,
  WMIC, a script host, a LOLBin or a program outside the Windows and Program Files folders
  (high), which catches RunasCs. Neither fires on the clean machines.
- Rules are measured on EVTX-to-MITRE-Attack too: 279 recorded attacks, each labelled with
  its technique, that no rule was written against, so a rule's "detects" can rest on attacks
  it was not written for. 885 of the 3,002 event rules now detect a recorded attack (830),
  and 53 leads, five of REMN's own among them, have their first. A rule written after
  studying a dataset is not measured on it, nor scored on it by `tools/head_to_head.py`.

## 0.1.1 (2026-09-07)

- Fixed: an account with the same name in another organisation
  (`alice@other-tenant.example`, `OTHER\alice`) joined `alice@northstar.example`'s
  attack chain and could even become its label. Identities now carry the domain or
  Windows domain they were seen in, and only accounts of the recipient's organisation
  join; the synthetic lab's cross-tenant decoy is now an assertion of the validator.
- The chain builder considers at most 50,000 events inside the window; it now says so
  on the Chains page when the cap is hit instead of silently cutting the window.

- Fixed: with the built frontend served by the Python API (run.py, Docker), every upload
  failed and a failed row could not be removed. The middleware put the API's closed policy
  (`default-src 'none'; sandbox`) on script assets too, and a web worker takes its policy
  from its own script's response, so the hashing and ingest workers could neither compile
  WebAssembly nor reach the API or the browser database. Scripts now carry the page's
  policy; a test pins both. Because the files are served immutable, a browser that loaded
  the earlier build would keep the old header in its cache, so every build now gets its
  own file names and a rebuilt server reaches every browser without a cache clear.
- Fixed: served by the Python API, a request for a missing file such as `favicon.ico` got
  the page instead of a 404, which browsers showed as a blank tab icon. The app now has a
  tab icon (the sidebar's mark, generated by `frontend/tools/make_icons.py`), and a
  file-like path that does not exist is a 404.
- Docker image hardening after a scan: base images pinned by digest and bumped by
  dependabot within Python 3.13 and Node 22, Debian security updates applied at build
  time, pip removed from the runtime image (extras go in through `--build-arg EXTRA_PIP`),
  and a CI job that builds, runs and Trivy-scans the image, failing on critical or high
  findings that have a fix. The compose file takes the host port from `REMN_PORT`.
- Docker full build: Python packages are installed in a build stage with a compiler and
  copied into the runtime image, so `--build-arg EXTRA_PIP="yara-python libpff-python"`
  (or `REMN_EXTRA_PIP` with compose) gives a container with PST and YARA support.

## 0.1.0 (2026-09-07)

The first tagged state of the tool.

- Repository scaffolding: Apache-2.0 licence and third-party notices, CI on every push
  (pytest, ruff, typecheck, ESLint, Prettier, vitest, build, bundle budget), release
  workflow, ruff and ESLint/Prettier configuration with pre-commit hooks, documentation
  split into `docs/`, contributing and security policies, a Dockerfile and compose file.
- Evidence text is framed as data on every path the model reads it; the synthetic lab
  carries a prompt-injection control (S07); the tag, reason, snapshot and undo around a
  model decision are covered by tests.
- Ingestion of Windows event logs (EVTX, archives), mailboxes (PST/OST, mbox, eml, msg)
  and Microsoft 365 audit and Entra sign-in exports; SHA-256 chain of custody; browser
  (IndexedDB) and server (DuckDB) stores; chunked resumable uploads and background jobs.
- Search with facets, filter DSL, regex, time and business-hours filters, entity pages,
  pivots, timeline, indicators with opt-in reputation lookups, STIX and CSV export.
- Detection: YAML rule DSL with two engines kept in parity, community packs (SigmaHQ,
  Sublime Security), mail risk scoring calibrated on public corpora, sender baseline
  and campaign clustering, applicability checks.
- Attack chains across mail, identity, Microsoft 365 and host activity, with scoring,
  a story view and a swimlane graph.
- Review workflow: chains and incidents in order, verdicts, rescoring, notes, narratives,
  report inclusion, unlinking chain members, model proposals and an undoable AI triage.
- AI analyst over the case through tools, with three transports: browser-direct Ollama,
  server proxy, Claude Code on the server machine.
- Printed report in REMN's own look, one self-contained HTML file, print-to-PDF.
- Security model: content security policy, sandboxed previews, no external access from
  the store, shared-token remote mode.
