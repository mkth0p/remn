# Changelog

Versions follow semantic versioning; the number lives in `backend/forensic/build.py`
and a `vX.Y.Z` tag on `main` makes a GitHub release with a built archive.

## Unreleased

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
