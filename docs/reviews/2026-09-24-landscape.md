# The tool landscape against the REMN 2.0 plan

24 September 2026. Branch `browser-only-mode`, from `51144f6`. This review sets the
[2.0 plan](2026-09-24-remn-2.0-plan.md) against the tools incident responders use or could
use today, and against what changed in the field in 2025 and 2026. It does not repeat the plan
or the [browser-only analysis](2026-09-22-browser-only-analysis.md); it says what the landscape
confirms, what it contradicts, and what it adds, release by release.

## 0. How this was done

Six research passes, one per area: Windows event logs and Sigma, mail and phishing, Microsoft 365
and Entra, DFIR platforms and case tools, AI in DFIR and SOC tools, and detection engineering with
its test data. Each fact was taken from the live source on 24 September 2026: GitHub repositories
and release feeds, PyPI, official documentation, and vendor or Microsoft blogs. Sites the sandbox
could not reach were read through their GitHub sources where possible.

- **(search)** marks a fact seen only in search-result text for the cited page.
- **(vendor)** marks a vendor's claim about its own product.
- Everything said about REMN was checked in the code of this branch.
- Checked directly for this document, in the sources themselves: MITRE's ATT&CK v19 crosswalk,
  the pyevtx-rs changelog, SigmaHQ at commit `272daf82` (the packs' upstream),
  EVTX-ATTACK-SAMPLES at `4ceed2f`, the property names Microsoft-Analyzer-Suite reads from
  Outlook inbox rules, EvtxECmd's `--tdt` code, the Invictus dataset's README, the
  `evtx-baseline` README, and the Office 365 and Azure AD dataset counts and Git LFS setup of
  Splunk's `attack_data`.

## 1. Bottom line

**The plan's direction is where the field is going.**
- Fast EVTX tooling moved to columns: Takajo made DuckDB its default in 2.16 (4 to 24 times
  faster, about 7 times smaller), EventHawk runs Arrow and DuckDB past 10 million events, and
  Zircolite 4.0 puts a literal prefilter in front of SQL. R1 and R2 follow the same road in the
  browser.
- The decoder R1 needs already runs in a page: the Rust `evtx` crate ships a WebAssembly explorer.
- AI investigation tools converge on what REMN has and R6 extends:
  - answers tied to evidence: Timesketch's investigation agent links its questions and
    conclusions to events, as Magnet's Intelligent Insights and Nuix's AI Chat do (search);
  - approval before anything counts: Valhuntir, Tracecat 1.0;
  - an append-only record of the model's work: Valhuntir's JSONL files, Protocol SIFT's audit
    hook.
- MCP became the integration layer of DFIR tools in 2026: Autopsy 4.23, Timesketch, TheHive,
  Cyber Triage 3.17 and 3.18 (search) and the XDR vendors all ship servers.

**One claim needs care.** Section 3.1 of the plan says no professional DFIR tool runs a full
case from a web page without a server or an install. Two tools come close:
- **LUMEN** (MIT, created November 2025, active through August 2026) parses EVTX in WebAssembly,
  runs Sigma and a model in the browser, and builds "storylines".
- **APT-Hunter V4.0** (GPL-3.0, 20 September 2026) has a web dashboard, attack chains on an
  incident timeline, local-model scoring, agentic triage and Word reports.

What neither does is REMN's combination: every record of a 15 GB collection kept, Microsoft 365
and mail beside Windows, one story per person with its gaps named, a report that carries its
proof, and a case that can be handed over. The claim should name that combination.

**What the landscape adds to the plan** (section 3 lists them with effort):
1. Microsoft 365 rules have no independent test set. Windows rules are measured on
   EVTX-ATTACK-SAMPLES; Microsoft 365 rules only on data REMN wrote (the lab, the parity
   fixture). R5's exit, "no default rule without a measured sample", needs more: Splunk's
   `attack_data` has 52 Office 365 datasets and about 35 Azure AD ones, each labelled by technique.
2. The Unified Audit Log truncates silently (5,000 records a call, 50,000 at most). A collection
   window holding exactly one of those counts is a gap the completeness ledger should name.
3. SigmaHQ ships per-rule ground truth: about 433 regression tests with an expected match count,
   and a false-positive run on a published benign baseline. Both feed R5's measured detection.
4. ATT&CK v19 (April 2026) revoked technique ids REMN's own rules used; fixed with this review.
5. The ATT&CK Navigator layer is the one common deliverable missing from R4's list.

**Found and fixed on the way** (section 4):
- the worst reputation verdict was ranked alphabetically;
- the lookup deadline did not stop queued calls;
- Graph audit exports gave no rows;
- the Sigma converter, which also converts the analyst's own rules in the Rules view, turned
  `|neq` into its opposite and ignored `|cased` and the regex flags (no rule in the packs used
  them yet);
- the report's threat profile missed every SigmaHQ finding tagged with the new Defense
  Impairment ids.

## 2. The landscape, release by release

### R1: EVTX in the browser

- **The decoder.** pyevtx-rs 0.13.0 (22 September 2026) moved to the Rust `evtx` 0.12.3 parser,
  "including faster record rendering and malformed-input handling fixes"; 0.13.1 is on PyPI.
  `backend/requirements.txt` still allows `evtx>=0.12.1`, so an existing environment can keep
  the parser without those fixes. The crate and its Python binding also offer checksum
  validation (`validate_checksums`), a WEVT template cache and basic record recovery.
- **Prior art in the browser.** The `evtx` crate's WebAssembly explorer (files stay local) and
  LUMEN (section 1).
- **Prior art for the completeness ledger (1b).**
  - Chainsaw 2.15 `analyse gaps`: EventRecordID and time gaps per channel, reported as possible
    selective deletion.
  - Timesketch's EVTX gap analyzer: record-number gaps and low-volume days, written as a Story.
  - Hayabusa 3.7 `--validate-checksums`.
  - EvtxECmd `--tdt`: a warning when a record's time runs backwards from the record before it
    by more than a threshold (one second by default), the trace of a clock change.
- **Duplicates.** Volume shadow copies and overlapping exports hold the same records twice.
  EvtxECmd has `--vss --dedupe`, Hayabusa `--remove-duplicate-detections`. REMN drops a
  Microsoft 365 record read twice (`recordKey`, cloud exports only) but keeps both copies of an
  EVTX record. R4's record key does not change that: it includes the file's SHA-256, so the live
  log and its shadow copy give two keys. A second key without the file (computer, channel,
  EventRecordID, time) finds the copies.

### R2: the 15 GB case

- **Speed references for the exit targets.**
  - Zircolite 4.0.0 (20 September 2026, self-reported): 452,554 events against 4,319 rules in
    11.6 s on an M1 Max, "2.1 times faster than Hayabusa 4.1.0 and 9.8 times faster than
    Chainsaw 2.16.0".
  - Takajo 2.16 on DuckDB and EventHawk on Arrow and DuckDB (section 1).
- **Collection containers** the plan names in R2:
  - Velociraptor 0.77 offline collectors write a ZIP with `uploads/auto` and `uploads/ntfs`,
    `results/`, `uploads.json` with each file's hashes, `client_info.json`,
    `collection_context.json` and `log.json`, optionally encrypted with X.509 or PGP.
  - KAPE writes a drive-letter tree to a folder, a ZIP or a VHDX.
  - UAC 3.4 writes a tar.gz or a zip with an acquisition log that holds hashes.
  The collector's own hashes can be checked against REMN's SHA-256 and both written into the
  chain of custody.

### R3: Microsoft 365 in the browser

- **Parser coverage.** This branch already keeps the sign-in session, token, protocol and transfer
  fields, reads Outlook-made inbox rules, and links MailItemsAccessed and deletions to message ids.
  One source was still dropped: records from the Graph audit log query, which Microsoft recommends
  over `Search-UnifiedAuditLog` and Microsoft-Extractor-Suite writes with `Get-UALGraph`. Fixed
  with this review.
- **Completeness (1b for Microsoft 365).**
  - `Search-UnifiedAuditLog` returns 5,000 records a call, 50,000 with `ReturnLargeSet`, and now
    reports `MoreRecordsAvailable`. Microsoft-Extractor-Suite 4.1.0 rebuilt `Get-UAL` around the
    5,000 cap after a change on Microsoft's side (MC1310672 (search)).
  - More than 1,000 MailItemsAccessed Bind records in 24 hours pause Bind logging for 24 hours and
    set `IsThrottled`.
  - Entra keeps sign-in logs for 7 days without a P1 or P2 licence and 30 days with one, often
    less than the incident window.
  Each of these is a gap to name in "Where it stops".
- **Tradecraft of 2025 and 2026** the rules should know:
  - Device-code phishing sold as a service. Tycoon2FA's operators are reported to have moved to
    it after the kit's takedown in March 2026, and the EvilTokens service to have reached about
    12,000 inboxes (search). This branch detects device-code sign-ins in the parser.
  - The Microsoft Authentication Broker (`29d9ed98-a469-4536-ade2-f981bc1d605e`) requesting the
    Device Registration Service, as in Storm-2372.
  - Tool user agents on sign-ins: `axios`, `node-fetch`, `undici`, `aiohttp`, `python`,
    `go-http-client`, `okhttp`, `curl`, `aadinternals`, among others.
  - One session id seen from several IPs or networks: Microsoft's linkable identifiers (session id
    and unique token id) now appear in sign-ins, Exchange and SharePoint audit records and Graph
    activity logs.
  Elastic's detection rules cover several of these, but they are under the Elastic License 2.0:
  reimplement the logic, do not copy the rules.
- **Reference data with compatible licences:** `merill/microsoft-info` (MIT, first-party app ids,
  updated daily), `huntresslabs/rogueapps` (MPL-2.0, ship as a separate file),
  `brianhama/bad-asn-list` (MIT).
- **Test data:**
  - Splunk `attack_data` (Apache-2.0; the logs are in Git LFS, so a harness fetches only the
    folders it needs): 52 Office 365 datasets and about 35 Azure AD ones, filed by technique.
  - The Invictus `o365_dataset` (CC BY 4.0): 9,608 Unified Audit Log records from real BEC
    intrusions, unlabelled. `tools/validate_public.py` already downloads it, as a parser smoke
    test only.
  - OTRF's GoldenSAML scenario.

### R4: the defensible record and the deliverables

Formats checked on 24 September 2026:

| Deliverable | Current version | What it needs |
|---|---|---|
| Timesketch timeline | Timesketch 20260630 | JSONL or CSV with `message`, `datetime` (ISO 8601) and `timestamp_desc`; other columns kept |
| Timeline Explorer | CSV | any columns; EvtxECmd's column names are the ones analysts expect |
| Plaso | 20260720 | `json_line`: `date_time`, `timestamp`, `timestamp_desc`, `message`, `parser`, `data_type`, `display_name`, `hostname`, `username`, `tag`, `pathspec` |
| STIX | 2.1 (`stix2` 3.0.2) | the existing export, with the analyst's verdicts |
| MISP | core format, IETF draft 16; MISP 2.5.47 | events, attributes, objects, tags |
| **ATT&CK Navigator layer** | layer format 4.5; Navigator 5.3.2; ATT&CK v19.2 | `name`, `domain`, `versions.layer: "4.5"`, and per technique `techniqueID`, `score`, `comment`, `links` |
| CASE/UCO (optional) | CASE 1.5.0 | JSON-LD for custody and provenance |

The Navigator layer is the ATT&CK exchange format between tools and teams: Takajo, Zircolite,
sigma-cli and mulder all write one. REMN has the data already (the counts on the findings
view's ATT&CK tab). The journal (2b) has open-source precedents worth reading:
- Valhuntir (MIT): findings are drafts until the examiner approves them, approvals are signed with
  HMAC, and actions, evidence access and approvals are append-only JSONL files.
- DFIR-IRIS activity reports and AiSOC's investigation ledger.

### R5: the story, at scale

- **Host lineage (3e)** as the other tools build it:
  - logon sessions: Takajo `timeline-logon`, Hayabusa `logon-summary` (RDP 4778/4779 since 4.0),
    Timesketch's sessionizers (4624 and 4778 to 4634, 4647 and 4779);
  - process trees: Takajo `sysmon-process-tree`;
  - PowerShell 4104 reassembly: Takajo `extract-scriptblocks`;
  - lateral movement: LogonTracer 2.0 (BSD-3, April 2026).
- **Stacking (5c):** Takajo's nine `stack-*` commands (command lines, computers, DNS, IPs,
  logons, processes, services, tasks, users) are the reference set.
- **"What the evidence cannot tell" (1e):** WELA (MIT) checks a host's audit policy against which
  Sigma rules could fire; the same mapping, run on the channels and event ids a case holds, gives
  the statement.
- **Measured detection (4a, 4b):**
  - SigmaHQ `regression_data`: about 433 tests, each a sample log with the number of matches the
    rule must give; rules with status test or stable must have one. They are true positives
    per rule, where EVTX-ATTACK-SAMPLES is organised by technique.
  - SigmaHQ's goodlog run: every rule over NextronSystems' `evtx-baseline` (Apache-2.0), with a
    list of known false positives. The baseline holds goodware logs (software installation and
    basic use, Sysmon on) from Windows 7, 10, 11 and Server 2022 machines. That is the benign
    background the plan's "benign hits per 10,000 events" needs.
- **Correlation.** The Sigma specification 2.1.0 has seven correlation types (`event_count`,
  `value_count`, `temporal`, `temporal_ordered`, and the metrics `value_sum`, `value_avg`,
  `value_percentile`) and filters. Hayabusa runs the first four, Velociraptor and Zircolite three,
  Chainsaw none. SigmaHQ itself ships no correlation rule yet; hayabusa-rules ships three. REMN's
  `then` is a two-step sequence; importing correlations needs a sequence primitive first.

### R6: handover and the co-investigator

- **Local models are weak at agentic security work, so measuring them is not optional.**
  - Elastic publishes a score per model and feature (1 to 10, 5 or below "not recommended"):
    GPT-OSS-20B 4.01, Qwen 3.6 27B 3.75, Gemma 4 31B 5.77, against 9.23 for Claude Opus 4.7.
    On Attack Discovery the three local models score 2.6, 0.0 and 2.8.
  - Frontier models do not saturate investigation benchmarks either: the best result on
    Microsoft's ExCyTIn-Bench is a 56.2% average reward.
  - REMN-Bench should publish per-feature results the way Elastic does. Its method can follow
    ExCyTIn-Bench (questions from an incident graph, partial credit) and AgentDojo (an injection
    suite built from variants of one control, here S07).
- **Prompt injection.** Adaptive attacks got past twelve published defences more than 90% of the
  time (arXiv 2510.09023 (search)). What the agent can do is the boundary. REMN's approval inbox
  is that boundary; two cheap additions:
  - accept a reputation lookup only for a value that appears verbatim in the case, so case data
    cannot be encoded into an outbound request (Meta's "rule of two");
  - datamark tool output (Microsoft's spotlighting).
- **Claims checked against rows.** The plan's R6 item is ahead of the field. The nearest tools
  check only that a citation exists: mulder requires every finding to cite a real tool call, and
  AiSOC sends a verdict back to a human when it cites an indicator absent from the evidence.
- **MCP.** The specification's current version is 2026-07-28, with a stateless core. The DFIR
  servers are read-only by default:
  - Autopsy 4.23: 18 tools, localhost with a token deleted when the case closes, results capped
    at 1 MB.
  - Cyber Triage 3.18: clients write back scores and notes only.
  - TheHive's server: read-only by default.
  The plan builds none. For self-hosted server-store cases a read-only server over the existing
  agent tools is small; for browser cases the tab would have to execute the calls.
- **Models for the guided setup:** Cisco's Foundation-sec-8B has official GGUF builds and is not
  in Ollama's library (search); a GGUF imports with `ollama create`.

### 2.1: mail in the browser

- **What the lures look like in 2026** (Microsoft's quarterly email threat reports):
  - QR-code phishing grew from 7.6 million messages a month in January to 18.7 million in March.
    PDFs carried 65 to 79% of QR attacks, and Word documents 40% by June.
  - Malicious payloads were HTML 31 to 38%, PDF 27 to 28% and SVG 8 to 19%.
  - Calendar invites rose 277% in June.
  - Tycoon2FA's lures: a QR code in a PDF or Word file, SVG redirectors, the victim's address in
    the URL, domains that live 24 to 72 hours, CAPTCHA gates.
- **What Sublime's 1,262 rules call** (counted at commit `f027da1`, 23 September 2026): NLU
  intent 363 rules, file explosion 305, sender profiles 232, link analysis 129, WHOIS 103,
  message screenshots 100, logo detection 100, OCR 142 (through `.scan.ocr`), QR 19.
  - 170 of the Sublime rules REMN skips call no enrichment function; they are blocked only by the
    converter.
  - Local file functions (explosion, OCR, QR, screenshots, EXIF, calendar files, HTML XPath)
    would make about 250 more convertible.
- **Libraries with licences that fit Apache-2.0:**
  - QR: zxing-cpp (Apache-2.0), which also builds to WebAssembly.
  - PDF rendering: pdfium through pypdfium2 (BSD-3 or Apache-2.0).
  - OCR: RapidOCR (Apache-2.0) or Tesseract.
  - Avoid PyMuPDF (AGPL) and zbar (LGPL).
- **Corpora.**
  - Phishing Pot is CC BY-NC 4.0 and its README says the last public commit has been made.
  - The benign corpus REMN measures against is SpamAssassin's 2003 mail. QR, OCR and intent
    features need modern legitimate mail to measure their false positives.

## 3. What the plan should add or adjust

| # | Item | Release | Effort | Evidence |
|---|---|---|---|---|
| 1 | Name the combination in the novelty claim, not browser parsing alone | now | S | LUMEN; APT-Hunter V4.0 |
| 2 | Measured Microsoft 365 detection: an adapter for the `attack_data` Office 365 and Azure AD datasets, hand labels on the Invictus set, results beside the Windows ones | R3 exit | M | 52 Office 365 and about 35 Azure AD labelled datasets; Microsoft 365 rules are tested only on data REMN wrote |
| 3 | Microsoft 365 completeness in the ledger: windows at exactly 5,000 or 50,000 records, `IsThrottled`, sign-in retention against the incident window | R3 (1b) | S | documented limits; Microsoft-Extractor-Suite 4.1.0 |
| 4 | SigmaHQ `regression_data` replayed on both engines, and SigmaHQ's goodlog run on `evtx-baseline` for benign hits per rule | R5 (4a, 4b) | S to M | about 433 tests; Apache-2.0 baseline |
| 5 | ATT&CK Navigator layer 4.5 among the deliverables | R4 | S | the format other tools write; the ATT&CK tab has the data |
| 6 | A second record key without the file hash, to find EVTX records read twice | R1 or R2 | S | shadow copies and overlapping exports; EvtxECmd, Hayabusa |
| 7 | Checksum validation and time running backwards in the EVTX ledger | R1 (1b) | S | Hayabusa 3.7, EvtxECmd `--tdt`, the crate's `validate_checksums` |
| 8 | Collector hashes (Velociraptor `uploads.json`) checked against REMN's and written into custody | R2 | S to M | the container format |
| 9 | Raise the parser floor to `evtx>=0.13.0` | now | S | malformed-input fixes in the Rust parser 0.12.3 |
| 10 | Identity rules for current tradecraft: one session from several networks, the broker asking for device registration, tool user agents, consent with `offline_access` and mail scopes | R3 or R5 | S each | Microsoft, Storm-2372, Elastic's 2025–26 logic reimplemented |
| 11 | A sequence primitive, then Sigma correlation import | after R5 | M | Sigma 2.1; Hayabusa |
| 12 | A read-only MCP server for self-hosted server-store cases | after 2.0 | M | Autopsy, Cyber Triage, TheHive, Timesketch |

## 4. Changes made with this review

On branch `claude/charming-curie-a16afh`, each with a regression test that failed before:
- A mail tied to a malicious and a suspicious indicator is marked malicious; the worst verdict
  was the alphabetical maximum of the labels.
- Reputation lookups stop at their deadline; queued calls are cancelled and reported as `timeout`.
- Graph audit log query records (`auditData`) are read instead of giving no row.
- REMN's own rules carry ATT&CK v19 ids, and the report's defense-evasion badge counts the
  Defense Impairment ids that 137 SigmaHQ rules carry.
- The Sigma converter keeps `|neq`, `|cased` and the regex flags `m` and `s`, refuses modifiers
  outside the Sigma 2.1 list and the time modifiers, and translates `base64`, `base64offset`,
  `utf16`/`wide` and IPv6 CIDRs of one address or a first-group prefix. Re-importing the packs at
  the same SigmaHQ commit adds 28 rules; no existing rule changes. The pack counts in
  `docs/detection.md` match the manifests again (they had drifted:
  `detection-engineering#D10` in the browser-only analysis).

Checked before pushing: the backend suite, ruff, the frontend typecheck, lint, format and
suite, and EVTX-ATTACK-SAMPLES at `4ceed2f` with the re-imported packs. On the SQL engine each
of the 271 samples with an expected detection still gets it; the browser engine gives the same
keys for every rule on every file.

## 5. Sources

**Windows event logs and Sigma**
- Hayabusa and its changelog: https://github.com/Yamato-Security/hayabusa, https://github.com/Yamato-Security/hayabusa/blob/main/CHANGELOG.md
- hayabusa-rules: https://github.com/Yamato-Security/hayabusa-rules
- Takajo: https://github.com/Yamato-Security/takajo
- WELA: https://github.com/Yamato-Security/WELA
- Chainsaw `analyse gaps`: https://github.com/WithSecureLabs/chainsaw/blob/master/src/analyse/gaps.rs
- Zircolite 4.0.0: https://github.com/wagga40/Zircolite/releases/tag/v4.0.0
- APT-Hunter: https://github.com/ahmedkhlief/APT-Hunter/releases
- EvtxECmd: https://github.com/EricZimmerman/evtx
- LogonTracer: https://github.com/JPCERTCC/LogonTracer
- LUMEN: https://github.com/Koifman/LUMEN
- EventHawk: https://github.com/Mihir-Choudhary/EventHawk
- The `evtx` crate and pyevtx-rs: https://github.com/omerbenamram/evtx, https://github.com/omerbenamram/pyevtx-rs/blob/master/CHANGELOG.md
- Sigma specification 2.1: https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md, https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-filters-specification.md
- SigmaHQ regression data and goodlog tests: https://github.com/SigmaHQ/sigma/blob/master/regression_data/README.md, https://github.com/SigmaHQ/sigma/blob/master/.github/workflows/goodlog-tests.yml
- evtx-baseline: https://github.com/NextronSystems/evtx-baseline
- Velociraptor's Sigma evaluator and offline collections: https://github.com/Velocidex/velociraptor/blob/master/vql/sigma/evaluator/correlation.go, https://github.com/Velocidex/velociraptor-docs

**ATT&CK**
- v19 release notes and the Defense Evasion crosswalk: https://github.com/mitre-attack/attack-website/blob/master/modules/resources/static_pages/updates-april-2026.md, https://github.com/mitre-attack/attack-website/blob/master/modules/resources/docs/subtechniques/de-split-crosswalk.csv
- Navigator layer format 4.5: https://github.com/mitre-attack/attack-navigator/tree/master/layers/spec/v4.5

**Microsoft 365 and Entra**
- Microsoft-Extractor-Suite: https://github.com/invictus-ir/Microsoft-Extractor-Suite
- Microsoft-Analyzer-Suite (read for the Outlook rule format; GPL-3.0, nothing copied): https://github.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite
- Invictus dataset: https://github.com/invictus-ir/o365_dataset
- Splunk attack_data: https://github.com/splunk/attack_data
- Tycoon2FA: https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/
- First-party apps and rogue apps: https://github.com/merill/microsoft-info, https://github.com/huntresslabs/rogueapps
- Elastic detection rules (Elastic License 2.0): https://github.com/elastic/detection-rules

**Mail**
- Microsoft email threat landscape, Q1 and Q2 2026: https://www.microsoft.com/en-us/security/blog/2026/04/30/email-threat-landscape-q1-2026-trends-and-insights/, https://www.microsoft.com/en-us/security/blog/2026/07/23/email-threat-landscape-q2-2026-trends-and-insights/
- Sublime rules: https://github.com/sublime-security/sublime-rules
- Phishing Pot: https://github.com/rf-peixoto/phishing_pot
- zxing-cpp, pypdfium2, RapidOCR: https://pypi.org/project/zxing-cpp/, https://pypi.org/project/pypdfium2/, https://pypi.org/project/rapidocr/

**DFIR platforms**
- Timesketch and its LLM features: https://github.com/google/timesketch, https://github.com/google/timesketch/blob/master/docs/guides/admin/llm-features.md
- Timesketch MCP server: https://github.com/timesketch/timesketch-mcp-server
- DFIR-IRIS: https://github.com/dfir-iris/iris-web
- Tracecat: https://github.com/TracecatHQ/tracecat
- Protocol SIFT: https://github.com/teamdfir/protocol-sift
- Velociraptor: https://github.com/Velocidex/velociraptor
- UAC: https://github.com/tclahr/uac
- TheHive MCP server: https://github.com/StrangeBeeCorp/TheHiveMCP
- Autopsy's MCP server: https://github.com/sleuthkit/autopsy/tree/develop/Core/src/org/sleuthkit/autopsy/mcp
- Valhuntir, mulder, AiSOC: https://github.com/AppliedIR/Valhuntir, https://github.com/calebevans/mulder, https://github.com/beenuar/AiSOC

**AI**
- Elastic's model performance matrix: https://github.com/elastic/docs-content/blob/main/solutions/security/ai/large-language-model-performance-matrix.md
- ExCyTIn-Bench: https://github.com/microsoft/SecRL, https://www.microsoft.com/en-us/security/blog/2025/10/14/microsoft-raises-the-bar-a-smarter-way-to-measure-ai-for-cybersecurity/
- AgentDojo: https://github.com/ethz-spylab/agentdojo
- MCP specification releases: https://github.com/modelcontextprotocol/modelcontextprotocol/releases
- Spotlighting: https://arxiv.org/abs/2403.14720
