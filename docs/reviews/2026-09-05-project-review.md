# REMN project review — 5 September 2026

REMN is a substantial local investigation application with a coherent workflow: ingest Windows logs and mail, normalize evidence, search and pivot, run detections, correlate activity, review findings, and produce a report. Its strongest qualities are its practical forensic features and the separation between parsers, analysis services, storage, and UI. The next milestone should concentrate on correctness, preservation of analyst work, and failure recovery.

This assessment comes from source inspection across the frontend, backend, detection engines, parsers, persistence, and tests, with small isolated reproductions of selected issues. It is not a complete security audit or a live usability assessment. No application source was changed.

Validation completed:

- Backend: **247 tests passed**, four heavy tests excluded by the normal configuration. The initial run encountered a sandbox permission problem in pytest's default temporary directory; rerunning with a temporary directory inside the workspace passed.
- Frontend: **58 tests passed** across ten test files.
- TypeScript checking and the production build passed. The build reports ineffective dynamic imports and emits a main JavaScript bundle of approximately 1.26 MB before compression.
- Heavy benchmarks, fresh-machine installation, real multi-GB acquisitions, live external reputation providers, and browser interaction tests were not run.

**What is working well**

- **The product has a clear purpose.** Windows, mailbox, and M365 evidence share searches, timelines, findings, and pivots. This is useful for investigations that cross endpoint and identity/mail activity.
- **The architecture supports the intended workload.** Pure Python analysis functions, a shared ingestion pipeline, the frontend `DataSource` interface, browser workers, virtualized tables, and DuckDB batch writes provide sensible boundaries. The browser/server split is an appropriate option for different case sizes, though maintaining equivalent behavior needs stronger tests.
- **There is meaningful forensic detail.** Client/server hashes, raw records, attachment hashes, deleted/orphaned PST items, evidence references, and inspection of score drivers support analyst verification.
- **Detection transparency is unusually useful.** Silent-rule diagnostics distinguish absent data, missing settings, exclusions, and unmet thresholds. Community packs carry upstream versions and skipped-rule explanations. Unsupported conversion constructs are surfaced rather than universally treated as supported.
- **The mail calibration reflects real workflows.** Tests cover Exchange internal mail, newsletters, calendar objects, preheaders, gateway-wrapped links, and PST/MSG peculiarities. This shows attention to false positives.
- **Hostile-content handling has several good safeguards.** The mail preview uses DOMPurify, an iframe sandbox and CSP, disabled links, and blocked images. The launcher defaults to loopback; token checks and custom-header protection have tests. External reputation lookup is opt-in in the normal analyst workflow.
- **The test suite is a real asset.** Parser, converter, SQL, API, upload, and AI transport tests provide a good base for fixing the issues below.

**Highest-priority correctness and safety findings**

1. **Case import breaks finding-to-evidence links.** Browser imports allocate new event/mail IDs but copy findings without remapping `refs`. An isolated run of the actual import function produced original event ID 1, imported event ID 2, and imported finding references still equal to `[1]`. The case ownership checks prevent ordinary detail lookup from returning the other case's record, but the imported finding no longer opens its evidence. Server exports also discard row IDs, while browser evidence IDs are reassigned independently during import. Fix this with stable identities or complete source-specific ID maps, including server evidence relationships, and a full case round-trip test. See [export.ts:175](frontend/src/util/export.ts:175), [export.ts:192](frontend/src/util/export.ts:192), and [store.py:202](backend/api/views/store.py:202).

2. **Case switching can mix AI conversations and evidence.** `AiView` reloads the session list when the case changes but preserves the selected session and messages. A subsequent prompt can query case B and save into case A's session. Reset or scope all conversation state by case, abort pending work when its case changes, and verify ownership on persistence. Similar drawer state should be audited. See [AiView.tsx:44](frontend/src/views/AiView.tsx:44) and [AiView.tsx:90](frontend/src/views/AiView.tsx:90).

3. **Mail trust can suppress a spoofed sender's risk.** The code accepts SPF or DKIM pass with DMARC absent without requiring sender-domain alignment. A reproduced message claiming `finance@contoso.com`, with SPF pass for an unrelated envelope domain, received risk **12** despite alignment/mismatch flags. Authentication headers also lack a configured trusted-receiver boundary. Make reported authentication, alignment, and trusted provenance distinct before applying risk caps. See [common.py:368](backend/services/parsers/mail/common.py:368) and [headers.py:189](backend/services/analysis/headers.py:189).

4. **Attack chains merge unrelated identities.** `identity_key` removes both Windows-domain and email-domain scope. A reproduced seed to `alice@contoso.com` and log-clear event for `alice@unrelated.example` generated a high-severity chain, score 58. Preserve qualified identities and connect them through explicit alias mappings; expose uncertain correlations as uncertain. See [chains.py:37](backend/services/analysis/chains.py:37).

5. **Large archive members can disappear without an incomplete-ingestion warning.** ZIP/TAR members above 4 GiB are skipped without a skipped-member record or error. A scaled-down reproduction yielded zero records and zero errors for a member exceeding the limit. Legitimate large PST/EVTX archives can therefore look successfully processed when evidence is missing. Record every omission and its reason, distinguish complete/partial/failed outcomes, and support bounded streaming of large members where practical. See [pipeline.py:112](backend/services/ingest/pipeline.py:112).

6. **Some attachment decompression is unbounded.** BZ2/XZ handling limits compressed input, expands it fully in memory, and checks output size afterward. A bounded reproduction expanded 48 compressed bytes beyond the configured 15 MiB nested cap without warning. Some OOXML reads are also unrestricted. Enforce output and cumulative expansion budgets while reading, record truncated analysis, and isolate expensive parsers in processes that can be terminated. See [archive.py:132](backend/services/analysis/attachments/archive.py:132) and [office.py:32](backend/services/analysis/attachments/office.py:32).

7. **Timeline tooltips have an HTML injection path.** Finding titles are interpolated into HTML returned to ECharts; rule titles can arrive through imported/custom rules. The installed ECharts implementation assigns formatter output to `innerHTML`. This is a source-confirmed path; no browser exploit was executed. Escape inserted text or use non-HTML tooltips, then test hostile rule titles. See [TimelineView.tsx:52](frontend/src/views/TimelineView.tsx:52).

8. **Increasing evidence volume can lower detection severity.** Above the 200-match collapse threshold, both engines remove `then_flags`. A reproduced macro rule produced 200 critical findings for 200 autoexec messages, but only one high finding at 201 messages. Aggregation should preserve maximum severity and supporting escalation evidence. See [rules.py:148](backend/services/store/rules.py:148) and [engine.ts:260](frontend/src/rules/engine.ts:260).

9. **Reputation aggregation orders labels alphabetically.** DuckDB `max()` over `malicious`, `suspicious`, and `clean` returns `suspicious`. A message linked to both malicious and suspicious indicators can be downgraded. Rank verdicts numerically before mapping back to labels. See [casestore.py:319](backend/services/store/casestore.py:319).

**Other concrete gaps**

- **Browser and SQL filters differ.** For a list such as `['att_office_macro']`, SQL list `contains_any ['macro']` uses exact membership while the browser uses substring matching. The same filter can therefore return different results by storage mode. Add shared differential fixtures. References: [sqlfilter.py:214](backend/services/store/sqlfilter.py:214), [filter.ts:274](frontend/src/rules/filter.ts:274).
- **Event facets break at the third selected value.** The first two selections become `in [A,B]`; the third adds `eq C`, yielding an impossible conjunction for distinct values. Deselection is also affected. Reference: [EventsView.tsx:86](frontend/src/views/EventsView.tsx:86).
- **Long AI sessions drop their newest messages.** Both transports retain the first 200 messages, so new prompts and tool results eventually disappear from requests. Retain recent complete turns with a summary and a token budget. References: [transport.ts:129](frontend/src/ai/transport.ts:129), [ai.py:32](backend/api/views/ai.py:32).
- **Reputation deadlines do not stop queued work.** Leaving the executor context waits for all queued jobs after result collection stops. A mocked 20 ms deadline took 645 ms, ran all eight requests, and returned only one result. Implement cancellable scheduling and explicit pending outcomes. Reference: [base.py:176](backend/services/reputation/base.py:176).
- **Disconnected ingestion can miss cleanup.** Streaming generators yield a terminal record inside `finally` before cleaning up. A mocked response close left cleanup uncalled. Keep cleanup in a non-yielding `finally`. Reference: [ingest.py:145](backend/api/views/ingest.py:145).
- **Server evidence deletion can falsely appear successful.** The frontend deletes browser metadata without checking the server DELETE response status. An HTTP error can leave server evidence behind while removing it from the local list. Reference: [source.ts:266](frontend/src/data/source.ts:266).
- **A case bundle is not a complete investigation backup.** Export excludes case-keyed `kv` entries such as the report summary, chain details, and rule-run diagnostics. It also does not snapshot the effective global rules/pack choices. This undermines reproducibility even when row data survives. References: [export.ts:87](frontend/src/util/export.ts:87), [ReportView.tsx:30](frontend/src/views/ReportView.tsx:30), [chains.ts:122](frontend/src/data/chains.ts:122).

**Architectural and product improvements**

The most valuable next release would address these in order:

1. **Preserve investigative meaning.** Fix case import references, case-scoped UI/AI state, authentication trust, qualified identities, severity collapse, and reputation ranking. Add regression coverage for each reproduced failure.
2. **Make completeness and reproducibility explicit.** Persist ingestion outcomes, omitted-member manifests, parser/app versions, rule-pack commits, effective rule settings, and analysis timestamps. Save report summaries and chain details with the case. Mark findings stale after evidence/settings changes. Hashes are useful integrity checks; the current evidence table does not replace a history of acquisition and analyst actions.
3. **Test complete workflows and failure paths.** Add browser integration tests for ingest → rules → triage → export → import, case switching, three-value facets, interrupted jobs, server deletion errors, and hostile displayed text. Existing frontend tests use a Node environment and do not exercise React views. Add cross-engine fixtures and alert severity boundary tests. Automate tests and builds in CI; no tracked CI configuration was found.
4. **Harden the large-case lifecycle.** Stream bundle export/import rather than collecting all rows and multiple full JSON strings in browser memory. The current server export still accumulates `serverRows` in the browser. Persist background job state and support recoverable, transactional case migration. Keep analyst notes and triage when converting storage modes. Snapshot investigation metadata together with the DuckDB evidence store.
5. **Improve maintenance and communication.** Lock Python dependencies for reproducible installs; add a clean-install check and schema/bundle migration policy. Update the README's obsolete “stateless”/“keeps no database” descriptions. Its claim that confidential rows reach the server only in server-store mode is misleading: browser-mode evidence is also uploaded to the API for parsing. Distinguish processing location from persistent storage. Correct timezone labels, expose query failures instead of empty results, and improve keyboard/focus behavior.

REMN already has enough functionality to be useful. Reliable case portability, trustworthy correlations, visible partial-analysis states, and predictable recovery would improve it more than adding another data source or another large rule pack at this stage.

**Mail false-positive follow-up**

The user reports ordinary messages appearing as high/critical in both the Mails and Findings views. Five harmless synthetic examples were passed through the actual mail parser, attachment analyzers, DuckDB writer, and built-in mail rules. These messages supplied aligned passing authentication results; they are diagnostic fixtures, not samples from the user's mailbox. No attachment content was executed and no external reputation calls were made.

| Synthetic example | Mail score | High/critical finding |
|---|---:|---|
| Static HTML report inside a ZIP, no scripts or links | 60 — high | Critical: `mail-html-smuggling` |
| PDF containing harmless JavaScript (`var total = 42;`) | 67 — high | High: `mail-pdf-active-content` |
| HTML report with a local CSV-export button using Blob/createObjectURL/download | 90 — critical | Critical: `mail-html-smuggling` |
| Plain bank-details-change notice | 13 | High: `mail-bank-detail-change` |
| Ordinary invoice with a Reply-To address at Gmail | 55 — medium | Critical: `mail-bec-pattern`; high: `mail-replyto-diverted` |

There are three independently assigned visual priorities:

- The Mails row uses the stored numeric score: high begins at 60, critical at 80.
- Findings take severity directly from the matched YAML rule and optional escalation, even when the message score is low.
- Flag badges derive their color from regular expressions over flag names, independent of message context. For example, an encrypted-archive flag receives critical styling. See [ui.tsx:21](frontend/src/components/ui.tsx:21).

The largest demonstrated sources of noise are:

- `mail-html-smuggling` accepts `att_archive_contains_html` without any smuggling behavior. A static HTML file is sufficient. See [content-attachments.yaml:78](rules/mail/content-attachments.yaml:78).
- The HTML analyzer gives Blob, createObjectURL, and download two points each; five points label the attachment smuggling. An ordinary CSV export therefore satisfies the heuristic. See [html.py:96](backend/services/analysis/attachments/html.py:96).
- Attachment scoring adds several related flags and then sets a floor for the mail score at 90% of attachment risk. Sender-trust reductions occur before that floor. Related clues such as HTML-in-archive and single-HTML-file are counted as additional support although they describe the same object. See [analyzer.py:52](backend/services/analysis/attachments/analyzer.py:52) and [common.py:176](backend/services/parsers/mail/common.py:176).
- `mail-bank-detail-change` assigns high severity based on wording alone. The BEC rule also has an independent critical branch requiring only financial wording and a webmail Reply-To. See [content-attachments.yaml:155](rules/mail/content-attachments.yaml:155) and [content-attachments.yaml:169](rules/mail/content-attachments.yaml:169).

Recommended calibration changes:

1. Separate observed capabilities from attack evidence: HTML present, JavaScript present, encrypted content, and bank-change wording should remain visible as review signals. Escalate on suspicious behavior, destination, identity mismatch with appropriate context, or reliable malicious-content evidence.
2. Group correlated features before scoring. Require independent support for stronger conclusions; a file type plus its wrapper plus a keyword should not count as three independent indicators. Critical classifications should require strong evidence appropriate to the detector.
3. Give rules confidence and explicit escalation criteria. Keep impact severity distinct from confidence, and make the mail score, findings, and flag colors explain their relationship.
4. Use chronological sender/recipient history to assess relationship changes. Known correspondents are context, not an unconditional exemption: compromised accounts can send malicious content. Missing sender history in a partial export should remain unknown.
5. Add these benign fixtures as full parser-to-rule regressions alongside malicious controls. Measure false positives per rule and per unique message, separately for the built-in and Sublime packs. Rank the user's reviewed false positives by rule and score driver before making broad changes.
6. Provide a versioned rescore operation over retained mail data with explicit limits when original attachment bytes are unavailable. Currently, rerunning rules does not recompute stored scores; sender baselining only adds history columns, and marking a finding false positive does not recalibrate future scoring. Trust-setting changes likewise do not automatically rescore existing mail.

These reproductions establish several causes of false positives in the code, but do not establish their frequency in the user's actual mailbox. A representative set of reviewed normal and malicious messages is needed to validate the final operating thresholds.
