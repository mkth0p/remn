# REMN — forensic analyzer for Windows event logs and mailboxes

Local investigation tool: drop `.evtx` files and mailboxes (`.pst`/`.ost`,
`.msg`, `.eml`, `.mbox`, zip/tar archives of EVTX files or mail corpora) into
the browser, everything is hashed (SHA-256) and parsed by a local Django API.
Two storage modes per case:

* **Browser store** — rows live only in the browser's IndexedDB. Portable,
  zero server state, comfortable up to a few hundred MB of evidence.
* **Server store** — rows live in a DuckDB file per case on this machine
  (`backend/data/cases/<uuid>/`). Built for gigabytes: chunked uploads with
  resumable offsets, background ingestion jobs, SQL-backed search / facets /
  rules, and a `sql` tool for the AI. The browser still keeps cases, findings,
  notes and AI sessions. A browser case can be converted to a server store from
  Settings (or automatically when a file above the threshold is dropped).

Three ways to work the data:

1. **Search** — clickable facets, filter chips, regex on any field or the raw
   record, time ranges, business-hours filter, saved searches, CSV/JSON export.
2. **Rules** — a YAML catalogue (brute force, password spraying, out-of-hours
   logons, RDP from outside, PsExec / admin shares, persistence, log clearing,
   Defender tampering, PowerShell cradles, credential dumping, display-name
   spoofing, lookalike domains, macro / PDF / HTML-smuggling attachments, BEC
   lexicon, forged headers, …) with MITRE ATT&CK tags. Editable in the UI.
3. **AI analyst** — local Ollama model with tool calling: it queries the
   browser database through tools (search, aggregate, timeline, pivot, regex
   test, reputation lookup) and cites record ids. Also builds filters from plain
   language, explains records, drafts rules and writes the report summary.

Plus: unified timeline, indicator extraction with opt-in reputation lookups
(URLhaus, MalwareBazaar, ThreatFox, VirusTotal, AbuseIPDB, GreyNoise, ipinfo,
RDAP domain age, Spamhaus DNSBL, Google Safe Browsing, offline block lists,
GeoLite2), STIX 2.1 / CSV export, HTML report with chain of custody, case bundle
export/import (hashed), integrity re-verification.

## Requirements

* Windows 11 (tested), Python 3.13, Node 24
* [Ollama](https://ollama.com) with a model that supports tools (e.g. `gemma4`, `qwen3`, `llama3.1`)
* Optional: `libpff-python` for PST/OST, `yara-python` for YARA scanning

## Setup

```bash
# backend (venv with Python 3.13)
py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
# optional: PST / YARA
.venv\Scripts\python.exe -m pip install -r backend\requirements-optional.txt

# frontend
cd frontend && npm install && npm run build && cd ..

# configuration (optional): copy .env.example to .env and set API keys / OLLAMA_MODEL
```

## Run

```bash
# single port, production-style (serves frontend/dist)
.venv\Scripts\python.exe backend\run.py --port 8000
# then open http://127.0.0.1:8000
```

Development (hot reload):

```bash
.venv\Scripts\python.exe backend\manage.py runserver 127.0.0.1:8000
cd frontend && npm run dev        # http://127.0.0.1:5173 (proxies /api)
```

## Gigabyte-scale cases (server store)

Measured on a laptop with 200k synthetic events (55 Windows rules, `samples/synthetic/scale_test.py`):

| Operation | Time |
|---|---|
| ingestion (parse + DuckDB write) | ~10k events/s |
| count / aggregate / timeline | 1-30 ms |
| regex over the raw JSON of every event | ~70 ms |
| full-text search across 20 columns | ~0.5 s |
| 55 rules (bursts, spraying, out-of-hours, LOLBins, …) | ~20 s |

Ingestion of a 1 GB Security.evtx (~3.5M events) therefore takes a few minutes;
queries stay interactive. Settings in `.env`: `FORENSIC_CASES_DIR`,
`FORENSIC_STORE_THRESHOLD_MB` (UI suggestion threshold, default 150),
`FORENSIC_MAX_CHUNKED_GB` (default 64), `FORENSIC_CHUNK_MB` (default 16).
Per-row rules that match more than 200 rows are collapsed into one finding per
entity (user, host, IP…) with a count, instead of thousands of identical alerts.

### Before ingesting real case exports (checklist)

1. **PST/OST first**: `pip install libpff-python`, then a smoke test with ONE
   .pst before the big export. `/api/health` -> `optional.pst` must say `true`.
   The PST path was validated against a real-world Outlook export (mail, meeting
   requests, appointments, RTF-only notifications).
   That run also calibrated the scoring on real Exchange Online mail:
   `X-MS-Exchange-Organization-AuthAs: Internal` marks intra-tenant mail as
   authenticated (flag `exchange_internal`; Exchange neither signs nor
   DMARC-evaluates it), the gateway's own verdicts surface as
   `gateway_spam_verdict` (SCL >= 5) / `gateway_bulk_verdict` (BCL >= 4),
   calendar objects get `calendar_item`, and brand-owned domains (`.microsoft`
   TLD, onmicrosoft.com, service-now.com…) are never lookalikes. Links that stay
   on an authenticated sender's own domain, ESP click-tracker redirects and
   file-name anchor text no longer count as lures, hidden text is only "content
   salting" when the sender or a link is already suspect, and the medium content
   rules (hidden/obfuscated content, suspicious links, link-text mismatch) fire
   only when the score corroborates (`risk|gte: 40`). The regression set is
   `tests/backend/test_mail_calibration.py`.
2. **Disk**: the DuckDB store plus temp files need roughly **2x the input
   size** free (store ~= input, plus the upload copy until ingestion ends).
3. **deepAttachments**: for a first look at a huge mailbox, turn OFF
   "deep attachment analysis" in Settings (macro/PDF analyzers dominate the
   cost); re-ingest with it ON once the interesting time range is known.
4. **Expected throughput** (laptop, one core): EVTX ~10k events/s; mail
   ~150-300 msg/s with deep analysis off (a 300k-mail export ~= 20-35 min).
   The heavy validation suite (`pytest -m heavy -s`) reproduces these numbers
   with synthetic data (`samples/synthetic/make_big.py`).
5. **If an ingest job fails**: the store stays consistent - check the job
   error in the console (or `GET /api/jobs`), cancel leftovers, fix the cause
   (usually disk or a corrupt member file), delete the evidence and re-ingest.
   Interrupted chunked uploads resume automatically when the same file is
   dropped again.

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

## Sender baseline and campaigns (enrichment pass)

"baseline senders" in the Mails view runs one pass over the case's mails, in
time order, and writes history columns every rule and the DSL can use:
`senderPrevalence` (new / rare / common: earlier mails from the address),
`senderPriorCount`, `senderFirstSeen`, `senderDaysKnown`, `senderSolicited`
(an internal sender wrote to that address first, so its reply is expected),
`senderAuthRegression` (the domain passed SPF/DKIM/DMARC at least three times
before and fails now), and `campaignId` / `campaignSize` / `campaignSenders`
(mails sharing a subject skeleton plus link domains or attachment hashes,
with the number of distinct senders behind them). `rules/mail/baseline.yaml`
uses them: first contact with a lure, unsolicited first-contact attachment,
authentication regression, campaign clusters (one finding per campaign).
Server cases are updated inside DuckDB; browser cases post the minimal rows
and write the columns back to IndexedDB (`POST /api/enrich/mails`). Sublime
rules using `profile.by_sender().prevalence / .solicited / .days_known` now
translate onto these columns.

## Deleted and orphaned mail (PST / OST)

Messages inside Deleted Items and the Exchange Recoverable Items dumpster
(Purges, Deletions, Versions, DiscoveryHolds, in the common Outlook locales)
are flagged `deleted_item`. Messages that were deleted and detached from every
folder are recovered from the PST/OST item tree as libpff orphan items, listed
under a synthetic "(orphaned)" folder and flagged `deleted_item` +
`orphan_item`. The rule `mail-deleted-message-with-indicators` reports the
ones that also score 45 or more, since a cleaned mailbox is itself evidence.
Outlook *exports* rarely contain orphans; original PST/OST files do.

## Attack chains (cross-source correlation)

The Chains view links a suspicious mail to what its recipient did next, across
the three sources of a case. A *seed* is a mail above the risk threshold or
carrying a medium+ finding. Its recipients are normalised to an identity
(`alice@contoso.com`, `CONTOSO\alice` and a UAL `UserId` all become `alice`),
and every step of that identity inside the window (72 h by default) is
collected and scored: replies to the sender (same thread), Entra sign-ins
(country, legacy client, identity-protection risk), MailItemsAccessed bursts,
inbox rules and mailbox forwarding, consent grants, role and MFA changes,
Windows logons, processes spawned by Outlook or a browser, DNS queries, network
connections and file writes that name the mail's URL domains or attachment
names (strong *artifact links*), Defender detections, persistence and
log-clearing events. Bursts collapse into one step, findings of the last rule
run attach to the steps they reference, one chain is kept per identity per day
with the other seeds listed as related. Chains are also stored as findings
(rule `chain`) so they reach the report. Server-store cases are correlated
inside DuckDB; browser-store cases post the relevant rows to the local API
(`POST /api/chains/build`). `services/analysis/chains.py` is pure functions
over plain rows, tested on the synthetic BEC scenario plus host events.

## Community rule packs (SigmaHQ, Sublime Security)

The public collections ship with REMN as **packs** under `rules/community/`,
already converted to the REMN DSL so both engines run them without a
converter round-trip:

| pack | upstream | rules | default |
|---|---|---|---|
| `sigma-windows` | SigmaHQ `rules/` (Windows, stable + test) | 2,374 of 2,410 | on |
| `sigma-emerging-threats` | SigmaHQ `rules-emerging-threats/` (Windows) | 319 of 323 | on |
| `sigma-threat-hunting` | SigmaHQ `rules-threat-hunting/` (Windows) | 116 of 128 | off (noisy by design) |
| `sublime` | sublime-security `detection-rules/` | 168 of 1,227 | on |

Each pack directory holds the rules grouped by log source (`process_creation.yaml`,
`registry_set.yaml`, ...) or by Sublime rule family, a `pack.json` manifest with
the upstream repository, the exact commit, the licence and the counts, the
upstream `LICENSE` verbatim, and `skipped.json` naming every upstream rule that
was not converted and why (a rule is skipped rather than weakened: base64 /
utf16 / fieldref modifiers, IPv6 CIDRs, `file_access` sources, Sublime ML
classifiers, `file.explode`, link analysis, ...). The SigmaHQ rules are
redistributed under the Detection Rule License 1.1, the Sublime rules under MIT.

The Rules view lists the packs with a toggle each. `/api/meta` only carries the
manifests; a pack's rules are fetched once per session from
`GET /api/rules/packs/<id>` when it is on, so the app does not pay for 3,000
rules it does not use. Single rules can still be switched off in the table, and
a custom rule with the same id overrides a pack rule. Analysts' pack choices are
kept in the browser (`packOverrides`).

Running 3,000 rules stays practical on both engines: the browser worker groups
rules by the event ids they pin and reads each event subset from IndexedDB once
(the ~1,500 process-creation rules share one read of the Sysmon 1 / 4688 rows;
2,987 rules over a 972-event PowerShell log ran in 10 s), and the SQL engine
runs the same set in about 90 s as a background job (35 ms per rule including
the zero-finding diagnostics). Two DuckDB pitfalls are handled in the engine: a
parameter-binding probe for pandas that rescanned `sys.path` on every bound
value when pandas is absent (50 ms per rule, short-circuited in `casestore.py`),
and list operators such as a 179-item `contains_any` on script blocks, which are
compiled to one regex alternation instead of a chain of `lower(col) LIKE ?`
(5.6 s per rule down to 0.04 s).

**Refreshing the packs**: `tools/import_community_rules.py all --download`
resolves the branch heads on GitHub, fetches those exact commits, converts them
with the same code as the import buttons and rewrites the pack directories in
place (stable order, no YAML aliases), so an update is one reviewable commit.
`--zip <archive> --sha <commit>` works offline from a downloaded archive.

**Importing other collections** (`import Sigma` / `import Sublime` in the Rules
view) still converts one `.yml` or a `.zip` through `POST /api/rules/convert/sigma`
and `POST /api/rules/convert/sublime` and stores the result as custom rules.
Sigma: Windows logsources map to channel + event id (Sysmon 1 and Security 4688
for `process_creation`, ...), fields map to the parser's flattened columns
(`Image` matches both Sysmon and 4688), unmapped EventData fields are reachable
as `data.<Field>`, globs become the right operator or an anchored regex,
`1 of x*` / `all of them` become `any_of` / `all_of`. Sublime: the structural
subset of MQL translates (sender / subject / header comparisons, `strings.*` and
`regex.*` matchers, `any(body.links | attachments | recipients.* | headers.reply_to)`,
`length()` counts, `$org_domains` / `$org_vips` from the case settings, the
common `$lists`, `strings.ilevenshtein` through the `levenshtein` operator,
`1 of (...)`, `all()` with negated predicates, `profile.by_sender()` through the
sender-baseline columns).

## Test data (public)

* **EVTX**: [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
  (200 files by ATT&CK tactic), [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack)
  (270+ samples, Security / Sysmon / PowerShell), [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx)
  (both of the above plus DeepBlueCLI samples), the `samples/` folder of
  [omerbenamram/evtx](https://github.com/omerbenamram/evtx) (security_big_sample.evtx, sysmon.evtx).
  Download the repository ZIP and drop it as is: REMN walks the archive and
  tags every event with its source file.
* **Phishing / spam**: the [Nazario phishing corpus](https://monkey.org/~jose/phishing/)
  (yearly mbox files, 2005-2025, up to 31 MB each), the
  [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/)
  (tar.bz2 of extension-less messages, dropped as is), [phishing_pot](https://github.com/rf-peixoto/phishing_pot)
  (real `.eml` samples from honeypots).
* **Large mailboxes**: the [CMU Enron maildir](https://www.cs.cmu.edu/~enron/)
  (1.7 GB tar.gz, ~500k messages, extension-less files) and the
  [EnronData PST set](https://enrondata.readthedocs.io/en/latest/data/edo-enron-email-pst-dataset/)
  (148 custodian PSTs, 734 MB 7z / 8.6 GB; PST needs `libpff-python`).
* **Attachments**: the [oletools test corpus](https://github.com/decalage2/oletools/tree/master/tests/test-data)
  (macros, DDE, encrypted, RTF exploits) and [PayloadsAllThePDFs](https://github.com/luigigubello/PayloadsAllThePDFs).
* Your own machine: `wevtutil epl Security C:\evidence\Security.evtx` (admin),
  Outlook → Export to `.pst`, Thunderbird profile `.mbox` files.

## Mail risk scoring

The 0-100 risk score is indicator-driven, not additive noise:

* **Strong indicators** (domain spoofing/lookalikes, display-name tricks, hidden
  text, IP-literal or credential-harvest URLs, risky attachments, gated BEC /
  credential-phishing patterns) set the score on their own.
* **Weak signals** (urgency/finance wording, trackers, shorteners, bulk-mail
  headers) only amplify a strong indicator. Without one the score is capped at
  45, and authenticated senders are capped lower: internal + SPF/DKIM/DMARC pass
  ≤ 12, authenticated newsletters ≤ 20.
* Links wrapped by mail gateways (Microsoft Safe Links, Proofpoint v2/v3,
  Mimecast…) are unwrapped and the real destination is analysed, so protected
  corporate links no longer trip text/destination-mismatch or redirect flags.
* "login/account/invoice" in a URL is only a signal on an already-suspicious
  URL; on a normal one it becomes the informational `login_link` flag. Microsoft
  Forms / Google Forms count as `form_saas`, not free hosting.
* The BEC and credential-phishing composite flags require sender or URL
  suspicion on top of the wording, so IT password-expiry notices and CEO
  newsletters stay quiet.
* Hidden marketing preheaders count as informational, not as hidden-text
  salting; click-tracker link mismatches are expected in newsletters; `.msg` /
  `.pst` exports without transport headers are not treated as forged mail; a
  valid ARC seal restores trust for mailing-list forwarding.
* The mail detail drawer shows the score drivers (each flag's weight, strong
  indicators starred) so any score can be audited at a glance.

Re-ingest existing evidence after upgrading: risk is computed at parse time.

After a rule run, the **Rules view shows why every silent rule found nothing**
(event ids absent from the case, empty Settings lists disarming it, everything
whitelisted, below threshold), so "no findings" is always explainable.

## AI mode notes

* **Transport**: by default the browser talks directly to the analyst's own
  Ollama (`http://localhost:11434`) - prompts, tool results and evidence
  excerpts never reach the REMN server. Settings → AI switches to the server
  proxy (the pre-existing `/api/ai/*` path) for machines without a local
  Ollama. Prompts and tool schemas stay server-defined (`GET /api/ai/meta`).
* The analyst agent sends the system prompt + tool definitions on every turn;
  with a 7-8B model running **on CPU** a turn takes 2-4 minutes (prompt
  evaluation dominates). On a GPU the same turn takes a few seconds. Check
  `curl http://127.0.0.1:11434/api/ps` → `size_vram` should not be 0.
* Smaller / faster models work for the filter builder ("ask" button) and for
  "explain"; the agent needs a model with the `tools` capability.
* `OLLAMA_MODEL`, `OLLAMA_NUM_CTX` and `OLLAMA_HOST` are set in `.env`.
* Debugging a model's tool-calling behaviour:
  `.venv\Scripts\python.exe samples\synthetic\ai_repro.py <model> [true|false]`
  replays a second agent turn and prints the raw Ollama chunks.

## Remote access (home-server mode)

By default everything binds to loopback. To host REMN on a home server and use
it from anywhere, set two environment variables and put a TLS proxy in front:

```
FORENSIC_AUTH_TOKEN=<long-random-string>     # shared access token, required for every /api call
FORENSIC_ALLOWED_HOSTS=remn.example.com      # extra Host header values (comma list)
```

The first time a browser hits a token-protected server, the app shows a token
prompt; the value is kept in that browser's IndexedDB and sent as the
`X-Forensic-Client` header. A wrong token gets `401 {"code":"auth"}`.

**Recommended: Tailscale Serve.** Keep `run.py` on `127.0.0.1` and run
`tailscale serve --bg 8000`; you get HTTPS (a secure context, which the app
needs for crypto/clipboard APIs) with zero open ports, and only devices in your
tailnet can even reach it. Set `FORENSIC_ALLOWED_HOSTS` to your tailnet name.

**Alternative: Caddy** (`caddy reverse-proxy --from remn.example.com --to 127.0.0.1:8000`)
gives automatic HTTPS. With nginx, disable response buffering
(`proxy_buffering off;`) or streaming (chunked uploads, NDJSON ingest, SSE)
stalls.

**AI in remote mode.** The default transport is browser-direct: each analyst's
page calls *their own* local Ollama at `http://localhost:11434`, so prompts and
evidence excerpts never reach the server. Because the page origin is then your
remote hostname, each analyst must allow it once on their machine:
`setx OLLAMA_ORIGINS "https://remn.example.com"` (then restart Ollama).
Chrome, Edge and Firefox allow an HTTPS page to call `http://localhost`
(loopback exemption); Safari does not — switch that analyst to the server-proxy
transport in Settings → AI.

**Accepted v1 trade-offs** (single shared token, keep the deployment private):
no per-user accounts or audit log, no rate limiting, DuckDB case stores are not
encrypted at rest, and anyone with the token can read or delete every case
store. Confidential rows only reach the server when a case uses the *server
store*; browser-store cases keep evidence in the analyst's browser.

## Tests

```bash
.venv\Scripts\python.exe -m pytest                      # parsers, analyzers, API, rule catalogue (from the project root)
cd frontend && npm test                                 # filter DSL, rule engine, IndexedDB queries
```

## Layout

```
backend/            Django project (stateless API) + services/ (pure Python: parsers, analysis, reputation, AI)
frontend/           Vite + React + TypeScript SPA (Dexie/IndexedDB, web workers, ECharts)
rules/              bundled detection rules (YAML DSL, served by /api/meta)
samples/            local EVTX exports (gitignored) + synthetic/ mail generator for tests
tests/backend/      pytest suite
backend/data/       lists/ (offline block lists), yara/ (rules), geoip/ (GeoLite2 .mmdb)
```

## Security model

* Server binds to `127.0.0.1`, keeps no database and deletes upload temp files at
  the end of each request. Every `/api` call needs the `X-Forensic-Client`
  header (cookie-less CSRF protection); cross-origin preflights are refused.
  With `FORENSIC_AUTH_TOKEN` set, the header value must equal the token
  (see "Remote access").
* Parsed content is treated as hostile: React escaping, HTML previews in a
  sandboxed iframe with DOMPurify, images blocked, links disabled and defanged.
  Attachments are analysed statically, never opened or executed.
* No outbound request unless "allow external lookups" is enabled for the case;
  the AI model only sees what the tools return from the local database.

## Rule DSL (short)

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

Operators: `eq ne in nin contains not_contains contains_any contains_all
startswith not_startswith endswith not_endswith re not_re gt gte lt lte exists
empty in_setting nin_setting`. Dotted paths reach nested values
(`attachments.flags`, `data.LogonType`).
