# Detection

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
page](sources.md). Every rule carries MITRE ATT&CK technique ids.

## Community rule packs

The public collections ship with REMN as packs under `rules/community/`, already
converted to the rule language so both engines run them without a converter round-trip:

| pack | upstream | rules | default |
|---|---|---|---|
| `sigma-windows` | SigmaHQ `rules/` (Windows, stable and test) | 2,374 of 2,410 | on |
| `sigma-emerging-threats` | SigmaHQ `rules-emerging-threats/` (Windows) | 319 of 323 | on |
| `sigma-threat-hunting` | SigmaHQ `rules-threat-hunting/` (Windows) | 116 of 128 | off (noisy by design) |
| `sublime` | sublime-security `detection-rules/` | 189 of 1,227 | on |

Each pack directory holds the rules grouped by log source (`process_creation.yaml`,
`registry_set.yaml`, …) or by Sublime rule family, a `pack.json` manifest with the
upstream repository, the exact commit, the licence and the counts, the upstream
`LICENSE` verbatim, and `skipped.json` naming every upstream rule that was not converted
and why. A rule is skipped rather than weakened: base64, utf16 and fieldref modifiers,
IPv6 CIDRs, `file_access` sources, Sublime ML classifiers, `file.explode`, link
analysis, and so on. The SigmaHQ rules are redistributed under the Detection Rule
License 1.1, the Sublime rules under MIT.

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
both Sysmon and 4688), unmapped EventData fields are reachable as `data.<Field>`, globs
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
  without transport headers are not treated as forged mail; a valid ARC seal restores
  trust for mailing-list forwarding.
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

## When a rule finds nothing

Rules pinned to event ids or channels the evidence does not contain (most of the Sigma
packs on a mail-only or Security-only case) are skipped before they run and reported as
"not applicable" on the Rules page, on both engines. After a run, the Rules page says
why every other silent rule found nothing: event ids absent from the case, empty
settings lists disarming it, everything whitelisted, below threshold. "No findings" is
always explainable.
