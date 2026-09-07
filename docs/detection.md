# Detection

_Rule DSL, community packs, mail risk scoring, sender baseline, engine parity._

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
empty in_setting nin_setting levenshtein length contains_cs startswith_cs
endswith_cs` (the `_cs` variants match case exactly; everything else is
case-insensitive). Dotted paths reach nested values
(`attachments.flags`, `data.LogonType`).

## Community rule packs (SigmaHQ, Sublime Security)

The public collections ship with REMN as **packs** under `rules/community/`,
already converted to the REMN DSL so both engines run them without a
converter round-trip:

| pack | upstream | rules | default |
|---|---|---|---|
| `sigma-windows` | SigmaHQ `rules/` (Windows, stable + test) | 2,374 of 2,410 | on |
| `sigma-emerging-threats` | SigmaHQ `rules-emerging-threats/` (Windows) | 319 of 323 | on |
| `sigma-threat-hunting` | SigmaHQ `rules-threat-hunting/` (Windows) | 116 of 128 | off (noisy by design) |
| `sublime` | sublime-security `detection-rules/` | 189 of 1,227 | on |

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
sender-baseline columns, `length()` of a text field through the `length`
operator, `$tenant_domains` / `$org_display_names` / `$recipient_emails`
through the case settings, `$tranco_10k` through the bundled list).

**Built-in reference lists.** `in_setting` / `nin_setting` fall back to a
bundled list when the case settings define none of that name. Today that is
`tranco_10k`, the top 10,000 of the [Tranco](https://tranco-list.eu) ranking
(list id and fetch date in `backend/services/reference/tranco.json`; Le Pochat
et al., NDSS 2019). Sublime's `$tranco_1m` is approximated with it, which only
makes those rules fire more often, never less. A case setting named
`tranco_10k` overrides the bundled list. Refresh with
`tools/import_community_rules.py tranco --download`.

**Rule operators added for the packs**: `field|length: "< 500"` (characters of a
text, items of a list, threshold syntax as for `threshold`), and the derived
URL fields `urls.subdomain` (host minus the registrable domain) and
`urls.fragment`, available in both engines. Settings gained *organisation
display names* (all staff) next to the VIP names, used by the employee
impersonation rules.

## Mail risk scoring

The 0-100 risk score is an investigation priority, not a probability of compromise.
Calibration **mail-2** groups correlated observations before scoring:

* **Strong indicators** (domain spoofing/lookalikes, display-name tricks, hidden
  text, IP-literal or credential-harvest URLs, risky attachments, gated BEC /
  credential-phishing patterns) set the score on their own.
* **Weak signals** (urgency/finance wording, trackers, shorteners, bulk-mail
  headers) only amplify a strong indicator. Without one the score is capped at
  45, and authenticated senders are capped lower: internal + aligned authentication
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
* Static HTML in an archive, a normal CSV-export button, PDF JavaScript,
  encrypted content and bank-change wording remain review signals. Stronger
  findings require payload behavior or corroborating identity/link/authentication
  evidence. Related attachment flags contribute once per family.
* Mail details show the calibration version, evidence confidence, grouped score
  drivers, attachment risk and analysis limitations. Findings display priority
  separately from a rule's declared confidence; flags use neutral observation
  badges. Confidence is qualitative and does not change automatically with a
  priority escalation. Rules without declared confidence show `unspecified`.

After upgrading/restarting REMN, open **Mails → rescore + refresh findings** for
each existing case. This updates chronological sender history, recalculates mail
and attachment scores from retained facts, refreshes score/flag facets, and reruns
enabled mail rules with current settings. It supports both browser and server
cases, preserves evidence IDs and original mail bodies, and retains analyst
status/notes for stable finding keys even if a finding disappears and later
reappears. Completed rule results replace previous findings atomically; a failed
rule retains its previous findings. Interrupted refreshes are marked incomplete
and can be retried. Server score updates roll back on failure/cancellation;
browser score updates commit in batches and may need a retry to finish.

Original attachment bytes are not stored with analysis summaries. Old HTML facts
can be reclassified when available; missing or skipped analysis is explicitly
marked incomplete, and uncertain previous high attachment scores are retained.
Re-ingest original evidence for a full fresh analysis in those cases. Changes to
parser extraction or internal-domain lookalike detection also need re-ingestion;
rescoring only reuses retained observations. Custom rule overrides and enabled
community packs retain their own priorities. Analyst false-positive decisions do
not train the scorer or automatically whitelist a sender.

Run the labelled calibration benchmark without changing a case:

```powershell
.\.venv\Scripts\python.exe tools/calibrate_mail.py --synthetic --output calibration-results.json
.\.venv\Scripts\python.exe tools/calibrate_mail.py --manifest corpus.json --output corpus-results.json
```

The manifest supplies local EML files and reviewed labels, with paths relative to
the manifest (originals are read-only; there are no network lookups):

```json
{"settings":{"internal_domains":["company.example"]},"messages":[
  {"path":"mail/invoice.eml","label":"benign","name":"Reviewed supplier invoice"},
  {"path":"mail/phishing.eml","label":"malicious","name":"Confirmed phishing"}
]}
```

The report ranks high/critical false positives by rule and counts unique message
references separately for core and Sublime packs. Large grouped findings cap
references, so those counts can understate coverage on a large corpus. The eight
synthetic controls yield **0/5 benign messages high/critical** in scores and core
findings, while **3/3 malicious controls** remain high/critical. Sublime matches
none of these eight examples; this is not a coverage or accuracy claim for that
pack or for a real mailbox. Reviewed real examples are needed for further tuning.

The browser rule-engine regression fixture is generated from the same Python
pipeline using `--synthetic --export-fixture samples/synthetic/mail-calibration.json`.

After a rule run, the **Rules view shows why every silent rule found nothing**
(event ids absent from the case, empty Settings lists disarming it, everything
whitelisted, below threshold), so "no findings" is always explainable.

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

An inbox-only export leaves prior solicitation unknown until outbound contact
has been observed. The **rescore + refresh findings** action also runs this
history pass and uses established, authenticated relationships to reduce weak
anomaly scores. Strong payload and deceptive-identity evidence still applies.

## Engine parity

Two rule engines exist on purpose: the browser engine lets confidential evidence be
analysed without a row ever reaching the server, the SQL engine handles GB-scale cases.
They are held to the same output by a fixture: `tools/parity_fixture.py` builds a
mixed scenario (Windows events, M365 rows, mails), runs every bundled rule on the SQL
engine and records the rows and finding keys under `tests/fixtures/parity/`;
`frontend/src/rules/parity.test.ts` runs the browser engine on the same rows and fails
on any difference. Regenerate the fixture after changing an engine or a rule and
review the diff.

Rules pinned to event ids or channels the evidence does not contain (most of the Sigma
packs on a mail-only or Security-only case) are skipped before they run and reported
as "not applicable" in the Rules view, on both engines.
