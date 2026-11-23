# Writing rules

A rule is a YAML document that describes rows of one case to raise as a finding. The same rule
runs on two engines: in the browser (`frontend/src/rules/engine.ts`), for a case whose evidence
stays in the analyst's browser, and in SQL on the server's case store
(`backend/services/store/rules.py`), for large cases. This page describes the format, how to try
a rule, the checks a rule shipped with REMN has to pass, how Sigma and Sublime rules are brought
in, and the regular expressions to avoid. The rule sets themselves, the mail score and the
detection level are described in [Detection](detection.md).

## Where rules live

| Place | What it holds | Rule ids |
| --- | --- | --- |
| `rules/windows/*.yaml` | Windows event log rules | `win-` |
| `rules/mail/*.yaml` | mail rules | `mail-` |
| `rules/m365/bec.yaml` | Microsoft 365 and Entra rows (business email compromise) | `m365-` |
| `rules/collection/host-artifacts.yaml` | rows read from a collected Windows host (services, autoruns, tasks, Prefetch, Defender) | `collection-` |
| `rules/community/<pack>/` | the SigmaHQ and Sublime Security packs, converted | `sigma-`, `sublime-` |
| the Rules page | custom rules, kept in the analyst's browser | any |

A file holds one rule or several, separated by `---`. The server reads every `.yaml` and `.yml`
file under `rules/` outside `rules/community/` and sends them to the page with the reference data
(`GET /api/meta`); it notices an added, removed or edited file on the next page load, without a
restart. The community packs are written by `tools/import_community_rules.py` and are not edited
by hand; `rules/community/levels.json` changes the level of pack rules that were measured too
noisy or too quiet at their upstream level, and keeps the upstream level and the reason beside
each entry.

A custom rule is saved in the browser's database and applies to every case opened in that
browser. A custom rule with the id of a bundled or pack rule replaces it.

## A rule, field by field

A rule that raises one finding per matching row:

```yaml
id: win-example-service-from-temp
title: Service installed from a temporary folder
description: A service was installed whose binary sits in a Temp folder.
severity: high
confidence: medium
source: events
attack: [T1543.003]
tags: [persistence]
where:
  eventId: 7045
  provider: Service Control Manager
  serviceFile|contains: ['\temp\', '\tmp\']
exclude:
  serviceName|in_setting: service_accounts
```

A rule that counts rows per group over a sliding window, and escalates when a follow-up row
appears:

```yaml
id: win-example-bruteforce-by-ip
title: Burst of failed logons from one address
severity: high
source: events
attack: [T1110.001]
where:
  eventId: 4625
  ipAddress|exists: true
group_by: [ipAddress]
window: 5m
threshold: ">= 5"
then:
  where: { eventId: 4624 }
  join: [ipAddress]
  within: 15m
  severity: critical
  title: followed by a successful logon
```

| Key | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Unique. Findings, analyst decisions and measures are keyed on it; a shipped rule uses lower case letters, digits and `-`. |
| `title` | yes | The finding's title. |
| `severity` | yes | `info`, `low`, `medium`, `high` or `critical`. |
| `source` | yes | `events` (event logs, Microsoft 365 and Entra rows, collected artifacts) or `mails`. |
| `description` |  | Shown in the finding panel and the report. |
| `confidence` |  | `low`, `medium` or `high`, shown beside the severity. |
| `attack` |  | MITRE ATT&CK technique ids, as of ATT&CK v19 (`T1110.001`). |
| `tags` |  | Free words, searchable in the Rules page. |
| `enabled` |  | `false` ships the rule turned off; the analyst turns it on in the Rules page. |
| `where` |  | The rows the rule looks at (see [Conditions](#conditions)). Without it, every row of the source. |
| `exclude` |  | Rows taken out after `where`, in the same syntax. |
| `group_by` |  | Fields whose values form a group; one finding per group. |
| `threshold` |  | How many rows a group needs: `">= 5"`, `"> 2"`, `"== 1"`; a bare number means at least that many. |
| `distinct` |  | With `threshold`, counts the different values of this field instead of rows. |
| `window` |  | With `threshold`, the rows must fall within this sliding window: `30s`, `5m`, `1h`, `2d`, `1w` (a bare number is seconds). |
| `any_in_group` |  | A condition that at least one row of the group must meet. |
| `then` |  | A follow-up that escalates a finding (see [Groups, windows and follow-ups](#groups-windows-and-follow-ups)). |
| `then_flags` |  | Mail rules only: a list of `flag: severity` pairs; a finding whose mail carries the flag is raised to that severity. |
| `time` |  | `outside_business_hours: true`, `weekend: true`, or `hours: [start, end]`, read in the case's time zone; `field` names another time column. |
| `require_setting` |  | The name of a case setting; while it is empty the rule does not run and says which setting is missing. |
| `entities` |  | The fields a finding shows. Defaults to `group_by`, or to host, accounts, address, process and service for events, and sender, domain, subject and origin address for mails. |
| `max_findings` |  | The number of findings a run keeps (2,000 by default). |
| `collapse_after` |  | For a rule with one finding per row: past this many rows (200 by default) it gives one finding per combination of its entity fields instead. |

Both engines refuse a rule that asks for something they would otherwise skip: `then`, `window`,
`distinct` or `any_in_group` without `group_by` or `threshold`, a `then` without a `where`, and
`then_flags` on an events rule. The Rules page shows the error when the rule is saved.

## Conditions

A condition is a mapping of `field: value` or `field|operator: value` entries, all of which must
hold:

- `field: value` is equality, without regard to case. A list, `eventId: [4624, 4625]`, matches
  any of its values.
- `any_of:` takes a list of conditions of which one must hold, `all_of:` a list of which all
  must hold, and `not:` one condition that must not. A mapping cannot hold the same key twice,
  so a second group is written `any_of_2:`, `all_of_2:` and so on.
- A dotted path reaches a nested value: `data.LogonType` for an EventData field the parser keeps
  in `data`, `attachments.ext` or `urls.domain` for the attachments and links of a mail.

On a mail, a condition on `attachments.*` or `urls.*` holds when any attachment or link meets it;
a negative operator (`ne`, `nin`, `not_contains`, `not_startswith`, `not_endswith`, `not_re`,
`nin_setting`) holds when none does.

The columns of each source are listed by `GET /api/store/<key>/schema` on a server-store case and
in the SQL view of the page. The ones rules use most:

- events: `eventId`, `provider`, `channel`, `computer`, `targetUser`, `subjectUser`, `logonType`,
  `ipAddress`, `status`, `processName`, `commandLine`, `parentProcessName`, `image`,
  `parentImage`, `serviceName`, `serviceFile`, `taskName`, `scriptBlockText`, `targetObject`,
  `destinationIp`, `query`, and `data.<EventData name>` for the rest;
- mails: `fromAddr`, `fromDomain`, `fromRegistrable`, `fromNameNorm`, `replyToDomain`,
  `originIp`, `subject`, `spf`, `dkim`, `dmarc`, `risk`, `flags`, `attachments.*` (`name`,
  `ext`, `realExt`, `risk`, `flags`) and `urls.*` (`url`, `host`, `domain`, `flags`, plus the
  derived `urls.subdomain` and `urls.fragment`).

The mail flags are listed with their weights in the reference data (`flags` in `GET /api/meta`).

## Operators

| Operator | Holds when |
| --- | --- |
| `eq`, `ne` | the value equals, or does not equal, the one given (a number compares as a number) |
| `in`, `nin` | the value is, or is not, one of a list |
| `contains`, `not_contains` | the text contains, or does not contain, the string; on a list field (flags, recipients) a list of values matches whole elements |
| `contains_any`, `contains_all` | the text contains any, or all, of the strings |
| `startswith`, `not_startswith`, `endswith`, `not_endswith` | the text starts or ends with one of the strings |
| `contains_cs`, `startswith_cs`, `endswith_cs` | the same, with case kept |
| `re`, `not_re` | a regular expression matches, or does not, without regard to case |
| `re_cs` | a regular expression matches with case kept, unless the pattern starts with `(?i)` |
| `gt`, `gte`, `lt`, `lte` | the value read as a number is greater or smaller |
| `exists` | the value is present and not empty; `exists: false` holds when it is absent or empty |
| `empty` | the value is absent, empty, or an empty list |
| `length` | the number of characters of a text, or of items of a list, meets a threshold: `"< 500"` |
| `levenshtein` | the value is within an edit distance of a string: `[microsoft.com, 2]` |
| `in_setting`, `nin_setting` | the value is, or is not, in a list of the case settings (next section) |

Every comparison except the `_cs` operators ignores case, `re` included. A regular expression
has to mean the same thing in both engines: the browser's JavaScript `RegExp` and DuckDB's RE2.
Lookahead, lookbehind and backreferences are not in RE2, and atomic groups and possessive
quantifiers are not in JavaScript, so a rule uses none of them. Both engines read only the first
65,536 characters of a value with `re`, `not_re` and `re_cs`
([the last section](#patterns-that-backtrack-in-the-browser-engine) says why and how a rule shows
it).

## Case settings

`in_setting` and `nin_setting` read a list from the case settings: `internal_domains`,
`internal_ips` (ranges in CIDR form), `vip_names`, `org_display_names`, `trusted_senders`,
`admin_accounts`, `service_accounts`, `expected_countries`. The snake_case and camelCase forms
of a name are both read. Display names are compared after normalisation (accents and punctuation
removed, word order ignored), and a domain matches its subdomains. When a case defines no list of that
name, a bundled list of the same name is read: today `tranco_10k`, the top 10,000 domains of the
[Tranco](https://tranco-list.eu) ranking (Le Pochat et al., NDSS 2019; the list id and the date
it was fetched are in `backend/services/reference/tranco.json`), refreshed by
`tools/import_community_rules.py tranco --download`. A case setting named `tranco_10k` replaces
it.

An empty setting has no members, so `nin_setting` holds on every row until the analyst fills it.
A rule whose only guard is a `nin_setting` also carries `require_setting` with the same name;
until the setting is filled the rule does not run, and the Rules page offers to open the
settings.

## Groups, windows and follow-ups

`group_by` with `threshold` counts the rows of each group; `distinct` counts the different
values of one field instead (`distinct: fromRegistrable` with `threshold: ">= 2"` is the same
display name seen from two domains). With `window`, the count is taken over a sliding window and
a finding covers one burst.

`then` looks, after a finding, for a row that meets `then.where` and shares the values of the
`join` fields (the `group_by` fields by default; `a=b` joins the finding's `a` to the follow-up's
`b`) between the first row of the finding and `within` after its last. When it finds one, the
finding takes `then.severity`, names `then.title` as its escalation, and refers to that row too.

## How many findings a rule keeps

A run keeps at most 2,000 findings per rule, or `max_findings`, and both engines keep the same
ones. Past the cap, a rule with a threshold of two or more keeps its largest groups, any other
grouped rule its rarest, equal groups in the order of their values; a rule with a `window` keeps
its first bursts in the order of the grouped fields, and a rule with one finding per row its
first rows in time order. The number left out is shown beside the rule in the Rules page, above
the list in the Findings page and on the findings of that rule, and the message at the end of
the run says how many findings were left out and by how many rules. A finding keeps at most 5,000 row references.

## What the language cannot say

There is one follow-up step and no ordered sequence of three events or more; a `window` with
`distinct: eventId` counts different events in any order. A condition cannot compare one field
with another. A group is counted (rows or distinct values) but not summed or averaged.

## Trying a rule

In the Rules page, **new rule** opens an editor with a template, and the pencil beside a bundled
rule copies it into the editor as a custom rule. **Save** checks the YAML and the rule (required
keys, operators, thresholds, durations, regular expressions) and refuses it with the reason. The
rule then runs with the others: **run rules** in the Findings page, or **apply level** in the
Rules page. A rule that found nothing says why in the Rules page: no row it applies to, no row past
its conditions, every row excluded, no row in its hours, no group up to its threshold, or a
missing setting.

When an analyst model is configured, the **draft** box in the Rules page asks it for a rule from
a sentence; the draft opens in the editor and is saved only by the analyst.

## Adding a rule to REMN

A rule shipped with REMN goes in the file of its subject under `rules/`, with an id of the
folder's prefix and the ATT&CK ids of what it detects. In the commands below, `python` is the
virtual environment's interpreter: `.venv/bin/python` on Linux and macOS,
`.venv\Scripts\python.exe` on Windows.

1. Write a positive sample. For a Windows rule, add the event in
   `samples/synthetic/rule_samples.py` as the log records it (EventData or UserData), so the
   parser's field mapping is exercised too. A test in `tests/backend/test_own_rule_logic.py`
   that builds the event and runs the rule on the SQL engine, with a near miss that must not
   fire, is the place to pin what the description says.
2. Regenerate the engine parity fixture, which runs every bundled rule on the SQL engine over a
   mixed scenario and records the findings:

   ```
   python tools/parity_fixture.py
   ```

   `frontend/src/rules/parity.test.ts` then runs the browser engine over the same rows and fails
   on any finding that differs in key, severity, count or escalation, and when the set of
   bundled rules differs from the fixture's.
3. Run the checks:

   ```
   python -m pytest tests/backend/test_rules_yaml.py tests/backend/test_own_rule_logic.py -q
   cd frontend
   npx vitest run src/rules src/test/regexTiming.test.ts
   ```

4. For an event rule, measure it (next section) and commit `rules/measures.json` and
   `rules/measures-detail.json` with the rule.

| Check | What it holds |
| --- | --- |
| `tests/backend/test_rules_yaml.py` | Every file parses with no duplicate key; ids are unique and well formed; operators exist; thresholds and windows parse; ATT&CK ids are current; no rule asks for what the engines refuse. |
| `tests/backend/test_own_rule_logic.py` | Each own rule fires on the event its description names, and not on the near miss. |
| `tests/fixtures/parity/` with `parity.test.ts` | Both engines give the same findings for every bundled rule, including the findings kept past a cap. |
| `frontend/src/test/regexTiming.test.ts` | Every pattern of the own rules answers a hostile value of 100,000 characters within 250 ms in the browser engine (see [the last section](#patterns-that-backtrack-in-the-browser-engine)). |
| `tests/fixtures/evtx-attack-samples/expected.json` | The rules reviewed as identifying each file of EVTX-ATTACK-SAMPLES still fire on it, on both engines (`tools/evtx_attack_samples.py`, the attack samples job of CI). |
| `rules/measures-detail.json` with `.github/workflows/measure-rules.yml` | No rule loses a detection, and no high or critical rule raises more findings on a clean machine. |
| `tests/backend/test_quoted_measures.py` | The figures the README and [Detection](detection.md) quote are those of the committed measures. |

Mail rules are not measured on recordings; the mail score and the mail rules are calibrated
with `tools/calibrate_mail.py` and `frontend/src/rules/mail-calibration.test.ts` (see
[Detection](detection.md#measuring-the-calibration)).

### Measuring a rule

`tools/measure_rules.py` runs every event rule, own and pack, on five sets of recorded attacks and
on the logs of seven clean Windows installations, each at a pinned version, and writes what each
rule detected and how often it fired on the clean machines:

```
python tools/measure_rules.py --datasets DIR --fetch --out rules/measures.json --detail rules/measures-detail.json
```

`--fetch` downloads the datasets missing from `DIR` first (the clean machines are 8 GB unpacked).
Each measure carries a hash of the rule's logic, everything but its title, description and other
metadata. A rule changed since it was measured is shown as changed rather than with a measure
that is not its own, and the test of the shipped measures warns until the measure is taken again.
The detection level of a case reads the measured noise of each rule
([Detection level](detection.md#detection-level)).

The gate, `--gate rules/measures-detail.json`, runs weekly and on every pull request that changes
the rules, the SQL rule engine, the parsers or the measuring tool. It fails when a rule no longer
detects a recording it detected when the committed detail was measured, a SigmaHQ rule no longer
fires on its own sample, a recording is no longer read, or a high or critical rule raises more
findings on a clean machine. A change that means to do one of those commits the two files the
run uploads.

## Importing Sigma and Sublime rules

**import Sigma** and **import Sublime** in the Rules page take one `.yml` file or a `.zip` of a
rules folder, convert it on the server (`POST /api/rules/convert/sigma` and
`POST /api/rules/convert/sublime`), show what translated and what was skipped with the reason,
and add the converted rules as custom rules. Nothing is stored on the server. The same
conversion from a shell, on an instance with accounts off:

```
curl -H "X-Forensic-Client: remn" -F file=@rule.yml http://127.0.0.1:8000/api/rules/convert/sigma
```

The Sigma converter takes Windows log sources: the log source becomes channel and event id
conditions, field names become the parser's columns (anything else is reachable as
`data.<Field>`), value modifiers become operators, and the condition becomes `any_of`, `all_of`
and `not`. Encoded values (`base64`, `base64offset`, `utf16`, `wide`) are expanded into the
literal strings they can appear as, matched with case kept; `cased` selects the `_cs` operators;
a regular expression keeps its case unless `|i` says otherwise. A rule is skipped, never
weakened, when its meaning cannot be kept: for example when it needs `fieldref`, `expand`, a time-part modifier, an aggregation
(`| count() > 5`), a `timeframe`, `N of` other than `1 of` and `all of`, a product other than
Windows, a correlation, or a wildcard inside an encoded value; an `informational` rule is
skipped as enrichment. The ids become `sigma-<Sigma id>`.

The Sublime converter takes MQL rules over mail. A rule that relies on Sublime's own services
(classifiers, link analysis, sender profiles, file explosion, screenshots, WHOIS) or compares
two fields is skipped. A rule converted with an approximation (the whole body read for the
current thread, several predicates inside one `any()` matched independently) is kept with a
warning, which the import dialog lists. The ids become
`sublime-<Sublime id>`.

The bundled packs are refreshed with the same converters, from a pinned upstream commit:

```
python tools/import_community_rules.py all --download
python tools/import_community_rules.py sigma --zip sigma-master.zip --sha <commit>
```

Each pack is written under `rules/community/<pack>/` with `pack.json` (upstream repository,
commit, licence, counts, skip reasons), the upstream `LICENSE`, and `skipped.json`. A refresh is
one commit, and the measure gate runs on it.

## Patterns that backtrack in the browser engine

On the server the store runs `re` with RE2, whose time grows linearly with the text. The browser
engine runs the same pattern with JavaScript's `RegExp`, which backtracks: a pattern that can
match the same characters in many ways tries each of them before it fails, and on a long field of
the evidence (a command line, a script block, a mail header) that holds the rules worker for
seconds, or minutes past 100,000 characters. The timing tests read every `re` pattern of the own
rules and try it on values built to make it backtrack.

A rule's `re`, `not_re` and `re_cs` therefore read the first 65,536 characters of a value (counted
as characters, not bytes), in both engines: as many as the parsers keep of a command line or a
script block. A pattern that tries a run again from each occurrence of a token takes a time that
grows with the square of the value: minutes on a mail body of a few hundred thousand characters,
seconds at most on 65,536. A match past that point is not found, and `not_re` holds there. The
rule says so: the Rules view shows "long values read in part" beside it, with how many of its rows
held a longer value in a field its regular expressions read (a value the parser already cut,
65,536 characters and `…`, is one of them), and the message at the end of the run says how many
rules read one. The rows of a `then` follow-up are read the same way and not counted. An
analyst's own search and filter read the whole value.

Shapes that backtrack, with what to write instead:

| Shape | Example | Instead |
| --- | --- | --- |
| A repetition inside a repetition, or over alternatives that overlap | `(a+)+b`, `(a\|aa)*b` | One repetition: `a+b`, `a*b`. |
| Two runs side by side that take the same characters | `^[a-z]:\\[^"]* [^"]*\.exe` (both runs take spaces) | Stop the first run at the character that starts the second: `^[a-z]:\\[^" ]* [^"]*\.exe`. |
| Two runs around a separator they both take | `^\\[^\\]+-[^\\]+-[0-9]+-std(in\|out\|err)$` (both take dashes) | Exclude the separator from one run: `^\\[^\\][^\\-]*-[^\\]*[^\\]-[0-9]+-std(in\|out\|err)$`. |
| A run at the start of an unanchored pattern | `\s+$`, `\s*,` | Anchor it, or start with a literal: the engine tries again from every position. |
| A token, any text, then another token | `netsh(\.exe)?\s+trace\s+start\b[^\n]*capture=yes` | When the order does not matter, `contains_all: [netsh, trace start, capture=yes]`; otherwise bound the text between them: `[^\n]{0,1000}capture=yes`. |

The last shape is tried again from each occurrence of the first token, so its time grows with
the number of occurrences times the length after them. Keeping what it matches would take an
atomic group or a lookahead, which RE2 does not read, so the text between the tokens is bounded
instead: `[^\n]{0,1000}` rather than `[^\n]*`, since RE2 repeats up to 1,000. A command line
with more than 1,000 characters between the two tokens is then not matched. Every own rule of
this shape bounds it, so no own rule keeps it. The browser runs rules in a worker, so a slow
value delays the run of the rules, not the page. A new rule of this shape is bounded the same
way or written as `contains_all`; one that cannot be is listed in the timing test with its
reason.

Other points that keep a pattern linear and portable:

- A negated class that cannot take the character that follows it (`[^"]*"`) gives each
  character one way to match.
- `contains`, `startswith`, `endswith` and `contains_all` say most of what a pattern is used for
  and run in linear time in both engines.
- Patterns run without regard to case under `re`; `(?i)` is needed only with `re_cs`.
- The pattern is matched against the text of the field, against each item of a list (flags,
  recipients), and against the JSON text of an object. `^` and `$` anchor that text, not a line
  of it, unless the pattern starts with `(?m)`.
