# Interface

The pages follow the order of an investigation. Evidence goes in on the Evidence page;
Events and Mails are the two tables with their search bar, and the Timeline draws both;
Findings, Stories, Graph, Rules and Indicators are what the detection produced; the AI analyst,
Review and Case notes are where the analyst works the case; Report prints it; Settings
holds the case context the rules and the model read. This page describes each, the
keyboard, the review workflow and the report, and closes with the tests that cover the
pages.

## Look and keyboard

The interface follows the conventions of analyst tooling (Elastic Security, Sentinel,
Timesketch, DFIR-IRIS): neutral surfaces with colour reserved for severity and status,
dense tables with a frozen time column, a flyout for details instead of a page change,
and pivots on every entity value. Light is the default; the switch in the top bar stores
the choice in this browser and both modes share the same tokens in
`frontend/src/ui/theme.css`. The wordmark and view titles use
[Gulax](https://velvetyne.fr/fonts/gulax/) by Morgan Gilbert (Velvetyne, SIL Open Font
License 1.1; the licence and copyright files ship in `frontend/public/fonts/`). The
wordmark opens a short intro page: one sentence, what goes in, what comes out, where it
stays. The sidebar collapses to an icon rail with the button at its foot, remembered per
browser.

On every list, `j` and `k` move the selection and `/` focuses the search. The Review page
adds `r`, `e`, `f` and `x` for its decisions.

## Evidence

The Evidence page is the drop zone and the chain of custody: every file with its kind,
size, row count, SHA-256 computed in the browser, integrity state and the time it was
added. "Verify" re-hashes a copy of the file and compares. Removing a file deletes
everything derived from it, as described on the [storage page](storage.md).
A file that records a gap in itself (records missing from its numbering, a chunk that
fails its checksum, an audit log export cut at a service limit) carries a "gaps" badge,
and its detail lists what it cannot show.

## Events and Mails

Events and Mails share one query bar (search, time range, conditions, business hours,
regex, saved searches, and a plain-language "ask" that the model turns into a filter)
and a histogram of the current result set above the table; clicking a bar narrows the
time range to that bucket. The Mails search covers the sender, the recipients, the
subject, the links, the attachment names and hashes and the full body, which the browser
store keeps apart from the mail row. Values picked in one facet are alternatives (any of
them); picking one again removes it. A facet lists its 500 most frequent values, and its
search box reaches every stored value; a field with more distinct values than one import
counts says so. Times follow the display setting and the column headers say which zone
they show; the time range is always entered in UTC. An entry added to the case timeline
from a row that has no event time (a collection snapshot) says "no event time" rather
than taking the time of the click.

The Events page's "stack" button turns the table into a stack of one field, the
least-frequency view: each distinct value among the events the current filter and search
keep, with its number of events, the number of hosts it was seen on ("on 1 of 12 hosts",
the hosts named when five or fewer) and its first and last time. The rarest come first,
fewest hosts and then fewest events, or the most frequent on request. The fields are the
image and parent image, process and parent process names, command line and parent command
line, path, service name and file, scheduled task, object name, file created, image
loaded, subject and target user, workstation, IP and destination IP, DNS query, and the
provider and event ID pair. Paths, programs, services and accounts group without regard to
case, as Windows names them (the value shown is one of its spellings); command lines keep
their case. Hosts are counted by the computer name without its domain, as the stories count
them, and N is the number of hosts among the events that have the field. The stack lists
500 values and says how many exist when there are more (a button shows up to 5,000), and
how many matching events have no value. Clicking a value filters the events to it and
returns to the table. Both stores give the same stack; `tests/fixtures/parity/stacks.json`
holds it.

Selecting a mail opens a bottom pane: the message (text, or HTML in a sandbox), headers,
hops, URLs, attachments, a Related tab (findings on the mail and the recipients' host and
cloud events from 15 minutes before to 72 hours after delivery) and JSON, with an
evidence-context column on the right (entities, sender history from the baseline pass,
findings, score drivers, source file). The pane is resizable (drag the grip above it,
double-click to reset) and can be expanded over the table; its header keeps the subject
and sender on one line each and shows the strongest flags with the quieter observations
behind a "+N more" link, so the tabs and the body stay reachable at any window size.

The Mails page also holds the two actions that recompute a case's mail analysis:
"baseline senders" and "rescore + refresh findings", both described on the [detection
page](detection.md).

## Entity pages

Every user, host, IP, sender address or domain value opens an entity page as a flyout
over the current view: first and last seen, counts, a merged timeline of the entity's
findings, mails and events, insights (what else the entity was seen with, sender
history), and pivots to the filtered Events or Mails lists or to the analyst.

## Timeline

The Timeline page draws events and mails over time, one chart per source that has data,
with the curated case-timeline entries (see Case notes below) marked on it. Clicking a
point narrows the lists to that time.

## Findings

The Findings page is a triage queue. Its default unit is the incident: every finding on
one mail (the rules that fired, the score band) is one line, event findings about the
same user, host or IP within six hours are one line, the way Sentinel and Elastic group
alerts on shared entities, and a chain with the findings on its steps is one line (see
[Attack chains](chains.md)). An entity incident is about one person, whatever the
spelling: `daniel.roy`, `NORTHSTAR\daniel.roy` and `daniel.roy@northstar.example` are one
account when the NetBIOS domain is the first label of a domain seen in the case, and a
bare name joins the one domain that has it (or the internal one, from Settings, when
several do). Accounts of different domains never merge, and the incident lists the other
spellings it was seen as. Incidents are derived from the findings table, nothing new
is stored, and setting an incident's status sets every member. Flat, rule, entity and
source views keep the per-rule detail. Severity tiles show the change since the last run,
and the flyouts carry About, Investigation (entity pages, referenced rows), Insights
(prevalence of the entities in the case, related chains, false-positive history of the
rule) and Notes. The ATT&CK tab counts techniques observed against the enabled rules that
map to them. A finding of a rule never seen to detect what it looks for on a recorded attack
is marked "lead" in the list, and the flyout says what the rule's measure shows: the
recorded attacks it fires on, and how often it fires on the logs of clean machines (see
[measured rules](detection.md#measured-rules)).

Findings with a saved review severity override show an asterisk and the original rule
severity in their detail, and the incident uses the review severity too. "Reset to rule
severity" clears only the override; review status, notes and other decisions remain,
and the reset also clears the copy kept across rule reruns, so the override does not
return.

Findings are only as fresh as the last rule run, so three things keep them aligned with
the evidence. The enabled rules run automatically when an ingest finishes (a case
setting, on by default). A banner on the Findings page says when evidence was added, a
rescore did not finish its findings refresh, or a sender baseline ran after the last
run, with a one-click run; a second banner lists rules that failed in the last run, so
their findings are stale or missing rather than silently absent. And the score bands are
mirrored by rules, so a mail the Mails page paints high or critical always has at least a
score-band finding. A status carried over from an earlier evaluation of the same finding
key is labelled as such in the flyout. Findings keep up to 5,000 row ids, so every mail
of a mailbox-wide burst stays linked from its own preview pane.

## Stories

The Stories page reads the case as one story per person, or per host when the records name
no one, and per incident ([Stories](stories.md) explains how). The left list ranks the
stories by score, each with its worst severity, its headline (the worst finding of each
phase, in order), a strip of the fifteen ATT&CK tactics lit where it has steps, its span and
its counts; a search and a people/hosts filter narrow it. A case with findings and no stories
yet is read into stories when the page opens; **Rebuild stories** reads it again. Stories the
case has moved past (a rule run, a false positive, a severity set by hand, evidence or settings
changed since) are built again when the page opens if the last build was small, and otherwise
say they are out of date, with a button to rebuild. Notes and decisions whose story a rebuild no
longer holds are listed under the stories, to attach to the open story or delete. A decided
story carries its decision in the list ("confirmed incident", "benign" and so on, dimmed when
dismissed), a story with others merged into it says "+N merged", and the second part of a split
story is listed on its own.

The selected story opens with its subject (the account, whose forms and joins are one click
away, or the host), its score, span and the confidence of its ties, a few plain sentences, the
sources its findings name, its hosts, its campaign, a link to review its phishing chain, and the
analyst's note, checked against the story's own records. The **story decision** bar under it
sets open, reviewed, confirmed incident, benign or false positive, with a reason (required for
the last three); beside it, the timeline exports as CSV, JSON or Markdown (or copy the
Markdown), and **merge into another story** opens a form with the story to merge into and the
reason, which asks in the page before merging two organisations' stories. Under it, the phase
rail shows the tactics in ATT&CK's order, lit and numbered in the story's order; a tactic
filters the timeline. **Story** is the timeline by day: time and phase in the gutter, a mailbox,
Microsoft 365 or host icon, what happened, the host, address and accounts, the findings with
their rule's measure, and why the step is in the story, with a dot for how surely; folded runs
show their count. `j` and `k` move between steps. A step's pane gives its phase and why, why it
is in the story, each finding with what its rule was measured to be worth, the session, hops and
process tree around it, the links its records support in the relationship graph (with their
review), and opens its records. Its **Your decision** section confirms or disputes the step with
an optional reason (a disputed step is struck out and left out of the phases and severity; "also
mark the finding false positive" writes its findings' status too), takes its records out of the
story ("not part of this story") or splits the story there, each of the last two with a reason.
**Lineage** lists the story's hops, logon sessions and process trees; **Who is who** the forms
of the account, how sure each join is, and the accounts kept apart (namesakes in other
organisations, bare names several accounts share); **Where it stops** what its hosts' evidence
cannot show and the case's own file gaps; **Decisions** every decision on the story with its
reason and date, each with its undo (set back to open, take back, put back, undo the merge, undo
the split), and the step decisions a rebuild could no longer place; **JSON** the story as data.
A story or a step can go to the case timeline (its entry opens that step again, or says the
story is gone), and **ask the analyst** hands the story to the AI view, with what the records
wrote (step titles, names, reasons) between evidence markers, never as the analyst's own words.

**Campaigns** groups the stories that share the attacker's infrastructure and lists the
accounts outside them that the same sources reached; flagged mails and failed logons in no
story are grouped by sender domain and address. **Explore** browses the relationship graph:
its build controls, the entities with a search and a type filter, the neighbours of the
selected one and its links with their review.

## Graph

The Graph page draws the attack chains that building the stories keeps. The left list
ranks the chains, each with its severity, identity, seed, span, score and step count.
**this chain** lays the selected chain out as a swimlane, time left to right and one lane
per source, with routine runs folded into one node; **all chains** draws every chain against
the sender addresses, link domains, IPs and hosts they share, and a chain clicked there opens
in its own graph. A step clicked in the graph opens its pane: source, time, rows, what ties
it to the seed and its findings, and **Open** takes it to its mail or events. `j` and `k`
move between steps. A case with no chains yet points to Stories, which builds them.

## Rules and Indicators

The Rules page lists the bundled rules, the community packs with a toggle each, and the
custom rules, with an editor, the import buttons, and after a run the reason every
silent rule found nothing. Its "measured" column gives each rule's measure (detects, lead,
misses its sample, fires on clean machines, changed, needs settings) with the sentences
behind it on hover, and a filter lists the leads, the rules that miss their own test sample
or those that fire on clean machines. The Indicators page lists the IPs, domains, URLs and hashes
extracted from the evidence with their counts and, when external lookups are enabled
for the case, their reputation; it exports STIX 2.1 and CSV. The STIX bundle carries every
value as a cyber-observable and makes an indicator only of the values a reputation check
flagged, with identifiers derived from the content (an export imported twice is the same
objects), an identity for the case and a TLP:AMBER marking. On a browser-only server the
page offers no lookups, which the server refuses; it says so and offers the exports.

## AI analyst

The AI analyst page runs the agent described on the [AI page](ai.md): a question or a
playbook card starts an investigation that the model plans and carries out through
read-only tools, with the step budget, "answer now" and "stop" in the toolbar. The chat
shows each round as its tool calls and results (the results on demand), and the answer
with its citations as chips that open the row, or struck through when no tool returned
them. The side panel has four tabs: the plan with the step count and the context used;
the inbox, where every change the agent proposes waits to be accepted (one by one, edited,
or all at once), rejected, or undone after acceptance; the hypothesis board; and the AI
ledger with a check of its hash chain. Past investigations are listed on the left.

## Review

The Review page is where a case gets cleared. It walks the analyst through every attack
chain (by score) and then every incident (by severity), one card at a time, with `j` and
`k` to move and `r`, `e`, `f` and `x` for reviewed, confirmed, false positive and
in-or-out of the report.

A chain card takes a verdict (confirmed, unsure, benign), a severity, an inclusion switch
and a narrative that replaces the automatic summary in the report; "draft with the
analyst" asks the model for a first version from the chain's steps alone. It lists the
findings linked to the chain, each with an "unlink" button, and "unlink all". An
incident card takes a decision (which writes the status of every member finding), a
rescore (members above the target take an override, the rule severity stays visible), an
inclusion switch and a note printed with the incident. The same bar sets what the report
contains: the severity floor, the chain detail level (steps tied to the mail or carrying
a finding, plus weighted steps, or every step), the chain graphs, and the sections
(chains, case timeline, tasks, notes, indicators, evidence, false positives, reviewed
items only). Decisions live on the findings and in the case's key-value store and travel
with the case bundle. The verdict bar counts the stories decided on the Stories page as the
report does: a confirmed story as a confirmed incident, a reviewed one as reviewed, a benign or
false positive one with the false positives.

### The model in the review

The model can take part in three ways. "Ask the model to decide" on a card asks for a
proposal on that item (decision, severity, in or out of the report, findings to unlink,
reason, and the narrative or note) and shows it as a box the analyst applies or
dismisses. On the AI analyst page the agent queues the same kind of proposal with the
`propose_decision` tool, on a finding or a chain, citing the rows it read; decision
proposals show on the Review page next to their item and in the approval inbox of the AI
page, and accepting one in either place settles it in both.

"Triage with the model" sends the whole queue (undecided items by default, or
everything) in batches of four (Ollama) or eight (Claude Code) and records a proposal for
each item: a decision, a severity, whether the report carries it, a narrative or a note,
and a reason. Nothing is written. Each proposal waits on its item, tagged "AI", until the
analyst applies or dismisses it, exactly like a proposal from the chat. A popup lists the
proposals of the pass (item, decision, severity before and after, in or out of the
report, reason). Text in the evidence can try to steer a model, and a pass that wrote its
answers straight away could take a critical incident out of the report with nobody
looking; a proposal to lower a severity or leave an item out deserves a second look. The
executive summary is drafted from the Report page.

The triage prompt is `SYSTEM_TRIAGE` in `backend/services/ai/prompts.py`. The reply is a
JSON array checked item by item: unknown ids, wrong words and unlink ids that are not
linked findings are dropped and listed as "not applied", and the words models use
instead of the exact decisions (escalate, dismiss, false positive on a chain, …) are
mapped to the item's vocabulary. A decision made by the model is a decision like any
other: changing it on the card makes it the analyst's. What keeps evidence text from
steering the model is on the [security page](security.md).

## Report

The Report page assembles the report from the Review page's decisions and says how many
items still have no decision. It holds the executive summary (drafted by the model or
written by hand), the case bundle export and import, and a preview. "Download HTML"
saves the report, "print / PDF" opens the browser's print dialog on it, and "open in a
tab" shows it as its own page for the browser's print-to-PDF. Printing runs from a frame
that runs no script but keeps the app's origin, which the browser requires before the
page may call print on it.

Before it is issued, the Report page runs a preflight: the rules ran on every file,
every file was read completely and has a verified digest, every item has a decision, the
decisions taken from the model's proposals were checked, every confirmed item is
printed, and what the report says holds against the rows it cites. The report is a draft, and its cover says so, until each check passes or is
waived with a reason; "issue as final" then prints it as final with the time, and the
waivers appear in "Where it stops". A new open check (evidence added, a rule run that
failed) returns it to draft.

"Where it stops" begins with what the evidence cannot show (`frontend/src/data/evidenceGaps.ts`),
each statement checkable against the evidence: records missing from an event log's
numbering, write times that step back where no clock change or restart explains it (a
record put in later), clocks set back (the times either side do not give the order of
events), chunks that fail their checksum, record numbers
in none of the files of one log (a missing archive), logs that start after the first
finding (overwritten or not collected), Unified Audit Log exports of exactly 5,000 or
50,000 records (cut at a service limit), event records read from an XML export (no record
numbering to check them against), MailItemsAccessed throttled for a mailbox (item reads
not recorded for 24 hours), and Entra sign-ins that start after the first finding (Entra
keeps them 7 or 30 days). The first finding is the earliest one of medium severity
or above that is not a false positive.

What the report says about rows is read back against the rows before it prints
(`frontend/src/data/claims.ts`), through the case's data source, so a browser case and a
server case are checked alike:

- each printed finding: the rows it cites (the first 50) are still in the case, match its
  rule as the rule is now, hold the values it names and begin at its time;
- each chain narrative and incident note: the addresses, accounts and hashes it names are in
  that chain's or incident's own rows;
- the executive summary: the addresses and hashes it names are somewhere in the evidence.

A claim is verified, unsupported (a row it cites is gone, or a value it names is in none of
its rows) or contradicted (its rows say otherwise). Each rule's line in the report reads "rows
checked", "rows missing" or "rows disagree" and names its first row by its place in its own
file (`frontend/src/data/recordKeys.ts`): an event log's record number with the computer and
channel, a mailbox's message number, a cloud record's own id, under the file whose SHA-256
the evidence table prints. REMN's row ids change when evidence is removed and added again or a
bundle is imported into another browser; these references do not, and a reader can check them
in any tool. A text that names what its rows do not hold says so under it, every claim that
does not hold is listed under "Where it stops" and on the Report page, and the preflight keeps
the report a draft until they all hold or the analyst waives the check with a reason.

The printed report (`frontend/src/data/reportHtml.ts`) is one self-contained HTML file in
REMN's own look, laid out for A4 and print-to-PDF. Every time in it is UTC, whatever the
display setting. Its verdict is about the case, not about what prints: a confirmed item
below the severity floor or left out still counts, and the cover says how many are not
printed. Its confidence is never "high" while a file was not read completely (a parse
error, a limit, a skipped archive member, listed in the evidence table's "read" column),
while the rules have not run or evidence arrived after the last run, and it says
indicators were checked only when a lookup actually ran on them. "What happened" says
when it lists only the first of more items. The cover carries the wordmark (the
Gulax face embedded as base64 from the app's own files), an accent rule, the case name,
five key numbers, a severity bar, the decision counts and a numbered table of contents.
Then come numbered sections: the executive summary, the evidence with its hashes, the
attack chains (with narrative, step table and the findings linked to them, at the chosen
detail level), the other incidents with their notes and member findings at the effective
severity, the indicators, the case timeline, the tasks, the notes, the findings in time
order, "How AI was used" when a model took part (runs, models and where they ran, tool
calls, what it proposed and what became of it, whether the AI ledger's hash chain holds)
and the case settings.

Each rule's line in the report is marked "lead" when the rule was never seen to detect what
it looks for, and notes when it also fires on clean machines; the method says how many of the
rules behind the printed findings detect recorded attacks, and "Where it stops" counts the
findings that come from leads.

Stories come first ([Stories](stories.md#in-the-report)): a card per story with its phases in
order, what marks each, the analyst's note, the analyst's decisions on it and where its evidence
stops; a story decided a confirmed incident counts in the verdict, one decided benign or false
positive is not printed. Chains are cards with
a severity pill, the verdict, a score meter split into its parts,
the narrative in an accent block, the swimlane picture, the step table with a lane mark
per source and the linked findings; incidents are cards with the note, the findings and
their ATT&CK chips; the case timeline is a vertical line with severity dots. With "chain
graphs" on (the default), each printed chain carries its swimlane graph as a picture,
drawn off-screen from the same chain model the Review page reads, in the report's light palette,
and a report with several chains opens with the shared-entity graph and its insights. The
pictures are PNG data URLs embedded in the HTML, so the report stays one file. Runs of
the same step (the same title, source, machine and ties in a row) print as one row with a
count and a time span, at most 60 rows per chain, and table headers repeat on every page.
Every string from the case is escaped, markdown fields go through the app's renderer, and
only PNG data URLs the app drew itself are embedded.

## Case notes

Case notes hold what the analyst decides to keep: a curated timeline (entries added with
the "timeline" button on findings, mails, events and chain steps, each linked back to its
row, or typed by hand), a task checklist and markdown notes. The three are stored with
the case, travel in the case bundle, and are printed in the report before the automatic
timeline of findings.

## Settings

Settings holds the case's context and the analyst's preferences: the case name, analyst
and notes; the storage mode and the conversion to the server store; the organisation
context the rules read (internal domains, VIP and organisation display names, brands,
trusted senders, with a scan that suggests trusted senders from the case); the Windows
context (internal IP ranges, expected sign-in countries, admin and service accounts);
business hours and time zone; whether external reputation lookups are allowed; and the
AI transport and model, described on the [AI page](ai.md).

At the bottom are the two destructive actions. "Delete all case data" empties the case
(every row, finding, note and session, and the server store when it has one) and keeps
the case with its settings. "Delete this case" removes the case itself, custom rules and
settings included, and switches to the most recently updated remaining case, or to a
fresh one when none is left. Both ask for confirmation and neither can be undone.

## Interface tests

Component tests run under jsdom with `fake-indexeddb` (`*.test.tsx` next to the views:
the Findings queue grouping and status writes, the severity-override reset, the Case
notes page). The engine, incident, review, report and data-layer tests stay in Node.
`npx vitest run` runs all of them; the jsdom files are the slow ones.
