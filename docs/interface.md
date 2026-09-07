# Interface

The pages follow the order of an investigation. Evidence goes in on the Evidence page;
Events and Mails are the two tables with their search bar, and the Timeline draws both;
Findings, Chains, Rules and Indicators are what the detection produced; the AI analyst,
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

## Events and Mails

Events and Mails share one query bar (search, time range, conditions, business hours,
regex, saved searches, and a plain-language "ask" that the model turns into a filter)
and a histogram of the current result set above the table; clicking a bar narrows the
time range to that bucket.

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
[Attack chains](chains.md)). Incidents are derived from the findings table, nothing new
is stored, and setting an incident's status sets every member. Flat, rule, entity and
source views keep the per-rule detail. Severity tiles show the change since the last run,
and the flyouts carry About, Investigation (entity pages, referenced rows), Insights
(prevalence of the entities in the case, related chains, false-positive history of the
rule) and Notes. The ATT&CK tab counts techniques observed against the enabled rules that
map to them.

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

## Chains

The Chains page reads a chain as a story: the left list ranks them by severity and
score, the middle column is the ordered narrative (time and offset from the seed mail,
a source icon for mailbox, Microsoft 365 or host, what happened, and the artifact or
finding that tied the step to the seed), and the right column details the selected step
and opens its rows. `j` and `k` move between steps. The score's parts show under the
chain header.

The Graph tab draws the same chain as a time-ordered swimlane graph (attacker side,
mailbox, identity, Microsoft 365, host, machines and IPs): repeated actions fold into
one node, routine runs into one grey dot, and every artifact that ties a step to the
mail is a labelled edge back to the seed's domain, attachment or sender. Its "all
chains" mode draws every chain of the case against the sender addresses, link domains,
IPs and hosts they share, and lists the shared ones.

## Rules and Indicators

The Rules page lists the bundled rules, the community packs with a toggle each, and the
custom rules, with an editor, the import buttons, and after a run the reason every
silent rule found nothing. The Indicators page lists the IPs, domains, URLs and hashes
extracted from the evidence with their counts and, when external lookups are enabled
for the case, their reputation; it exports STIX 2.1 and CSV.

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
with the case bundle.

### The model in the review

The model can take part in three ways. "Ask the model to decide" on a card asks for a
proposal on that item (decision, severity, in or out of the report, findings to unlink,
reason, and the narrative or note) and shows it as a box the analyst applies or
dismisses. In the AI analyst chat the model records the same kind of proposal with the
`suggest_review` tool, on a finding or a chain, after looking at a chain with
`get_chain`; proposals show on the Review page next to their item.

"Triage with the model" sends the whole queue (undecided items by default, or
everything) in batches of four (Ollama) or eight (Claude Code) and writes each decision
straight away, tagged "AI" in the rail and on the card with the model's reason. The same
pass writes the text the report prints: a narrative for each chain and a note for each
incident. A text the analyst wrote is kept; one the model drafted earlier is replaced,
and editing it makes it the analyst's. When the switch in the triage dialog is on, the
pass ends by drafting the executive summary from the reviewed chains and incidents. A
popup then lists every decision (item, decision, severity before and after, in or out of
the report, unlinked findings, reason) with undo per line or for the whole run, and
"last AI triage" reopens it.

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

The printed report (`frontend/src/data/reportHtml.ts`) is one self-contained HTML file in
REMN's own look, laid out for A4 and print-to-PDF. The cover carries the wordmark (the
Gulax face embedded as base64 from the app's own files), an accent rule, the case name,
five key numbers, a severity bar, the decision counts and a numbered table of contents.
Then come numbered sections: the executive summary, the evidence with its hashes, the
attack chains (with narrative, step table and the findings linked to them, at the chosen
detail level), the other incidents with their notes and member findings at the effective
severity, the indicators, the case timeline, the tasks, the notes, the findings in time
order and the case settings.

Chains are cards with a severity pill, the verdict, a score meter split into its parts,
the narrative in an accent block, the swimlane picture, the step table with a lane mark
per source and the linked findings; incidents are cards with the note, the findings and
their ATT&CK chips; the case timeline is a vertical line with severity dots. With "chain
graphs" on (the default), each printed chain carries its swimlane graph as a picture,
drawn off-screen from the same model as the Chains page in the report's light palette,
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

## Interface tests

Component tests run under jsdom with `fake-indexeddb` (`*.test.tsx` next to the views:
the Findings queue grouping and status writes, the severity-override reset, the Case
notes page). The engine, incident, review, report and data-layer tests stay in Node.
`npx vitest run` runs all of them; the jsdom files are the slow ones.
