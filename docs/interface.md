# Interface

_The pages, the review workflow, the report, interface tests._

## Interface

The interface follows the conventions of analyst tooling (Elastic Security, Sentinel,
Timesketch, DFIR-IRIS): neutral surfaces with colour reserved for severity and
status, dense tables with a frozen time column, a flyout for details instead of a
page change, and pivots on every entity value. Light is the default; the switch in
the top bar stores the choice in this browser (`remn-theme`) and both modes share the
same tokens in `frontend/src/ui/theme.css`. The wordmark and view titles use
[Gulax](https://velvetyne.fr/fonts/gulax/) by Morgan Gilbert (Velvetyne, SIL Open Font
License 1.1; licence and copyright files ship in `frontend/public/fonts/`). The wordmark
opens a short intro page: one sentence, what goes in, what comes out, where it stays.

The Findings view is a triage queue. Its default unit is the incident: every finding
on one mail (the rules that fired, the score band, the attack chain it seeded) is one
line, and event findings about the same user, host or IP within six hours are one
line, the way Sentinel and Elastic group alerts on shared entities. Incidents are
derived from the findings table (nothing new is stored); setting an incident's status
sets every member. Flat, rule, entity and source views keep the per-rule detail.
Severity tiles show the change since the last run, `j` / `k` / `/` move and search,
and the flyouts carry About, Investigation (entity pages, referenced rows), Insights
(prevalence of the entities in the case, related chains, false-positive history of
the rule) and Notes. The ATT&CK tab counts techniques observed against the enabled
rules that map to them.

Findings with a saved review severity override show an asterisk and the original
rule severity in their detail. The incident uses the review severity too. In an
incident or finding, **reset to rule severity** clears only the severity override;
review status, notes and other decisions remain. The reset also clears the saved
override used during rule refreshes, so it does not return after rerunning rules.

Findings are only as fresh as the last rule run, and that is where the Mails and
Findings pages used to disagree: a mail scored at ingest showed as phishing on the
Mails page while the Findings page still reflected an older run. Three things keep
them aligned now. The enabled rules run automatically when an ingest finishes (case
setting, on by default). A banner on the Findings page says when evidence was added,
a rescore did not finish its findings refresh, or a sender baseline ran after the last
run, with a one-click run; a second banner lists rules that failed in the last run
(their findings are stale or missing rather than silently absent). And the score bands
are mirrored by rules: a mail the Mails page paints high (60-79) or critical (80+)
always has at least a score-band finding, so the specific indicator rules can stay
precise. A status carried over from an earlier evaluation of the same finding key is
labelled as such in the flyout. Findings keep up to 5,000 row ids (was 500), so every
mail of a mailbox-wide burst stays linked from its own preview pane.

Events and Mails share one query bar (search, time range, conditions, business
hours, regex, saved searches, plain-language "ask") and a histogram of the current
result set above the table; clicking a bar narrows the time range to that bucket.
Selecting a mail opens a bottom pane: the message (text or sandboxed HTML), headers,
hops, URLs, attachments, a Related tab (findings on the mail and the recipients'
host and cloud events from 15 minutes before to 72 hours after delivery) and JSON,
with an evidence-context column on the right (entities, sender history from the
baseline pass, findings, score drivers, source file). The pane is resizable (drag the
grip above it, double-click to reset) and can be expanded over the table; its header
keeps the subject and sender on one line each and shows the strongest flags with the
quiet observations behind a "+N more" link, so the tabs and the body stay reachable at
any window size. `j` / `k` move the selection, `/` focuses the search. The sidebar
collapses to an icon rail (button at its foot, remembered per browser).

Every user, host, IP, sender address or domain value opens an entity page as a
flyout over the current view: first and last seen, counts, a merged timeline of the
entity's findings, mails and events, insights (what else the entity was seen with,
sender history), and pivots to the filtered Events or Mails lists or to the analyst.

Chain scores are bounded and explained: seed mail risk (0-30), steps tied to the
mail by an artifact (0-30), weight of the non-routine steps with diminishing returns
(0-20), the worst finding on the seed and on a step (0-15), and more than one source
involved (0-5). A chain with no artifact link cannot be critical (cap 79), and one
with neither a link, a finding-bearing step nor a strong step stays medium at most
(cap 54). The Chains page shows the breakdown under the chain header.

Chains are read as stories: the left list ranks them by severity and score, the
middle column is the ordered narrative (time and offset from the seed mail, source
icon for mailbox / Microsoft 365 / host, what happened, and the artifact or finding
that tied the step to the seed), and the right column details the selected step and
opens its rows. `j` / `k` move between steps. The Graph tab draws the same chain as a
time-ordered swimlane graph (attacker side, mailbox, identity, Microsoft 365, host,
machines and IPs): repeated actions fold into one node, routine runs into one grey dot,
and every artifact that ties a step to the mail is a labelled edge back to the seed's
domain, attachment or sender. Its "all chains" mode draws every chain of the case against
the sender addresses, link domains, IPs and hosts they share, and lists the shared ones.

An attack chain and the findings whose rows are its steps are one item. When
the chains are built, every finding whose rows all sit among a chain's steps
(or on its seed mail) joins that chain's incident, so a phishing mail's rule
hits and the findings on the recipient's later logons are never listed twice:
once inside the chain and once on their own. The chain's verdict writes the
status of its linked findings (confirmed → confirmed, benign → false positive,
unsure → reviewed). A finding that does not belong can be unlinked on the
Review page (one, or all of a chain): it leaves the chain, goes back into the
queue on its own and keeps its own decisions; "link back" undoes that. Findings
with more than 500 rows describe a pattern rather than steps and stay separate.
Unlinks, rescoring and report exclusions survive a rule rerun like statuses and
notes do.

The Review page is where a case gets cleared. It walks the analyst through every
attack chain (by score) and then every incident (by severity), one card at a time,
with `j` / `k` to move and `r` / `e` / `f` / `x` for reviewed, confirmed, false positive
and in-or-out of the report. A chain card takes a verdict (confirmed, unsure, benign),
a severity, an inclusion switch and a narrative that replaces the automatic summary in
the report; "draft with the analyst" asks the local model for a first version from the
chain's steps alone. An incident card takes a decision (which writes the status of every
member finding), a rescore (members above the target take an override, the rule
severity stays visible), an inclusion switch and a note printed with the incident. The
same bar sets what the report contains: the severity floor, the chain detail level
(steps tied to the mail or carrying a finding, plus weighted steps, or every step), and
the sections (chains, case timeline, tasks, notes, indicators, evidence, false
positives, reviewed items only). Decisions live on the findings and in the case's
key-value store, travel with the bundle, and the Report page prints from them: attack
chains with narrative, step table and the findings linked to them, the other
incidents with their notes and member findings at the effective severity, then
indicators, timeline, tasks, notes and the findings timeline. The Report page says
how many items still have no decision.

The printed report (`frontend/src/data/reportHtml.ts`) is one self-contained
HTML file in REMN's own look, laid out for A4 and the browser's print-to-PDF: the
wordmark (the Gulax face embedded as base64 from the app's own files, OFL) and
an accent rule on the cover, the case name, five key numbers, a severity bar,
the decision counts, a numbered table of contents, then numbered sections.
Chains are cards with a severity pill, the verdict, a score meter split into
its parts (seed, ties, steps, findings, sources), the narrative in an accent
block, the swimlane picture, the step table with a lane mark per source and the
linked findings; incidents are cards with the note, the findings and their
ATT&CK chips; the case timeline is a vertical line with severity dots. Every
string from the case is escaped, markdown fields go through the app's renderer,
and only PNG data URLs the app drew itself are embedded. Runs of the same step (the
same title, source, machine and ties in a row) print as one row with a count and
a time span, at most 60 rows per chain, and table headers repeat on every page.
"Print / PDF" prints from a frame that runs no script but keeps the app's origin
(a sandboxed frame without it makes the browser refuse the print call); "open in
a tab" shows the report as its own page for the browser's print-to-PDF.

The model can take part in the review in three ways. "Ask the model to decide"
on a card asks for a proposal on that item (decision, severity, in or out of the
report, findings to unlink, reason) and shows it as a box the analyst applies or
dismisses. In the AI analyst chat the model records the same kind of proposal
with the `suggest_review` tool (on a finding or a chain), after looking at a
chain with `get_chain`; proposals show on the Review page next to their item.
"Triage with the model" sends the whole queue (undecided items by default, or
everything) in batches of four (Ollama) or eight (Claude Code) and writes each
decision straight away, tagged "AI" in the rail and on the card with the
model's reason. The same pass writes the text the report prints: a narrative
for each chain and a note for each incident (a text the analyst wrote is kept;
one the model drafted earlier is replaced, and editing it makes it the
analyst's), and, when the switch in the triage dialog is on, drafts the
executive summary at the end from the reviewed chains and incidents; a popup then lists every decision (item, decision, severity
before and after, in or out of the report, unlinked findings, reason) with undo
per line or for the whole run, and "last AI triage" reopens it. The triage
prompt is `SYSTEM_TRIAGE` in `backend/services/ai/prompts.py`; the reply is a
JSON array checked item by item (unknown ids, wrong words and unlink ids that
are not linked findings are dropped and listed as "not applied"), and the words
models use instead of the exact decisions (escalate, dismiss, false positive on
a chain…) are mapped to the item's vocabulary. A decision made by the model is
a decision like any other: changing it on the card makes it the analyst's. With
"chain graphs" on (the default), each printed chain carries its swimlane graph
as a picture, drawn off-screen from the same model as the Chains page in the
report's light palette, and a report with several chains opens with the
shared-entity graph and its insights (senders, domains, IPs and hosts common to
chains). The pictures are PNG data URLs embedded in the HTML, so the report
stays one self-contained file.

Case notes hold what the analyst decides to keep: a curated timeline (entries added
with the "timeline" button on findings, mails, events and chain steps, each linked
back to its row, or typed by hand), a task checklist and markdown notes. The three
are stored with the case, travel in the case bundle, and are printed in the report
before the automatic timeline of findings.

## Interface tests

Component tests run under jsdom with `fake-indexeddb` (`*.test.tsx` next to the views:
the Findings queue grouping and status writes, the Case notes page). The engine,
incident, staleness and data-layer tests stay in Node. `npx vitest run` runs all of
them; the jsdom files are the slow ones.
