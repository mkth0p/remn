# Questions

An investigation is asked questions before it finds answers: when did the attacker get in, did
they move to another host, did they read the CEO's mail. The Questions page turns those
questions into the case's checklist. The analyst picks the scenarios the case is about, and each
of their questions says what REMN can answer it with, whether this case holds the evidence to
answer it at all, and takes the analyst's answer, with the records and findings it rests on. The
report prints every question with its answer, and flags the ones left open.

The questions come from [DFIQ](https://dfiq.org), the Digital Forensics Investigative Questions
catalog (Apache-2.0, Copyright 2024 Google LLC), and from REMN's own layer for Microsoft 365 and
mail and for the dwell time every intrusion report states. The model is DFIQ's: a scenario (the
kind of case), its facets (sub-questions, often an ATT&CK tactic), its questions, and for some
questions DFIQ's approaches (how a given tool answers it, and what that way does not cover). An
answer is what DFIQ calls a conclusion.

## The scenarios

| Id | Scenario | From |
| --- | --- | --- |
| S1001 | Data Exfiltration | DFIQ |
| S1003 | Suspicious DNS Query | DFIQ |
| S1007 | Host Persistence Audit | DFIQ |
| S1008 | Lateral Movement | DFIQ |
| S0001 | Dwell time (first and last attacker activity) | REMN |
| S0002 | Business email compromise exposure | REMN |

DFIQ ids are kept as they are, so a question here is the same question in Timesketch or on
dfiq.org. REMN's own start with 0 (S0001, F0001, Q0001), the range DFIQ keeps for private
content. Of DFIQ 1.0.1's six scenarios, Data Infiltration (an insider bringing a former
employer's files) and Cloud Project Compromise Assessment (Google Cloud) are left out, and so are
the questions of the other four that nothing REMN reads can answer: macOS launch agents and
dylib hijacking, Linux cron jobs and systemd timers, Chrome extensions, screenshots, AirDrop and
Bluetooth, incognito sessions. The catalog lists them (`skipped`). What is left is 33 DFIQ
questions and 20 of REMN's.

REMN's two scenarios:

- **Dwell time** asks when the attacker first got in and how (phishing, a valid account, an
  exposed service), whether the logs reach back that far, when they were last active, whether
  their accounts were disabled and the activity stopped, what persistence would outlive the
  containment, which hosts and accounts they touched, and whether the logs have holes during
  the attack window.
- **Business email compromise exposure** asks whether the account was taken over (sign-ins from
  unexpected places, MFA changed or bypassed, spraying), what the attacker left in the mailbox
  or the tenant (inbox rules, forwarding, consented applications, delegated access), what they
  read or took (MailItemsAccessed, content searches, SharePoint and OneDrive downloads), and
  whether they sent mail from the account, asked for payment changes, or reached other people
  with the same campaign.

## What each question shows

- **Evidence in this case.** Each question lists the kinds of evidence that can answer it (the
  Security log, Sysmon, the Task Scheduler log, the Unified Audit Log, Entra sign-ins, mailboxes,
  browser history, the collected autoruns...). The page reads what the case holds from the
  channel and category counts that ingestion keeps (no scan of the rows) and from the mail
  count, and says "covered by the Security log (1,204 rows)" or "not covered: no browser history
  in this case". A question the case cannot cover is marked "no evidence" in the list. The check
  is at the level of a log or an artefact kind: a case holding the Security log covers a
  question about accounts created whether or not account management auditing was on; the
  question's note says what else it takes when that matters.
- **Answer it with.** One or more searches, each opening the Events or Mails page with its
  filter set, with the number of rows it finds in this case. A question about the attacker's
  first and last activity shows the earliest or latest finding of medium severity or more that is
  not a false positive; the question about how far the logs reach lists each log's first record
  and names those that start after that first activity; the question about holes in the logs
  lists the case's [evidence gaps](interface.md#report).
- **Related rules.** The rules whose ATT&CK techniques match the question's (a parent technique
  matches its sub-techniques, and the other way round) or whose tags it names, each with the
  number of findings it raised in this case; a click opens the first of them.
- **DFIQ approaches**, when DFIQ has any, with what each does not cover.

## Answers

An answer has a status (open, answered, or cannot be answered from this evidence), the
analyst's text (markdown, printed as written) and its citations: event and mail rows and
findings. A finding is cited from the question's panel, the findings of the related rules first.
A row is cited from its detail on the Events or Mails page: a search opened from a question makes
that question the one its rows are cited for ("cite for Q1074"); otherwise the detail offers a
list of the case's questions.

A citation keeps what it cites across the case's life. A row is kept by its record key (the SHA-256
of its file and its place in it, `data/recordKeys.ts`), with its row id as the place it was last
seen. When the evidence is removed and added again, the rows are renumbered; the page looks the
record up by its key (its record number, message index or cloud record id) and follows it to its
new row. A cited finding is kept by the key its decision is archived under, which is also the
record's. A citation whose record is no longer in the case says so and stays in the answer.

The chosen scenarios are a record of the case, the answers rows of their own table
(`questionAnswers`, added in version 8 of the browser database, with no change to anything
already stored). Both go with the case bundle: an imported case keeps its questions, answers
and citations, the row ids renumbered like every other reference.

## In the report

The report gets a Questions section when the case has a scenario chosen, after "What happened":
each scenario, its facets, and each question with its status, the analyst's answer, what it
cites (the file and record of each row, the title of each finding) and, for a question not
answered, whether the case holds the evidence to answer it. An open question is marked
unanswered; an answer that cites nothing says so. "Where it stops" counts the questions still
open, those of them no evidence in the case could answer, and those that cannot be answered from
this evidence. The Word report does not carry the section yet.

## Updating the catalog

The catalog is `frontend/src/data/questions/dfiq.gen.json`, generated and committed, never
fetched. `tools/dfiq_import.py` reads a DFIQ release (an unpacked `dfiq` wheel or a clone of
github.com/google/dfiq, which the repository does not vendor) and `tools/dfiq_remn.yaml`, REMN's
layer: which DFIQ scenarios to take, the evidence table, and for each DFIQ question kept its
evidence, searches, techniques and rule tags, and REMN's own scenarios. A DFIQ question without
hints is left out.

    python tools/dfiq_import.py path/to/dfiq            # rewrite the catalog
    python tools/dfiq_import.py path/to/dfiq --check    # exit 1 when it is out of date

`tests/backend/test_dfiq_import.py` checks the importer on a small release of its own, and that
the committed catalog carries what `tools/dfiq_remn.yaml` says, so an edit to the layer without a
new catalog fails. The frontend tests (`src/data/questions/questions.test.ts`,
`src/data/reportHtml.questions.test.ts`, `src/views/QuestionsView.test.tsx`) cover the catalog,
the coverage, the answers and their bundle round trip, and the report section.

DFIQ is being revised to 1.1; the importer reads 1.0's layout and names the release it read.
