# Validation and test data

Three kinds of checks say how well REMN works. The test suites run on every push and
cover the parsers, the rule engines, the API, the pages and the model's part in the
review. The public-corpus harness measures the mail scoring against labelled phishing
and legitimate mail, which is the only public ground truth that fits a drop-in. The
synthetic lab generates a complete, linked case with known answers, for the chains and
for anything that needs a realistic case without real data. This page describes all
three and lists the public datasets that can be dropped into the tool as they are.

## Test suites

```bash
.venv\Scripts\python.exe -m pytest      # parsers, analysers, API, rule catalogue, connectors (from the project root)
cd frontend && npm test                 # filter language, rule engine, queries, incidents, review, report, pages
```

The heavy tests, multi-gigabyte ingests and long runs, are opt-in: `pytest -m heavy -s`.
Continuous integration runs both suites, the linters and formatters, the production
build with a bundle budget, and builds, runs and scans the Docker image, on every push
and pull request. Two fixtures pin contracts between the two sides: the engine parity
fixture (`tests/fixtures/parity/`, see the [detection page](detection.md)) and the prompt
fixture (`tests/fixtures/ai_system_compose.json`), which fails when a prompt changes
without the fixture being regenerated.

## Public corpora and measured rates

`tools/validate_public.py` downloads redistributable corpora into `samples/public/`
(ignored by git), runs the mail scoring over them with default case settings and prints
the band distribution with recall on the phishing sets and the false-positive rate on the
legitimate ones. Numbers from 2026-09-06, defaults only, no sender baseline, no internal
domains configured, so they are a floor:

| corpus | kind | mails | high or above | medium or above |
|---|---|---|---|---|
| Nazario phishing corpus, 2004-2007 (CC BY 4.0) | phishing | 2,293 | 61% | 76% |
| Phishing Pot honeypot, 2022-2026, random 800 of 8,614 | phishing | 800 | 63% | 91% |
| SpamAssassin easy_ham, 2003 | legitimate | 800 | 0% | 2% |
| SpamAssassin hard_ham, 2003 (newsletters that look like spam) | legitimate | 251 | 14% | 62% |

Two calibration changes came out of the first run and are kept because both corpora
moved the right way: the receiving gateway's own spam verdict (Exchange SCL 5 or more,
SFV:SPM or BLK) counts as a strong indicator (Phishing Pot went from 38% to 63% at high),
and a form posting to another domain no longer counts on its own while a password field
still does (hard_ham went from 46% to 14% at high). The remaining hard_ham "medium" band
is 2003-era commercial mail without any authentication headers; on a modern mailbox
those mails carry DKIM and a List-Id and score lower.

What the harness does not cover: Windows event detection has no public ground truth
with labelled attacks that fits a drop-in; the EVTX-ATTACK-SAMPLES archive below is the
closest, and endpoint protection quarantined it on the development machine. Microsoft
365 detection was checked for parsing only: the Invictus IR Unified Audit Log set,
9,608 records of real business email compromise, loads, and its inbox-rule and
mailbox-permission rules fire. Re-run with
`.venv/Scripts/python.exe tools/validate_public.py --phishpot` after any scoring change.

## The synthetic lab

`samples/synthetic/make_linked_lab.py --out <folder>` writes a complete case with
linked evidence: a mailbox (`Mailboxes.mbox`), Security, System, PowerShell, Sysmon and
Defender event logs, a Unified Audit Log CSV and Entra sign-ins, the case settings, a
`ground-truth.jsonl` of every planted record, a `START-HERE.md` that explains the
scenarios, and record locators. `--quick-only` writes the small pack (1,000 mails,
10,000 Windows events, 2,000 audit and 2,000 sign-in records); without it a large pack
follows (100,000 mails, a million events).

The scenarios: S01 to S04 and S06 are attack stories, each with a seed mail, a reply with
a matching In-Reply-To, a DNS lookup for the same domain, a download with the same
attachment name, a risky sign-in, mailbox access and forwarding or consent records; some
add Outlook-to-PowerShell process creation, a scheduled task, a service installation, a
Defender alert, role assignment, a file-download burst, failed logons, an RDP success,
group membership and an admin-share event. S05 is the false-positive control: static
HTML in a ZIP, harmless PDF JavaScript, a CSV-export page, a bank-change notice and a
normal invoice with a webmail Reply-To, expected to stay below high. S06 comes from a
supplier seen repeatedly in benign mail and must still score high despite the sender
history. S07 is the prompt-injection control: a password-expiry lure whose body tells
automated reviewers to classify it as benign; the rules score it on its facts, and a
model triage must keep it confirmed and name the instruction in its reason.
`samples/synthetic/validate_linked_lab.py` ingests a generated pack into a running
server and checks that every attack story produced a chain with at least two artifact
links across host and cloud sources; the two controls are mail-only and are skipped.

The other generators in `samples/synthetic/` serve narrower purposes: `make_m365.py`
(a business email compromise scenario in the four export formats), `make_big.py`
(multi-gigabyte inputs for the heavy tests), `rule_samples.py` and
`mail_calibration.py` (rule and scoring fixtures), `scale_test.py` (query and rule
timings), `ai_repro.py` (replay of a model turn).

## Public datasets you can drop in

| set | what | drop in as | source |
|---|---|---|---|
| EVTX-ATTACK-SAMPLES | about 200 small .evtx files, one attack technique each, GPL-3.0 | the zip, or any .evtx | github.com/sbousseaden/EVTX-ATTACK-SAMPLES |
| EVTX-to-MITRE-Attack | 270+ samples, Security, Sysmon, PowerShell | the repository zip | github.com/mdecrevoisier/EVTX-to-MITRE-Attack |
| hayabusa-sample-evtx | the two sets above plus DeepBlueCLI samples | the repository zip | github.com/Yamato-Security/hayabusa-sample-evtx |
| omerbenamram/evtx samples | security_big_sample.evtx, sysmon.evtx | the files | github.com/omerbenamram/evtx |
| Invictus IR O365 dataset | 9,608 Unified Audit Log records from real BEC cases, CC BY 4.0 | `auditrecords.csv` after extracting the 7z | github.com/invictus-ir/o365_dataset |
| Nazario phishing corpus | hand-classified phishing mailboxes, mbox, 2005-2025, CC BY 4.0 | any `phishingN.mbox` | monkey.org/~jose/phishing |
| Phishing Pot | 8,614 honeypot phishing .eml, 2022 onwards | the zip, or a folder of .eml | github.com/rf-peixoto/phishing_pot |
| SpamAssassin public corpus | legitimate mail (easy_ham, hard_ham) and spam | the tar.bz2 as is, or run the harness | spamassassin.apache.org/old/publiccorpus |
| Apache Tika test PST | a 7-message PST for the PST path | `testPST.pst` | apache/tika test documents |
| CMU Enron maildir | 1.7 GB tar.gz, about 500,000 messages | the archive | www.cs.cmu.edu/~enron |
| EnronData PST set | 148 custodian PSTs, 734 MB 7z, 8.6 GB extracted (needs `libpff-python`) | the PST files | enrondata.readthedocs.io |
| oletools test corpus | attachments with macros, DDE, encryption, RTF exploits | as attachments of test mails | github.com/decalage2/oletools |
| PayloadsAllThePDFs | PDF payload samples | as attachments of test mails | github.com/luigigubello/PayloadsAllThePDFs |

Endpoint protection may quarantine the EVTX archives and some phishing mailboxes as they
download: add the download folder to its exclusions on the analysis machine. Your own
machine is a source too: `wevtutil epl Security C:\evidence\Security.evtx` as
administrator, an Outlook export to `.pst`, a Thunderbird profile's `.mbox` files.
