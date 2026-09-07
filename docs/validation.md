# Validation and test data

_Public corpora, measured detection rates, synthetic labs, the test suites._

## Validation on public data

`tools/validate_public.py` downloads redistributable corpora into `samples/public/`
(ignored by git), runs REMN's mail scoring over them with default case settings and
prints the band distribution with recall (phishing sets) and false-positive rates
(legitimate sets). Numbers from 2026-09-06, defaults only, no sender baseline, no
internal domains configured, so they are a floor:

| corpus | kind | mails | high or above | medium or above |
|---|---|---|---|---|
| Nazario phishing corpus, 2004-2007 (CC BY 4.0) | phishing | 2,293 | 61% | 76% |
| Phishing Pot honeypot, 2022-2026, random 800 of 8,614 | phishing | 800 | 63% | 91% |
| SpamAssassin easy_ham, 2003 | legitimate | 800 | 0% | 2% |
| SpamAssassin hard_ham, 2003 (newsletters that look like spam) | legitimate | 251 | 14% | 62% |

Two calibration changes came out of the first run and are kept because both corpora
moved the right way: the receiving gateway's own spam verdict (Exchange SCL 5+,
SFV:SPM/BLK) now counts as a strong indicator (Phishing Pot 38% to 63% at high), and
a form posting to another domain no longer does on its own, a password field still
does (hard_ham 46% to 14% at high). The remaining hard_ham "medium" band is 2003-era
commercial mail without any authentication headers; on a modern mailbox those mails
carry DKIM and a List-Id and score lower.

What the harness does not cover: Windows event detection has no public ground truth
with labelled attacks that fits a drop-in, the EVTX-ATTACK-SAMPLES archive (see
"Public datasets") is the closest and was quarantined by endpoint protection on the
development machine; M365 detection was checked for parsing only (the Invictus IR
Unified Audit Log set, 9,608 records of real business email compromise, loads and
its inbox-rule and mailbox-permission rules fire). Re-run with
`.venv/Scripts/python.exe tools/validate_public.py --phishpot` after any scoring change.

### Public datasets you can drop in

| set | what | drop in as | source |
|---|---|---|---|
| EVTX-ATTACK-SAMPLES | ~200 small .evtx files, one attack technique each, GPL-3.0 | the zip, or any .evtx | github.com/sbousseaden/EVTX-ATTACK-SAMPLES |
| Invictus IR O365 dataset | 9,608 Unified Audit Log records from real BEC cases, CC BY 4.0 | `auditrecords.csv` after extracting the 7z | github.com/invictus-ir/o365_dataset |
| Nazario phishing corpus | hand-classified phishing mailboxes, mbox, CC BY 4.0 | any `phishingN.mbox` | monkey.org/~jose/phishing |
| Phishing Pot | 8,614 honeypot phishing .eml, 2022 onwards | the zip (.eml archive) or a folder of .eml | github.com/rf-peixoto/phishing_pot |
| SpamAssassin public corpus | legitimate mail (easy_ham, hard_ham) and spam, message files | extract and rename to .eml, or run the harness | spamassassin.apache.org/old/publiccorpus |
| Apache Tika test PST | a 7-message PST for the PST path | `testPST.pst` | apache/tika test documents |

Endpoint protection may quarantine the EVTX archive and some phishing mailboxes as
they download: add the download folder to its exclusions on the analysis machine.

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

## Tests

```bash
.venv\Scripts\python.exe -m pytest                      # parsers, analyzers, API, rule catalogue (from the project root)
cd frontend && npm test                                 # filter DSL, rule engine, IndexedDB queries
```
