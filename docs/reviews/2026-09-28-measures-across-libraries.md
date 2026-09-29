# Every rule on five libraries and an emulated intrusion (2026-09-28)

REMN's rules were measured on two libraries they were not written against: EVTX-to-MITRE-Attack
([head-to-head](2026-09-25-head-to-head.md)) and Splunk attack_data's Windows datasets
([noise and held-out](2026-09-25-noise-and-held-out.md)). This round adds a third, OTRF's
Security-Datasets, and MITRE's APT29 evaluation as OTRF recorded it, and runs every rule on all of
them at one commit, keeping every finding, so the home page can show detection by library and by
tactic from one run.

## Method

`tools/library_measures.py harvest` runs every rule of REMN's set and of SigmaHQ's three packs, at
every level, on each recording with a new case's settings, on the SQL engine, and keeps every
finding with its host, time and count. `figures` scores it:

- **Detected**: a rule of the default set (REMN's own rules, SigmaHQ's windows and
  emerging-threats packs; 2,975 rules) tagged with the recording's ATT&CK technique, its parent or
  a sub-technique (ATT&CK v19, revoked ids mapped to their successors), raises a finding at or above
  the level cut. A rule without a technique tag is scored on the technique its title names, the
  title map `tools/head_to_head.py` applies to every tool alike; without it the counts at medium and
  above are given too.
- **Held out**: no REMN rule was written against the library. The rules written after studying
  one (`WRITTEN_AGAINST` in `tools/measure_rules.py`: 46 on EVTX-to-MITRE-Attack, 39 on
  attack_data) are not counted on it.
- **Tactic**: the tactic each technique plays in an intrusion, from the story engine's map
  (`backend/services/analysis/stories.py`).

Rules at `7513740` (main after PR #41), run 2026-09-28 on four cores: 1,745 units (the 1,650 recordings
scored below, attack_data's 92 Microsoft 365 and Entra datasets, one empty Windows dataset and the
two APT29 days), 2.4 million events, 1,523 s loading and 12,729 s running rules, about half a minute a
recording whatever its size.

The run reproduces the published figures where they overlap: 249, 123 and 266 recordings detected
at any level on attack_data, EVTX-to-MITRE-Attack and EVTX-ATTACK-SAMPLES, and 112 and 264 at medium
and above on the last two ([detection level](../detection.md#detection-level)). attack_data at
medium and above is 246, one more than the 245 published before `win-discovery-burst`.

### OTRF Security-Datasets

`tools/security_datasets.py` reads the atomic Windows datasets of
[Security-Datasets](https://github.com/OTRF/Security-Datasets) at `d9d40ef`: 100 metadata files
with host logs, of which 99 have their files in the repository (757,375 records). Each is one lab
run of one technique, labelled with its ATT&CK techniques by its metadata. The logs were shipped
three ways, all as JSON: NXLog through Logstash (508,612 records), NXLog alone (243,385) and
Winlogbeat 6 (5,378). The first two carry the lab's local time whatever their suffix says; each
file's offset from UTC is read from its Sysmon records, which carry their own `UtcTime` (the
offsets found run from UTC-19 to UTC+8, one per file). 2,197 lines of 14 zips are macOS resource
forks and are skipped.

No REMN rule was written against these datasets. SigmaHQ's authors have used them, so the share
REMN's own rules detect alone is given apart.

### MITRE's APT29 evaluation

The two days OTRF recorded of MITRE's ATT&CK Evaluations round 2 (APT29), 196,081 and 587,286
NXLog records of four hosts, read as `tools/apt29_stories.py` reads them. They are not scored by
technique (the records carry no step labels); the findings of each host are counted.

## Detection by library

| Library | Recordings | Events | Any level | Medium and above | High and above | Medium, author tags only | Medium, REMN's own rules alone |
|---|---:|---:|---:|---:|---:|---:|---:|
| EVTX-to-MITRE-Attack (held out) | 279 | 10,625 | 123 (44%) | **112 (40%)** | 80 | 104 | 60 |
| attack_data, Windows up to 20 MB (held out) | 535 | 785,361 | 249 (47%) | **246 (46%)** | 167 | 246 | 103 |
| Security-Datasets, atomic Windows (held out) | 99 | 757,375 | 81 (82%) | **80 (81%)** | 66 | 80 | 46 |
| **Held out together** | 913 | 1,553,361 | 453 (50%) | **438 (48%)** | 313 | | |
| EVTX-ATTACK-SAMPLES (reviewed against) | 278 | 37,364 | 266 | 264 | 210 | 264 | 180 |
| SigmaHQ regression samples (their own rules') | 459 | 495 | 423 | 421 | 254 | 421 | 79 |

The held-out libraries record 122 ATT&CK techniques (parent ids); 72 of them are detected at
medium and above in at least one recording (EVTX-to-MITRE-Attack 30 of 52, attack_data 66 of
117, Security-Datasets 29 of 34).

Security-Datasets is detected far more often than the other two. Its datasets are single runs of
common offensive tooling (Empire, Covenant, Mimikatz, Rubeus, LOLBins) on hosts logging Sysmon and
Security auditing, the ground SigmaHQ's and REMN's rules cover best. The 19 it misses at medium and
above are discovery through Empire, Covenant and Seatbelt that leaves only PowerShell or LDAP
traces (group, user and session listing, 7), DCOM through Excel (2), credential theft inside
PowerShell (Powerdump, a credential prompt, a vault read), two registry changes (WDigest,
command-line logging turned off), VBScript run by Empire, two HTTP listeners, NinjaCopy's raw NTFS
read and one run labelled `T0000`.

## By tactic, held out, medium and above

| Tactic | EVTX-to-MITRE | attack_data | Security-Datasets | All held-out |
|---|---:|---:|---:|---:|
| Reconnaissance | – | 1 / 12 | – | **1 / 12** |
| Resource development | – | 0 / 6 | – | **0 / 6** |
| Initial access | 0 / 4 | 3 / 25 | – | **3 / 29** |
| Execution | 7 / 13 | 32 / 60 | 7 / 10 | **46 / 83** |
| Persistence | 40 / 97 | 44 / 78 | 12 / 12 | **96 / 187** |
| Privilege escalation | 2 / 10 | 11 / 23 | 2 / 2 | **15 / 35** |
| Stealth | 6 / 21 | 57 / 105 | 19 / 21 | **82 / 147** |
| Defense impairment | 21 / 32 | 22 / 29 | 6 / 7 | **49 / 68** |
| Credential access | 19 / 48 | 25 / 59 | 16 / 19 | **60 / 126** |
| Discovery | 3 / 29 | 16 / 41 | 2 / 9 | **21 / 79** |
| Lateral movement | 11 / 17 | 17 / 33 | 15 / 17 | **43 / 67** |
| Collection | 0 / 1 | 0 / 10 | 1 / 1 | **1 / 12** |
| Command and control | 0 / 2 | 13 / 24 | – | **13 / 26** |
| Exfiltration | – | 1 / 10 | – | **1 / 10** |
| Impact | 3 / 5 | 4 / 18 | – | **7 / 23** |

The gaps are where Windows event logs say least: reconnaissance, resource development, initial
access, collection and exfiltration are mostly network or cloud activity, and discovery is mostly
commands that look like administration.

## MITRE's APT29 evaluation

Findings of the default rule set at medium and above (high and critical in brackets), counted
before folding:

| Host | Day 1 | Day 2 |
|---|---:|---:|
| SCRANTON (day 1: attacked) | 404 (221) | 37 (11) |
| NASHUA (day 1: attacked) | 197 (121) | 4 (1) |
| NEWYORK (domain controller; day 1: not attacked) | 45 (8) | 64 (26) |
| UTICA (day 1: not attacked) | 4 (1) | 590 (290) |

On day 1, the day the evaluation's checks describe (`tools/apt29_stories.py`), 601 of the 650
findings are on the two hosts the operator worked on.

## What the run does not say

- **Technique scoring is a proxy**, as in the head-to-head: a detection tagged with another
  technique is a miss, and a broadly tagged rule can be credited for a side event.
- **Security-Datasets is small and one-technique-per-run**, and SigmaHQ's authors have used it; its
  81% says what the default set does on clean single-technique runs, not on a noisy host.
- **attack_data is capped at 20 MB a dataset** here (36 larger datasets and 14 missing at the pinned
  commit are left out), as in the per-rule measure.
- **No false-positive figure is new here**: the clean machines are measured in the per-rule measure
  and the [detection level](../detection.md#detection-level) figures.

## Reproduce

```
.venv/bin/python tools/library_measures.py fetch --datasets DS
.venv/bin/python tools/library_measures.py harvest --datasets DS --out OUT --no-clean
.venv/bin/python tools/library_measures.py figures --harvest OUT --json frontend/src/data/libraryMeasures.json
```

`harvest` without `--no-clean` also runs the seven clean machines of evtx-baseline (about 11 GB with
them); `--max-dataset-mb` raises attack_data's cap.
