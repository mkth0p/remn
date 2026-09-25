# REMN, Hayabusa and Chainsaw on a library REMN's rules were not written for (2026-09-25)

REMN detects 269 of the 278 recordings of EVTX-ATTACK-SAMPLES, but that is a practice score: 56 of
those samples are detected only by the 75 rules written for them after the
[2026-09-23 review](2026-09-23-evtx-attack-samples.md), and every verdict was judged by REMN's own
reviewers. This run measures REMN on a library its rules were not written against, and puts
Hayabusa and Chainsaw on the same files under the same scoring.

**The library**: [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack)
(`4748560`, 2026-05-21), 293 event logs and 12,812 events, filed by ATT&CK tactic and technique
(`TA0006-Credential Access/T1558-Steal or Forge Kerberos Tickets/...`). The 279 files in a
technique folder carry their author's label; the other 14 (full attack chains, Defender events)
are counted apart. No REMN or Chainsaw rule cites the library; 2 SigmaHQ rules and 8 of Hayabusa's
own rules do.

**The tools**, each with every rule it ships:

- **REMN** at `e90a455`: the SQL engine with a new case's settings, its default rules (its own and
  SigmaHQ's Windows and emerging-threats packs, converted from SigmaHQ `272daf82`), and again with
  the hunting pack. Every file parsed with no parse or rule error, and the browser engine gives the
  same findings as the SQL engine on every file.
- **Hayabusa v4.1.0** with hayabusa-rules `610b16b` (2026-09-24): `dfir-timeline -w`, every rule
  (4,658; its noisy, deprecated and unsupported rules stay off, as by default).
- **Chainsaw v2.16.5** with SigmaHQ at `272daf82`, the commit REMN's packs come from
  (`rules/windows`, `rules-emerging-threats`, `rules-threat-hunting`: 2,857 rules load, 270 do not)
  through its `sigma-event-logs-all` mapping, and its own 74 rules; again without the
  threat-hunting rules.

Both were built from their release tags (Rust 1.98.1); their release downloads were not reachable
from the machine that ran this.

**The scoring** (`tools/head_to_head.py`): a file is detected when an alert fires on it from a rule
tagged with the file's technique, its parent or one of its sub-techniques, ATT&CK v19's revoked
ids mapped to their successors on both sides. Every tool ran with all its levels; the level cut is
applied when scoring, the same for all three. A rule with no technique counts through one map
of titles, the same for all three: SigmaHQ rules their authors left without a technique (all
three tools carry them), Hayabusa's own rules and Chainsaw's own rules (which carry no ATT&CK tags
at all) are tagged where the title names one technique or tool; rules about a generic event
(Hayabusa's "Sysmon Alert" rules, a password change, a logon type, antivirus alerts) stay
untagged. The map is in the script, and the scores as the rules' authors tagged them are given
too.

## The answer

| Of 279 recorded attacks | Any level | Medium and above | High and above |
|---|---:|---:|---:|
| REMN, default rules | 123 (44%) | **109 (39%)** | 80 (29%) |
| REMN, with the hunting pack | 128 (46%) | 109 (39%) | 80 (29%) |
| Hayabusa, every rule | 106 (38%) | **86 (31%)** | 55 (20%) |
| Hayabusa, without threat-hunting rules | 99 (35%) | 86 (31%) | 55 (20%) |
| Chainsaw, SigmaHQ with hunting and its own rules | 70 (25%) | **52 (19%)** | 32 (11%) |
| Chainsaw, without threat-hunting rules | 67 (24%) | 52 (19%) | 32 (11%) |

Scored as the rules' authors tagged them, with no title map, at medium and above: REMN 101 (36%),
Hayabusa 74 (27%), Chainsaw 45 (16%). Hayabusa loses the most to untagged rules: 15% of its rules
that fire at medium and above here carry no technique, against 7% of REMN's.

- **On attacks it was not written for, REMN detects about four in ten** at medium level and above,
  where it detects 97% of EVTX-ATTACK-SAMPLES. That is the number to quote for unseen attacks.
- **It detects more than Hayabusa and Chainsaw** on the same files: 23 files more than Hayabusa
  and 57 more than Chainsaw at medium and above, and more at every level and in either scoring.
- **The three together detect 113 files (41%)**; 166 files raise nothing of their technique at
  medium or above in any of them. Many recordings show one technique through events that are
  also everyday activity (discovery commands, a logon, a group change).
- **The rules written for EVTX-ATTACK-SAMPLES barely carry over**: 2 of REMN's 109 detections here
  involve one of those 75 rules, and 1 rests on them alone. REMN's lead comes from the rules it had
  before that review.

| Medium and above, by tactic | Files | REMN | Hayabusa | Chainsaw | Any of the three |
|---|---:|---:|---:|---:|---:|
| Persistence | 82 | 33 | 29 | 17 | 36 |
| Defense Evasion | 55 | 26 | 20 | 8 | 26 |
| Credential Access | 47 | 19 | 14 | 11 | 19 |
| Discovery | 29 | 2 | 2 | 1 | 2 |
| Execution | 19 | 10 | 6 | 5 | 10 |
| Privilege Escalation | 19 | 5 | 6 | 5 | 6 |
| Lateral Movement | 17 | 11 | 6 | 4 | 11 |
| Impact | 5 | 3 | 3 | 1 | 3 |
| Initial Access | 3 | 0 | 0 | 0 | 0 |
| Command and Control | 2 | 0 | 0 | 0 | 0 |
| Collection | 1 | 0 | 0 | 0 | 0 |

(REMN with the hunting pack, Hayabusa with every rule, Chainsaw with hunting and its own rules.)

## Where they differ

At medium and above, **26 files only REMN detects**, 23 of them through REMN's own rules: account
creation and an account deleted soon after, Kerberos password spraying and bursts of
pre-authentication failures, PsExec-style execution and admin-share access, scheduled tasks
created and deleted by ATexec and SMBexec, a member added to DnsAdmins, BITS transfers,
audit-policy and firewall changes, Defender exclusions, certutil downloads, diskshadow. On 10 of
the 26, Hayabusa or Chainsaw fires a rule of the same technique at a lower level: there the
difference is severity, not detection.

**Four files the others detect and REMN does not**, at medium and above:

- **Two users added to a global security group** (4728): Hayabusa's "User Added To Global Security
  Grp" (medium). REMN flags additions to privileged groups only. A gap to close.
- **A RunasCs logon** (4648 and 4624): Hayabusa's "Explicit Logon Attempt (Susp Proc) - Possible
  Mimikatz PrivEsc" (high), an explicit-credential logon from an unusual process. A gap to close.
- **A service installed for Mimikatz** (7045): Chainsaw's "Credential Dumping Tools Service
  Installation". REMN fires three high rules on it ("Credential Dumping Tools Service Execution -
  System", "HackTool Service Registration or Execution", "Mimikatz Use"), tagged credential
  dumping and service execution rather than service creation, so the scoring misses it. Not a gap.

At any level, with each tool's hunting rules, the others add three: Credential Manager enumeration
(5379, 5381, 5382; Hayabusa's own rule), a local brute force through 4776 and 4625 and a universal
group change (Chainsaw's own informational rules).

## The same tools on EVTX-ATTACK-SAMPLES

On the library REMN's rules were reviewed and extended against, which is also the example data in
Chainsaw's repository, files with an alert at medium level and above: REMN 268 of 278, Hayabusa
218, Chainsaw 195. Scored against the techniques of the rules REMN's reviewers credited with each
sample (and the title map), REMN detects 258 of 266 at medium and above (circular: those are the
rules it was checked against), Hayabusa 180 (68%) and Chainsaw 166 (62%).

## False alarms on clean machines

The seven clean Windows machines of evtx-baseline `v0.8.4` (6.6 million events), each tool without
its threat-hunting rules. REMN's counts are the events each rule matched there
(`rules/measures.json`); Hayabusa's and Chainsaw's are their alerts, run on the same logs.

| On clean machines | Medium and above | High and above | Critical |
|---|---:|---:|---:|
| REMN | 99 rules, 21,100 events | 39 rules, **5,005 events** | 3 rules, 2,589 events |
| Hayabusa | 81 rules, 32,649 events | 22 rules, **1,296 events** | none |
| Chainsaw | 48 rules, 5,077 events | 18 rules, **1,204 events** | 4 rules, 11 events |

- **REMN's lead costs false alarms.** On machines where nothing happened it raises about four times
  as many high and critical alerts as Hayabusa or Chainsaw, and 3,788 of its 5,005 come from its
  own rules, the same rules its lead comes from.
- **One rule is half of it**: "Credential dumping indicators (LSASS access, ntds.dit, SAM)",
  critical, 2,504 events on 6 of the 7 machines. Then Run-key persistence (529, on all 7), unsigned
  DLLs loaded by system processes (148), TeamViewer or KeePass memory read by another program
  (120) and remote threads (117). One SigmaHQ rule ("Windows Shell/Scripting Application File
  Write to Suspicious Folder", 991 events on one machine) fires alike in all three tools.
- **Some of it is true**: the machines' logs were cleared before they were exported (80 critical
  "Security audit log cleared" events in REMN).
- **At medium level Hayabusa raises the most** (32,649 events, from 81 rules).

## What to do next

1. **Tune REMN's noisy rules**, starting with "Credential dumping indicators": it is critical and
   fires 2,504 times on 6 of the 7 clean machines, so what trips it there is the first thing to
   read and exclude.
2. **Close the two gaps**: users added to any security group (4728, 4732, 4756) at a level below
   privileged groups, and explicit-credential logons from unusual processes (RunasCs).
3. **Measure rules on this library too.** Its files carry a technique each, so
   `tools/measure_rules.py` can take it as a source of recorded attacks; a rule's "detects" then
   rests on attacks it was not written for, not only on EVTX-ATTACK-SAMPLES.
4. **Keep EVTX-to-MITRE-Attack out of rule writing**, so this measure stays a test of unseen
   attacks.

## What the run does not say

- **Technique scoring is a proxy.** A detection tagged with another technique counts as a miss (the
  Mimikatz service above), and a broadly tagged rule can be credited for a side event. On every
  file where the tools disagree at medium and above, the rules credited were checked by hand
  against what the file records: one credit to the others is wrong (the Mimikatz service), one to
  REMN is loose (a new file share, credited to REMN's admin-share access rule), the rest hold.
- **The title map is a judgement.** It is listed in the script and applied to all three tools
  alike; without it the order and most of the gaps stay (REMN 101, Hayabusa 74, Chainsaw 45).
- **One library.** 279 labelled recordings, mostly one technique each, weighted to persistence and
  defense evasion; the rates depend on that make-up.
- **Each tool as shipped.** Hayabusa's default filters (its channel filter, 12 noisy rules off),
  Chainsaw's 270 SigmaHQ rules it cannot load and its mapping, REMN with a new case's settings.
  Hayabusa's rules are a day older than this run; REMN's and Chainsaw's SigmaHQ rules come from
  `272daf82`.
- **Speed** was not compared.

## Reproduce

```
git clone https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack lib && git -C lib checkout 474856008f037ccd42753f02a631b42690195829
.venv/bin/python tools/evtx_attack_samples.py --library lib --out /tmp/remn
hayabusa dfir-timeline -d lib -r hayabusa-rules -c hayabusa-rules/config -t jsonl -p verbose -w -q -C -U -K -Q -o /tmp/hayabusa.jsonl
chainsaw hunt lib -s sigma/rules/windows -s sigma/rules-emerging-threats -s sigma/rules-threat-hunting \
  --mapping mappings/sigma-event-logs-all.yml -r rules/evtx --json -o /tmp/chainsaw.json
chainsaw hunt lib -s sigma/rules/windows -s sigma/rules-emerging-threats \
  --mapping mappings/sigma-event-logs-all.yml -r rules/evtx --json -o /tmp/chainsaw-default.json
.venv/bin/python tools/head_to_head.py --library lib --remn /tmp/remn --hayabusa /tmp/hayabusa.jsonl \
  --chainsaw /tmp/chainsaw.json --chainsaw-default /tmp/chainsaw-default.json --hayabusa-rules hayabusa-rules
```

The clean-machine counts: Hayabusa with `-m medium` and Chainsaw with `--level medium --level high
--level critical` (without the threat-hunting rules) on each machine of evtx-baseline `v0.8.4`, then
`tools/head_to_head.py --remn /tmp/remn --clean DIR --hayabusa-rules hayabusa-rules`.
