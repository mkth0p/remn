# Less noise, a gate on the measures and a second held-out library (2026-09-25)

The [head-to-head](2026-09-25-head-to-head.md) left REMN with the best detection of the three tools
on a library its rules were not written for, and about four times the high and critical alerts of
Hayabusa or Chainsaw on clean machines, three quarters of them from its own rules. This round cuts that noise without giving up a detection,
makes losing one fail CI, and measures the rules on a second library they were not written for:
the Windows datasets of Splunk attack_data, which REMN could not read before.

## Noise on the clean machines

REMN's own rules on the seven clean machines of evtx-baseline `v0.8.4` (6.6 million events), and
what they detect on the libraries they were measured on before (the SigmaHQ samples,
EVTX-ATTACK-SAMPLES, attack_data's Microsoft 365 and Entra datasets, EVTX-to-MITRE-Attack):

| Own rules | High and critical on clean machines | Medium and above | Rule-recording detections | Recordings detected |
|---|---:|---:|---:|---:|
| before (`e7ede85`) | 895 findings, 3,684 events (22 rules) | 2,016 findings | 433 | 340 |
| now | **200 findings**, 2,698 events (19 rules) | 1,332 findings | 435 | 342 |

No recording is detected less. One detection moved: SigmaHQ's quiet `msiexec` install sample is
now the low rule's (`win-msiexec-quiet-install`) rather than the LOLBin rule's, which gained the
two samples of `msiexec` running a DLL. Of the 2,698 events, 2,380 are two findings: the Avast
installer reading LSASS memory 2,379 times, which Sysmon records as unsigned, and one program
reading TeamViewer's memory 119 times. 80 of the 85 critical findings are the logs cleared before
the machines were exported, which is true.

With SigmaHQ's Windows and emerging-threats packs, as REMN runs by default, the high and critical
findings on the clean machines fall from 1,122 over 4,901 events to 427 over 3,915 events. The
head-to-head counted events against Hayabusa's 1,296 and Chainsaw's 1,204 alerts; 2,380 of REMN's
3,915 are the two findings above, and the other 1,535 are about as many as theirs.

What changed, rule by rule (findings on the clean machines, with the events they cover, and the
recordings of what the rule looks for that it detects, outside attack_data's Windows datasets):

| Rule | Level | Clean before | Clean now | Detects before | Detects now |
|---|---|---:|---:|---:|---:|
| `win-registry-run-key` | high | 258 (529) | 5 (5) | 11 | 11 |
| `win-registry-run-key-program` (new) | low | | 67 (79) | | 0 |
| `win-credential-app-memory-read` | high | 120 (120) | 1 (119) | 1 | 1 |
| `win-remote-thread-injection` | high | 117 (117) | 4 (6) | 7 | 7 |
| `win-remote-thread-windows-routine` (new) | low | | 9 (111) | | 0 |
| `win-lolbin-suspicious-commandline` | high | 84 (84) | 0 (0) | 38 | 39 |
| `win-msiexec-quiet-install` (new) | low | | 5 (47) | | 1 |
| `win-powershell-suspicious-scriptblock` | high | 76 (76) | 4 (4) | 19 | 19 |
| `win-wmi-persistence` | high | 26 (26) | 0 (0) | 5 | 5 |
| `win-system-process-unsigned-dll` | high | 21 (148) | 0 (0) | 10 | 10 |
| `win-system-process-unsigned-system-dll` (new) | medium | | 4 (15) | | 0 |
| `win-lsass-memory-access` | high | 9 (2,400) | 2 (2,380) | 14 | 14 |
| `win-lsass-memory-access-signed` (new) | medium | | 7 (20) | | 0 |

- **Grouping** (one finding per program per machine, or per command line and machine) is most of
  it: a busy machine matches the memory-read, remote-thread, script-block and LOLBin rules over
  and over for the same program.
- **Splitting by confidence**: the Run-key rule fired 258 times, almost all on installers
  registering a program under Program Files; that is the new low rule now, and the high rule keeps
  a value naming a user folder, a script, a LOLBin, an empty value name, a hijack value (IFEO
  `Debugger`, `GlobalFlag`, `VerifierDlls`) or a print monitor. The unsigned-DLL rule keeps loads
  from outside the system folder and phantom DLL names; an unsigned DLL in System32 itself (a
  driver package's) is medium. A thread started in another process at a Windows routine is low;
  at no module, or at a loader routine, it stays high. The remote-thread rule now reads Sysmon 8's
  start module and function: an injected thread starts in no module, which is what sets it apart.
- **Exclusions of what Windows does itself**: the WMI persistence rule no longer fires on the SCM
  Event Log consumer every Windows installation registers (26 findings, one per boot).
- **Found on the second held-out library, after measuring it** (below): the LOLBin rule matched
  `wmic ... /format:list`, one of wmic's own output formats, in 27 of attack_data's recordings (in
  all but one of which it matches another command line too) and in 6 SigmaHQ samples of wmic
  reconnaissance. It now matches `/format:` only when it names a stylesheet file or URL, as
  SigmaHQ's XSL rule does. The change only narrows the rule, so its detections there can
  only fall, and they did not (57 of 106 recordings, before and after).

## The signer of a program reading LSASS

A program outside Windows opening LSASS with the right to read its memory is how credential
dumpers work, and also what security products' installers and updaters do: Avira, Avast, AVG and
Malwarebytes on the clean machines. What tells them apart is whose program it is. Sysmon records
that when the program starts, on its own image load (Sysmon 7: `Signed`, `Signature`,
`SignatureStatus`), and the EVTX parser now carries it to the program's later events: a Sysmon 8 or
10 gets `sourceSigner`, the signature Sysmon found valid on its source process's executable, as
long as every image the log shows that process loading before was signed too (a signed program
that loaded an unsigned DLL is not vouched for by its signature). The row's `enriched` field says
so, and the record is unchanged.

The LSASS rule is then two: a program Sysmon saw signed by a vendor other than Microsoft is medium
(`win-lsass-memory-access-signed`: 7 findings on the clean machines, all security products), and
an unsigned one, one signed by Microsoft (a LOLBin), or one whose signer the log does not show
stays high (2 findings: the Avast installer, 2,379 of their 2,380 events, which Sysmon records as
unsigned, and one other program). A dump tool a vendor signs (Avast's AvDump, which attackers
borrow) is medium, and the rule says to check which program it is. On the 17 recordings of LSASS credential dumping the high rule detects
14 before and after, and both engines agree on every file of EVTX-ATTACK-SAMPLES.

## The gate

`tools/measure_rules.py --detail` writes, next to `rules/measures.json`, what each rule detects
recording by recording and the findings it raises on each clean machine
(`rules/measures-detail.json`). `--gate rules/measures-detail.json` measures again and fails when:

- a rule no longer detects a recording it detected when the committed detail was taken;
- a SigmaHQ rule no longer fires on its own regression sample;
- a recording is no longer read (a parser that stops reading a file loses what it holds);
- a high or critical rule raises more findings on a clean machine than it did, or raises any
  there after being raised to high or critical from a lower level.

What was gained, and more findings from a low or medium rule, are printed and do not fail. A
change that means to lose a detection or add noise commits the measures it takes, so the diff of
the two files is the review of what it changed. The datasets are fetched at their pinned versions
by `--datasets DIR --fetch`, and `.github/workflows/measure-rules.yml` runs the gate weekly, on
demand, and on a pull request that touches the rules, the rule engine, the parsers or the tool,
uploading the new measures as an artifact. It takes about two hours on four cores, the seven
clean machines 45 minutes of it.

## attack_data's Windows datasets, held out

Splunk's [attack_data](https://github.com/splunk/attack_data) (`7a5e9d5`) keeps the event logs of
its attack range as XmlWinEventLog: each record's XML, one a line, as Splunk indexes it. REMN could
not read them; it reads event records exported as XML now ([data sources](../sources.md#windows-event-logs)),
into the rows the same records give from an `.evtx` (the 50,176 records of EVTX-ATTACK-SAMPLES and
EVTX-to-MITRE-Attack read both ways agree but for line breaks, boolean text and control characters).
Some of its exports leave an ampersand or markup inside a value unescaped (`&($ShellId[1] + 'ex')`,
a PowerShell `<#` comment, a task's XML in TaskContent); those 34 records are read once escaped, and
the parser says so. One record whose tags were broken by hand (`<Le>0</Level>`) is not read.

Of the 586 descriptors with Windows logs, 536 are measured and 535 read: 785,361 events, labelled
with 226 ATT&CK techniques. The 36 whose logs are larger than 20 MB together (days of a lab's Sysmon
around one test) and the 14 whose files are not at the pinned commit are left out, and one file
labelled XmlWinEventLog is a CSV export, which is not read. No rule was written against them before they
were measured; the one rule changed since (the LOLBin rule's `/format:`, above) was only narrowed.

Scored as the head-to-head scores: a recording is detected when a rule of its technique (the same
ATT&CK v19 id, its parent or a sub-technique) that can read it raises a finding at the level or
above.

| attack_data Windows, 535 recordings | Medium and above | High and above |
|---|---:|---:|
| REMN's own rules | 91 (17%) | 76 |
| SigmaHQ's Windows and emerging-threats packs | 194 (36%) | 124 |
| Both, as REMN runs by default | **227 (42%)** | 162 |
| With the threat-hunting pack too | 228 | 162 |

The same measure on EVTX-to-MITRE-Attack gives 101 (36%) of its 279 recordings by default at
medium and above.

- **The packs carry attack_data.** Its recordings are mostly Atomic Red Team tests seen by Sysmon
  (476 of its 756 Windows logs are Sysmon), which SigmaHQ's process-creation rules cover well.
  REMN's own rules, written for EVTX-ATTACK-SAMPLES' Security-channel, multi-channel and
  sequence attacks, detect 91 (17%), and 33 recordings only they detect.
- **Where it misses**, by parent technique (recordings undetected at medium and above, by default):
  T1059 (command and scripting interpreter, 14 of 36), T1218 (system binary proxy execution, 10 of
  25), T1574 (hijack execution flow, 10 of 14), T1021 (remote services, 9 of 23), T1078 (valid
  accounts, 9 of 10), T1558 (Kerberos tickets, 8 of 12), T1071 (application-layer protocol, 7 of
  8), T1110 (brute force, 7 of 10). These are the next rules to write; a rule written after
  studying these recordings goes in `WRITTEN_AGAINST` and is not measured on them.
- **137 rules that no recording showed detecting before have their first** here, four of them
  REMN's own: Kerberoasting, password spraying, a suspicious DNS query and a member added to a
  security group.

## The story engine's three limits

The [stories](../stories.md) listed three things host lineage did not read. It reads them now:

- **WMI and WinRM hops.** On the target, a program started by `WmiPrvSE.exe` or the WinRM plug-in
  host belongs to the network logon of a person in the minute before it (medium: tied by time,
  since neither process logs the logon id it runs under), and a WinRM shell (WinRM 91) marks the
  session it came in on. On the source, a command line or a script block that reaches another host
  (`wmic /node:`, `Invoke-Command -ComputerName`, `Enter-PSSession`, `winrs -r:`, PowerShell's WMI
  and CIM cmdlets with `-ComputerName`), the WinRM client's connection (WinRM 6) and a WMI query a
  remote host refused (WMI-Activity 5858) are hops; a hop is strong when the network logon on the
  named host follows. Explicit credentials (4648) are read as WMI, WinRM or RDP by the program that
  used them.
- **Addresses to hosts.** Besides a host's own Sysmon connections and a logon's workstation name,
  a DNS answer on a host of the case (Sysmon 22 or the DNS client's 3008, private answers only)
  and a DHCP lease (the DHCP
  server's audit log, now read as a collection artifact) attribute an address, each with the time
  span of its records, so an address that moved between hosts is read at a step's time as the host
  whose records are nearest.
- **Entra devices to hosts.** A sign-in's device (`deviceDetail.displayName`, join type) of the
  name of a host of the case is that host: the cloud step is placed on the laptop the person also
  logged on to, and a device the case has no logs of is said to be one.

Each has a test on records made for it (`tests/backend/test_lineage.py`), both stores select the
new records the same way (`tests/backend/test_stories.py`, `frontend/src/data/stories.test.ts`),
and the synthetic lab reads into the same stories as before. What they cannot do is in the
stories page's limits: a DHCP lease has no time (the audit log writes local time without a zone),
two people's network sessions opened in the same minute on one host cannot be told apart for a WMI
or WinRM program, and a device is matched to a host by name only.

## What this does not say

- **No busier clean baseline.** The seven machines of evtx-baseline are mostly fresh
  installations: a rule quiet on them can still be loud on a working server or an administrator's
  workstation. No public set of clean Windows logs busier than evtx-baseline was found at a version
  that can be pinned (its `v0.8.5` holds the same seven machines), and the machine that ran this
  could not browse for more. attack_data gives a hint instead, not a rate: its lab machines run
  the Attack Range's own tooling alongside each test (Ansible over WinRM starts
  `powershell -EncodedCommand`, wmic gathers facts, the Atomic Red Team harness runs in
  PowerShell), and the high rules that fire most on recordings of other techniques are the ones
  such tooling sets off. The encoded-command rule fires on 83 recordings, 11 of them of its
  technique, nearly all on Ansible's `-NoProfile -NonInteractive -ExecutionPolicy Unrestricted
  -EncodedCommand`; the LOLBin rule on 98, 18 of them; the rule on a program reading LSASS memory
  on 47, 1 of them, in 41 for PowerShell itself opening LSASS. Some of those are real (a
  Caldera agent, credential dumpers run for another technique's test), and a network managed the
  same way will set off the same rules the same way.
- **attack_data's labels are its authors' tests**, and each dataset also holds what else the lab
  did, so a rule firing on a recording of another technique is not counted either way.
- **What is left out of attack_data**: 36 Windows datasets larger than 20 MB (days of a lab's
  Sysmon around one test), 14 descriptors whose files are not at the pinned commit, and one file
  labelled XmlWinEventLog that is a CSV export, which is counted as not read.
- **The gate guards what the recordings hold.** A rule no recording shows detecting (a lead) can
  lose its logic without the gate noticing; the attack-samples job still holds the samples
  reviewed as identifying a rule, and both engines to the same findings.
- **An XML export is not the log file**: it holds what its query selected, a Windows line break in
  a value is read as a line feed, and a boolean is the text Windows writes (`true`).

## Reproduce

```sh
# every dataset at its pinned version under DIR (about 10 GB), then the measures and their detail
.venv/bin/python tools/measure_rules.py --datasets DIR --fetch --out rules/measures.json --detail rules/measures-detail.json
# the gate CI runs: measure again, compare with the committed detail
.venv/bin/python tools/measure_rules.py --datasets DIR --out /tmp/measures.json --detail /tmp/detail.json --gate rules/measures-detail.json
# the XML reader, the new hops and addresses, the gate's rules
.venv/bin/python -m pytest tests/backend/test_evtx.py tests/backend/test_packages.py tests/backend/test_lineage.py tests/backend/test_rule_measures.py
```

The per-rule tables above come from a harness that parses every recording and clean machine once
and runs REMN's own rules on the stores; `tools/measure_rules.py` takes the same measures for every
rule, the packs' included, in one run.
