# Stories

A story answers the question an investigation keeps asking: what happened to this person,
or to this host? REMN reads a case into one story per person, or per host when the records
name no one, and per incident: the records around what raised a flag, read along the
phases of ATT&CK, each step saying why it belongs and how surely. Stories that share the
attacker's infrastructure form a campaign. The Stories page replaced the Chains and
Relationships pages; the phishing chains ([Attack chains](chains.md)) are one of the things a
story is built from, and the relationship graph is still there to explore.

The engine is `backend/services/analysis/stories.py`, with the identity resolver
(`identity.py`) and host lineage (`lineage.py`) it builds on: pure functions over plain rows,
the same for both stores.

## What starts a story

A story starts from a flag: a finding of medium severity or more on a record, or a phishing
mail its recipient acted on (a mail-led chain with a step tied to the mail: the link resolved,
the attachment saved, a reply to the sender), or low findings of several rules on one person or
host within a week (below). Two kinds of flag start nothing on their own: a
mail received, and a password guessed wrong. Hundreds of people receive the same phishing mail
and a spray tries thousands of accounts; each would be a story that says only "this happened to
you". A chain whose steps are only the recipient's routine day after a flagged mail is still a
mail received. They join the story of their person when there is one, and otherwise stay with
their campaign, where they are counted.

The flags that start a story are one incident of their person until two of them are more than
two days apart; then they are two stories. A mail received or a failed logon joins the incident
nearest it, within two days, and never joins two: a spray's daily failures between two
intrusions three weeks apart leave them two stories, and the failures far from both are listed
with the flags in no story. A flag that names no person, a service installed or a program run by
SYSTEM, belongs to the person whose session, process tree or way into the host it is part of,
and when there is none it starts a story of its own host.

Low findings add up (Splunk ES's risk-based alerting). A person or a host whose low findings,
within seven days, come from at least three rules covering at least two tactics, or from at
least four rules whatever their tactics, starts a story of those findings even though none of
them would start one alone. One rule firing a hundred times is one rule; a mail received and a
failed logon do not count, nor does a finding marked false positive. The run holds together
however far apart its findings are within the week (the two-day cut between incidents does not
split it). Low findings within two days of one of the same person's or host's other incidents
start nothing: that story already reads the records around it. Each of these steps is tied as a
flag with the basis "findings of 3 rules on them within 7 days" (and how the record is theirs),
the story says `startKind: "accumulated"` (other stories say `"flag"`), its summary starts by
saying it was built from low findings, its severity is low, and the stats count these stories
(`accumulated`). The thresholds are the case settings `stories_low_days` (7; 0 turns this off),
`stories_low_rules` (3), `stories_low_tactics` (2) and `stories_low_rules_any` (4), read as
posted with the build.

A finding marked false positive starts nothing and weighs nothing; the analyst's severity
override is the severity the story reads.

## Who is who

A case names one account many ways: `alice@contoso.com`, `CONTOSO\alice`, a SID, an Entra
object id, `CN=alice,OU=Staff,DC=contoso,DC=com`, a bare `alice`. The resolver joins these
forms into identities, and each join says why and how surely:

- **strong**: one record states both forms (a logon's account name and its SID, a sign-in's
  UPN and its object id), or renames one to the other (4781);
- **medium**: the organisation's naming rules join them: `CONTOSO\alice` and
  `alice@contoso.com` when the case showed `CONTOSO` beside `contoso.com`, when `CONTOSO` is
  the first label of an internal domain, or when `contoso.com` is the one organisation's domain
  of the case that `CONTOSO` is the first label of; a distinguished name and the address of its
  domain; a bare name when only one account of that name is in the case, and that account is
  not another organisation's;
- **weak**: only a display name, or a bare name several accounts share, matches. That is
  written as "possibly the same" and never joins two identities.

A record names an account by its fields and by the SID in its System header, the account the
event was logged under: PowerShell's script blocks (4104), and many operational logs, name
their user only there. That SID names its account when it is a user's (a logon states it
beside the account's name); SYSTEM's, which heads every Sysmon record, and the other SIDs of
Windows' own name no one. The header does not say which of the record's accounts it is, so it
joins none of them.

Accounts of two organisations never join, whatever else matches: `alice.martin@other-tenant.example`
is not `alice.martin@northstar.example`, and the resolver names it a namesake, kept apart. A
bare `alice.martin` is only possibly the other tenant's account, even when it is the only
account of that name in the case, unless it was seen on one of that organisation's hosts. A
NetBIOS name the case never shows beside a domain, and that no internal domain starts with,
joins no address when it is the first label of two organisations' domains in the case: beside
`contoso.com`, an attacker's `alice@contoso.co` leaves `CONTOSO\alice` possibly either. With
`contoso.com` internal, the lookalike is a namesake, kept apart.

A machine account (`WS-001$`) never joins a user account unless a record renames one to the
other; an account written both as a machine and without its `$` is noted, since renaming a
machine account that way is how sAMAccountName spoofing (CVE-2021-42278) begins. One name
stated with two SIDs of its domain is noted too: a SID is never reused, so the account was
deleted and created again, or two accounts of that name followed each other.

Built-in accounts and well-known SIDs are identities of their own kind: SYSTEM, LOCAL SERVICE,
DWM-1, `BUILTIN\Administrators`, a service's own SID (`NT SERVICE\...`, S-1-5-80), an IIS
application pool's, a virtual machine's, the domain's groups. A SID written where a name goes,
as a firewall rule's `ModifyingUser` is, is read as a SID. None of these, nor a machine
account, nor an account known only by a SID, is ever a story's subject: a service a site
server's machine account installed over `ADMIN$` (an SCCM client push) is a story of the host
it was installed on. The built-in Administrator is an account people log on with, and can be
one.

A form's confidence is that of the surest path of joins from the identity's label. A step
that names the person by a form joined by the organisation rules is tied to the story with
medium confidence; the "Who is who" tab shows every form, its count and its joins.

On a server case the resolver reads the distinct combinations of the fields that name
accounts from SQL, with their counts, so millions of events are a few thousand records. It
reads them over the whole case, not only the records selected around the flags: a bare name
two accounts write is ambiguous whatever days the stories read, and a script block's SID is
its account's though the logon that says so was a week before. Past 200,000 combinations it
reads the most frequent ones and those of the selected records, and the page says so.

## Sessions, hops and what ran

Host lineage reads, for each host:

- **logon sessions**: a logon (4624) and its logoff (4634, 4647), keyed by host and logon id,
  holding every event that names that logon id as its subject between the two, give or take
  five seconds (4688, 4698, 4720, 4732, 5140, 1102 ...); special privileges (4672) and split
  tokens are noted. Windows hands logon ids out again after a reboot, so a record after its
  id's session ended, before the first logon of that id, or of another account than the
  session's is not in that session. Activity whose logon is not in the evidence still makes a
  session, marked as such, except a machine account's or Windows' own;
- **hops**, how an account came to a host: an RDP logon (4624 type 10, and 4778, 1149 or the
  session manager's 21 and 25), a network session that opened an admin share or an execution
  pipe (`svcctl`, `atsvc`, `PSEXESVC`), created a task or a service or ran a program; a
  service installed within five minutes of an admin share being opened (PsExec's pattern),
  medium when time is all that ties them and strong when the service manager's or the tool's
  pipe (`svcctl`, `PSEXESVC`) was opened in that connection, the service was installed under
  its logon id (4697) or its program was written through the share (5145);
  explicit credentials used towards another host (4648), strong when the logon there follows,
  and read as WMI, WinRM or RDP by the program that used them (`wmic.exe`, `winrs.exe`,
  `mstsc.exe`); a Sysmon connection to a remote-access port of another host of the case;
- **WMI and WinRM hops**: on the target, a program started by `WmiPrvSE.exe` or by the WinRM
  plug-in host (`wsmprovhost.exe`) belongs to the network logon of a person just before it
  (medium: tied by time, since neither logs the logon id it runs under), and a WinRM shell
  started there (WinRM 91) marks the network session it came in on (by time too, so medium);
  such a program keeps its medium tie in a hop that the logon's other records make strong; on
  the source, a command that reaches another host (`wmic /node:`,
  `Invoke-Command -ComputerName`, `Enter-PSSession`, `winrs -r:`,
  `Invoke-WmiMethod -ComputerName`, in a process's command line or a script block),
  the WinRM client's own connection (WinRM 6), strong when the network logon on the named host
  follows, and a WMI query refused by a remote host (WMI-Activity 5858, medium). A hop's source
  is a host when the case names it (the workstation name of the logon) or shows whose address it
  is (below), otherwise the address;
- **addresses**: a private address is a host's when the host's own Sysmon connections come from
  it, a logon names the host as its workstation from it, a DNS answer on a host of the case gives
  it for that host's name (Sysmon 22 or the DNS client's log, 3008; private answers only), or the
  DHCP server leased it to that
  host (its audit log, `DhcpSrvLog-*.log`, events 10 and 11). Each attribution keeps its basis
  and the time span of its records, so an address that moved from one host to another is read,
  at a step's time, as the host whose records are nearest;
- **devices**: an Entra sign-in names the device it came from (its display name and join type,
  from `deviceDetail`); a device of the name of a host of the case is that host, so a sign-in
  from a joined laptop is a step on the laptop, and a device the case has no logs of is said to
  be one;
- **process trees**: Sysmon 1 by process GUID, 4688 by process id and creator id on one host
  (the latest creation of that id before the child, since ids are reused), a process both
  logged read as one, each placed in its logon session. When the 4688 names its parent's
  program, that creation must be of it (otherwise the parent started before the evidence and
  its id went to another program since) and may be up to a week old; with the id alone, a day;
- **what the evidence cannot show**: a host without Sysmon 1 has only 4688's view of what ran
  (parents by process id, no GUIDs or hashes, and no command lines when the audit policy left
  them out); one with neither has none; one without 4624 does not say who logged on; a cleared
  log does not hold what came before the clear.

## Steps, ties and phases

Every record of a story is a step, or folded into one, and every step says why it is there:

| tie | the record | confidence |
|---|---|---|
| flagged | carries a finding, and names the person, or (naming no one) is part of their session, process tree or way in | as sure as the form it names them by, or as lineage ties it: medium for a program WMI or WinRM started, a WinRM shell or an RDP session manager's record placed in the session by time, or a service tied to an admin share by time only |
| phishing chain | is a step of the person's mail-led chain | strong with a link to the mail, else medium |
| same session | is the logon of a session in which a flagged record happened, or the other logon of its split token | strong, medium when time alone placed the flagged record in the session |
| same way in | is part of the same hop (the service after the admin share) | strong, medium when this record or the flagged one is part of the hop by time only |
| process tree | started a flagged process | strong |
| same source | came from an address the story's findings name, or is that address trying another account | medium |
| same person | names the person and is something (a task, a rule, a group change) | as sure as the form |

A weak tie never puts a record in a story. The story's confidence is the weakest tie of its
flagged steps. A program run with no finding is most of a person's day, so their name alone
does not put one in a story: it joins when it ran in one of the story's logon sessions, or is,
or descends from, one of the story's processes, and its step says which.

A step's phase comes from its rule's first tactic tag, else its first technique's tactic; with
no finding, from what the record is: a phishing mail is initial access, a failed logon
credential access, a log cleared defense impairment, a scheduled task or a service
persistence, a program run execution. The DNS query, download or connection a mail-led chain
ties to the mail's link or attachment is execution (the user opened it). ATT&CK v19 split
Defense Evasion into Stealth and Defense Impairment, so a rule tagged `defense-evasion` reads
through its technique (T1685.005, the clearing of an event log, is defense impairment). A
successful logon is initial access or lateral movement whatever the brute force before it
reads as; an RDP logon from outside is initial access (external remote services), and the
same outside source reaching another host once it is in is lateral movement. Private
addresses, and carrier-grade NAT's shared space (100.64.0.0/10, a provider's or Tailscale's),
are inside.

Records that repeat without a finding (logons, sign-ins, mailbox reads, share access) fold
into one step per run of ten minutes; so do records with the same findings and tie, a spray's
failures among them. A story keeps at most 400 steps. Past them it keeps its flagged steps
first, the worst first; then the steps that change what an intruder holds (initial access,
persistence, privilege escalation, credential access, lateral movement, defense impairment,
exfiltration, impact); then its sessions, hops, process parents and sources; then the other
steps with a phase, the programs run with no finding among them; and routine records last.
The flags go worst first; within each group of context (sessions and after) the rarest in the
case go first (below); otherwise each group keeps its time order. A story that cut steps says how many
(`stepsTruncated`) and says so where it stops, the stats count the stories that did, and a flag
cut from its story is listed with the flags in no story.

A step says how rare it is in the case (`rarity`, after NoDoze's prevalence): for a program
started, on how many of the case's hosts that log process creations the same parent started the
same program ("cmd.exe → rclone.exe: seen on 1 of 40 hosts"); for a logon, how many of the
accounts that log on to that host came from the same source ("ws-004 → fs-001: seen for 1 of
the 12 accounts that log on to fs-001"); for a DNS query or a connection to an outside domain,
on how many hosts that domain (its registrable part) was looked up or reached. The counts are
over the rows the build read, in one pass; a case with one host to compare gives none. The step
pane shows it.

The phase rail at the top of a story shows the fifteen tactics in ATT&CK's order, lit where
the story has steps, numbered in the story's own order, coloured by the worst finding in each;
a phase is a filter for the timeline.

A story's score sorts the list and favours weight and attack order over breadth (after RapSheet,
IEEE S&P 2020). Each finding weighs its severity (critical 10, high 6, medium 3, low 1) times how
far its rule can be believed, from its measure: 1 for a rule seen to detect what it looks for on
recorded attacks, 0.8 for one never measured (a mail rule, your own, another tool's, one changed
since or that needs settings), 0.6 for a lead never seen to, 0.5 for one that misses its own
sample; a rule that fired on the logs of clean machines loses a quarter more, half when it fired
on all of them. The score is three points per unit of weight on the heaviest run of findings
whose phases follow ATT&CK's order as time goes (one technique per phase: a finding out of that
order is not part of it), plus the weight of the other techniques up to 20 points (a technique
counts once, however many findings its rules raised), plus ten for a mail-led chain, capped at
100. A lone critical finding from a rule that detects scores 30; an administrator's whoami,
PsExec and scheduled task, three medium findings of which only two come in ATT&CK's order, score
less than a critical shadow-copy deletion. The story says why (`scoreParts`: the run with each
finding's phase, technique, rule, verdict, precision and weight, its points, the other
techniques and their points, the chain's points, and how many techniques weigh less), in a
sentence of its summary and on the score's tooltip.

A story's severity is its worst finding, raised to high when three distinct techniques or more,
in three phases or more, each carry a finding of medium or more from a rule that is neither a
lead nor noisy on clean machines (a rule never measured counts). Three phases of an
administrator's routine from rules that fire on clean machines are not an intrusion.

## Measured marks

A finding on a step carries its rule's measure ([REMN's rules, measured](reviews/2026-09-24-measured-rules.md)):
a rule that detects what it looks for on recorded attacks, a lead that has never been seen to,
one that misses its own sample, one that fires on clean machines. The step pane gives the
sentences behind each. The same measures weigh each finding in the story's score and decide
which findings can raise its severity (above); the build reads them from `rules/measures.json`
by rule id, or from the finding when it carries its rule's measure (`measured`).

## Campaigns

The attacker's infrastructure in a story's flagged steps is: the addresses its findings name,
the outside sender domains, link domains and attachment digests of its flagged mails, the
forwarding addresses its inbox rules and mailbox settings name, and the applications its
people consented to. Stories that share any of these are one campaign. A campaign also lists
the accounts outside its stories that the same sources reached within two days of one of its
stories (an address can be someone else's a week later): the recipients of its flagged mails,
the accounts its addresses tried. Flagged mails and failed logons in no story and no campaign
are grouped by sender domain and by address. Nothing in a campaign's list of accounts says they
were compromised.

An address most of the organisation's users sign in from, an office's NAT or a VPN's egress, is
not the attacker's: at least five people of one organisation signed in from it with no finding
of medium or more on their records from it, and they are more than half of that organisation's
people the records show signing in from outside. The findings may name it, and the story says
so (`sharedAddresses`), but it ties no record to the story and joins no stories into a campaign.

## Where it stops

Each story lists what its evidence cannot show: its hosts' coverage (above), a story with no
initial access in the records it reads, and the limits of the build. The "Where it stops" tab
adds the case's own file gaps (holes in a log's record numbering, clocks set back, damaged
chunks, logs that start after the first finding, exports cut at a service limit).

## Notes and claim checks

An analyst's note on a story is checked against the story's own records: every address, hash
and case name it gives should be in them, and the page says which are not, when the note is
saved and each time it is shown again.

A note holds on to what its story is about: the forms its person's account goes by (or the
host's name) and the findings on its steps. New evidence can rename a story (an address form
becomes its label), move its first day (an earlier logon) and change its id and its rows; a
rebuild gives the note to the story of the same kind that keeps most of those forms and
findings, as long as it shares a form other than a bare account name (a namesake in another
organisation shares that) and one of the note's findings or a start within three days. Each
story takes one note. Notes saved before notes held on to their story are still read, by the
key they were saved under (the story's kind, label and UTC day of its start) or by a story of
the same subject near that day. A note no story holds any more is not dropped: the page says
so and lists it under the stories ("Notes whose story is gone"), to attach to the open story
(after the note it has) or delete; the report counts it.

The page asks before switching stories, leaving the Stories list or rebuilding throws away a
note being typed, and a note is saved in one database transaction, so two tabs saving notes
at once keep both.

**Ask the analyst** hands a story to the AI view. The request is the analyst's words; what the
story took from the records (the subject's name, step titles such as a mail's subject or a
command line, the reasons, where it stops) goes between `<evidence>` markers as a tool result
does, with REMN's notice when some of it addresses a model, so a record cannot speak as the
analyst.

## In the report

The report prints the stories at or above its severity floor, the highest-scoring first and at
most twenty, before the chains: each with its phases in the order they happened, what marks
each (its worst findings, else its first step), the analyst's note (checked against the
story's records like a chain's narrative) and where its evidence stops: its hosts' coverage and
a story no record shows starting (no initial access). Above the stories it says what the build
could not read (every cut the page lists, below) and, when the stories no longer read the case
as it is, that they are out of date and why; the Report page offers to rebuild them. The same
lines go to "Where it stops" at the end, and the number of notes whose story is gone is
printed too. With "reviewed items only", a story prints when it has a note. A story is how the
case reads, not a decision: the verdict on the cover still comes from the chains and incidents
the review decided.

## Explore

Explore browses the relationship graph of the evidence: every host, account, file, process,
digest, address and domain the records name explicitly, the records that name it, its
neighbours, and the links between them with their review ([identity and link
semantics](relationship-intelligence.md)). A story step shows the links of its own records
once the graph is built, with the same review; an accepted link can go to the report.

## Both stores

A server case asks the API (`POST /api/stories/build` with its store key) to select its rows by
SQL; a browser case selects them from IndexedDB and posts them. Both select the same way: the
records the findings cite; then, from a day before to three days after each flag, the records
that name the flagged people, the records from the outside addresses the findings name, and the
logons, sessions, processes, shares, services and tasks on the flagged hosts, with the WinRM
(6, 91), WMI-Activity (5858) and DNS client (3008) events, the process creations and script
blocks that reach another host, and their Sysmon DNS answers that give a private address (at
most 20,000); the DHCP leases (at most 20,000, whatever their time, since the audit log's local
times carry no zone and are kept without one); the mails the findings cite (at most 5,000), the
300 riskiest others (a risk of 45 or more) and the mails the flagged people sent. A build reads
the first 2,000 records each finding cites, at most 50,000 flagged records and 50,000 records
around them (a browser case under one cap for the three kinds, a server case 50,000 of each),
and 5,000 of the mails the flagged people sent; past 40 separate windows the flags are read as
one span from the first to the last. A selection past its cap reads first the records that are
something (a scheduled task, a service installed, an account or a group changed, a log cleared,
explicit credentials, a mailbox rule or permission, a consent), then those nearest a flag in
time, so what a cut loses is the routine far from every flag, not the late phases. A server case
selects by at most 2,000 account names, 500 flagged hosts and 500 outside addresses, those the
most flagged records name first, and the stats say which keys were cut (`truncated`).

Every cut is named, with what it left out when the page knows: the findings that cite more
than 2,000 records, the flagged or high-risk mails with no date (no story can place them), the
seeds past 300, the flag windows read as one, and, in a browser case, how many records of each
kind the shared cap left out. When a selection is cut the page says so, and an absent step is
then not a negative result. The browser posts only the fields the engine reads
(`STORY_EVENT_FIELDS`, compared with the Python by a test), and at most 56 MiB, under the 64 MiB
the server takes in one request: past it, the long text of each event (command lines, script
blocks, summaries) is cut to 2,000 characters, then the records around the flags are left out,
the last read first, and the page says how many. A build also returns the phishing chains of
the same rows, kept for the review and the report as before.

The snapshot is stored with the case, with a digest of what the build read: the findings (the
key, rule, effective severity, rows and time of each, false positives left out), the evidence
files and the case's settings. When those no longer match the case (a rule run, a finding
marked false positive, a severity set by hand, evidence added or removed, settings changed),
the stories are out of date: the page builds them again when it opens if the last build read
at most 20,000 records and cut nothing, and otherwise says so with a button to rebuild; the
report says so too. A snapshot built before builds kept their inputs counts as out of date. The
snapshot is cleared with the case's findings when evidence is removed; it is not in a case
export, since its references name this database's rows: the importing case reads its stories
again when the page opens. A case with findings and no snapshot is read into stories when the
page opens.

A story or a step added to the case timeline opens that story, and that step, again from the
timeline; when a rebuild no longer holds it, the page says so instead of opening another
story. A rebuild keeps the open story open, found by what it shares when its id changed.

## How well it reads the lab

`tests/backend/test_stories_lab.py` generates the synthetic linked lab, parses it, runs REMN's
rules and reads it into stories. Each of the five planted attacks (S01, S02, S03, S04, S06) is
one story of its victim, holding every planted record of its scenario (recall 1.00) with
precision from 0.97 to 0.99, nothing of another scenario, and at most ten background records,
each critical and scoring from 84 to 100; the other tenant's `alice.martin` who cleared a log on
her own host is a story of her own that no Northstar story holds (critical, scoring 15: one
finding, from a rule that fired on every clean machine it was measured on), the domain seen on
Alice's host two weeks earlier is in no story, and the benign controls and the prompt-injection
lure raise none. S04 reads as initial access,
credential access, execution, persistence, lateral movement, collection and defense
impairment, with its RDP session from 203.0.113.69 on WS-004, the log cleared inside that
session, and the admin share and the service installed a minute later on FS-001; with Sysmon
removed it says what ran on WS-004 is not in the evidence. The browser-only end-to-end test
(`frontend/e2e/browser-only.spec.ts`) reads the same lab as a visitor would, in a browser case
with no internal domain set and the default rule packs on, and finds the same six stories. These
are synthetic scenarios: a regression benchmark, not a measured accuracy on field cases.

The stories are also read on a recorded intrusion: MITRE's APT29 evaluation as OTRF's
Security-Datasets recorded it (the Sysmon, Security and PowerShell logs of four hosts in NXLog
JSON, MIT, fetched on demand and never committed). `tools/apt29_stories.py --data DIR` (`--fetch`
downloads the pinned zips into DIR) converts the records to the rows an `.evtx` of them gives, runs
REMN's own rules on a server store (`--packs` adds the default SigmaHQ packs), builds the stories
as a server case does, and prints each story with the checks below;
`REMN_APT29=DIR pytest -m heavy tests/backend/test_apt29_stories.py` runs the same checks, day 1 in
about a minute. On day 1 (196,081 records: pbeesly's payload, UAC bypass, discovery, credential
access and persistence on SCRANTON, then PsExec to NASHUA; NEWYORK is the domain controller and
UTICA is left alone) REMN's own rules raise 258 findings and the build makes five stories in
under four seconds. No story is about a SID or a service account, and pbeesly's story holds the
31 flagged script blocks pbeesly ran on SCRANTON and NASHUA (their header names pbeesly's SID)
and reaches NASHUA through the explicit credentials, the PsExec service and WinRM. Two checks
still fail, and the test holds them as expected failures until the work they wait for lands:
NEWYORK and UTICA are high host stories made of Windows' own scheduled tasks and DSC script
blocks (a host story needs a minimum of evidence), and SCRANTON's and NASHUA's host stories hold
flags of the same intrusion with nothing linking them to pbeesly's.

## Limits

- A person is joined across forms only as the records and the naming rules allow: two
  accounts one person uses (an admin account beside a user account) are two identities.
- A DHCP lease has no time: the audit log writes the server's local time without its zone,
  and REMN does not guess one. An address leased to several hosts is read at a step's time
  from the other records that attribute it, and otherwise as the host it was leased to most.
- A WMI or WinRM program on the target is tied to the network logon just before it by time
  only (within a minute): two people's network sessions opened in the same minute on one host
  cannot be told apart, and the step says it was tied by time.
- An Entra device is matched to a host by name only: a device renamed, or one whose name two
  hosts of different domains share, is not joined; a device id is not read against the
  machine's own records.
- A finding's measure is its rule's by rule id: a rule of your own that replaces a bundled rule
  of the same id is weighed by the bundled rule's measure unless the finding carries its own
  (`measured`), which the page does not send yet. Mail rules and Hayabusa's are not measured and
  weigh as rules never measured.
- The thresholds at which low findings add up are case settings the build reads, but the page's
  settings do not offer them yet: a case posted by the page uses the defaults.
- A case keeps at most 200 stories, the highest-scoring first; the flags of the stories past
  them are listed with the flags in no story, saying why. The API holds what a caller asks for
  to at most 1,000 stories and 2,000 steps a story, and a gap between one hour and thirty days.
- An address is read as the organisation's shared egress from the records a build reads: an
  attacker who signed in to five accounts or more from one address with no finding on any of
  those sign-ins, and so outnumbers the people the records show signing in from outside, would
  be taken for one.
