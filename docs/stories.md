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
the attachment saved, a reply to the sender). Two kinds of flag start nothing on their own: a
mail received, and a password guessed wrong. Hundreds of people receive the same phishing mail
and a spray tries thousands of accounts; each would be a story that says only "this happened to
you". A chain whose steps are only the recipient's routine day after a flagged mail is still a
mail received. They join the story of their person when there is one, and otherwise stay with
their campaign, where they are counted.

The flags of one person are one incident until two of them are more than two days apart;
then they are two stories. A flag that names no person, a service installed or a program run by
SYSTEM, belongs to the person whose session, process tree or way into the host it is part of,
and when there is none it starts a story of its own host.

A finding marked false positive starts nothing and weighs nothing; the analyst's severity
override is the severity the story reads.

## Who is who

A case names one account many ways: `alice@contoso.com`, `CONTOSO\alice`, a SID, an Entra
object id, `CN=alice,OU=Staff,DC=contoso,DC=com`, a bare `alice`. The resolver joins these
forms into identities, and each join says why and how surely:

- **strong**: one record states both forms (a logon's account name and its SID, a sign-in's
  UPN and its object id), or renames one to the other (4781);
- **medium**: the organisation's naming rules join them: `CONTOSO\alice` and
  `alice@contoso.com` when `CONTOSO` is the first label of the address's domain or of an
  internal domain, or when the case showed the two side by side; a distinguished name and the
  address of its domain; a bare name when only one account of that name is in the case;
- **weak**: only a display name, or a bare name several accounts share, matches. That is
  written as "possibly the same" and never joins two identities.

Accounts of two organisations never join, whatever else matches: `alice.martin@other-tenant.example`
is not `alice.martin@northstar.example`, and the resolver names it a namesake, kept apart. A
machine account (`WS-001$`) never joins a user account unless a record renames one to the
other; an account written both as a machine and without its `$` is noted, since renaming a
machine account that way is how sAMAccountName spoofing (CVE-2021-42278) begins. Built-in
accounts and well-known SIDs (SYSTEM, LOCAL SERVICE, DWM-1, `BUILTIN\Administrators`) are
identities of their own kind and never a story's subject; neither is an account known only by
a SID. The built-in Administrator is an account people log on with, and can be one.

A form's confidence is that of the surest path of joins from the identity's label. A step
that names the person by a form joined by the organisation rules is tied to the story with
medium confidence; the "Who is who" tab shows every form, its count and its joins.

On a server case the resolver reads the distinct combinations of the fields that name
accounts from SQL, with their counts, so millions of events are a few thousand records.

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
flagged steps.

A step's phase comes from its rule's first tactic tag, else its first technique's tactic; with
no finding, from what the record is: a phishing mail is initial access, a failed logon
credential access, a log cleared defense impairment, a scheduled task or a service
persistence, a program run execution. The DNS query, download or connection a mail-led chain
ties to the mail's link or attachment is execution (the user opened it). ATT&CK v19 split
Defense Evasion into Stealth and Defense Impairment, so a rule tagged `defense-evasion` reads
through its technique (T1685.005, the clearing of an event log, is defense impairment). A
successful logon is initial access or lateral movement whatever the brute force before it
reads as; an RDP logon from outside is initial access (external remote services), and the
same outside source reaching another host once it is in is lateral movement.

Records that repeat without a finding (logons, sign-ins, mailbox reads, share access) fold
into one step per run of ten minutes; so do records with the same findings and tie, a spray's
failures among them. A story keeps at most 400 steps, those with findings first.

The phase rail at the top of a story shows the fifteen tactics in ATT&CK's order, lit where
the story has steps, numbered in the story's own order, coloured by the worst finding in each;
a phase is a filter for the timeline.

A story's severity is its worst finding, raised to high when three phases or more each carry a
finding of medium or more. Its score sorts the list: four points per unit of each phase's worst
finding (critical 5, high 4, medium 2, low 1), ten for a mail-led chain, two per flagged phase
up to ten, capped at 100.

## Measured marks

A finding on a step carries its rule's measure ([REMN's rules, measured](reviews/2026-09-24-measured-rules.md)):
a rule that detects what it looks for on recorded attacks, a lead that has never been seen to,
one that misses its own sample, one that fires on clean machines. The step pane gives the
sentences behind each.

## Campaigns

The attacker's infrastructure in a story's flagged steps is: the addresses its findings name,
the outside sender domains, link domains and attachment digests of its flagged mails, the
forwarding addresses its inbox rules and mailbox settings name, and the applications its
people consented to. Stories that share any of these are one campaign. A campaign also lists
the accounts outside its stories that the same sources reached: the recipients of its flagged
mails, the accounts its addresses tried. Flagged mails and failed logons in no story and no
campaign are grouped by sender domain and by address. Nothing in a campaign's list of accounts
says they were compromised.

## Where it stops

Each story lists what its evidence cannot show: its hosts' coverage (above), a story with no
initial access in the records it reads, and the limits of the build. The "Where it stops" tab
adds the case's own file gaps (holes in a log's record numbering, clocks set back, damaged
chunks, logs that start after the first finding, exports cut at a service limit).

## Notes and claim checks

An analyst's note on a story is checked against the story's own records: every address, hash
and case name it gives should be in them, and the page says which are not. A note is kept by
what the story is about and the UTC day it starts, so it outlives a rebuild and a case export.

## In the report

The report prints the stories at or above its severity floor, the highest-scoring first and at
most twenty, before the chains: each with its phases in the order they happened, what marks
each (its worst findings, else its first step), the analyst's note (checked against the
story's records like a chain's narrative) and where its evidence stops. With "reviewed items
only", a story prints when it has a note. A story is how the case reads, not a decision: the
verdict on the cover still comes from the chains and incidents the review decided.

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
times carry no zone and are kept without one); the high-risk mails and the mails the flagged
people sent. A build reads at most 50,000 flagged records and
50,000 records around them (a server case, 50,000 of each of the three kinds), and 5,000 of the
mails the flagged people sent; when a selection is cut the page says so, and an absent step is
then not a negative result. The browser posts only the fields the engine reads (`STORY_EVENT_FIELDS`, compared with
the Python by a test). A build also returns the phishing chains of the same rows, kept for the
review and the report as before.

The snapshot is stored with the case and cleared with it when evidence is removed; it is not in
a case export, since its references name this database's rows: the importing case reads its
stories again when the page opens. A case with findings and no snapshot is read into stories
when the page opens.

## How well it reads the lab

`tests/backend/test_stories_lab.py` generates the synthetic linked lab, parses it, runs REMN's
rules and reads it into stories. Each of the five planted attacks (S01, S02, S03, S04, S06) is
one story of its victim, holding every planted record of its scenario (recall 1.00) with
precision from 0.92 to 0.99, nothing of another scenario, and at most ten background records;
the other tenant's `alice.martin` who cleared a log on her own host is a story of her own that
no Northstar story holds, the domain seen on Alice's host two weeks earlier is in no story, and
the benign controls and the prompt-injection lure raise none. S04 reads as initial access,
credential access, execution, persistence, lateral movement, collection and defense
impairment, with its RDP session from 203.0.113.69 on WS-004, the log cleared inside that
session, and the admin share and the service installed a minute later on FS-001; with Sysmon
removed it says what ran on WS-004 is not in the evidence. The browser-only end-to-end test
(`frontend/e2e/browser-only.spec.ts`) reads the same lab as a visitor would, in a browser case
with no internal domain set and the default rule packs on, and finds the same six stories. These
are synthetic scenarios: a regression benchmark, not a measured accuracy on field cases.

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
- A case keeps at most 200 stories, the highest-scoring first.
