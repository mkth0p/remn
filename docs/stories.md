# Stories

A story answers the question an investigation keeps asking: what happened to this person,
or to this host? REMN reads a case into one story per person, or per host when the records
name no one, and per incident: the records around what raised a flag, read along the
phases of ATT&CK, each step saying why it belongs and how surely. Stories that share the
attacker's infrastructure form a campaign. The Stories page replaced the Chains and
Relationships pages; the phishing chains ([Attack chains](chains.md)) are one of the things a
story is built from, and the relationship graph is still there to explore. The analyst decides
what a story is, and can dispute a step, merge two stories or split one ([Decisions](#decisions)).

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
SYSTEM, belongs to the person whose session, process tree or way into the host it is part of.
When the records tie it to no one, it belongs to the one person who was on the host then: whose
console, RDP or cached-credential session there was open at its time (a session whose logoff is
not in the evidence counts as open for two days after its logon), or whose own flagged steps
there fall within fifteen minutes of it, when that person has a flag of their own within two
days. Their own flagged steps are what they did: a program run, a service or a task created, a
script block; not a logon, a share opened, or the connections, lookups, file writes, image loads
and handle opens every session makes (a domain logon opens IPC$ on a domain controller). The tie
is medium and says so: "on WS-004 while daniel.roy's session 0x9a01 was open". Such a flag
supports the story; it does not start one, so it never joins two incidents of its person. When
two people or more were on the host then, the flag stays the host's and its step says who was on;
when there is no one, it starts a story of its own host.

A host's own flags make a story only on evidence of their own: a rule that fires on clean
machines fires on a host's own maintenance too (Windows updating its built-in scheduled tasks,
Desired State Configuration's script blocks, a console's handle on its shell). They stand when
one of them is critical; when one is of a rule measured to detect what it looks for on recorded
attacks and not seen firing on clean machines ([measured marks](#measured-marks)); when findings
of medium or more fall in two phases or more from rules not seen firing on clean machines (a rule
never measured on clean machines counts here); or when the story has a strong or medium link to a
person's story ([incidents](#incidents)). The story says which (`standing`). Otherwise its flags
are listed with the flags in no story, as "a host's lone lead", and the stats count them
(`hostLeads`). "Measured to detect" alone is not the bar: on the first day of the APT29
evaluation, the rules that flag a domain controller's and a workstation's own tasks, script
blocks and console handles all detect what they look for on recorded attacks (the scheduled task
rule twelve of twelve), and two of them fire on half the clean machines or more.

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
  is (below), or the domain controllers' records name it (below), otherwise the address;
- **the domain controllers' records**: the hosts that write Kerberos records (4768, 4769) are
  the domain controllers, flagged or not. A service ticket (4769) granted
  with the logon GUID of a logon (4624) is that logon's ticket (strong); without the GUID, a
  ticket for the host's own account (`FS-001$`, which `cifs` and `host` ask for) that the same
  account asked for from the logon's address, within a minute before its network logon there, is
  its ticket by time (medium). A hop then says which service was asked for ("with a Kerberos
  ticket for FS-001$ from dc-01"), holds the ticket as one of its records, and, when the logon
  names neither an address nor a workstation, comes from the ticket's client address, read as a
  host when the case knows whose it is (medium). Explicit credentials (4648) whose target logon
  GUID is the logon's, or the ticket's, were used on the logon's source: the hop comes from that
  host (strong by the logon's GUID, as sure as the ticket's tie through it), and the 4648 reaches
  the logon there by it rather than by time. An NTLM validation (4776) of the account within a
  minute before a network logon that names no workstation, on a domain controller or on the host
  itself, names the workstation it came from (medium, by account and time; validations from two
  workstations in that minute name none). A host whose logons consistently follow their tickets
  by more than a minute, or precede them, has a clock that differs from the domain controller's:
  the host says by how much (`clock`, the median of its logons matched by GUID, from two of them
  on) and its limits say so, and the ties by time between its logons and the domain controllers'
  records allow for it instead of silently missing;
- **other credentials**: a NewCredentials logon (4624 type 9, as `runas /netonly` and
  pass-the-hash tools make) whose network account differs from its own is a step "used other
  credentials (…) for the network", lateral movement, that names both accounts as explicit
  credentials (4648) do, so it joins the stories of both; a network logon of that account on
  another host from this one, while the session is open (or within twelve hours when its logoff
  is not in the evidence), is a way into that host with those credentials (medium, by account,
  source and time);
- **addresses**: a private address is a host's when the host's own Sysmon connections come from
  it, a logon names the host as its workstation from it, a DNS answer on a host of the case gives
  it for that host's name (Sysmon 22 or the DNS client's log, 3008; private answers only), the
  DHCP server leased it to that
  host (its audit log, `DhcpSrvLog-*.log`, events 10 and 11), a domain controller gave the host's
  own account a Kerberos ticket there (4768, 4769), or explicit credentials used on the host
  asked for their ticket from it (a 4648 and a 4769 of one logon GUID). Each attribution keeps
  its basis and the time span of its records, so an address that moved from one host to another
  is read, at a step's time, as the host whose records are nearest;
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
| flagged | carries a finding, and names the person, or (naming no one) is part of their session, process tree or way in, or happened on a host only they were on then | as sure as the form it names them by, or as lineage ties it: medium for a program WMI or WinRM started, a WinRM shell or an RDP session manager's record placed in the session by time, a service tied to an admin share by time only, or a flag on a host only they were on |
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

## Spine

A story's spine is the few steps a reader takes in at a glance: from the way in to the worst of
it, each keeping the tie that put it in the story. It is DEPIMPACT's cut (USENIX Security 2022:
keep what joins an alert to the ways into the system) and RapSheet's skeleton (the alerts and
what connects them), over the story's own steps. What led to what, among the steps:

- a logon before what happened in its session (both logons of a split token), else the
  session's first step before the rest;
- a program before those it started: the nearest ancestor whose creation the story holds, six
  generations up at most;
- a hop's first record before the rest of it, and the session open on the source host at the
  hop's time (the hop's person's first) before the hop, else the source host's last flag before it;
- a way in from an address the story's findings name before what else came from that address;
- a phishing mail before what its link or attachment reached (a chain step tied to the mail by
  an artifact) and before a way in from an address the findings name;
- last, a host record none of these reaches, naming the person of a session open on that host
  then, after that session's logon (the engine's tie by time and place).

The anchor is the step of the worst finding: of equal ones, one that is not a way in itself,
then one that changes what an intruder holds, then the first; of the ten worst, the first
whose ties lead back to a way in (a step of initial access). The ties are walked back from the
anchor to the ways in, then forward from the ways in; the spine is the steps on both walks that
lead to the anchor or to another flag, from the first way in on, in time order. A flag
repeated on its host (the same phase and rules: the service PsExec installs each time it runs)
is kept once. A spine holds fifteen steps at most: past them it keeps the way in and the
anchor, then the flags that change what an intruder holds and the steps that lead to them, then
the other flags, then what joins them, and a step kept only for joining others stays only when
something it leads to stays.

When the anchor's ties reach no way in, the spine starts at the story's earliest flag and runs
forward from it, from the anchor and from as far back as the anchor's ties go. It says the way
in is not in the evidence or, when the story has initial access steps its ties do not reach,
that they lead back to none of them.

A story carries `spine` (the step ids, in time order) and `spineBasis`: `anchor` (a step id),
`wayIn` (the ways in the ties reach first, empty when none), `tied`, `cut` (the steps on those
paths left to the full timeline) and `text`, the sentence the page and the report print
("Anchored on … The story's ties lead back from it to the way in: …"). A story with no step
has an empty spine and no basis.

The page opens a story on its spine, the first thing of its Story tab under the phase rail:
the basis, then the steps as a line of knots coloured by their worst finding, the way in and
the anchor marked, each with its time, how long after the step before, its phase, its worst
finding and its tie. "Full timeline" shows every step; picking a phase or opening a step off
the spine (from the case timeline) shows it too, and "Spine" goes back. j and k move along
what shows. A story built before spines opens on its timeline: build the stories again for its
spine.

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

## Incidents

One intrusion is often several stories: the person who came in, the service account they then
used, the server whose own flags name no one. Stories are linked when the records join them, and
the stories their strong and medium links join are an incident. Each link says which story it
reaches, its kind, why (`basis`), how surely and the records it rests on (`refs`):

| link | when | confidence |
|---|---|---|
| hop | a story's person, or a host story's host while its flags were raised, reaches another story's host (RDP, an admin share, a remote service, WMI, WinRM) from an hour before its first flag to its last | the hop's own when the host story holds the hop's records, else medium at most; weak for a bare connection to a remote-access port |
| explicit credentials | the same, with explicit credentials (4648: its subject is who took the way in), or one person's hop into another story's host or account with another person's account | the hop's own |
| process tree | a program of one story descends, within six generations, from a program of another story's flags or of its person's session (a `runas`) | strong |
| one record names both | one record whose two people are two stories' subjects: a password reset of one by the other, an account enabled | the weaker of the two names |
| on the host then | a host's flag left the host's because two people or more were on it: its story and theirs | weak |

A weak link is shown on the story but joins nothing; a hop from a person who was one of several
on a host when its flags were raised is weak too, since it makes no one's the more. A link never
passes through a record of a finding marked false positive (as Defender XDR never correlates
through an alert so marked), and never joins two organisations: when both stories' subjects have
one and they differ, there is no link. An incident holds twenty stories at most, the
highest-scoring first; one that joined more says how many it left out and which (`cut`,
`cutStories`), those stay stories of their own, and the stats count the incidents that cut
(`incidentsCut`).

The build lists its incidents (`incidents`), the highest-scoring first: `id`, a `label` from its
two highest-scoring stories, its `stories` in time order, `start`, `end`, `severity` (its worst story's),
`score` (its best story's), `people`, `hosts`, `cut` and `cutStories`. Each story says its
incident (`incident`, or null) and its links (`links`: `story`, `kind` of `hop`, `credentials`,
`process`, `record` or `session`, `basis`, `confidence`, `refs`), the surest first; a host story
says what it stands on (`standing`). An incident is not a campaign: a campaign is the stories
that share the attacker's infrastructure, which can be one actor's separate intrusions; an
incident is the stories one intrusion's own records join. Campaigns are read as before.

The page lists an incident's stories together, in time order, where its first story stood, under
a line that says "one intrusion", how many stories and over what span; it says "one intrusion"
since the app's own incidents are the rules' findings grouped. An open story lists the stories it
links to, each with its kind, confidence and basis, one click away, and a host story says what it
stands on.

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

## Decisions

A story is how the case reads; the analyst decides what it is. The decisions are kept in the
case beside the notes (the `story-decisions-<case>` entry of its key-value store,
`frontend/src/data/storyDecisions.ts`), go with the case bundle and are deleted with the case.
Each is dated, and each that changes what a story holds carries the analyst's reason, which the
page shows beside it and the report prints.

**The story.** The bar under a story's head decides it: open (the default), reviewed, confirmed
incident, benign or false positive. Confirmed, benign and false positive need a reason; reviewed
takes one if given. The list tags a decided story and dims one decided benign or false
positive. A story decided benign or false positive dismisses the stories merged into it too, and
the bar says so before it is saved. The decision is on the story, not on its findings: their
statuses stay the Findings and Review pages'.

**A step.** A step's pane confirms the step and its tie, or disputes it, with an optional reason.
A disputed step stays in the timeline, struck out and grey, and is left out of the story's
phases, its phase rail, its severity, its headline and its findings; a confirmed step counts as
a strong tie. Disputing a step changes no finding by itself: when the step carries findings the
pane offers "also mark the finding false positive", which writes them through the path the
findings review uses (`findingReviews.ts`: status false positive, decided by the analyst, a line
in their notes naming the step, kept when a rule run finds it again), so the Review page and
the report see it. Taking the dispute back does not set the finding back.

**Not part of this story.** A step's records can be taken out of its story, with a reason: the
story leaves them out after every rebuild, and the Decisions tab lists them to put back. The
records stay in the case and in every other view; they are taken out of this story, not moved
into another.

**Merge and split.** "merge into another story" reads a story as part of another, with a reason:
its steps join the other's in time order, the list no longer shows it and marks the other "+1
merged". "split the story here" makes a step and the steps after it a story of their own, the
"second part", which takes its own decision; a story is split once, and not at its first step.
Both are overrides applied to the engine's stories after each build, never changes to the
engine, and the Decisions tab undoes them. A story decided benign or false positive takes
nothing merged into it (change its decision first), and a split story is not merged until the
split is undone. Stories of two organisations can be merged, but the page asks first, in the
page and not in a browser dialog, and the merge keeps both organisations' names, which the
report prints.

When decisions change what a story holds, its phases, severity (the worst finding of its
steps, and high when three phases carry a finding of medium or more), headline, summary, span,
hosts and findings are read again from the steps the decisions leave, the way the engine reads
them; its score stays the engine's (the higher one of merged stories).

**After a rebuild.** A story's decisions hold on to it as a note does (its anchor: the
account's forms or the host, and its findings), and each story takes one entry. Inside the
story, a step decision holds on to the step's records (the step that holds its first record,
else most of them), records taken out to their own ids, a split to the record its step starts
with and a merge to the anchor of the story it went into. A step decision whose records no story
step holds any more, a split whose step no longer comes after another, and a merge whose story
is gone are listed on the Decisions tab and not applied (the merged story reads on its own
again) until the analyst undoes them. Decisions whose story is gone are listed under the stories
("Decisions whose story is gone"), to put on the open story or delete after a second click in
the page; the report counts them. A case bundle renumbers the records' ids on import, and the
finding keys in the anchors of notes and decisions with them.

**Exports.** A story's timeline, as the page shows it with the decisions applied, goes out as
CSV or JSON through the app's export helpers (`util/export.ts`, whose CSV neutralises a cell a
spreadsheet would read as a formula) and as Markdown to paste into a report, or copied. Each
has one row per step: the time in UTC, host, accounts, phase, title, tie and its confidence,
findings with their severity, the record references and the analyst's call on the step
(`timeUtc`, `host`, `account`, `phase`, `title`, `tie`, `confidence`, `findings`, `refs`,
`analyst`). The JSON (`format: remn-story-timeline`) adds the story (its subject, organisation,
severity, score, span, phases, hosts, sources and which part of a split it is), its decision,
what was merged into it, the split and the records taken out. In Markdown a disputed step's
title is struck out, and what the records wrote is escaped so it cannot become a link, markup or
a column (web addresses print defanged, `hxxp://`).

## In the report

The report prints the stories at or above its severity floor, the highest-scoring first and at
most twenty, before the chains, as the Stories page shows them with the analyst's decisions
applied: each with its spine (a row per step: when, its phase with its worst finding's
severity, the step and that finding, the way in and the anchor marked, and why it is in the
story, then how the spine was drawn), its phases in the order they happened, what marks each
(its worst findings, else its first step), the analyst's note (checked against the story's records like a chain's
narrative), the analyst's decision and its reason, what the analyst merged into it, split off it
or took out of it (each with its reason), and where its evidence stops: its hosts' coverage and
a story no record shows starting (no initial access). A step the analyst disputed is left out of
the phases and severity and listed under its story with the reason; a step the analyst confirmed
is counted. A merged story's note prints under the story it went into. Above the stories it says
what the build could not read (every cut the page lists, below) and, when the stories no longer
read the case as it is, that they are out of date and why; the Report page offers to rebuild
them. The same lines go to "Where it stops" at the end, and the number of notes and of decisions
whose story is gone is printed too. The printed stories of one incident print together, in time
order, under one heading ("One intrusion", its label, its worst severity, its span and hosts),
with why they read as one (the bases of the strong and medium links between them) and how many
of its stories are not printed or were left out of it past twenty.

A story decided a confirmed incident counts in the verdict on the cover as a confirmed incident
does (its severity, and its findings in the threat profile), and one decided reviewed counts as
a reviewed item; both go to "What happened". A story decided benign or false positive is not
printed and counts with the false positives; the section says how many were left out. The
report has no section of dismissed items. The verdict is read in one place
(`computeVerdict` in `reportHtml.ts`), so the Review page's verdict bar counts decided stories
the same way; a confirmed story the report does not print (below the floor, past the first
twenty) still counts and the cover says it is not printed. With "reviewed items only", a story
prints when it has a note or a decision other than open. An undecided story decides nothing:
the verdict comes from the chains, incidents and stories the analyst decided.

## Export

A story downloads as a MITRE CTID Attack Flow ("Download Attack Flow" in its head): a STIX 2.1
bundle with the Attack Flow extension (`extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4`,
schema 2.0.0, its definition in the bundle), one `attack-flow` of scope `incident`, and an
`attack-action` per step of the spine, in its order, each leading to the next (`effect_refs`),
the first in the flow's `start_refs`. An action is named by its step's worst finding (one with
an ATT&CK technique first), with its technique (`technique_id`, from the finding's ATT&CK tags;
none when the rule has none), its tactic (`tactic_id`, the step's phase), its time, why it is in
the story, and the confidence of its tie: strong 90, medium 70. The hosts, accounts and
addresses a step touches are `attack-asset`s; an account's refers to an `identity` (individual,
or system for a service account), an address's to `infrastructure` that consists of the address
(`ipv4-addr` or `ipv6-addr`, with STIX's own id for it). The flow's description is the spine's
basis and the story's summary. A story built before spines exports its flagged steps, fifteen
at most.

A campaign downloads as a STIX 2.1 `grouping` of context `suspicious-activity` ("Download STIX
grouping"): the Attack Flow of each of its stories, its infrastructure (addresses as
infrastructure, sender and link domains as `domain-name`, attachment digests as `file`,
forwarding addresses as `email-addr`, consented applications as `software`) and the accounts
its sources reached, as identities whose description says nothing shows they were compromised.

Both are marked TLP:AMBER and authored by the case's identity, as the indicator export is.
Every id but the bundle's comes from the case and the content, so the same export twice gives
the same objects. An action is named by its finding's title: REMN ships no table of ATT&CK's
technique names.

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
times carry no zone and are kept without one); in the same windows, the domain controllers'
Kerberos and NTLM records (4768, 4769, 4776) of the flagged accounts, of the accounts that logged
on to a flagged host over the network or that a NewCredentials logon used on it, of the flagged
hosts' own accounts and workstation names, and of their client addresses (the outside addresses
the findings name, the addresses a flagged host's network logons came from, its own), those
naming an account or a host first and then those nearest a flag (at most 20,000, a cut named);
the domain controllers need not be flagged; the mails the findings cite (at most 5,000), the
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
removed it says what ran on WS-004 is not in the evidence. Its spine, anchored on the log
cleared, runs from the phishing mail through the RDP logon and its session (the credential
access, the log cleared) to the admin share and the service installed on FS-001, and leaves
the rest of the story (the victim's own sign-ins from his usual address among them) to the full
timeline. The browser-only end-to-end test
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
UTICA is left alone) REMN's own rules raise 258 findings and the build reads one story:
pbeesly's, holding the flags of SCRANTON (her RDP session) and NASHUA (her PsExec sessions) that
name no one, while the domain controller's and UTICA's own maintenance are leads. No story is
about a SID or a service account, pbeesly's story holds the 31 flagged script blocks she ran on
SCRANTON and NASHUA (their header names her SID), and it reaches NASHUA through the explicit
credentials, the PsExec service and WinRM. Without the joins above it read five stories: hers
and four host stories, all four high. On day 2 it reads two incidents: dschrute's and mscott's
stories with UTICA's and NEWYORK's, joined by explicit credentials, and kmalone's with the local
account on SCRANTON she enabled (one record names both).

## Limits

- A spine's way in is a step whose phase is initial access: a logon a rule tags valid accounts
  (T1078), out of hours or with special privileges, reads as one. The spine starts at a way in
  only when the ties reach it; its basis says when they do not.
- A person is joined across forms only as the records and the naming rules allow: two
  accounts one person uses (an admin account beside a user account) are two identities.
- A DHCP lease has no time: the audit log writes the server's local time without its zone,
  and REMN does not guess one. An address leased to several hosts is read at a step's time
  from the other records that attribute it, and otherwise as the host it was leased to most.
- A WMI or WinRM program on the target is tied to the network logon just before it by time
  only (within a minute): two people's network sessions opened in the same minute on one host
  cannot be told apart, and the step says it was tied by time.
- A Kerberos ticket or an NTLM validation that shares no logon GUID with a logon is tied to it by
  account and time only (within a minute, allowing for a host's clock as its GUID matches measure
  it): of two network logons of one account to one host in that minute the nearest takes it, and
  the hop says it was tied by time. A ticket is a step on the domain controller that issued it, so
  the domain controller is among the hosts of a story whose way in it names.
- A NewCredentials logon's step reaches the host its network account logged on to as a hop of
  the story: the records of that logon are steps of the network account's story, not of the
  account that set the credentials.
- An Entra device is matched to a host by name only: a device renamed, or one whose name two
  hosts of different domains share, is not joined; a device id is not read against the
  machine's own records.
- A finding's measure is its rule's by rule id: a rule of your own that replaces a bundled rule
  of the same id is weighed by the bundled rule's measure unless the finding carries its own
  (`measured`), which the page does not send yet. Mail rules and Hayabusa's are not measured and
  weigh as rules never measured.
- The thresholds at which low findings add up are case settings the build reads, but the page's
  settings do not offer them yet: a case posted by the page uses the defaults.
- A flag that names no one joins the person on its host by time and place: a job an intruder
  left running on a host fires in the session of whoever is on it then, and reads as theirs
  (medium, and the step says so). A session whose logoff is not in the evidence counts as open
  for two days after its logon.
- A host's flags stand on their rules' measures (read by rule id, as above). A rule measured
  quiet on the clean machines can still fire on a host's own configuration: with the SigmaHQ packs on, the
  first day of the APT29 evaluation keeps a story of its domain controller (NEWYORK) standing on
  a PowerShell core library loaded by a process other than PowerShell, which Desired State
  Configuration does on its schedule there. The measures cannot tell configuration
  management from an intruder; how rare a rule's findings are across the case's hosts would.
- A hop links two stories by the time and the place it was taken: a person who reached a host
  an hour before its flags, for their own reasons, links to its story (medium unless the story
  holds the hop's own records).
- Incidents are formed from the stories a case keeps (200 at most): a story cut past them links
  to nothing. An incident past twenty stories keeps the twenty highest-scoring, which the stories
  it left out may be what joined.
- A case keeps at most 200 stories, the highest-scoring first; the flags of the stories past
  them are listed with the flags in no story, saying why. The API holds what a caller asks for
  to at most 1,000 stories and 2,000 steps a story, and a gap between one hour and thirty days.
- An address is read as the organisation's shared egress from the records a build reads: an
  attacker who signed in to five accounts or more from one address with no finding on any of
  those sign-ins, and so outnumbers the people the records show signing in from outside, would
  be taken for one.
- A decision reads a story again from the steps it leaves (phases, severity, headline), in the
  engine's way, but keeps the engine's score and does not tie steps again: records taken out of
  a story, or the steps split off it, take no other records with them, and a step tied through
  one taken out keeps its tie. A story is split once.
