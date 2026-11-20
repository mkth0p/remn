# Attack chains

A chain answers the question a phishing investigation starts with: this mail looks bad,
so what did its recipient's accounts and machines do next? REMN links a suspicious mail
to the later activity of its recipient across the three sources of a case, scores the
result, and treats the chain and the findings on its steps as one item for review and
for the report. This page describes how a chain is built, how it is scored, how it
relates to findings, and where it is stored. Chains are no longer a page of their own: a
story build builds them from the same rows, and each is a part of its person's
[story](stories.md) (its steps are that story's "phishing chain" steps) and an item of the
Review page.

## Authentication campaigns from one source

Chains also work without mail. Windows Security 4625/4624 events or Entra sign-ins can
form an authentication campaign: at least ten failures within thirty minutes for the
same qualified account, source IP and destination. Failures alone score 50 (medium).
A successful login after the tenth failure in that window scores 75 (high); it warrants
investigation and does not establish that the attacker succeeded. Sporadic mistakes,
different tenants, source IPs and destination hosts are kept separate. Event seeds open
the event itself and retain their source in findings, reports and case backups.

A campaign against the person a mail-led chain is about, starting in that chain's window,
joins that chain instead of standing as a second one, whatever spelling the logs use for
the account: `NORTHSTAR\daniel.roy` in the Security log and the mail to
`daniel.roy@northstar.example` are one person when the NetBIOS name is the first label of
the recipient's domain (or of an internal domain), or when the case shows the two side by
side; `OTHER\daniel.roy`, tied by the case to another organisation, is not. The campaign's
steps replace the routine logon steps they cover, the chain is scored again, and the chain
says which campaign it took in. This happens whether or not a rule has flagged the
failures yet, so the chains read the same before and after a rule run. A campaign fully
represented by a chain of another account is not duplicated.

This first event-led pattern detects repeated attempts against one account. Distributed
password spraying across many accounts or IPs needs a separate grouping pattern.

## How a mail-led chain is built

A *seed* is a mail above the risk threshold (45 by default) or carrying a medium or
higher finding. Its recipients are normalised to an identity: `alice@contoso.com`,
`CONTOSO\alice` and a Unified Audit Log `UserId` all name the account `alice`, scoped
by the organisation the name was seen in. A UPN or address matches the recipient when
its domain is the same organisation (`corp.contoso.com` and `contoso.com` are one,
`contoso.com` and `other-tenant.example` are not); a Windows domain name (`CONTOSO`)
matches when it is the first label of the recipient's domain or of an internal domain
from the case settings, and is rejected when it is the first label of another
organisation seen in the case; a bare account name cannot be told apart and is
accepted. So `alice@other-tenant.example` never joins `alice@contoso.com`'s chain, and
the chain is always labelled with the recipient's address. Every step of that identity
inside the window (72 hours by default) is collected: replies to the sender
(same thread), Entra sign-ins (country, legacy client, identity-protection risk),
MailItemsAccessed bursts, inbox rules and mailbox forwarding, consent grants, role and
MFA changes, Windows logons, processes spawned by Outlook or a browser, DNS queries,
network connections and file writes that name the mail's URL domains or attachment
names, Defender detections, persistence and log-clearing events.

Steps that name the mail's URL domains, attachment names or sender are *artifact links*,
the strongest tie between the mail and what followed. Links to the organisation's own
domains (the internal domains of the case settings, and the domains of the mail's own
recipients, so a case with no internal domain set is read the same) are not artifacts. A
burst collapses into one step only when its events agree on what makes them distinct: the
operation, the host and program, the account, the address and what was acted on (a command
line, a query, a destination, a file, a share, a service, a script), so logons from two
addresses are two steps. A flagged event of a kind the builder does not model (a process
access, an RDP authentication record, a share file access) is kept as a step that names the
record and what it says. Findings of the last rule run
attach to the steps they reference, and one chain is kept per identity per day with the
other seeds listed as related. Deduplication uses the recipient's full address, so two
organisations' accounts named Alice retain separate chains. A bare alias on the same event
cannot bypass a qualified foreign account, and each event contributes only once.

The chains are built from the rows a story build selects ([both stores](stories.md#both-stores)):
a server case selects them in DuckDB, a browser case selects them in the browser and posts
them, and the story build hands the same rows to the chain builder. A chain therefore reads
what the stories read around the flags and the riskiest mails, under the same caps, and an
authentication campaign no rule flagged, away from every flag, is not read.
`services/analysis/chains.py` is pure functions over plain rows, tested on the synthetic
scenarios; `POST /api/chains/build` runs it on posted rows only and refuses a server case's
store key. Seed and output-chain limits are recorded in the saved result, with the story
build's own cuts, shown persistently on the Review page and included in exported reports. A
result with any limit warning is incomplete; an absent chain is not evidence of absent activity.

## The score

Chain scores are bounded and explained, and the Review page shows the parts under the
chain header:

| part | range |
|---|---|
| seed mail risk | 0 to 30 |
| steps tied to the mail by an artifact | 0 to 30 |
| weight of the non-routine steps, with diminishing returns | 0 to 20 |
| the worst finding on the seed and on a step | 0 to 15 |
| more than one source involved | 0 to 5 |

Routine steps (logons, sign-ins, DNS lookups, mailbox reads without a link or a finding)
add at most 3 points, and a chain made only of them is dropped. A chain with no artifact
link cannot be critical (the score is capped at 79), and one with neither a link, a
finding-bearing step nor a strong step stays medium at most (capped at 54).

## Chains and findings

A chain is also stored as a finding (rule `chain`), so it reaches the findings list and
the report. The finding carries the ATT&CK techniques the chain's own steps show: a mail-led
chain is phishing (T1566, its seed); email collection (T1114) when a step forwards the
mailbox, sets an inbox rule, or reads the mailbox with a finding on the read; valid accounts
(T1078) when a sign-in or logon that worked carries a finding or a sign it was not the person
(an unexpected country, legacy authentication, an identity protection risk). An
authentication campaign is brute force (T1110), and valid accounts when a guessed password
worked. Beyond that, a chain and the findings whose rows are its steps are one item:
when the chains are built, every finding whose rows all sit among a chain's steps, or on
its seed mail, joins that chain's incident. A phishing mail's rule hits and the findings
on the recipient's later logons are therefore never listed twice, once inside the chain
and once on their own. Findings with more than 500 rows describe a pattern rather than
steps and stay separate.

The chain's verdict on the Review page writes the status of its linked findings:
confirmed becomes confirmed, benign becomes false positive, unsure becomes reviewed. A
finding that does not belong can be unlinked there, one at a time or all of a chain: it
leaves the chain, goes back into the queue on its own and keeps its own decisions;
"link back" undoes that. Unlinks survive a rule rerun, like statuses and notes.

## Where chains live

The review and the report read the last built snapshot, stored with the case and written
by each story build, so a rebuild is explicit. Rebuilding with no seed left replaces the
snapshot with an empty one. Removing evidence deletes the snapshot along with everything
else derived from the removed rows (see [Storage modes](storage.md)).

The Stories page reads each chain within its person's story; the report draws chains as
swimlane graphs; the [interface page](interface.md) describes both.
