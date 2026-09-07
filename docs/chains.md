# Attack chains

A chain answers the question a phishing investigation starts with: this mail looks bad,
so what did its recipient's accounts and machines do next? REMN links a suspicious mail
to the later activity of its recipient across the three sources of a case, scores the
result, and treats the chain and the findings on its steps as one item for review and
for the report. This page describes how a chain is built, how it is scored, how it
relates to findings, and where it is stored.

## How a chain is built

A *seed* is a mail above the risk threshold (45 by default) or carrying a medium or
higher finding. Its recipients are normalised to an identity: `alice@contoso.com`,
`CONTOSO\alice` and a Unified Audit Log `UserId` all become `alice`. Every step of that
identity inside the window (72 hours by default) is collected: replies to the sender
(same thread), Entra sign-ins (country, legacy client, identity-protection risk),
MailItemsAccessed bursts, inbox rules and mailbox forwarding, consent grants, role and
MFA changes, Windows logons, processes spawned by Outlook or a browser, DNS queries,
network connections and file writes that name the mail's URL domains or attachment
names, Defender detections, persistence and log-clearing events.

Steps that name the mail's URL domains, attachment names or sender are *artifact links*,
the strongest tie between the mail and what followed. Links to the organisation's own
domains are not artifacts. Bursts collapse into one step, findings of the last rule run
attach to the steps they reference, and one chain is kept per identity per day with the
other seeds listed as related.

Server-store cases are correlated inside DuckDB; browser-store cases post the relevant
rows to the local API (`POST /api/chains/build`). `services/analysis/chains.py` is pure
functions over plain rows, tested on the synthetic scenarios.

## The score

Chain scores are bounded and explained, and the Chains page shows the parts under the
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
the report. Beyond that, a chain and the findings whose rows are its steps are one item:
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

The Chains page shows the last built snapshot, stored with the case, so a rebuild is
explicit. Rebuilding with no seed left replaces the snapshot with an empty one. Removing
evidence deletes the snapshot along with everything else derived from the removed rows
(see [Storage modes](storage.md)).

The Chains page reads chains as stories and draws them as swimlane graphs; the [interface
page](interface.md) describes both views.
