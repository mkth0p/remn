# Attack chains

_Cross-source correlation: seeds, steps, score, graph._

## Attack chains (cross-source correlation)

The Chains view links a suspicious mail to what its recipient did next, across
the three sources of a case. A *seed* is a mail above the risk threshold or
carrying a medium+ finding. Its recipients are normalised to an identity
(`alice@contoso.com`, `CONTOSO\alice` and a UAL `UserId` all become `alice`),
and every step of that identity inside the window (72 h by default) is
collected and scored: replies to the sender (same thread), Entra sign-ins
(country, legacy client, identity-protection risk), MailItemsAccessed bursts,
inbox rules and mailbox forwarding, consent grants, role and MFA changes,
Windows logons, processes spawned by Outlook or a browser, DNS queries, network
connections and file writes that name the mail's URL domains or attachment
names (strong *artifact links*), Defender detections, persistence and
log-clearing events. Bursts collapse into one step, findings of the last rule
run attach to the steps they reference, one chain is kept per identity per day
with the other seeds listed as related. Chains are also stored as findings
(rule `chain`) so they reach the report. Server-store cases are correlated
inside DuckDB; browser-store cases post the relevant rows to the local API
(`POST /api/chains/build`). `services/analysis/chains.py` is pure functions
over plain rows, tested on the synthetic BEC scenario plus host events.

The Chains view shows the last built snapshot (kv `chains-<case>`), so a rebuild is
explicit. **Removing evidence deletes everything derived from it at once**: its
events, mails, bodies, attachments and URLs, the case's findings, chain snapshot and
last-run diagnostics (they reference rows that no longer exist), the upload-resume
record and any server-side partial. Browser cases recompute facets and indicators
from the rows that remain (reputation results of surviving indicators are kept);
server cases delete the rows from DuckDB and checkpoint the file so the space is
released. Analyst decisions are archived and reattached when the same findings
reappear on the next rule run.
Rebuilding chains with no seed left replaces the snapshot with an empty one.
Links to the organisation's own domains are not artifacts, routine steps (logons,
sign-ins, DNS, mailbox reads without a link or a finding) add at most 3 points, a
chain made only of them is dropped, and one without any link, strong step or
finding stays below high.
