# Explore: the relationship graph

Explore, on the [Stories](stories.md) page, browses the relationship graph of the evidence
(`backend/services/analysis/relationships.py`): every record is a node, every host, account,
file, process, digest, address and domain a record names explicitly is a node, and a link says
the record reports the entity. A story step shows the links of its own records. Build the graph
again after upgrading: version 2 invalidates older graph caches and keeps the analyst's link
reviews.

## Identity and link semantics

- A digest identifies reported content; a file node identifies a host-scoped location. Different digests at one location remain separate versions.
- A process instance requires a nonzero, syntactically valid GUID and host, or a subject PID plus explicit start time and host. A writer PID is never used as the subject. Invalid lifetimes retain the observation and expose an identity issue. Snapshot resolution requires a unique matching host, normalized PID, package and collection time within the process lifetime.
- A logon session requires a host and logon GUID, or a host, boot ID and normalized logon ID. Unscoped logon IDs and bare PIDs remain individual observations. Collection exports can supply `BootId`, `LogonGuid`, `TargetLogonId`, `ProcessEndTime` or `ExitTime`. Server stores add the new optional columns automatically.
- Local authorities and well-known SIDs are host-scoped. Aliases (hosts and accounts mapped to a canonical name) remain explicit analyst decisions, saved with each review.
- **Observed** means a source reports the fields; it does not prove the assertion is true in the world. **Correlated** identifies an inferred snapshot match or ambiguous file-to-digest attribution.

Links expose source references, matching fields, rule version and assumptions. Shared entities
do not establish causation, and a link's high confidence means the relationship is explicitly
reported, not that the source is truthful or the activity malicious.

## Coverage

Repeated imports with the same source digest and source index count once, even if filenames
change. Without content digests, filenames and record provenance provide a conservative
fallback; unknown duplicates and overlapping exports cannot always be detected. Edge counts
beyond a reference cap can still contain duplicate imports; capped samples are labelled.

**Build relationships** scans successive pages of 1,000 events and 1,000 mails, with progress
and a **Stop after this page** control; **Continue scanning** resumes a stopped scan. A partial
graph says so: the absence of a link is then not evidence of absence.

## Link reviews

A link can be accepted or rejected, annotated, and an accepted one included in the report
("Reviewed evidence relationships"). Accepting a link does not turn correlation into causation.

## Regression benchmark

`tests/backend/test_relationship_intelligence.py` covers PID reuse, GUID normalization, invalid
lifetimes, logon boot boundaries, local accounts, snapshot resolution, duplicate imports and
ambiguous digests. These synthetic fixtures are a regression benchmark, not a measured
field-accuracy claim.
