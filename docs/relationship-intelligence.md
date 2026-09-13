# Relationships: evidence and investigation

Rebuild Relationships after upgrading. Version 2 invalidates older graph caches while preserving analyst reviews. Choose a story, then **Investigate** to inspect association confidence, evidence coverage, contradictions, excluded records, and ranked searches.

## Identity and link semantics

- A digest identifies reported content; a file node identifies a host-scoped location. Different digests at one location remain separate versions. Common Windows and Program Files executable paths cannot join stories by themselves.
- A process instance requires a nonzero, syntactically valid GUID and host, or a subject PID plus explicit start time and host. A writer PID is never used as the subject. Invalid lifetimes retain the observation and expose an identity issue. Snapshot resolution requires a unique matching host, normalized PID, package and collection time within the process lifetime.
- A logon session requires a host and logon GUID, or a host, boot ID and normalized logon ID. Unscoped logon IDs and bare PIDs remain individual observations. Collection exports can supply `BootId`, `LogonGuid`, `TargetLogonId`, `ProcessEndTime` or `ExitTime`. Server stores add the new optional columns automatically.
- Accounts, SIDs and hosts supply context; they cannot alone merge records into stories. Local authorities and well-known SIDs are host-scoped. Aliases remain explicit analyst decisions.
- **Observed** means a source reports the fields; it does not prove the assertion is true in the world. **Correlated** identifies an inferred snapshot match or ambiguous file-to-digest attribution. **Hypothesized** is reserved for reviewable AI proposals and never becomes an observed edge automatically.

Links expose source references, matching fields, rule version and assumptions. Mutable locations, domains and addresses require comparable times within the configured window. Exact content and scoped process/session identities can cross that window; their association does not establish causal order. Entity hops cannot borrow an unrelated record's file-version evidence.

## Confidence, severity and coverage

Severity comes only from active findings and analyst severity overrides. The priority score sorts work; it is not a probability and never raises severity. Confidence describes the evidence for an association: limited, supported, or strong. Strong requires an exact identity across source contents, at least two identified telemetry families, and no detected contradiction or truncation.

Repeated imports with the same source digest and source index count once toward corroboration, even if filenames change. Without content digests, filenames and record provenance provide a conservative fallback; unknown duplicates and overlapping exports cannot always be detected. Edge counts beyond a reference cap can still contain duplicate imports; capped samples are labelled and cannot justify strong confidence.

Coverage reports unique records, source contents, represented telemetry families, event times, snapshots and scan limits. It describes imported evidence, not complete environmental visibility. No search result is treated as proof an event did not happen. Collection timestamps are never described as execution times.

## Investigation and analyst feedback

Checks prioritize conflicting file versions, exact process traces, content reuse and logon boundaries. Searches use the existing browser/server data source, return at most 50 matching rows, and expose the actual filter. Each check explains what additional evidence to collect when unavailable. Search hits can be opened for review; rebuild after collecting new evidence.

Rejected link reviews immediately stop those links joining stories. They remain accessible in Explore for correction. Accepted reviews do not convert correlation into causation. AI hypotheses support separate persistent keep/reject decisions and notes, tied to the evidence version used to generate them.

## AI cost and validation

AI runs only after **Review selected story with AI** is clicked, using the configured connection. It receives at most 30 records, 40 existing links and eight approved checks from one story, with explicit omission counts. There is one model turn, no tool execution, no automatic retries, a 90-second limit and a 20,000-character response limit. Cancel stops an active review. No live model is called by the test suite.

The validator rejects invented record IDs, claims citing a different edge's evidence, unknown checks, and oversized or malformed responses. These checks validate provenance and structure; they do not prove the model's prose. Explanations remain labelled AI annotations, and new interpretations remain hypotheses.

Reviews are cached against the selected story's evidence, findings, relevant link reviews, assessment and model settings. Unrelated link reviews do not invalidate the cache. At most 20 AI responses are retained per case; analyst decisions are stored separately. Changed or removed evidence invalidates the review identity. An oversized input asks the analyst to narrow the story instead of sending the whole case.

## Regression benchmark

`tests/backend/test_relationship_intelligence.py` covers PID reuse, GUID normalization, invalid lifetimes, logon boot boundaries, local accounts, snapshot resolution, duplicate imports and ambiguous digests. Frontend intelligence tests cover true associations and hard negatives, temporal windows, file versions, rejected reviews, independent telemetry, mail/execution ordering and borrowed attribution. Assistant tests exercise citation validation, caching, cancellation and persistent feedback; the view test verifies that opening Investigate makes no AI request. These synthetic fixtures are a regression benchmark, not a measured field-accuracy claim.
