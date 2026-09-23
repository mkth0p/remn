# Security model

REMN handles evidence that is often confidential and sometimes hostile: mail written by
attackers, logs from compromised machines, attachments built to exploit whatever opens
them. The model that reads the case is one more consumer of that hostile text. This page
says where evidence lives, what leaves the machine and when, what the server and the
browser application do to keep case data from running or escaping, and what stands
between text in the evidence and a decision taken by the model. The short policy version
is [SECURITY.md](../SECURITY.md) at the repository root.

## Where evidence lives

In the browser store, rows live only in the analyst's browser; the server parses each
file in a temporary location and keeps nothing. In the server store, rows live in a
DuckDB file per case on the REMN host, unencrypted at rest. In both modes the browser
keeps the case, the findings, the notes, the chains, the decisions and the AI sessions.
Upload temporary files are deleted when the parse ends, including when the client goes away
part-way through; a resumable chunked upload that is never completed is removed by the sweep
described below. See [Storage modes](storage.md).

## What leaves the machine

Nothing, unless the analyst switches it on:

- reputation lookups (URLhaus, MalwareBazaar, ThreatFox, VirusTotal, AbuseIPDB,
  GreyNoise, ipinfo, RDAP, Spamhaus, Google Safe Browsing) go out only when "allow
  external lookups" is enabled for the case, and only the indicator values;
- the browser-direct AI transport sends prompts and tool results to the analyst's own
  Ollama on the analyst's own machine;
- the server proxy sends them to the Ollama the REMN host is configured with;
- the Claude Code connector sends prompts, tool results (evidence excerpts) and answers
  to Anthropic under the REMN host's Claude account, and the server keeps nothing.

The [AI page](ai.md) describes the transports. The public-corpus harness and the rule
pack importer download from their sources on request, never during an investigation.

## Hardening in place

- The server binds to `127.0.0.1` and keeps no database. Every `/api` call needs the
  `X-Forensic-Client` header (cookie-less CSRF protection); cross-origin preflights are
  refused. With `FORENSIC_AUTH_TOKEN` set, the header value must equal the token (see
  [remote access](setup.md#remote-access)). The remote mode is one shared token, with no
  per-user accounts, audit log or rate limit; keep such a deployment private.
- Parsed content is treated as hostile: React escaping, HTML previews in a sandboxed
  iframe with DOMPurify, images blocked, links disabled and defanged. Attachments are
  analysed statically, never opened or executed.
- The browser application carries a Content Security Policy (no inline script, scripts
  and workers from the app origin only, WebAssembly allowed for hashing, frames only for
  the sandboxed mail and report documents, no object or base tags) as a `<meta>` tag in
  `index.html` and as a header from the server, which adds `frame-ancestors 'none'`. The
  script files carry the same policy, because a web worker takes its policy from the
  response that served its script, and the hashing and ingest workers need WebAssembly,
  the API and the browser database. Every response also carries `X-Frame-Options: DENY`,
  `nosniff`, a `no-referrer` policy, same-origin opener and resource policies, and API
  bodies get a closed policy (`default-src 'none'; sandbox`) that forbids rendering them.
  The theme bootstrap is an external file for that reason. A request for a file that
  does not exist gets a 404, never the page.
- Markdown from the model and from notes is escaped before the light markup pass (no
  links or raw HTML are produced); JSON views are escaped; the report is built from
  escaped cells and printed from a frame that runs no script but keeps the app's origin,
  which the browser requires before the page may call print on it. Links whose target
  comes from data (reputation providers, pack manifests, ATT&CK ids) pass through a
  scheme check and get `rel="noopener noreferrer"`; anything but http(s) is dropped.
- The raw SQL endpoint and the analyst's `sql` tool accept one read statement (SELECT,
  WITH, DESCRIBE, SHOW) with write keywords rejected, and every DuckDB connection runs
  with external access disabled and the configuration locked, so a prompt-injected
  query cannot read or write files on the server or load extensions.
- Identifiers that reach the filesystem are validated (case keys and upload ids by
  pattern, pack ids without separators, static files resolved inside the build
  directory); rule archives are capped per member and in total; CSV exports neutralise
  spreadsheet formula injection.
- The Docker image is built from base images pinned by digest, takes Debian's security
  updates at build time, runs as a non-root user without a package manager, and is
  scanned by Trivy in continuous integration.

## Browser-only mode and request budgets

An instance open to people you do not know runs with `FORENSIC_BROWSER_ONLY=1`. The
server then does what it does for a browser-store case and nothing else: parse evidence
and return the rows, run rules and correlation over posted rows, convert rules, serve the
rule packs and the prompt bundle for the analyst's own model. Everything that keeps state
on the server, reaches a third party or runs a model on the server's account answers 403
with the code `browserOnly`: the server store and its jobs, reputation lookups, the
server-proxy and Claude Code transports. Chunked uploads stay open: a file larger than
32 MiB reaches the parser that way, staged exactly as a single-request upload would be. The
health endpoint says `"mode": "browser-only"` and stops reporting paths and platform
details, and the interface hides the server store, the conversion, the two server-side
transports and the lookups toggle. Every case, its evidence rows included, lives in the
visitor's browser.

Two limits go with it, one on how often requests arrive and one on how many run at once.

- `FORENSIC_RATE_LIMIT_PER_MIN` gives each client a budget on the heavy paths (parsing,
  correlation, enrichment, conversion, lookups, models, store writes and store queries that
  run rules or SQL); over budget is a 429 with a Retry-After, and health, meta, rule packs
  and plain reads are never counted. A client is an IPv4 address, or an IPv6 /64: one host
  is normally given a whole /64, and a budget kept per address would give it a fresh one for
  every request.
- `FORENSIC_MAX_HEAVY_REQUESTS` and `FORENSIC_MAX_HEAVY_PER_CLIENT` cap the heavy requests in
  flight: in browser-only mode, all worker threads but two, and two per client. A streamed
  parse to a client that stops reading holds its worker thread until the client goes away,
  so without a cap a handful of such clients took every thread and the page itself stopped
  answering. `FORENSIC_MAX_JSON_INFLIGHT_MB` (64 in that mode) caps the JSON bodies being
  worked on at once by size, since parsing one takes about seventeen times its size in
  memory. Past any of these the answer is 503 with a Retry-After.

Behind a reverse proxy every request arrives from the proxy's address, so
`FORENSIC_TRUST_PROXY=1` takes the client address from the rightmost X-Forwarded-For entry,
the one the proxy added; set it only when a proxy you control is the only way to reach the
server. `docker-compose.public.yml` is this configuration with Caddy in front, and
`FORENSIC_MAX_UPLOAD_MB` lowered.

The health endpoint reports the build (`version+commit`) and a link to that exact source in
every mode, and the app shows both: a visitor who trusts the server with evidence can read the
code that parses it. It withholds the machine: paths, platform, interpreter, and which native
libraries are compiled in, reporting only coarse formats (`"formats": {"pst": true}`). The
source is public, so the commit tells an attacker nothing the repository does not, and it tells
a visitor what they need to check. The content security policy narrows `connect-src` to the origin and
loopback in that mode. An operator's own instance may point the browser-direct model transport
at any address on their network, so it stays open there; a public page served over HTTPS can
only reach loopback anyway, so the narrower policy costs that deployment nothing and removes the
channel a script injection would otherwise use to send evidence somewhere.

### Evidence in transit

Browser-only mode means the server keeps no case, not that files never reach it. A browser-store
ingest uploads the file, the server writes it to the staging area under `FORENSIC_TMP_DIR`, parses
it, streams the rows back, and deletes it. So evidence is on the server's disk for the length of a
parse, and the question that matters on a public instance is what happens when a parse never
finishes.

- **A short window.** `FORENSIC_UPLOAD_MAX_AGE_S` defaults to 30 minutes in browser-only mode and
  6 hours otherwise. An operator can lengthen it; a stranger-facing instance should not hold
  someone's evidence for a day because nobody set a variable.
- **Swept on a timer**, every `FORENSIC_UPLOAD_SWEEP_S` seconds (300 by default) as well as at
  startup, so an abandoned upload clears without waiting for a restart. Set it to 0 to disable.
  The sweep covers Django's own multipart spool as well as the chunked staging area: a request
  that dies part-way through a single-request upload leaves a file there too. It also covers the
  parsers' own staging, the `.member`, `.decoded` and `.manifest` files a parse writes while it
  works. A parse releases those itself, and a process killed mid-parse cannot.
- **A total budget.** `FORENSIC_TMP_MAX_GB` (4 by default) caps what the staging area may hold at
  once. A new upload that would exceed it triggers a sweep and is then refused with 507, so a
  stream of abandoned uploads cannot fill the disk however short the lifetime is.
- **Private to the server account.** The staging directory is 0700 and each staged file 0600, so
  evidence in transit is not readable by other accounts on the host.
- **A ceiling on what one parse holds.** A package parse holds artifacts back to decode them in
  groups, and that hold is capped per request rather than per archive, so nesting cannot multiply
  it. A client that disconnects mid-parse releases everything the parse was holding rather than
  stranding it for the sweeper to find later.
- **A ceiling on how long one parse runs.** `FORENSIC_INGEST_MAX_S` (30 minutes in
  browser-only mode, off otherwise) ends an ingest stream at the limit with the rows already
  sent, an error line saying why, and the result marked incomplete. The limit is checked
  between archive members as well as between rows, so an archive whose members produce no
  rows cannot walk around it. The rate limiter shapes how
  fast requests arrive, not how many are in flight, and the server cannot reap a request once it
  is running; this is what stops a few slow parses holding every worker thread indefinitely.
- **External engines under the same bounds.** Hayabusa, when installed, runs as a separate
  process watched for memory (`HAYABUSA_MAX_MB`, 1536 by default and 768 in the public
  compose), output (256 MiB) and time (`HAYABUSA_MAX_S`, 300 s by default, and never past the
  request deadline), and is killed rather than trusted past any of them. Only
  `HAYABUSA_CONCURRENCY` runs share the box at once, one by default, so two uploads cannot add
  up to the container's memory limit; an ingest that finds the engine busy waits
  `HAYABUSA_WAIT_S` and then carries on without it, saying so. A collection's event logs are held back for one engine run within the same per-request
  hold allowance as prefetch, and released with the parse. The binary in the image is pinned by
  version and by the SHA-256 of its release archive.
- **A ceiling on what one message costs.** Parsing a mail holds about a dozen copies of it, and
  a highly compressible message makes a small upload large: a 128 MiB message inside a 128 KiB
  zip took the parser past 1.7 GiB. A message larger than `FORENSIC_MAX_MESSAGE_MB` (48 in
  browser-only mode, 256 otherwise) is not parsed; it becomes an error row that says why. An
  archive member larger than half the staging budget is not copied out, and bzip2, xz and
  LZMA data inside attachments and archives is expanded only up to the analysis limit, with
  the attachment flagged as a decompression bomb when it goes past it.
- **Every member accounted for.** An archive's members are listed in the stream's last line
  as parsed (with their row count), skipped or failed, with the reason: too large, encrypted,
  a compression method that is not read, not a mail file, not an event log. Nothing is left
  out without a line saying so.
- **Rules read without expansion.** The Sigma and Sublime converters take YAML from visitors,
  and a safe YAML loader is safe against object construction, not against anchors that each
  repeat the last one ten times: 450 bytes took five seconds and half a gigabyte. Uploaded
  rules with YAML aliases are refused; neither rule format uses them.
- **The request spool on the staging volume.** The web server writes a request body over
  512 KiB to a temporary file before the application sees it. `backend/run.py` points those
  at `FORENSIC_TMP_DIR`, the volume sized for evidence, rather than at the system `/tmp`,
  which the public compose keeps at 64 MiB.
- **A ceiling on what one parse spends.** Every native decode is counted and timed against one
  allowance per package, whether it succeeds or fails, and cabinets are counted against the same
  allowance rather than being free. A cabinet that claims to expand by more than a couple of
  hundred times its own size is refused: real support cabinets are around ten to one.

### What the server log holds

The log is the one thing on a browser-only server that outlives a parse. It holds operational
lines: requests refused, sweeps, the engine's state. In browser-only mode a failure in the
parsing code is logged by exception type and place (`UnicodeDecodeError at common.py:104`),
never with the exception's text, which is often a piece of the input, and never with a file,
member or attachment name. `docker-compose.public.yml` rotates the log (three files of 10 MB)
rather than keeping it for the life of the container.

This is what lets a public instance take real evidence: the exposure of a file is bounded to one
parse, and nothing of it is kept. Before the first upload to a parser on another machine, the app
shows a notice that says where the file goes, what the server keeps and which build it runs, with a
link to that exact source. The notice states only what the server declares: the RAM-only staging
and the absence of a route off the host are claimed only when health reports the `public` profile
that `docker-compose.public.yml` sets. Evidence that may not leave the analyst's machine belongs in
a local instance, where the same notice says the file is parsed on this machine.

### The parser's isolation

The server exists to run hostile binary formats through libpff, the EVTX reader, oletools and
pypdf, which are among the most CVE-prone libraries in any stack. That cannot be made
unexploitable, so `docker-compose.public.yml` makes an exploit worth as little as possible. The
application container has what the deception archive already had:

- **No route off the host.** It sits on a Docker network marked `internal`, reachable by Caddy and
  nothing else. In browser-only mode the application makes no outbound calls at all: reputation,
  Ollama and Claude are closed, and the domain parser uses a bundled public-suffix snapshot rather
  than fetching one. An exploited parser has nowhere to send anything and nothing to fetch a second
  stage from.
- **A read-only root**, with the staging area and `/tmp` as tmpfs mounted `noexec,nosuid,nodev`.
  Evidence in transit therefore never reaches physical disk and cannot survive a restart.
- **No capabilities and no privilege escalation**, running as an unprivileged user, with process
  and memory ceilings so a decompression bomb cannot take the host with it.

Verified rather than asserted: from inside the running container the effective capability set is
empty, the root filesystem refuses writes, the staging area reports as tmpfs, and connections to a
hostname, to a raw address on 443 and to a resolver on 53 all fail, while a 14 MiB EVTX still
parses to 6000 events with a matching digest.

What remains is that an exploit still gets execution inside that container for the life of one
request, and can read whatever else is staged at that moment. Isolating each parse into its own
throwaway sandbox is the next step and is not configuration.

The per-address budget reads the **rightmost** X-Forwarded-For entry, the one the trusted proxy
observed and appended, not the leftmost, which is whatever the client sent. Caddy's default
replaces the header rather than appending, which hides the difference, but that is a property of
one proxy's configuration: put a CDN in front, or set `trusted_proxies`, and a leftmost read
becomes forgeable. The shipped Caddyfiles also set the header explicitly rather than relying on
that default.

For the full mode, one change came with this: listing every server store (`GET
/api/store`) is an operator action and is only answered when an access token is
configured. A case reaches its store by the key it holds, and the keys are random, so
without the listing a store cannot be found by a client that was never given it.

## Text in the evidence that addresses the model

The analyst chat reads tool results, the triage pass reads item summaries, and the
Claude Code connector reads a transcript; all three carry text that came from the
evidence, which an attacker may have written. Three things stand between that text and
a decision:

- Every prompt on those paths says the case text is evidence, never an instruction, and
  that a record asking to be ignored or marked benign is evidence of intent to be named
  in the reason (`backend/services/ai/prompts.py`, `claude_code.py`, the triage
  instruction in `frontend/src/data/aiReview.ts`; `tests/backend/test_ai_meta.py` checks
  the sentences are there).
- The synthetic lab carries a control, S07, a password-expiry lure whose body tells
  automated reviewers to classify it as benign. The rules score it on its facts; a model
  that follows the text fails the control.
- The model proposes and the analyst decides. The triage pass and the chat record
  proposals, each with its reason, and nothing takes effect until the analyst applies it.
  An applied proposal is written with a tag and a snapshot of what it replaced
  (`frontend/src/data/aiReview.test.ts` and `aiReview.db.test.ts`), so it stays visible in
  the rail and undo puts the previous state back.
