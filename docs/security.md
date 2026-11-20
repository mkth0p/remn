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
keeps the case, the findings, the notes, the chains, the stories, the decisions and the AI
sessions.
Upload temporary files are deleted when the parse ends, including when the client goes away
part-way through; a resumable chunked upload that is never completed is removed by the sweep
described below. See [Storage modes](storage.md).

REMN encrypts neither a store nor a backup of one, nor the browser's database. Evidence kept
on a server therefore needs the disk under it encrypted: the cases folder
(`FORENSIC_CASES_DIR`), the staging area (`FORENSIC_TMP_DIR`) and wherever store backups are
written belong on an encrypted volume (LUKS on Linux, BitLocker on Windows, FileVault on
macOS, or a cloud provider's encrypted disks), with the key kept off that disk. With Docker
that is the disk that holds Docker's volumes `remn-data` and `remn-tmp` (under
`/var/lib/docker` by default). This is the minimum for evidence on a server, not an option:
without it, whoever has the disk, a copy of a backup or an image of the virtual machine reads
every case. The volume protects a disk that is taken or discarded, not a running server:
whoever reaches the API with a token that opens the cases, or logs in to the host, reads them
as before.
The analyst's own machine, where the browser store lives, is covered the same way by its
system's disk encryption.

## What leaves the machine

Nothing, unless the analyst switches it on:

- reputation lookups (URLhaus, MalwareBazaar, ThreatFox, VirusTotal, AbuseIPDB,
  GreyNoise, ipinfo, RDAP, Spamhaus, Google Safe Browsing) go out only when "allow
  external lookups" is enabled for the case, and only the indicator values. The server
  holds to that choice too: a lookup that would reach one of these providers is refused
  (403, code `lookupsNotAllowed`) before any provider is asked unless the request says
  that the case allows it (`networkAllowed: true`), which the page sends from the case's
  setting. The offline lists and GeoIP stay on the machine and need no such word;
- the browser-direct AI transport sends prompts and tool results to the analyst's own
  Ollama on the analyst's own machine;
- the server proxy sends them to the Ollama the REMN host is configured with;
- the Claude Code connector sends prompts, tool results (evidence excerpts) and answers
  to Anthropic under the REMN host's Claude account, and the server keeps nothing.

The [AI page](ai.md) describes the transports. The public-corpus harness and the rule
pack importer download from their sources on request, never during an investigation.

## Hardening in place

- The server binds to `127.0.0.1` and keeps no database. It does not start on an address
  other machines can reach without an access token or accounts, unless `FORENSIC_ALLOW_NO_TOKEN=1`
  says that this is intended; a container is judged by the address its port is published
  on (`FORENSIC_PUBLISHED_ON`, which `docker-compose.yml` sets). Every `/api` call needs the
  `X-Forensic-Client` header (cookie-less CSRF protection); cross-origin preflights are
  refused. The one exception is a GET of `/api/health`, which a caller without the header
  gets as `{"ok": true}` only. With `FORENSIC_AUTH_TOKEN` set, the header value must equal
  the token (see [remote access](setup.md#remote-access)). Wrong tokens are counted per
  client address (per /64 for IPv6): past `FORENSIC_AUTH_FAILURES_PER_MIN` (10 by default)
  in a minute, that address gets 429 with a Retry-After for every request that carries a
  token, the right one included, until its allowance refills. The fixed values the page and
  the documented commands send before they hold a token (`remn`, `1`) are refused but not
  counted. Behind a proxy without `FORENSIC_TRUST_PROXY=1` every client shares the proxy's
  address and so one allowance.
  The shared token is the single-user mode: everyone who holds it is the same user, opens every
  case and leaves no record. A team on one server uses accounts instead (next section).
- Parsed content is treated as hostile: React escaping, HTML previews in a sandboxed
  iframe with DOMPurify, images blocked, links disabled and defanged. Attachments are
  analysed statically, never opened or executed.
- The regular expressions that read evidence take a time that grows with the length of the
  text, not with its square: a pattern that backtracks would let one crafted field hold a
  server worker or the browser for minutes. `tests/backend/test_regex_timing.py` and
  `frontend/src/test/regexTiming.test.ts` find every pattern the code writes, and the `re`
  patterns of the bundled rules, build hostile text from the parts of each pattern that
  repeat, and fail on a pattern that runs past its budget at 100,000 characters, naming it
  and its file. A pattern that reads no evidence, or whose caller limits the text it
  searches, is listed in the test with the reason. The store runs a rule's `re` pattern
  with RE2, which does not backtrack. The browser engine does: seven bundled rules and some
  converted community rules keep a pattern that a crafted value of that length slows down,
  in the rules worker rather than the page, because no rewrite that RE2 also accepts keeps
  what they match.
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
- The raw SQL endpoint and the analyst's `sql` tool accept one SELECT statement (WITH,
  DESCRIBE, SHOW and SUMMARIZE included), as DuckDB's own parser reads it, on the case's
  tables: a table function other than `range`, `generate_series`, `unnest`, `json_each`
  and `json_tree` (those that read files among them) and a file path used as a table are
  refused, while a word such as `Set-MpPreference` or `update` inside a string is not.
  Every DuckDB connection also runs with external access disabled and the configuration
  locked, so a prompt-injected query cannot read or write files on the server or load
  extensions. The two settings are read back when a case store opens, and a store on
  which they did not take effect is not opened.
- Identifiers that reach the filesystem are validated (case keys and upload ids by
  pattern, pack ids without separators, static files resolved inside the build
  directory); rule archives are capped per member and in total; CSV exports neutralise
  spreadsheet formula injection.
- A reputation lookup value is checked against its kind (an IP address, a domain name, an
  MD5, SHA-1 or SHA-256 digest, a URL with a scheme and a host) before the cache or any
  provider sees it; a value that fails gets an error verdict that says it was not looked
  up and why. A value goes into a provider URL as one path segment. A provider's redirect
  is followed over HTTPS on the host that sent it, at most five times, because the request
  carries the provider key; RDAP, whose requests carry no key, may be sent on to the
  registry by name, never to an address.
- The Docker image is built from base images pinned by digest, takes Debian's security
  updates at build time, runs as a non-root user without a package manager, and is
  scanned by Trivy in continuous integration.

## Accounts, roles and the audit log

A server that a small team shares runs with accounts. The accounts and the cases each may open
are in one file, `accounts.json` in the data directory (`FORENSIC_DATA_DIR`), which
`backend/manage.py accounts` writes; [Setup](setup.md#accounts-for-a-team) has the commands. While
that file holds no account the server works as without it: no token on a machine of one's own, or
the one shared `FORENSIC_AUTH_TOKEN`. Once it holds one:

- **Every request carries a personal token**, in the same `X-Forensic-Client` header, and the
  shared token is no longer accepted. A token is 32 random bytes with a short public id
  (`remn_<id>_<secret>`), shown once when it is made and kept only as a salted SHA-256 digest; the
  file is replaced whole on every change and is readable by the server's account only (0600; on
  Windows it has the permissions of its folder). A token is revoked, or rotated (every token of the
  account revoked and a new one made); an account is disabled, which refuses its tokens until it
  is enabled again. Changes take effect at the next request, without a restart. Wrong tokens count
  against the same per-address allowance as wrong shared tokens. A file that exists and cannot be
  read refuses every request rather than opening the server.
- **A role per account.**

  | Role | May |
  |---|---|
  | admin | everything: every case, its membership and owner, the stores no case record covers, the audit log |
  | analyst | create cases, add and remove evidence, run lookups and enrichment, on the cases it owns or is a member of; change the members of the cases it owns |
  | viewer | read the cases it is a member of (search, rule runs, stories, the AI analyst, export) and change nothing on the server; cancel a job it started |

- **A case records its owner and members.** The analyst or admin whose request first writes to a
  new case key becomes its owner. The owner or an admin changes the members, by account name;
  only an admin gives a case another owner, and only the owner or an admin deletes it. The case
  key no longer opens a store on its own: a request for a case its account may not open gets the
  same 404 as a key nobody uses, and a member whose role does not allow a change gets a 403 that
  says why. The case listing (`GET /api/store`) and the job routes show each account only the
  cases it may read. A store written before accounts were turned on has no record: only an admin
  opens it until an owner is given (`manage.py accounts case <key> --owner <name>`).
- **Every route declares what it needs** (`backend/forensic/access.py`), and with accounts on a
  route that declares nothing is refused. `tests/backend/test_route_permissions.py` enumerates
  the URL patterns and fails on a route without a declaration.

**The audit log.** With accounts on, the server appends one line to `audit.log` in the data
directory for every request that changes something on the server, brings evidence in (uploads,
parses, imports), takes it out (exports) or sends it to a model or a reputation provider, for
every failed authentication, and for every request the access check refuses; reads are not
recorded. Each entry holds the time (UTC), the account and its role, the client address, the
method, the route and path, the case, the HTTP status and the outcome; for a failed
authentication, the account the token names, when it names one. The management command records
the changes it makes to accounts and cases the same way. The status is the one the request was
answered with: a streamed export that fails part-way is recorded as begun.

Each entry carries an HMAC-SHA-256 of itself and of the entry before it, under the audit key:
`FORENSIC_AUDIT_KEY`, or, when that is empty, a random key written at first use to `audit.key`
beside the log (0600). An admin checks the chain with `manage.py audit verify` or `GET
/api/audit/verify`, and reads it with `manage.py audit show` or `GET /api/audit`. Verification
finds an entry that was changed, removed, inserted or moved, and an entry written without the key;
nobody without the key can write one that passes. Entries cut off the end leave a chain that
still holds: `verify` prints the newest entry's code, and given an earlier one with `--head`
(`?head=` on the route) it fails when that entry is no longer in the log. Note the code somewhere
the server cannot write; the server also checks the entry it wrote last while it runs.

What the audit log does not protect against: whoever holds the key, which includes whoever runs
the server or can read its data directory or environment, can rewrite the whole log so that it
passes. It records, it does not prevent: a request is answered before its entry is written, and
an entry that cannot be written (a full disk) is reported in the server log, not undone. Setting
`FORENSIC_AUDIT_KEY` keeps the key out of the data directory, so a copy of that directory, a
backup of it or a parse process (which starts without the server's environment) cannot rewrite
the log; it does not keep it from the server's administrator.

Still out of scope: single sign-on (OIDC, SAML) and multi-factor authentication, passwords
and sessions (a token is the only credential), encryption at rest (above), and shared case state:
findings, notes, decisions and the AI sessions still live in each analyst's browser, so a member
who opens a case sees its evidence, not another member's findings or notes. A viewer can still mark
findings in its own browser; nothing it does there reaches the server.

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

A GET of the health endpoint without the `X-Forensic-Client` header is the one request the
server answers without it, and it answers `{"ok": true}` and nothing else: that is what a
container health check or a load balancer can send. With the header (and the token, when one
is set), the health endpoint reports the build (`version+commit`) and a link to that exact source in
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
  works and the folders it expands a 7z into or stages event logs in for Hayabusa. A parse
  releases those itself, and a process killed mid-parse cannot. A parse still reading an expanded
  7z touches its folder as it takes each member, so the age is the time since last use. At
  startup, when nothing is being parsed, all of it is removed whatever its age; chunked uploads
  stay, since a client can resume them. The total budget below counts those folders too.
- **A total budget.** `FORENSIC_TMP_MAX_GB` caps what the staging area may hold at once: 4 in
  browser-only mode, and otherwise 0, which is the free space of the disk under the staging area
  less a tenth of that disk (at most 10 GiB) kept for the case stores and the system. A configured
  total is never taken as more than that disk can hold. A file larger than the whole budget is
  refused with 413 and a message naming what sets the budget, since waiting cannot change it. A
  new upload that fits the budget but not what other uploads hold now triggers a sweep and is
  then refused with 507, saying how much is held and how much is free, so a stream of abandoned
  uploads cannot fill the disk however short the lifetime is. One archive member copied out for
  parsing may take at most half the budget, and never more than 4 GiB.
- **Private to the server account.** The staging directory is 0700 and each staged file 0600, so
  evidence in transit is not readable by other accounts on the host.
- **A ceiling on what one parse holds.** A package parse holds artifacts back to decode them in
  groups, and that hold is capped per request rather than per archive, so nesting cannot multiply
  it. Everything a package parse holds in the staging area at once, the member being read at each
  nesting level, an expanded 7z and a decoded cabinet included, stays within what the area had
  room for when the parse began. An archive expands to at most 200 times its own size, and never
  less than 64 MiB; that counts what a compressed tar decompresses to pass over a member and what
  a 7z decompresses to reach one, and the members past it are listed as skipped with the reason.
  A client that disconnects mid-parse releases everything the parse was holding rather than
  stranding it for the sweeper to find later.
- **A ceiling on how long one parse runs.** `FORENSIC_INGEST_MAX_S` (30 minutes in
  browser-only mode, off otherwise) ends an ingest stream at the limit with the rows already
  sent, an error line saying why, and the result marked incomplete. The parse process is asked
  to stop at the limit and is killed five seconds later if it has not, so a parser stuck inside
  one record or one archive member cannot outlast it. The rate limiter shapes how
  fast requests arrive, not how many are in flight, and the server cannot reap a request once it
  is running; this is what stops a few slow parses holding every worker thread indefinitely.
- **External engines under the same bounds.** Hayabusa, when installed, runs as a separate
  process that starts without the server's environment, over the event logs the parse process
  staged (regular files only, moved out of the parse's folder first), watched for memory (`HAYABUSA_MAX_MB`, 1536 by default and 768 in the public
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
  the attachment flagged as a decompression bomb when it goes past it. A tar inside an
  attachment is walked over at most that analysis limit of data, whatever compression it
  carries, and over at most 10,000 headers and 10 seconds; an attachment whose walk stops early
  is flagged as partly analysed.
- **Every member accounted for.** An archive's members are listed in the stream's last line
  as parsed (with their row count), skipped or failed, with the reason: too large, past the
  archive's expansion allowance, encrypted, a compression method that is not read, not a mail
  file, not an event log. Nothing is left
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
lines: requests refused, sweeps, the engine's state. A failure in the parsing code, in a request
or in the web server is logged by exception type and place (`UnicodeDecodeError at common.py:104`),
never with the exception's text, which is often a piece of the input or a path on the server. This
holds in every mode; `FORENSIC_DEBUG=1` keeps the text and the traceback for a developer on their
own machine, and has no such effect in browser-only mode. In browser-only mode the log also never
names a file, member or attachment. `docker-compose.public.yml` rotates the log (three files of
10 MB) rather than keeping it for the life of the container.

A client is told no more than the log holds. A request, a parse or a job that fails on the server
answers with what failed, the exception's type and a reference (`the store query failed on the
server (OSError); the server log has the cause under reference 3f9a01c2`), and the log line of
that failure carries the same reference, so the operator can find the cause for the analyst who
reports it. Two kinds of text are still passed on as they are: a statement or filter the database
cannot run gets DuckDB's diagnostic as a 400, because the analyst, and the model's `sql` tool,
correct the query from it; and the per-file entries of a package or mailbox ingest (a member that
could not be read, an unparseable message) keep the parser's message for that file, which can
quote the file.

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
- **It does not serve the app.** Caddy serves the frontend build from its own image (the
  Dockerfile's `static` stage) and passes only `/api/*` to the parser, so a parser taken over
  cannot hand later visitors a page of its own, and a parser kept busy does not delay the page.
  The page gets the same headers from Caddy as from Django (a test holds them equal), and
  `deploy/update.sh` validates the new proxy image and Caddyfile before it replaces anything.

Verified rather than asserted: from inside the running container the effective capability set is
empty, the root filesystem refuses writes, the staging area reports as tmpfs, and connections to a
hostname, to a raw address on 443 and to a resolver on 53 all fail, while a 14 MiB EVTX still
parses to 6000 events with a matching digest.

What remains is that an exploit still gets execution inside that container, which the next
section bounds further.

### Each parse in a process of its own

Every parse of uploaded evidence runs in a process the server starts for that parse and removes
after it (`backend/services/ingest/isolation.py`): event logs and their archives, mail of every
format including PST, packages and collections, the attachment analysis inside them, and a
single attachment dropped for analysis. The server keeps the stream to the browser, the writes
to the case store, the statistics and per-file entries, Hayabusa, the deadline and the cancel of
a job. The parse process sends its rows back in batches, as JSON, one message a line; nothing it
sends is unpickled or run, and no line it sends is longer than the server is prepared to hold.

That process:

- **Starts without the server's environment.** It gets the path, the locale and time zone and,
  on Windows, the variables an interpreter needs to start: not the access token, not the provider
  keys, not anything else the server was started with. It does not load the server's settings
  either, only the few a parser reads (the staging area, the message and staging limits, the YARA
  rules folder, logging). The native decoders it starts, and Hayabusa, which the server starts,
  get the same environment.
- **Works in a folder of its own** in the staging area, which the server removes when the parse
  ends, however it ends, and which the staging budget and the sweep count like the other folders
  a parse uses.
- **Is stopped at its limits, and says so.** At the deadline, at its memory limit, at its
  processor-time limit, when the job is cancelled, or when it dies, the parse process is
  stopped and the processes it started go with it. The rows read before the stop are kept; the
  stream's error line or the job's error says what stopped it and while reading which member;
  the result is marked incomplete, and the members it had not finished are errors with the
  reason. A member that ran the parse out of memory and was given up says so on its entry, and
  the parse goes on with the next one.

What each system enforces:

| | Linux | macOS | Windows |
|---|---|---|---|
| The server's environment and settings | not passed | not passed | not passed |
| Memory, `FORENSIC_PARSE_MAX_MB` (4096; 1024 in browser-only mode) | the kernel refuses private memory past the limit (`RLIMIT_DATA`) and the parse stops with what it read; the server also watches resident memory, shared memory included, and kills the process past the limit and a margin | the server watches resident memory every 50 ms and kills the process past the limit | the server watches the larger of the working set and the committed private memory every 50 ms and kills the process past the limit |
| Processor time, `FORENSIC_PARSE_MAX_CPU_S` (six hours) | the kernel (`RLIMIT_CPU`) | the kernel (`RLIMIT_CPU`) | not enforced: that takes a job object, which the standard library does not offer; the deadline, where one is set, is the bound |
| Deadline, `FORENSIC_INGEST_MAX_S` | asked to stop, killed five seconds later with its process group | as Linux | asked to stop, killed five seconds later with the processes under it the server can see |
| Network | none, where the system lets an unprivileged process have a network namespace of its own: the process has no interface, loopback included; otherwise not isolated | not isolated | not isolated |
| Another account, `FORENSIC_PARSE_UID` | when the server runs as root | when the server runs as root | not available |
| Core dumps | off | off | not applicable |

The server logs what took effect at the first parse, and again if it changes (`parse processes:
memory kernel, processor time kernel, network none (namespace), account 1000`). Ubuntu 24.04
restricts unprivileged user namespaces through AppArmor, and Docker's default seccomp profile
refuses them, so there the network line says it is not isolated and why; in
`docker-compose.public.yml` the container's internal network is what keeps a parse off the
network. Nothing in the parse process checks its own sockets: a check inside a process that may
have been taken over is not a boundary, so where the system offers none, this page says so
instead.

What a parse process still reaches is what its account can. As the server's own account, that
is the staging area with any other upload in it, the case stores, the accounts file (digests of
the tokens, not the tokens), the audit log and its key when `FORENSIC_AUDIT_KEY` is not set, and a
`.env` file if the configuration is kept in one: the access token is then in that file even though
it is not in the environment. Running the server as root with `FORENSIC_PARSE_UID` set to an unprivileged account
(a name or a number) closes that on Linux and macOS: the parse runs as that account, in a folder
it owns (0700), on evidence the server hands it by a link, and the staging area, the case stores
and the configuration stay the server's. The interpreter, the virtual environment and the code
must then be readable by that account and the folders above the staging area passable; the
server lets other accounts pass through the staging folder, not list it. Nothing requires it: a
container that runs as an unprivileged user, as the public compose does, and gets its token as an
environment variable already keeps the token out of the parse's reach, since no file in the
container holds it.

A parse process that has been taken over can still fill the disk under the staging area or
`/dev/shm`, and can start processes that leave its process group and outlive it. Containing that
takes something this server does not set up: a container (the public compose), cgroups or a job
object.

Starting the parse process adds about 0.2 s to every file. On an archive of 90,000 synthetic
events the browser-store stream was 7% slower and the server-store ingest 25% shorter, because
the parse and the writes to the store then run side by side on two cores.

`FORENSIC_PARSE_ISOLATION=0` parses inside the server process, as before. It is for debugging a
parser, and it gives up everything above: the parser then runs with the token, the keys and every
case store in reach, without a memory or a processor-time limit, without a network namespace or
another account, and the deadline is checked only between records and archive members, so a
parser stuck inside one record holds its worker thread until it returns.

The per-address budget reads the **rightmost** X-Forwarded-For entry, the one the trusted proxy
observed and appended, not the leftmost, which is whatever the client sent. Caddy's default
replaces the header rather than appending, which hides the difference, but that is a property of
one proxy's configuration: put a CDN in front, or set `trusted_proxies`, and a leftmost read
becomes forgeable. The shipped Caddyfiles also set the header explicitly rather than relying on
that default.

For the full mode, one change came with this: listing every server store (`GET
/api/store`) is an operator action and is only answered when an access token is
configured; with accounts, each account is listed the cases it may read. A case reaches its
store by the key it holds, and the keys are random, so without the listing a store cannot be
found by a client that was never given it; with accounts, the key is not enough either. The
background jobs follow the same rule: they are listed per case (`GET /api/jobs?case=<key>`),
a job is read, followed and cancelled only with its case's key, and no answer about a job
carries the key. Reading a store (an export included) never creates one: a key nobody wrote
to is a 404.

## Text in the evidence that addresses the model

The analyst agent reads tool results, the triage pass reads item summaries, and the
Claude Code connector reads a transcript; all three carry text that came from the
evidence, which an attacker may have written. Five things stand between that text and a
change to the case:

- The model cannot change the case. No tool writes: the agent's propose_* tools queue a
  proposal in the approval inbox, and the triage pass records proposals too. Only the
  analyst's click accepts one, and an accepted proposal is written with a tag and a
  snapshot of what it replaced, so undo puts the previous state back
  (`frontend/src/ai/inbox.ts`, `frontend/src/ai/inbox.test.ts`,
  `frontend/src/data/aiReview.db.test.ts`). Nothing in the evidence can accept anything.
- Tool results reach the model between `<evidence>` markers the evidence cannot close, and
  text that addresses a model, an assistant or a reviewer is found before the model reads
  it: the result opens with a notice naming the rows, the chat shows the text, the AI
  ledger records it, and every proposal the run makes afterwards is marked so that
  "accept all" leaves it for a one-by-one look; so is one made after evidence too long for
  the check to read whole. The triage pass marks every proposal of a batch in which any item
  does the same (`frontend/src/ai/evidence.ts`, `evidence.test.ts`). The check is a handful
  of English patterns and finds about one in four of an invented set of payloads; what it
  misses goes through "accept all" unmarked ([AI analyst](ai.md#evidence-that-addresses-the-model)).
- Every prompt on those paths says the case text is evidence, never an instruction, and
  that a record asking to be ignored or marked benign is evidence of intent to be named
  in the reason (`backend/services/ai/prompts.py`, `claude_code.py`, the triage
  instruction in `frontend/src/data/aiReview.ts`; `tests/backend/test_ai_meta.py` checks
  the sentences are there, and that no tool the model is offered writes to the case).
- Claims are checked. A citation the tools never returned is shown as unverified, and a
  proposal that cites nothing the agent has seen is refused.
- The synthetic lab carries a control, S07, a password-expiry lure whose body tells
  automated reviewers to classify it as benign. The rules score it on its facts, the
  detector flags it, and a model that follows the text fails the control.

The local OpenAI-compatible transport sends no key and refuses any address that is not on
the analyst's machine or local network, so a mistyped cloud endpoint receives nothing.
