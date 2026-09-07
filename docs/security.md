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
Upload temporary files are deleted when the request ends. See [Storage modes](storage.md).

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
- Whatever the model decides is written with a tag, a reason and a snapshot of what it
  replaced (`frontend/src/data/aiReview.test.ts` and `aiReview.db.test.ts`), so a
  steered decision is visible in the rail, in the log popup and in the report, and undo
  puts the previous state back.
