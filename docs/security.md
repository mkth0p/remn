# Security model

_What leaves the machine, what is stored where, hardening in place._

## Security model

* Server binds to `127.0.0.1`, keeps no database and deletes upload temp files at
  the end of each request. Every `/api` call needs the `X-Forensic-Client`
  header (cookie-less CSRF protection); cross-origin preflights are refused.
  With `FORENSIC_AUTH_TOKEN` set, the header value must equal the token
  (see "Remote access").
* Parsed content is treated as hostile: React escaping, HTML previews in a
  sandboxed iframe with DOMPurify, images blocked, links disabled and defanged.
  Attachments are analysed statically, never opened or executed.
* The built app carries a Content Security Policy (no inline script, scripts and
  workers from the app origin only, WebAssembly allowed for hashing, frames only for
  the sandboxed mail and report documents, no object or base tags) as a `<meta>` tag
  in `index.html` and as a header from the server, which adds `frame-ancestors 'none'`.
  Every response also carries `X-Frame-Options: DENY`, `nosniff`, a `no-referrer`
  policy, same-origin opener and resource policies, and API bodies get a CSP that
  forbids rendering them. The theme bootstrap is an external file for that reason.
* Markdown from the model and from notes is escaped before the light markup pass
  (no links or raw HTML are produced); JSON views are escaped; the report is built
  from escaped cells and printed from a sandboxed frame. Links whose target comes
  from data (reputation providers, pack manifests, ATT&CK ids) pass through a
  scheme check and get `rel="noopener noreferrer"`; anything but http(s) is dropped.
* The raw SQL endpoint and the analyst's `sql` tool accept one read statement
  (SELECT, WITH, DESCRIBE, SHOW) with write keywords rejected, and every DuckDB
  connection runs with external access disabled and the configuration locked, so a
  prompt-injected query cannot read or write files on the server or load extensions.
* Identifiers that reach the filesystem are validated (case keys and upload ids by
  pattern, pack ids without separators, static files resolved inside the build
  directory); rule archives are capped per member and in total; CSV exports
  neutralise spreadsheet formula injection.
* No outbound request unless "allow external lookups" is enabled for the case;
  the AI model only sees what the tools return from the local database.

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
  replaced (`frontend/src/data/aiReview.test.ts` and `aiReview.db.test.ts`), so a steered
  decision is visible in the rail, in the log popup and in the report, and undo puts the
  previous state back.
