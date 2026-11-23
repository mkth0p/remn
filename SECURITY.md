# Security

## Reporting

Report a vulnerability privately, with GitHub's private vulnerability reporting: on the
repository, open the "Security" tab, then "Report a vulnerability"
(https://github.com/mkth0p/remn/security/advisories/new), and fill in the form. The report
is a draft security advisory that only you and the repository's maintainers can read. The
discussion, a fix in a temporary private fork and, when the fix is released, the published
advisory (with a CVE identifier when one is requested) all happen there. Reports are
acknowledged within a week.

Do not put evidence, credentials or exploit details in a public issue. If the "Report a
vulnerability" button is missing, open an issue that says only that you have a security
report and asks for a private channel, with nothing of the report in it.

## What REMN promises

- Evidence stays on the machines the analyst chooses. In the browser store nothing is
  persisted server-side; in the server store rows live in a DuckDB file under
  `backend/data/cases/` on the REMN host. Uploads transit through `backend/tmp` and are
  deleted after parsing.
- Nothing leaves those machines unless the analyst switches it on: reputation lookups
  (per case), the browser-direct Ollama transport (the analyst's own machine), the server
  proxy (the REMN host's Ollama), or the Claude Code connector (the REMN host's Claude
  account, sending prompts, tool results and answers to Anthropic).
- The report and every preview render case data through escaping; the report prints
  from a frame that runs no script; the API refuses cross-origin requests and ships a
  content security policy. Details are in `docs/security.md`.

## What it does not promise

- No encryption at rest of its own, for the server store, its backups or the browser
  database. A server that keeps evidence must keep its cases folder, staging area and
  backups on an encrypted volume; `docs/security.md` says what that covers and what it
  does not.
- No single sign-on: a team on one server uses accounts with personal tokens and three
  roles, and an audit log whose chain whoever holds its key (the server's administrator
  included) could rewrite. Without accounts, the remote mode is one shared token.
- No sandboxed execution: attachments are analysed statically (structure, macros,
  scripts, URLs, YARA), never opened or run.
- Model output is untrusted. Evidence text reaches the model, so a crafted mail can try
  to steer it. Every prompt that carries case text says that text is evidence, never an
  instruction; the synthetic lab has a control mail (S07) that tries exactly this; and
  decisions the model takes are tagged, logged and undoable, and never bypass the
  analyst.

## Scope of a report

In scope: anything that lets evidence or decisions leave the machine, cross a case, or
be altered without the analyst; script execution from case data; bypasses of the
token or the CSP; parser crashes on crafted files. Out of scope: the local development
server bound to loopback without a token, and issues in the third-party rule packs
(report those upstream).
