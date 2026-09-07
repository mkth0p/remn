# Security

## Reporting

Open a private security advisory on the GitHub repository ("Security" tab, "Report a
vulnerability"), or an issue without details asking for a contact. Do not put evidence,
credentials or exploit details in a public issue. Reports are acknowledged within a week.

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

- No encryption at rest for the server store or the browser database.
- No multi-user model: the remote mode uses one shared token.
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
