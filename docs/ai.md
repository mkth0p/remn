# AI analyst

A language model helps in five places: the AI analyst page, where it answers questions
about the case through tools and cites record ids; the "ask" button on the Events and
Mails pages, where it turns a sentence into a filter; "explain" on a record; rule drafting
on the Rules page; and the review, where it drafts narratives, proposes decisions,
triages the queue and writes the executive summary. This page describes where the model
runs and what leaves the machine in each case, the tools it has, and what to expect from
it in practice. Prompts and tool schemas are defined once, on the server
(`backend/services/ai/prompts.py`, `GET /api/ai/meta`), whatever the transport.

## Transports

Settings → AI chooses one of three ways to reach a model.

**Browser-direct Ollama** is the default. The analyst's page calls the analyst's own
Ollama at `http://localhost:11434`; prompts, tool results and evidence excerpts never
reach the REMN server, and each analyst uses the models on their own machine. When REMN
is served from another host, Ollama must allow that origin once
(`setx OLLAMA_ORIGINS "https://remn.example.com"`, then restart Ollama); Safari blocks
an HTTPS page from calling localhost, so a Safari user takes the next transport.

**Server proxy.** The REMN server relays to the Ollama configured in its `.env`
(`OLLAMA_HOST`, `OLLAMA_MODEL`, `OLLAMA_NUM_CTX`); nothing is persisted on the server.
For machines without a local Ollama.

**Claude Code.** The REMN server runs the `claude` command line installed on its
machine, signed in with that machine's Claude account, as the analyst model. One command
per model turn, in print mode, with REMN's system prompt in place of Claude Code's, its
own tools, hooks, plugins and MCP servers off (`--safe-mode --tools ""`) and no session
file (`--no-session-persistence`). The browser still owns the conversation and runs the
REMN tools; Claude asks for them with a JSON reply (`{"tool_calls": [...]}`) that the
server holds back and hands to the agent loop, and the command line is stopped as soon
as that object is complete, so the model cannot invent the tool result. Models are the
`sonnet`, `opus`, `fable` and `haiku` aliases. Prompts, tool results (evidence excerpts)
and answers leave the server for Anthropic; the server keeps nothing. Not for evidence
that may not leave the organisation. Install with `npm install -g @anthropic-ai/claude-code`,
run `claude` once to sign in, restart REMN. `CLAUDE_CODE_ENABLED=0` switches the
connector off, `CLAUDE_CODE_BIN` points at the binary, `CLAUDE_CODE_TIMEOUT` (600 s) caps
a turn. Endpoints: `GET /api/ai/claude/status`, `POST /api/ai/claude/chat` (server-sent
events, the same chunks as the Ollama proxy), `POST /api/ai/claude/query`. The
connector is not available in the Docker image.

## Tools

The analyst agent works through tools that the browser executes against the case data;
only what a tool returns reaches the model. `get_case_summary` for the shape of the
case; `search_events`, `aggregate_events` and `timeline_events`, and the same three for
mails, all taking the filter language of the query bar; `get_event` and `get_mail` for
one record; `list_findings`; `get_chain` for a chain's steps and the findings linked to
it; `suggest_review` to record a review proposal for the analyst; `regex_test`;
`pivot` on a value across sources; `lookup_ioc`, which returns a notice unless the case
allows external lookups; and `sql`, one read statement over the DuckDB tables, on
server-store cases only. The prompt asks the model to aggregate before it lists rows,
keep result sizes small, chain at most about eight calls per question, and cite record
ids and UTC times in its answer.

## What to expect

- The agent sends the system prompt and the tool definitions on every turn. With a 7 to
  8 billion parameter model running on CPU, a turn takes 2 to 4 minutes, dominated by
  prompt evaluation; on a GPU the same turn takes a few seconds. Check
  `curl http://127.0.0.1:11434/api/ps`: `size_vram` should not be 0.
- Smaller and faster models are enough for the filter builder and for "explain"; the
  agent needs a model with the `tools` capability. The Settings page tests the
  connection and lists the models.
- Every decision the model takes in the review is tagged, logged with its reason and
  undoable; see the [interface page](interface.md). Evidence text that tries to steer
  the model is covered on the [security page](security.md).
- To see exactly what a model does with a tool call:
  `.venv\Scripts\python.exe samples\synthetic\ai_repro.py <model> [true|false]` replays
  a second agent turn against Ollama and prints the raw chunks.
