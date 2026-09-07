# AI analyst

_Transports (browser Ollama, server proxy, Claude Code), tools, triage._

## AI mode notes

* **Transport**: by default the browser talks directly to the analyst's own
  Ollama (`http://localhost:11434`) - prompts, tool results and evidence
  excerpts never reach the REMN server. Settings → AI switches to the server
  proxy (the pre-existing `/api/ai/*` path) for machines without a local
  Ollama. Prompts and tool schemas stay server-defined (`GET /api/ai/meta`).
* **Claude Code connector** (Settings → AI → Claude Code): the REMN server runs
  the `claude` command line installed on its machine, signed in with that
  machine's Claude account, as the analyst model. One command per model turn,
  in print mode, with REMN's system prompt in place of Claude Code's, its own
  tools, hooks, plugins and MCP servers off (`--safe-mode --tools ""`) and no
  session file (`--no-session-persistence`). The browser still owns the
  conversation and runs the REMN tools; Claude asks for them with a JSON reply
  (`{"tool_calls": [...]}`) that the server holds back and hands to the agent
  loop, and the command line is stopped as soon as that object is complete so
  the model cannot invent the tool result. Models are the `sonnet`, `opus`,
  `fable` and `haiku` aliases. Prompts, tool results (evidence excerpts) and
  answers leave the server for Anthropic; the server keeps nothing. Not for
  evidence that may not leave the organisation. Install with
  `npm install -g @anthropic-ai/claude-code`, run `claude` once to sign in,
  restart REMN; `CLAUDE_CODE_ENABLED=0` switches the connector off,
  `CLAUDE_CODE_BIN` points at the binary, `CLAUDE_CODE_TIMEOUT` (600 s) caps a
  turn. Endpoints: `GET /api/ai/claude/status`, `POST /api/ai/claude/chat`
  (SSE, same chunks as the Ollama proxy), `POST /api/ai/claude/query`.
* The analyst agent sends the system prompt + tool definitions on every turn;
  with a 7-8B model running **on CPU** a turn takes 2-4 minutes (prompt
  evaluation dominates). On a GPU the same turn takes a few seconds. Check
  `curl http://127.0.0.1:11434/api/ps` → `size_vram` should not be 0.
* Smaller / faster models work for the filter builder ("ask" button) and for
  "explain"; the agent needs a model with the `tools` capability.
* `OLLAMA_MODEL`, `OLLAMA_NUM_CTX` and `OLLAMA_HOST` are set in `.env`.
* Debugging a model's tool-calling behaviour:
  `.venv\Scripts\python.exe samples\synthetic\ai_repro.py <model> [true|false]`
  replays a second agent turn and prints the raw Ollama chunks.
