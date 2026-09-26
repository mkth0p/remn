# Contributing

## Set up

```
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r backend\requirements.txt -r backend\requirements-dev.txt
cd frontend && npm ci
```

Run the API with `.venv\Scripts\python.exe backend\manage.py runserver 127.0.0.1:8000`
and the frontend with `npm run dev` in `frontend/`, or both on one port with
`backend\run.py` after `npm run build`. `docs/setup.md` has the details and the
optional pieces (PST support, YARA, GeoLite2, Ollama).

## Before you push

```
ruff check . && ruff format --check .     # backend, tools, tests
pytest -q                                  # backend tests (heavy ones are opt-in: pytest -m heavy)
cd frontend
npm run typecheck && npm run lint && npm run format:check
npm test
```

`pre-commit install` runs the linters and formatters on staged files; CI runs the same
commands on every pull request and on `main`.

## Branches

`main` is the line of work and takes changes only through a pull request. `server` holds
work meant only for self-hosted installs; it starts from `main` and takes `main`'s changes.
Everything else is a short-lived branch for one pull request, deleted once it is merged.

## Rules of the repository

- **No real evidence, ever.** Samples are synthetic (`samples/synthetic/`) or public
  corpora fetched on demand. The `.gitignore` blocks evidence extensions under
  `samples/`; keep it that way. No personal identifiers in code, tests or docs.
- **Two rule engines, one behaviour.** A change to a rule, an operator or the filter
  DSL must keep `frontend/src/rules/parity.test.ts` green; regenerate the fixture with
  `tools/parity_fixture.py` when the change is intentional.
- **Rules are measured.** A change to a rule, a pack, the rule engine or the EVTX parser is
  measured again before it is merged: `tools/measure_rules.py --datasets DIR --fetch --out
  rules/measures.json --detail rules/measures-detail.json` (one to two hours on four cores,
  or `--shard` it over several machines and `--merge` the shares), and both files are
  committed with the change. The rule-measures workflow fails a pull
  request that makes a rule stop detecting a recording or a high or critical rule noisier
  on the clean machines; when that is intended, the committed measures say so.
- **Prompts live in Python.** `backend/services/ai/prompts.py` is the source; the
  browser mirror is checked by `tests/fixtures/ai_system_compose.json`. After a prompt
  change, regenerate the fixture with `tools/ai_compose_fixture.py`. A new AI tool is
  declared in `backend/services/ai/tools.py`, run in `frontend/src/ai/tools.ts`, and never
  writes to the case: a change the model wants is a `propose_*` tool that queues it in the
  approval inbox (`frontend/src/ai/inbox.ts`).
- **Decisions survive reruns.** Anything an analyst sets on a finding (status, notes,
  severity, exclusion, unlink) is carried across rule reruns by
  `frontend/src/data/findingReviews.ts`; new decision fields go there too.
- **Docs move with the code.** Behaviour is described in `docs/`; a change that alters
  what the user sees updates the matching page in the same commit.
- **Commit messages say what changed and why**, in one sentence, from the user's point
  of view. No trailers.

## Style

Python: ruff (config in `ruff.toml`), double quotes, long lines allowed. TypeScript:
ESLint and Prettier (config in `frontend/`), no semicolons, single quotes. Comments
explain intent, not mechanics. UI text is plain and factual.

## Tests

Backend tests live in `tests/backend/` and use the synthetic generators from
`samples/synthetic/`. Frontend tests sit next to the code (`*.test.ts`, `*.test.tsx`);
component tests declare `// @vitest-environment jsdom` at the top. Add a test with every
fix that had a reproducible cause.
