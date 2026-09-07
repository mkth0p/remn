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
commands on every push.

## Rules of the repository

- **No real evidence, ever.** Samples are synthetic (`samples/synthetic/`) or public
  corpora fetched on demand. The `.gitignore` blocks evidence extensions under
  `samples/`; keep it that way. No personal identifiers in code, tests or docs.
- **Two rule engines, one behaviour.** A change to a rule, an operator or the filter
  DSL must keep `frontend/src/rules/parity.test.ts` green; regenerate the fixture with
  `tools/parity_fixture.py` when the change is intentional.
- **Prompts live in Python.** `backend/services/ai/prompts.py` is the source; the
  browser mirror is checked by `tests/fixtures/ai_system_compose.json`. After a prompt
  change, regenerate the fixture (`tests/backend/test_ai_meta.py` explains how).
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
