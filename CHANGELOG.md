# Changelog

Versions follow semantic versioning; the number lives in `backend/api/views/health.py`
and a `vX.Y.Z` tag on `main` makes a GitHub release with a built archive.

## Unreleased

- Repository scaffolding: Apache-2.0 licence and third-party notices, CI on every push
  (pytest, ruff, typecheck, ESLint, Prettier, vitest, build, bundle budget), release
  workflow, ruff and ESLint/Prettier configuration with pre-commit hooks, documentation
  split into `docs/`, contributing and security policies.

## 0.1.0

The state of the tool in September 2026, before any release.

- Ingestion of Windows event logs (EVTX, archives), mailboxes (PST/OST, mbox, eml, msg)
  and Microsoft 365 audit and Entra sign-in exports; SHA-256 chain of custody; browser
  (IndexedDB) and server (DuckDB) stores; chunked resumable uploads and background jobs.
- Search with facets, filter DSL, regex, time and business-hours filters, entity pages,
  pivots, timeline, indicators with opt-in reputation lookups, STIX and CSV export.
- Detection: YAML rule DSL with two engines kept in parity, community packs (SigmaHQ,
  Sublime Security), mail risk scoring calibrated on public corpora, sender baseline
  and campaign clustering, applicability checks.
- Attack chains across mail, identity, Microsoft 365 and host activity, with scoring,
  a story view and a swimlane graph.
- Review workflow: chains and incidents in order, verdicts, rescoring, notes, narratives,
  report inclusion, unlinking chain members, model proposals and an undoable AI triage.
- AI analyst over the case through tools, with three transports: browser-direct Ollama,
  server proxy, Claude Code on the server machine.
- Printed report in REMN's own look, one self-contained HTML file, print-to-PDF.
- Security model: content security policy, sandboxed previews, no external access from
  the store, shared-token remote mode.
