# REMN documentation

The README gives the short version. These pages carry the detail, each written to be
read on its own. A first-time reader takes them in this order: setup, storage, sources,
then detection and stories for what the tool finds, interface for how it is used, and the
rest as needed.

- [Setup and run](setup.md) — requirements, installation, the two ways to run, Docker, remote access, repository layout
- [Storage modes](storage.md) — browser store and server store, uploads and jobs, removing evidence, the checklist before real exports
- [Data sources](sources.md) — Windows event logs, mailboxes, Microsoft 365 and Entra exports, deleted mail
- [Detection](detection.md) — the rule language, bundled and community rules, mail risk scoring, sender baseline, the two engines
- [Stories](stories.md) — one story per person or host incident: who is who, sessions, hops and process trees, phases, campaigns, where a story stops
- [Attack chains](chains.md) — how a phishing chain is built and scored, and how it relates to findings and stories
- [Explore: the relationship graph](relationship-intelligence.md) — identity and link semantics of the graph Explore browses
- [Interface](interface.md) — the pages, the review workflow, the report, the tests that cover them
- [AI analyst](ai.md) — the investigating agent, playbooks, the approval inbox and ledger, the four transports, what leaves the machine
- [Validation and test data](validation.md) — the test suites, the public corpora and the measured rates, the synthetic lab
- [Security model](security.md) — where evidence lives, what leaves the machine, the hardening in place, evidence text and the model

Other files: [CONTRIBUTING](../CONTRIBUTING.md), [SECURITY](../SECURITY.md), [CHANGELOG](../CHANGELOG.md), [third-party notices](../THIRD_PARTY_NOTICES.md), [project review, September 2026](reviews/2026-09-05-project-review.md), [browser-only analysis, September 2026](reviews/2026-09-22-browser-only-analysis.md), [REMN 2.0 plan](reviews/2026-09-24-remn-2.0-plan.md), [the tool landscape against the 2.0 plan](reviews/2026-09-24-landscape.md), [REMN's rules, measured](reviews/2026-09-24-measured-rules.md), [REMN, Hayabusa and Chainsaw head to head](reviews/2026-09-25-head-to-head.md), [less noise, a gate on the measures and a second held-out library](reviews/2026-09-25-noise-and-held-out.md).
