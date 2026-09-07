# REMN documentation

The README gives the short version. These pages carry the detail, each written to be
read on its own. A first-time reader takes them in this order: setup, storage, sources,
then detection and chains for what the tool finds, interface for how it is used, and the
rest as needed.

- [Setup and run](setup.md) — requirements, installation, the two ways to run, Docker, remote access, repository layout
- [Storage modes](storage.md) — browser store and server store, uploads and jobs, removing evidence, the checklist before real exports
- [Data sources](sources.md) — Windows event logs, mailboxes, Microsoft 365 and Entra exports, deleted mail
- [Detection](detection.md) — the rule language, bundled and community rules, mail risk scoring, sender baseline, the two engines
- [Attack chains](chains.md) — how a chain is built and scored, and how it relates to findings
- [Interface](interface.md) — the pages, the review workflow, the report, the tests that cover them
- [AI analyst](ai.md) — what the model does, the three transports, the tools, what leaves the machine
- [Validation and test data](validation.md) — the test suites, the public corpora and the measured rates, the synthetic lab
- [Security model](security.md) — where evidence lives, what leaves the machine, the hardening in place, evidence text and the model

Other files: [CONTRIBUTING](../CONTRIBUTING.md), [SECURITY](../SECURITY.md), [CHANGELOG](../CHANGELOG.md), [third-party notices](../THIRD_PARTY_NOTICES.md), [project review, September 2026](reviews/2026-09-05-project-review.md).
