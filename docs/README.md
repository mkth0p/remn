# REMN documentation

The README gives the short version. These pages carry the detail, each written to be read on
its own. A first-time reader takes them in this order: setup, the frequently asked questions,
architecture, storage, sources, then detection and stories for what the tool finds, interface
for how it is used, and the rest as needed.

Getting started:

- [Setup and run](setup.md): requirements, installation on Linux, macOS and Windows, the two ways to run, Docker, a public instance, remote access, accounts, backup and upgrade
- [Frequently asked questions](faq.md): what leaves the machine, what REMN reads and does not do, how findings are measured, licences
- [Architecture](architecture.md): the parts, the two modes, where evidence goes, the processes, accounts and roles, the files on disk

Using REMN:

- [Storage modes](storage.md): browser store and server store, uploads and jobs, removing evidence, the checklist before real exports
- [Data sources](sources.md): Windows event logs, mailboxes, Microsoft 365 and Entra exports, deleted mail
- [Investigation packages](packages.md): mixed archives, triage collections, adapters, coverage and limits
- [Detection](detection.md): bundled and community rules, Hayabusa, the measured rules, the detection level, mail risk scoring, sender baseline, the two engines
- [Stories](stories.md): one story per person or host incident, with who is who, sessions, hops and process trees, phases, campaigns, where a story stops
- [Attack chains](chains.md): how a phishing chain is built and scored, and how it relates to findings and stories
- [Explore: the relationship graph](relationship-intelligence.md): identity and link semantics of the graph Explore browses
- [Interface](interface.md): the pages, the review workflow, the report, the tests that cover them
- [Investigative questions](questions.md): the case as DFIQ's investigative questions and REMN's own, what answers each, whether the case holds the evidence, the analyst's answers in the report
- [AI analyst](ai.md): the investigating agent, playbooks, the approval inbox and ledger, the four transports, what leaves the machine

Extending and checking:

- [Writing rules](rules.md): the rule format, fields and operators, trying a rule, the checks and measures a shipped rule passes, importing Sigma and Sublime rules, patterns that backtrack
- [API reference](api.md): every route under `/api/`, the role it needs and its main fields
- [Validation and test data](validation.md): the test suites, the public corpora and the measured rates, the synthetic lab
- [Security model](security.md): where evidence lives, what leaves the machine, the hardening in place, evidence text and the model
- [Releasing](releasing.md): what a tag publishes
- [Optional archive honeypot](honeypot.md): the decoy for a public instance, with its [design](honeypot-design.md) and [narrative](ghost-archive-narrative.md)

Other files: [CONTRIBUTING](../CONTRIBUTING.md), [SECURITY](../SECURITY.md), [CHANGELOG](../CHANGELOG.md), [third-party notices](../THIRD_PARTY_NOTICES.md).

Dated studies, which describe the code and the measures of their day: [project review, September 2026](reviews/2026-09-05-project-review.md), [browser-only analysis](reviews/2026-09-22-browser-only-analysis.md), [EVTX-ATTACK-SAMPLES](reviews/2026-09-23-evtx-attack-samples.md), [REMN 2.0 plan](reviews/2026-09-24-remn-2.0-plan.md), [the tool landscape against the 2.0 plan](reviews/2026-09-24-landscape.md), [REMN's rules, measured](reviews/2026-09-24-measured-rules.md), [REMN, Hayabusa and Chainsaw head to head](reviews/2026-09-25-head-to-head.md), [less noise, a gate on the measures and a second held-out library](reviews/2026-09-25-noise-and-held-out.md), [measures across libraries](reviews/2026-09-28-measures-across-libraries.md).
