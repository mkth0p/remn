# Frequently asked questions

Short answers, each with the page that has the detail.

## Does evidence leave my machine?

It goes where the REMN server runs. The page sends each file to the server to be parsed. With
the server on your own machine (`http://127.0.0.1:8000`), nothing leaves the machine. With the
server on another host, each file goes to that host: in a browser-store case it is deleted there
once parsed and its rows live only in your browser; in a server-store case its rows stay there in
a DuckDB file, unencrypted, so the disk under it has to be. With **parse .evtx files in this
browser** on in a case's settings, event logs are parsed in the page and never uploaded;
mailboxes, packages and cloud exports are always parsed by the server.

Beyond that, data leaves only when someone turns it on:

- Reputation lookups, per case ("allow external lookups"), send indicator values (addresses,
  domains, URLs, hashes) to the providers the operator configured, and nothing else. The server
  refuses a lookup for a case that does not allow it.
- The AI analyst sends prompts, tool results with evidence excerpts, and answers to the model.
  The browser-direct Ollama and OpenAI-compatible transports reach only addresses on the
  analyst's machine or local network; the server proxy reaches the Ollama the operator set; the
  Claude Code connector, off unless the operator turns it on, sends them to Anthropic under the
  server's sign-in.

REMN sends no telemetry and checks for no updates; the page loads its scripts, styles and fonts
from the REMN server only. Downloads happen when someone runs them: the tools that refresh the
rule packs or fetch the measurement datasets, and the Docker build, which downloads Hayabusa.
See [Security model](security.md#what-leaves-the-machine) and [AI analyst](ai.md#transports).

## What does REMN read?

- Windows event logs: `.evtx` files, archives of them, and event records exported as XML.
- Mailboxes: `.pst` and `.ost` (with the optional `libpff-python`), `.mbox`, `.eml`, `.msg`, and
  archives of `.eml` files.
- Microsoft 365 and Entra exports: the Unified Audit Log, sign-ins, directory audits, risk
  detections and risky users, and the Exchange message trace, in the forms the common
  acquisition tools write.
- Investigation packages and triage collections: a ZIP or TAR of mixed evidence, or a
  collection laid out like a drive (KAPE, Velociraptor's offline collector, acquire, a copy of a
  volume), from which it reads services, run keys, scheduled tasks, Defender's logs, Amcache,
  ShimCache, prefetch, browser history and more; the `$MFT` and USN journal when the case asks
  for them.

Everything becomes rows of two tables, events and mails. See [Data sources](sources.md) and
[Investigation packages](packages.md).

## What does REMN not do?

- It does not collect evidence: it installs nothing on the machines under investigation and
  acquires nothing remotely. It reads exports and collections made with other tools.
- It does not read disk images, memory images, network captures, or Linux and macOS logs. The
  Sigma converter skips rules for products other than Windows.
- It does not open or run attachments. They are analysed statically (structure, macros, PDF
  content, archives, YARA when installed), and their bytes are not kept.
- It does not contain, block or remediate anything on the machines under investigation.
- It does not encrypt the case stores, their backups or the browser database.
- The AI analyst changes nothing on its own: every change it proposes waits for the analyst's
  approval.
- It has not yet been exercised on real multi-gigabyte acquisitions; the large-case tests use
  generated evidence.

## How are findings measured?

Every event rule, REMN's own and those of the SigmaHQ packs, is run by `tools/measure_rules.py`
on five public sets of recorded attacks and on the logs of seven clean Windows machines, at
pinned versions. A rule that fires on a recording of what it looks for is shown as detecting;
the findings of a rule that never did are marked as leads, and a rule added or changed since it
was measured is shown as unmeasured or changed. In the committed measure, 1,020 of the 3,009
event rules measured fire on a recording of what they look for. A recording counts as detected
when a rule of its ATT&CK technique raises a finding anywhere in the file, so the counts say that
a rule fired, not that it found the attack's own events.

How often a rule fired on the clean machines sets, with the case's detection level, whether its
findings stand on their own or are folded per host; no level drops a finding. A weekly CI job
fails when a rule loses a detection or a high or critical rule gets noisier on a clean machine.
Mail rules and the mail risk score are calibrated on public mail corpora instead, and their
rates were measured on the corpora they were tuned on, so they are not held out. See
[Detection](detection.md#measured-rules), [Writing rules](rules.md#measuring-a-rule) and
[Validation](validation.md).

## What licences apply?

- REMN's own code: the Apache License 2.0 (`LICENSE`).
- An install from `backend/requirements.txt` contains packages under copyleft licences:
  `extract-msg` (GPL 3.0, read `.msg` mail) and the `dissect` packages (AGPL 3.0, in the separate
  worker process that reads registry hives, prefetch files and collections), among others.
- The default Docker image contains Hayabusa, under the AGPL 3.0. `docker build --build-arg
  HAYABUSA=0` leaves it out; an install from the repository does not contain it.
- The rule packs stay under their upstream licences: the SigmaHQ packs under the Detection Rule
  License 1.1, which asks that a match keeps the rule's author, and the Sublime pack under MIT.
- The bundled DFIQ questions are under the Apache License 2.0; the bundled Tranco list states no
  licence; the fonts are under the SIL Open Font License.
- The attack recordings and mail corpora used for the measures are downloaded by the tools and
  never committed; one of them, Phishing Pot, is for non-commercial use only.

[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) lists every package with its licence. The
Apache License covers REMN's own files, not an install or an image as a whole: read the copyleft
terms before passing one on.

## Where is a case kept, and how do I keep a copy?

The case itself (findings, notes, decisions, stories, AI sessions) is in the browser profile
that opened it, in IndexedDB. Its evidence rows are there too in a browser-store case, or in
`backend/data/cases/<id>/case.duckdb` on the server in a server-store case. Export a case
bundle from the case to keep a copy or move it to another browser; a browser short of space may
clear a site's storage unless it granted persistent storage, and the Dashboard says which
applies. See [Storage modes](storage.md).

## Can a team work on one server?

Yes, with accounts: each person has a token and a role (admin, analyst or viewer), each case an
owner and members, and changes are written to an audit log. Findings, notes and decisions stay
in each analyst's browser; members of a shared server-store case share its evidence rows, not
each other's findings. See [Architecture](architecture.md#accounts-and-roles) and
[Setup](setup.md#accounts-for-a-team).
