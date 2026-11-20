# Third-party notices

REMN's own code is licensed under the Apache License 2.0 (see `LICENSE`). What it ships, installs
or downloads also holds the work of others, under their own terms, listed here. Some of those
terms are copyleft: an install made from `backend/requirements.txt` contains packages under the
GNU GPL 3.0 and the GNU AGPL 3.0, and the default Docker image also contains Hayabusa, under the
GNU AGPL 3.0 ("Copyleft components" below). The Apache License covers REMN's own files, not an
install or an image as a whole: anyone passing one on should read those licences first.

## How this file is made

The package tables at the end, and the licence texts after them, are written by
`tools/third_party_notices.py` from the lock files an install or a build reads:
`backend/requirements.txt` and `backend/requirements-optional.txt` (written by
`tools/lock_requirements.sh`), `frontend/package-lock.json` and `frontend/wasm/evtx/Cargo.lock`.
A Python package's licence is the one its installed metadata declares, or, where the metadata is
vague ("BSD", "GPL"), the one its licence file states; npm licences are the ones the lock
records; crate licences are the ones cargo reports. The other sections are written by hand.

    python tools/third_party_notices.py --fetch --texts   # after npm ci in frontend/, with cargo installed
    python tools/third_party_notices.py --check

`tests/backend/test_third_party_notices.py` fails when a lock names a package these tables do
not, when an installed package declares another licence than the one given here, when a
copyleft package is missing from the next section, and when the Docker image's Hayabusa version
is not the one named below. Licences are given as each package declares them; the licence that
counts is the text the package itself distributes. The bill of materials of a release
(`tools/sbom.py`, see `docs/releasing.md`) lists the same packages with their versions.

## Copyleft components

| Component | Licence | Where | How REMN uses it |
| --- | --- | --- | --- |
| `extract-msg` | GPL-3.0-or-later | `backend/requirements.txt` | imported by the server process to read `.msg` mail (`backend/services/parsers/mail/msg.py`) |
| `rtfde` | LGPL-3.0-or-later | `backend/requirements.txt`, for extract-msg | imported by the server process to recover a `.msg` mail's HTML body from its RTF body |
| `pcodedmp` | GPL-3.0 | `backend/requirements.txt`, for oletools | installed, not run: oletools calls it to disassemble macro P-code only for a document it reads from disk, and REMN hands oletools the document in memory |
| `oletools`, its `thirdparty/xxxswf` folder | GPL-3.0 (the rest of oletools is BSD-2-Clause) | `backend/requirements.txt` | not imported by REMN |
| `dissect.target`, `dissect.regf`, `dissect.eventlog`, `dissect.evidence`, `dissect.hypervisor`, `dissect.ntfs`, `dissect.volume`, `flow.record` | AGPL-3.0-or-later | `backend/requirements.txt` | imported only by `backend/services/parsers/native_worker.py`, a separate process the server starts to read registry hives, prefetch files and collections laid out like a drive |
| `cabarchive` | LGPL-2.1-or-later | `backend/requirements.txt` | imported by the same worker process to expand `.cab` files |
| `certifi` | MPL-2.0 | `backend/requirements.txt`, for httpx and requests | its certificate bundle verifies outbound HTTPS connections |
| `libpff-python` | LGPL-3.0-or-later | `backend/requirements-optional.txt` | reads PST and OST mailboxes, when installed |
| `py7zr`, `pybcj`, `pyppmd`, `inflate64`, `multivolumefile` | LGPL-2.1-or-later | `backend/requirements-optional.txt` | read 7z archives, when installed |
| Hayabusa | AGPL-3.0 | the default Docker image | a separate program, run on EVTX files (next section) |

None of them is modified. The Python packages' sources are reachable from their pages on PyPI;
Hayabusa's is given in the next section. Nothing in the browser application is under the GPL,
the LGPL, the AGPL or the MPL alone: its npm packages and Rust crates are under permissive
licences or offer one (tables below), and its fonts are under the SIL Open Font License.

## Hayabusa, in the Docker image

The default build of the `Dockerfile` downloads Hayabusa 4.0.0 from its GitHub release (the
archive pinned by SHA-256) into `/opt/hayabusa`: the `hayabusa` program and its `rules` folder.
REMN runs it as a separate program on EVTX files and reads its output
(`backend/services/analysis/hayabusa.py`). Hayabusa is a Yamato Security project, licensed under
the GNU Affero General Public License 3.0. Its source for this version is at
https://github.com/Yamato-Security/hayabusa/tree/v4.0.0 and the licence text at
https://github.com/Yamato-Security/hayabusa/blob/v4.0.0/LICENSE.txt. The release archive the
image takes it from holds no licence file, so in the image this paragraph is what points to
both. The `rules` folder holds the Hayabusa project's own rules and the Sigma rules it
converted, under the Detection Rule License 1.1 (https://github.com/Yamato-Security/hayabusa-rules).

`docker build --build-arg HAYABUSA=0` builds the image without it. An install from the
repository or from the release archive does not contain Hayabusa: it runs there only when the
operator installs it, on the `PATH` or at `HAYABUSA_PATH`.

## Detection rule packs (`rules/community/`)

Converted by `tools/import_community_rules.py` from the upstream rules into REMN's rule
language: each pack file holds REMN's translation of the upstream rules, not a copy of them.
Each pack directory carries the upstream licence (`LICENSE`), a `pack.json` with the upstream
commit and the date it was taken, and a `skipped.json` with the rules that could not be
converted and why. Two translations are looser than the originals; `docs/detection.md` says
which. The packs stay under their upstream licences, not REMN's.

| Pack | Upstream | Licence | Changes |
| --- | --- | --- | --- |
| SigmaHQ Windows, emerging threats and threat hunting (`sigma-windows`, `sigma-emerging-threats`, `sigma-threat-hunting`) | https://github.com/SigmaHQ/sigma at `272daf82` | Detection Rule License 1.1 (DRL-1.1) | 2,824 of 2,861 rules converted. When a pack loads, the level of 119 rules is changed (110 raised from low to medium, 8 lowered from medium and 1 from high to low), each with its reason in `rules/community/levels.json` |
| Sublime Security (`sublime`) | https://github.com/sublime-security/sublime-rules at `b4fe3689` | MIT | 189 of 1,227 rules converted |

## Investigative questions (`frontend/src/data/questions/dfiq.gen.json`)

Scenarios, facets, questions and approaches of DFIQ, converted to JSON by
`tools/dfiq_import.py` with their ids and text unchanged, and bundled with the frontend. REMN's
own questions in the same file (ids starting with 0) are REMN's.

| Data | Upstream | Licence |
| --- | --- | --- |
| DFIQ (Digital Forensics Investigative Questions) 1.0.1, Copyright 2024 Google LLC | https://github.com/google/dfiq | Apache License 2.0 |

## Reference data in the repository

| Data | Where | Source | Terms |
| --- | --- | --- | --- |
| Tranco list V367N, the top 10,000 domains, fetched 2026-09-05 | `backend/services/reference/tranco_top10k.txt` (with `tranco.json`) on the server, and `frontend/src/reference/tranco10k.ts`, which is part of the browser application | https://tranco-list.eu; Le Pochat et al., "Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation", NDSS 2019 | The Tranco site states no licence for the list. The list is built from other providers' rankings, among them Cloudflare Radar (CC BY-NC 4.0, non-commercial) and the Chrome UX Report (CC BY-SA 4.0); whether their terms carry over to the list is not settled. |

## Samples written by real tools, in the test fixtures (`tests/fixtures/real/`)

Each folder's README names every file's source at a pinned commit, its SHA-256 and what was
trimmed. The files are unchanged unless that README says otherwise.

| Samples | Where | Source | Licence |
| --- | --- | --- | --- |
| Windows prefetch files, versions 17 to 31 | `tests/fixtures/real/prefetch/` | plaso test data, https://github.com/log2timeline/plaso | Apache-2.0 |
| Mail written by Outlook, Lotus Notes and GroupWise, and two mbox files | `tests/fixtures/real/mail/` | Apache Tika test data, https://github.com/apache/tika | Apache-2.0 |

## Fonts

| Font | Source | Licence |
| --- | --- | --- |
| Gulax (wordmark; embedded in printed reports) | `frontend/public/fonts/` | SIL Open Font License 1.1 (see `Gulax-LICENSE.txt` and `Gulax-COPYRIGHT.md` there) |
| Inter Variable | `@fontsource-variable/inter` | SIL Open Font License 1.1 |
| IBM Plex Sans (home page) | `@fontsource/ibm-plex-sans` | SIL Open Font License 1.1 |
| IBM Plex Mono (home page) | `@fontsource/ibm-plex-mono` | SIL Open Font License 1.1 |
| JetBrains Mono Variable | `@fontsource-variable/jetbrains-mono` | SIL Open Font License 1.1 |

## Data the operator downloads (not in the repository)

| Data | Source | Terms |
| --- | --- | --- |
| GeoLite2 databases | MaxMind | GeoLite2 End User License Agreement; requires a MaxMind account |
| Offline block lists (URLhaus, ThreatFox and others) | abuse.ch and others | Each list's own terms |

## Test corpora and attack recordings (downloaded for the tools, never committed)

The detection measures and the mail rates REMN publishes are taken on these, and the parser
tests marked heavy download theirs by URL and SHA-256 (`tests/backend/real_samples.py`). The
repository holds none of their files: only file names, hashes, counts and REMN's own results.

| Corpus | Used by | Source | Licence |
| --- | --- | --- | --- |
| SigmaHQ regression samples | `tools/measure_rules.py` | https://github.com/SigmaHQ/sigma | Detection Rule License 1.1 (the repository's licence) |
| EVTX-ATTACK-SAMPLES | `tools/measure_rules.py`, `tools/evtx_attack_samples.py`, CI | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES | GPL-3.0 |
| Splunk attack_data | `tools/measure_rules.py` | https://github.com/splunk/attack_data | Apache-2.0 |
| EVTX-to-MITRE-Attack | `tools/measure_rules.py` | https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack | CC0-1.0 |
| NextronSystems evtx-baseline | `tools/measure_rules.py` | https://github.com/NextronSystems/evtx-baseline | Apache-2.0 |
| OTRF Security-Datasets: MITRE's APT29 evaluation days 1 and 2, and the atomic Windows datasets | `tools/apt29_stories.py`, `tools/security_datasets.py` | https://github.com/OTRF/Security-Datasets | MIT |
| Nazario phishing corpus | `tools/validate_public.py` | https://monkey.org/~jose/phishing/ | CC BY 4.0, as `docs/validation.md` records it; not verified again for this file |
| Phishing Pot | `tools/validate_public.py` | https://github.com/rf-peixoto/phishing_pot | CC BY-NC 4.0: non-commercial use only. The phishing rates in `docs/validation.md` are measured partly on it |
| SpamAssassin public corpus | `tools/validate_public.py` | https://spamassassin.apache.org/old/publiccorpus/ | Not verified |
| Apache Tika test PST and test mail | `tools/validate_public.py`, `tests/backend/test_real_mail.py` (heavy tests) | https://github.com/apache/tika | Apache-2.0 (the repository's licence) |
| Invictus IR Microsoft 365 audit log dataset | `tools/validate_public.py` | https://github.com/invictus-ir/o365_dataset | CC BY 4.0 |
| Velociraptor test data and golden outputs | `tests/backend/test_real_*.py`, heavy tests | https://github.com/Velocidex/velociraptor | AGPL-3.0 (the repository's licence) |

## Base images of the Docker builds

| Image | Used for | Licence |
| --- | --- | --- |
| `python:3.13-slim` | the default image and its build stages, and the archive honeypot (`honeypot/Dockerfile`) | Python under the PSF License 2.0; Debian's packages under their own licences |
| `node:22-alpine` | the stage that builds the browser application; not part of an image REMN runs | Node.js under the MIT licence; Alpine's packages under their own licences |
| `caddy:2-alpine` | the static image of the public profile (`docker-compose.public.yml`), which serves the built application | Caddy under Apache-2.0; Alpine's packages under their own licences |

The static image holds the built application but not this file.

## Names and marks

REMN names other products and projects to say what it reads, what it runs and where its rules
come from. Microsoft, Windows, Microsoft 365 and Microsoft Entra are trademarks of the Microsoft
group of companies. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation;
technique identifiers and names are used under the ATT&CK terms of use
(https://attack.mitre.org/resources/terms-of-use/). The other product and project names in REMN
and its documentation (Sigma, Sublime, Hayabusa, Chainsaw, DFIQ, Tranco, Ollama, DuckDB and the
rest) belong to their owners. REMN is not affiliated with, endorsed by or
sponsored by any of them. REMN did not take part in MITRE's ATT&CK Evaluations: its APT29
results are its own scoring of the evaluation recordings that OTRF publishes.

## Where the licence texts are

- Python packages install their licence files with them, in
  `site-packages/<name>-<version>.dist-info/` (in the Docker image, under
  `/opt/venv/lib/python3.13/site-packages/`), pyarrow's `NOTICE.txt` among them. Of the
  packages of `backend/requirements.txt`, one does not: the `evtx` wheel installs no licence
  file. Its metadata declares MIT, and its source is pyevtx-rs
  (https://github.com/omerbenamram/pyevtx-rs).
- The npm packages and Rust crates of the browser application are compiled into the files of
  `frontend/dist`, which keep few of their notices. Their licence texts and copyright lines are
  in the last section of this file, which the repository, the release archive and the default
  Docker image carry. The application does not show them itself.

## Python packages (`backend/requirements.txt`)

Every package an install takes, on any platform. "Installed because of" is the lock's record
of what requires each package; "REMN" marks the ones REMN asks for itself. The development
tools of `backend/requirements-dev.txt` are not part of an install or of the image and are not
listed.

<!-- BEGIN generated: python -->
| Package | Licence | Installed because of |
| --- | --- | --- |
| `annotated-types` | MIT | pydantic |
| `anyio` | MIT | httpx |
| `asgiref` | BSD-3-Clause | django |
| `beautifulsoup4` | MIT | extract-msg |
| `cabarchive` | LGPL-2.1-or-later | REMN |
| `certifi` | MPL-2.0 | httpcore, httpx, requests |
| `cffi` | MIT-0 | cryptography |
| `charset-normalizer` | MIT | requests |
| `colorclass` | MIT | oletools |
| `compressed-rtf` | MIT | extract-msg |
| `confusable-homoglyphs` | MIT | REMN |
| `cryptography` | Apache-2.0 OR BSD-3-Clause | msoffcrypto-tool |
| `defusedxml` | PSF-2.0 | REMN, dissect-hypervisor, dissect-target |
| `dissect-cstruct` | Apache-2.0 | dissect-database, dissect-eventlog, dissect-evidence, dissect-hypervisor, dissect-ntfs, dissect-regf, dissect-target, dissect-volume |
| `dissect-database` | Apache-2.0 | dissect-target |
| `dissect-eventlog` | AGPL-3.0-or-later | dissect-target |
| `dissect-evidence` | AGPL-3.0-or-later | dissect-target |
| `dissect-hypervisor` | AGPL-3.0-or-later | dissect-target |
| `dissect-ntfs` | AGPL-3.0-or-later | dissect-target |
| `dissect-regf` | AGPL-3.0-or-later | REMN, dissect-target |
| `dissect-target` | AGPL-3.0-or-later | REMN |
| `dissect-util` | Apache-2.0 | dissect-database, dissect-eventlog, dissect-evidence, dissect-hypervisor, dissect-ntfs, dissect-regf, dissect-target, dissect-volume |
| `dissect-volume` | AGPL-3.0-or-later | dissect-target |
| `django` | BSD-3-Clause | REMN |
| `dnspython` | ISC | REMN |
| `duckdb` | MIT | REMN |
| `easygui` | BSD-3-Clause | oletools |
| `ebcdic` | BSD-2-Clause | extract-msg |
| `evtx` | MIT | REMN |
| `extract-msg` | GPL-3.0-or-later | REMN |
| `filelock` | MIT | tldextract |
| `flow-record` | AGPL-3.0-or-later | dissect-target |
| `h11` | MIT | httpcore |
| `httpcore` | BSD-3-Clause | httpx |
| `httpx` | BSD-3-Clause | REMN, ollama |
| `idna` | BSD-3-Clause | REMN, anyio, httpx, requests, tldextract |
| `lark` | MIT | rtfde |
| `msgpack` | Apache-2.0 | flow-record |
| `msoffcrypto-tool` | MIT | oletools |
| `olefile` | BSD-2-Clause | extract-msg, msoffcrypto-tool, oletools |
| `oletools` | BSD-2-Clause | REMN, pcodedmp, rtfde |
| `ollama` | MIT | REMN |
| `pcodedmp` | GPL-3.0 | oletools |
| `psutil` | BSD-3-Clause | REMN |
| `puremagic` | MIT | REMN |
| `pyarrow` | Apache-2.0 | REMN |
| `pycparser` | BSD-3-Clause | cffi |
| `pydantic` | MIT | ollama |
| `pydantic-core` | MIT | pydantic |
| `pyparsing` | MIT | oletools |
| `pypdf` | BSD-3-Clause | REMN |
| `python-dotenv` | BSD-3-Clause | REMN |
| `pyyaml` | MIT | REMN |
| `red-black-tree-mod` | MIT | extract-msg |
| `requests` | Apache-2.0 | requests-file, tldextract |
| `requests-file` | Apache-2.0 | tldextract |
| `rtfde` | LGPL-3.0-or-later | extract-msg |
| `soupsieve` | MIT | beautifulsoup4 |
| `sqlparse` | BSD-3-Clause | django |
| `structlog` | MIT OR Apache-2.0 | dissect-target |
| `tldextract` | BSD-3-Clause | REMN |
| `typing-extensions` | PSF-2.0 | anyio, beautifulsoup4, pydantic, pydantic-core, typing-inspection |
| `typing-inspection` | MIT | pydantic |
| `tzdata` | Apache-2.0 | django, flow-record, tzlocal; Windows only |
| `tzlocal` | MIT | extract-msg |
| `urllib3` | MIT | requests |
| `waitress` | ZPL-2.1 | REMN |
| `win-unicode-console` | MIT | pcodedmp; Windows only |
<!-- END generated: python -->

## Optional Python packages (`backend/requirements-optional.txt`)

What the optional parsers add to the set above. They are installed only on request
(`docs/setup.md`), and in the Docker image only when it is built with `EXTRA_PIP`.

<!-- BEGIN generated: python-optional -->
| Package | Licence | Installed because of |
| --- | --- | --- |
| `backports-zstd` | PSF-2.0 | py7zr |
| `brotli` | MIT | py7zr |
| `brotlicffi` | MIT | py7zr; PyPy only |
| `inflate64` | LGPL-2.1-or-later | py7zr |
| `libpff-python` | LGPL-3.0-or-later | REMN |
| `multivolumefile` | LGPL-2.1-or-later | py7zr |
| `py7zr` | LGPL-2.1-or-later | REMN |
| `pybcj` | LGPL-2.1-or-later | py7zr |
| `pycryptodomex` | BSD-2-Clause AND public domain | py7zr |
| `pyppmd` | LGPL-2.1-or-later | py7zr |
| `texttable` | MIT | py7zr |
| `yara-python` | Apache-2.0 | REMN |
<!-- END generated: python-optional -->

## npm packages of the browser application (`frontend/package-lock.json`)

The lock's packages other than development ones. The build tools, type checkers, linters and
test libraries are not part of the built application and are not listed.

<!-- BEGIN generated: npm -->
| Package | Licence | Required by |
| --- | --- | --- |
| `@fontsource-variable/inter` | OFL-1.1 | REMN |
| `@fontsource-variable/jetbrains-mono` | OFL-1.1 | REMN |
| `@fontsource/ibm-plex-mono` | OFL-1.1 | REMN |
| `@fontsource/ibm-plex-sans` | OFL-1.1 | REMN |
| `@tanstack/react-virtual` | MIT | REMN |
| `@tanstack/virtual-core` | MIT | @tanstack/react-virtual |
| `@types/react` | MIT | zustand |
| `@types/trusted-types` | MIT | dompurify |
| `argparse` | Python-2.0 | js-yaml |
| `csstype` | MIT | @types/react |
| `dexie` | Apache-2.0 | REMN |
| `dompurify` | (MPL-2.0 OR Apache-2.0) | REMN |
| `echarts` | Apache-2.0 | REMN |
| `hash-wasm` | MIT | REMN |
| `js-yaml` | MIT | REMN |
| `react` | MIT | REMN, @tanstack/react-virtual, react-dom, zustand |
| `react-dom` | MIT | REMN, @tanstack/react-virtual |
| `scheduler` | MIT | react-dom |
| `tslib` | 0BSD | echarts, zrender |
| `zrender` | BSD-3-Clause | echarts |
| `zustand` | MIT | REMN |
<!-- END generated: npm -->

## Rust crates of the EVTX decoder (`frontend/wasm/evtx/Cargo.lock`)

The decoder is compiled to `frontend/src/parsers/evtx/evtx.wasm`, which the browser application
loads. The lock lists every crate the decoder could need on any platform, build tools included;
fewer are compiled into the WebAssembly file (`cargo tree --target wasm32-unknown-unknown -e
normal`, run in `frontend/wasm/evtx`, lists them).

<!-- BEGIN generated: crates -->
| Crate | Licence | Required by |
| --- | --- | --- |
| `ahash` | MIT OR Apache-2.0 | evtx, sonic-rs |
| `autocfg` | Apache-2.0 OR MIT | num-traits |
| `bitflags` | MIT OR Apache-2.0 / MIT/Apache-2.0 | defmt, evtx, pulldown-cmark, rustix, winstructs |
| `bumpalo` | MIT OR Apache-2.0 | evtx, sonic-rs, wasm-bindgen-macro-support |
| `bytecount` | Apache-2.0/MIT | skeptic |
| `byteorder` | Unlicense OR MIT | evtx, winstructs |
| `bytes` | MIT | faststr, rkyv, sonic-rs |
| `camino` | MIT OR Apache-2.0 | cargo_metadata |
| `cargo-platform` | MIT OR Apache-2.0 | cargo_metadata |
| `cargo_metadata` | MIT | skeptic |
| `cfg-if` | MIT OR Apache-2.0 | ahash, crc32fast, getrandom, js-sys, sonic-number, sonic-rs, sonic-simd, wasm-bindgen |
| `chrono` | MIT OR Apache-2.0 | winstructs |
| `crc32fast` | MIT OR Apache-2.0 | evtx |
| `defmt` | MIT OR Apache-2.0 | jiff, jiff-core |
| `defmt-macros` | MIT OR Apache-2.0 | defmt |
| `defmt-parser` | MIT OR Apache-2.0 | defmt-macros |
| `encoding` | MIT | evtx |
| `encoding-index-japanese` | CC0-1.0 | encoding |
| `encoding-index-korean` | CC0-1.0 | encoding |
| `encoding-index-simpchinese` | CC0-1.0 | encoding |
| `encoding-index-singlebyte` | CC0-1.0 | encoding |
| `encoding-index-tradchinese` | CC0-1.0 | encoding |
| `encoding_index_tests` | CC0-1.0 | encoding-index-japanese, encoding-index-korean, encoding-index-simpchinese, encoding-index-singlebyte, encoding-index-tradchinese |
| `equivalent` | Apache-2.0 OR MIT | indexmap |
| `errno` | MIT OR Apache-2.0 | rustix |
| `error-chain` | MIT/Apache-2.0 | skeptic |
| `evtx` | MIT/Apache-2.0 | the decoder |
| `fastrand` | Apache-2.0 OR MIT | tempfile |
| `faststr` | MIT OR Apache-2.0 | sonic-rs |
| `futures-core` | MIT OR Apache-2.0 | futures-util |
| `futures-task` | MIT OR Apache-2.0 | futures-util |
| `futures-util` | MIT OR Apache-2.0 | js-sys |
| `getrandom` | MIT OR Apache-2.0 | the decoder, ahash, tempfile |
| `glob` | MIT OR Apache-2.0 | skeptic |
| `hashbrown` | MIT OR Apache-2.0 | indexmap, rkyv |
| `indexmap` | Apache-2.0 OR MIT | rkyv, serde_json |
| `itoa` | MIT OR Apache-2.0 | serde_json, sonic-rs |
| `jiff` | Unlicense OR MIT | evtx |
| `jiff-core` | Unlicense OR MIT | jiff, jiff-static |
| `jiff-static` | Unlicense OR MIT | jiff |
| `jiff-tzdb` | Unlicense OR MIT | jiff-tzdb-platform |
| `jiff-tzdb-platform` | Unlicense OR MIT | jiff |
| `js-sys` | MIT OR Apache-2.0 | uuid |
| `libc` | MIT OR Apache-2.0 | errno, getrandom, rustix |
| `linux-raw-sys` | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | rustix |
| `log` | MIT OR Apache-2.0 | evtx, jiff, jiff-core, winstructs |
| `memchr` | Unlicense OR MIT | pulldown-cmark, serde_json |
| `munge` | MIT | rkyv |
| `munge_macro` | MIT | munge |
| `num-derive` | MIT OR Apache-2.0 | winstructs |
| `num-traits` | MIT OR Apache-2.0 | chrono, winstructs |
| `once_cell` | MIT OR Apache-2.0 | ahash, tempfile, wasm-bindgen |
| `pin-project-lite` | Apache-2.0 OR MIT | futures-util |
| `portable-atomic` | Apache-2.0 OR MIT | jiff, portable-atomic-util |
| `portable-atomic-util` | Apache-2.0 OR MIT | jiff |
| `proc-macro2` | MIT OR Apache-2.0 | defmt-macros, jiff-static, munge_macro, num-derive, ptr_meta_derive, quote, ref-cast-impl, rkyv_derive, serde_derive, syn, thiserror-impl, wasm-bindgen-macro-support, zerocopy-derive |
| `ptr_meta` | MIT | rancor, rkyv |
| `ptr_meta_derive` | MIT | ptr_meta |
| `pulldown-cmark` | MIT | skeptic |
| `quote` | MIT OR Apache-2.0 | defmt-macros, jiff-static, munge_macro, num-derive, ptr_meta_derive, ref-cast-impl, rkyv_derive, serde_derive, syn, thiserror-impl, wasm-bindgen-macro, wasm-bindgen-macro-support, zerocopy-derive |
| `r-efi` | MIT OR Apache-2.0 OR LGPL-2.1-or-later | getrandom |
| `rancor` | MIT | rkyv |
| `ref-cast` | MIT OR Apache-2.0 | sonic-rs |
| `ref-cast-impl` | MIT OR Apache-2.0 | ref-cast |
| `rend` | MIT | rkyv |
| `rkyv` | MIT | faststr |
| `rkyv_derive` | MIT | rkyv |
| `rustix` | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | tempfile |
| `rustversion` | MIT OR Apache-2.0 | wasm-bindgen |
| `same-file` | Unlicense/MIT | walkdir |
| `semver` | MIT OR Apache-2.0 | cargo_metadata |
| `serde` | MIT OR Apache-2.0 | cargo-platform, cargo_metadata, chrono, evtx, faststr, semver, serde_json, sonic-rs, winstructs |
| `serde_core` | MIT OR Apache-2.0 | camino, jiff, semver, serde, serde_json |
| `serde_derive` | MIT OR Apache-2.0 | serde, serde_core |
| `serde_json` | MIT OR Apache-2.0 | the decoder, cargo_metadata, evtx, winstructs |
| `simdutf8` | MIT OR Apache-2.0 | faststr, sonic-rs |
| `skeptic` | MIT/Apache-2.0 | evtx |
| `slab` | MIT | futures-util |
| `sonic-number` | Apache-2.0 | sonic-rs |
| `sonic-rs` | Apache-2.0 | evtx, utf16-simd |
| `sonic-simd` | Apache-2.0 | sonic-rs |
| `syn` | MIT OR Apache-2.0 | defmt-macros, jiff-static, munge_macro, num-derive, ptr_meta_derive, ref-cast-impl, rkyv_derive, serde_derive, thiserror-impl, wasm-bindgen-macro-support, zerocopy-derive |
| `tempfile` | MIT OR Apache-2.0 | skeptic |
| `thiserror` | MIT OR Apache-2.0 | defmt-parser, evtx, sonic-rs, winstructs |
| `thiserror-impl` | MIT OR Apache-2.0 | thiserror |
| `tinyvec` | Zlib OR Apache-2.0 OR MIT | rkyv |
| `unicase` | MIT OR Apache-2.0 | pulldown-cmark |
| `unicode-ident` | (MIT OR Apache-2.0) AND Unicode-3.0 | proc-macro2, syn, wasm-bindgen-shared |
| `utf16-simd` | MIT OR Apache-2.0 | evtx |
| `uuid` | Apache-2.0 OR MIT | rkyv |
| `version_check` | MIT/Apache-2.0 | ahash, error-chain |
| `walkdir` | Unlicense/MIT | skeptic |
| `wasip2` | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | getrandom |
| `wasm-bindgen` | MIT OR Apache-2.0 | js-sys, uuid |
| `wasm-bindgen-macro` | MIT OR Apache-2.0 | wasm-bindgen |
| `wasm-bindgen-macro-support` | MIT OR Apache-2.0 | wasm-bindgen-macro |
| `wasm-bindgen-shared` | MIT OR Apache-2.0 | wasm-bindgen, wasm-bindgen-macro-support |
| `winapi-util` | Unlicense OR MIT | same-file, walkdir |
| `windows-link` | MIT OR Apache-2.0 | jiff, windows-sys |
| `windows-sys` | MIT OR Apache-2.0 | errno, rustix, tempfile, winapi-util |
| `winstructs` | MIT/Apache-2.0 | evtx |
| `wit-bindgen` | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | wasip2 |
| `zerocopy` | BSD-2-Clause OR Apache-2.0 OR MIT | ahash |
| `zerocopy-derive` | BSD-2-Clause OR Apache-2.0 OR MIT | zerocopy |
| `zmij` | MIT | evtx, serde_json, sonic-rs |
<!-- END generated: crates -->

## Licence texts of the browser application

<!-- BEGIN generated: texts -->
Each licence text below is given once, after the copyright lines of the packages that carry it, as
their licence files state them. Where a package offers a choice of licences, the text given is the one
REMN takes (MIT before Apache-2.0, then the others). Where a file holds the terms of the Apache License
2.0 word for word, they are not repeated: they are the terms in `LICENSE` at the root of this
repository, and only what the file adds to them is given. NOTICE files, which the Apache License asks
to be passed on, follow whole.

### 0BSD, text 1

- npm `tslib`: Copyright (c) Microsoft Corporation.

```text
Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
```

### Apache-2.0, text 1

- crate `sonic-number`: Copyright 2022 ByteDance Inc.
- crate `sonic-rs`: Copyright 2018-2019 The simdjson authors; Copyright 2022 ByteDance Inc.
- npm `dexie`, npm `dompurify`, crate `sonic-simd`, crate `winstructs`: no copyright line at the top of the licence file

```text
[The terms of the Apache License 2.0, as in LICENSE at the root of this repository.]
```

### Apache-2.0, text 2

- npm `echarts`: no copyright line at the top of the licence file

```text
[The terms of the Apache License 2.0, as in LICENSE at the root of this repository.]

========================================================================
Apache ECharts Subcomponents:

The Apache ECharts project contains subcomponents with separate copyright
notices and license terms. Your use of the source code for these
subcomponents is also subject to the terms and conditions of the following
licenses.

BSD 3-Clause (d3.js):
The following files embed [d3.js](https://github.com/d3/d3) BSD 3-Clause:
    `/src/chart/treemap/treemapLayout.ts`,
    `/src/chart/tree/layoutHelper.ts`,
    `/src/chart/graph/forceHelper.ts`,
    `/src/util/number.ts`
See `/licenses/LICENSE-d3` for details of the license.
```

### Apache-2.0, text 3

- npm `echarts`: Copyright 2010-2016 Mike Bostock

```text
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the author nor the names of contributors may be used to
  endorse or promote products derived from this software without specific prior
  written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### BSD-3-Clause, text 1

- npm `zrender`: Copyright (c) 2017, Baidu Inc.

```text
BSD 3-Clause License

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### MIT, text 1

- crate `ahash`: Copyright (c) 2018 Tom Kaitchuck
- crate `autocfg`: Copyright (c) 2018 Josh Stone
- crate `bitflags`, crate `glob`, crate `log`, crate `num-derive`, crate `num-traits`: Copyright (c) 2014 The Rust Project Developers
- crate `bumpalo`: Copyright (c) 2019 Nick Fitzgerald
- crate `bytecount`: Copyright (c) 2017 The bytecount Developers
- crate `bytes`: Copyright (c) 2018 Carl Lerche
- crate `camino`, crate `cargo-platform`, crate `cargo_metadata`, crate `fastrand`, crate `itoa`, crate `linux-raw-sys`, crate `once_cell`, crate `pin-project-lite`, crate `portable-atomic`, crate `portable-atomic-util`, crate `proc-macro2`, crate `quote`, crate `ref-cast`, crate `ref-cast-impl`, crate `rustix`, crate `rustversion`, crate `semver`, crate `serde`, crate `serde_core`, crate `serde_derive`, crate `serde_json`, crate `skeptic`, crate `sonic-rs`, crate `syn`, crate `thiserror`, crate `thiserror-impl`, crate `tinyvec`, crate `unicode-ident`, crate `wasip2`, crate `wit-bindgen`, crate `zmij`: no copyright line at the top of the licence file
- crate `cfg-if`, crate `js-sys`, crate `wasm-bindgen`, crate `wasm-bindgen-macro`, crate `wasm-bindgen-macro-support`, crate `wasm-bindgen-shared`: Copyright (c) 2014 Alex Crichton
- crate `defmt`, crate `defmt-macros`: Copyright (c) Ferrous Systems
- crate `equivalent`: Copyright (c) 2016--2023
- crate `errno`: Copyright (c) 2014 Chris Wong
- crate `error-chain`: Copyright (c) 2017 The Error-Chain Project Developers
- crate `faststr`: Copyright (c) 2022 Volo Contributors
- crate `futures-core`, crate `futures-task`, crate `futures-util`: Copyright (c) 2016 Alex Crichton; Copyright (c) 2017 The Tokio Authors
- crate `getrandom`: Copyright (c) 2018-2025 The rust-random Project Developers; Copyright (c) 2014 The Rust Project Developers; Copyright (c) 2018-2026 The rust-random Project Developers
- crate `hashbrown`: Copyright (c) 2016 Amanieu d'Antras
- crate `indexmap`: Copyright (c) 2016--2017
- crate `libc`: Copyright (c) The Rust Project Developers
- crate `munge`, crate `munge_macro`: Copyright 2024 David Koloski
- crate `ptr_meta`, crate `ptr_meta_derive`, crate `rend`, crate `rkyv`, crate `rkyv_derive`: Copyright 2021 David Koloski
- crate `rancor`: Copyright 2023 David Koloski
- crate `slab`: Copyright (c) 2019 Carl Lerche
- crate `tempfile`: Copyright (c) 2015 Steven Allen
- crate `unicase`: Copyright (c) 2014-2026 Sean McArthur
- crate `uuid`: Copyright (c) 2014 The Rust Project Developers; Copyright (c) 2018 Ashley Mannix, Christopher Armstrong, Dylan DPC, Hunar Roop Kahlon
- crate `zerocopy`, crate `zerocopy-derive`: Copyright 2023 The Fuchsia Authors
- npm `csstype`: Copyright (c) 2017-2018 Fredrik Nicol

```text
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### MIT, text 2

- crate `byteorder`, crate `jiff`, crate `jiff-core`, crate `jiff-static`, crate `jiff-tzdb`, crate `jiff-tzdb-platform`, crate `memchr`, crate `same-file`, crate `walkdir`, crate `winapi-util`: no copyright line at the top of the licence file

```text
This project is dual-licensed under the Unlicense and MIT licenses.

You may use this code under the terms of either license.
```

### MIT, text 3

- crate `byteorder`, crate `jiff`, crate `jiff-core`, crate `jiff-static`, crate `jiff-tzdb`, crate `jiff-tzdb-platform`, crate `memchr`, crate `walkdir`: Copyright (c) 2015 Andrew Gallant
- crate `encoding`: Copyright (c) 2013, Kang Seonghoon.
- crate `evtx`: Copyright (c) 2019 Omer Ben-Amram
- crate `same-file`, crate `winapi-util`: Copyright (c) 2017 Andrew Gallant
- crate `version_check`: Copyright (c) 2017-2018 Sergio Benitez

```text
The MIT License (MIT)


Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

### MIT, text 4

- crate `chrono`: no copyright line at the top of the licence file

```text
[The terms of the Apache License 2.0, as in LICENSE at the root of this repository.]

Rust-chrono is dual-licensed under The MIT License [1] and
Apache 2.0 License [2]. Copyright (c) 2014--2026, Kang Seonghoon and
contributors.

Nota Bene: This is same as the Rust Project's own license.


[1]: <http://opensource.org/licenses/MIT>, which is reproduced below:

~~~~
The MIT License (MIT)

Copyright (c) 2014, Kang Seonghoon.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
~~~~


[2]: <http://www.apache.org/licenses/LICENSE-2.0>, which is reproduced below:

~~~~
~~~~
```

### MIT, text 5

- crate `crc32fast`: Copyright (c) 2018 Sam Rijs, Alex Crichton and contributors
- crate `simdutf8`: no copyright line at the top of the licence file
- crate `sonic-number`, crate `sonic-rs`: Copyright (c) 2020 YaoYuan <ibireme@gmail.com>
- npm `@tanstack/react-virtual`, npm `@tanstack/virtual-core`: Copyright (c) 2021-present Tanner Linsley
- npm `react`, npm `react-dom`, npm `scheduler`: Copyright (c) Meta Platforms, Inc. and affiliates.
- npm `zustand`: Copyright (c) 2019 Paul Henschel

```text
MIT License


Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### MIT, text 6

- crate `linux-raw-sys`: no copyright line at the top of the licence file

```text
Short version for non-lawyers:

`linux-raw-sys` is triple-licensed under Apache 2.0 with the LLVM Exception,
Apache 2.0, and MIT terms.


Longer version:

Copyrights in the `linux-raw-sys` project are retained by their contributors.
No copyright assignment is required to contribute to the `linux-raw-sys`
project.

Some files include code derived from Rust's `libstd`; see the comments in
the code for details.

Except as otherwise noted (below and/or in individual files), `linux-raw-sys`
is licensed under:

 - the Apache License, Version 2.0, with the LLVM Exception
   <LICENSE-Apache-2.0_WITH_LLVM-exception> or
   <http://llvm.org/foundation/relicensing/LICENSE.txt>
 - the Apache License, Version 2.0
   <LICENSE-APACHE> or
   <http://www.apache.org/licenses/LICENSE-2.0>,
 - or the MIT license
   <LICENSE-MIT> or
   <http://opensource.org/licenses/MIT>,

at your option.
```

### MIT, text 7

- crate `pulldown-cmark`: Copyright 2015 Google Inc. All rights reserved.

```text
The MIT License


Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

### MIT, text 8

- crate `rustix`: no copyright line at the top of the licence file

```text
Short version for non-lawyers:

`rustix` is triple-licensed under Apache 2.0 with the LLVM Exception,
Apache 2.0, and MIT terms.


Longer version:

Copyrights in the `rustix` project are retained by their contributors.
No copyright assignment is required to contribute to the `rustix`
project.

Some files include code derived from Rust's `libstd`; see the comments in
the code for details.

Except as otherwise noted (below and/or in individual files), `rustix`
is licensed under:

 - the Apache License, Version 2.0, with the LLVM Exception
   <LICENSE-Apache-2.0_WITH_LLVM-exception> or
   <http://llvm.org/foundation/relicensing/LICENSE.txt>
 - the Apache License, Version 2.0
   <LICENSE-APACHE> or
   <http://www.apache.org/licenses/LICENSE-2.0>,
 - or the MIT license
   <LICENSE-MIT> or
   <http://opensource.org/licenses/MIT>,

at your option.
```

### MIT, text 9

- crate `unicode-ident`: Copyright © 1991-2023 Unicode, Inc.

```text
UNICODE LICENSE V3

COPYRIGHT AND PERMISSION NOTICE


NOTICE TO USER: Carefully read the following legal agreement. BY
DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR
SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE
TERMS AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT
DOWNLOAD, INSTALL, COPY, DISTRIBUTE OR USE THE DATA FILES OR SOFTWARE.

Permission is hereby granted, free of charge, to any person obtaining a
copy of data files and any associated documentation (the "Data Files") or
software and any associated documentation (the "Software") to deal in the
Data Files or Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, and/or sell
copies of the Data Files or Software, and to permit persons to whom the
Data Files or Software are furnished to do so, provided that either (a)
this copyright and permission notice appear with all copies of the Data
Files or Software, or (b) this copyright and permission notice appear in
associated Documentation.

THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
THIRD PARTY RIGHTS.

IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA
FILES OR SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall
not be used in advertising or otherwise to promote the sale, use or other
dealings in these Data Files or Software without prior written
authorization of the copyright holder.
```

### MIT, text 10

- npm `@types/react`, npm `@types/trusted-types`, crate `windows-link`, crate `windows-sys`: Copyright (c) Microsoft Corporation.

```text
    MIT License


    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
```

### MIT, text 11

- npm `hash-wasm`: Copyright (c) 2020 Dani Biró

```text
MIT License


Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Embedded C implementations might use other, similarly permissive licenses.
Check the beginning of the files from the /src directory.

Special thank you to the authors of original C algorithms:
- Alexander Peslyak <solar@openwall.com>
- Aleksey Kravchenko <rhash.admin@gmail.com>
- Colin Percival
- Stephan Brumme <create@stephan-brumme.com>
- Steve Reid <steve@edmweb.com>
- Samuel Neves <sneves@dei.uc.pt>
- Solar Designer <solar@openwall.com>
- Project Nayuki
- ARM Limited
- Yanbo Li dreamfly281@gmail.com, goldboar@163.comYanbo Li
- Mark Adler
- Yann Collet
```

### MIT, text 12

- npm `js-yaml`: Copyright (C) 2011-2015 by Vitaly Puzrin

```text
(The MIT License)


Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

### OFL-1.1, text 1

- npm `@fontsource-variable/inter`: Copyright 2016 The Inter Project Authors (https://github.com/rsms/inter) Inter-Italic[opsz,wght].ttf: Copyright 2016 The Inter Project Authors (https://github.com/rsms/inter)
- npm `@fontsource-variable/jetbrains-mono`: Copyright 2020 The JetBrains Mono Project Authors (https://github.com/JetBrains/JetBrainsMono) JetBrainsMono-Italic[wght].ttf: Copyright 2020 The JetBrains Mono Project Authors (https://github.com/JetBrains/JetBrainsMono)
- npm `@fontsource/ibm-plex-mono`: Copyright 2017 IBM Corp. All rights reserved. IBMPlexMono-ThinItalic.ttf: Copyright 2017 IBM Corp. All rights reserved. IBMPlexMono-ExtraLight.ttf: Copyright 2017 IBM Corp. All rights reserved. IBMPlexMono-ExtraLightItalic.ttf: Copyright 2017 IBM Corp. All rights reserved. IBMPlexMono-Light.ttf: Copyright 2017 IBM Corp. All rights reserved. IBMPlexMono-LightItalic.ttf: Copyright 2017 IBM Corp. All rights reserved. IBMPlexMono-Regular.ttf: Copyright 2017 IBM Corp. All rights reserved. IBMPlexMono-Italic.ttf: Copyright 2017 IBM Corp. All rights reserved. IBMPlexMono-Medium.ttf: Copyright 2017 IBM Corp. All rights reserved. IBMPlexMono-MediumItalic.ttf: Copyright 2017 IBM Corp. All rights reserved. IBMPlexMono-SemiBold.ttf: Copyright 2017 IBM Corp. All rights reserved. IBMPlexMono-SemiBoldItalic.ttf: Copyright 2017 IBM Corp. All rights reserved. IBMPlexMono-Bold.ttf: Copyright 2017 IBM Corp. All rights reserved. IBMPlexMono-BoldItalic.ttf: Copyright 2017 IBM Corp. All rights reserved.
- npm `@fontsource/ibm-plex-sans`: Copyright 2019 IBM Corp. All rights reserved. IBMPlexSans-Italic[wdth,wght].ttf: Copyright 2019 IBM Corp. All rights reserved.

```text
This Font Software is licensed under the SIL Open Font License, Version 1.1.
This license is copied below, and is also available with a FAQ at:
http://scripts.sil.org/OFL


-----------------------------------------------------------
SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007
-----------------------------------------------------------

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide
development of collaborative font projects, to support the font creation
efforts of academic and linguistic communities, and to provide a free and
open framework in which fonts may be shared and improved in partnership
with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves. The
fonts, including any derivative works, can be bundled, embedded,
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works. The fonts and derivatives,
however, cannot be released under any other type of license. The
requirement for fonts to remain under this license does not apply
to any document created using the fonts or their derivatives.

DEFINITIONS
"Font Software" refers to the set of files released by the Copyright
Holder(s) under this license and clearly marked as such. This may
include source files, build scripts and documentation.

"Reserved Font Name" refers to any names specified as such after the
copyright statement(s).

"Original Version" refers to the collection of Font Software components as
distributed by the Copyright Holder(s).

"Modified Version" refers to any derivative made by adding to, deleting,
or substituting -- in part or in whole -- any of the components of the
Original Version, by changing formats or by porting the Font Software to a
new environment.

"Author" refers to any designer, engineer, programmer, technical
writer or other person who contributed to the Font Software.

PERMISSION & CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining
a copy of the Font Software, to use, study, copy, merge, embed, modify,
redistribute, and sell modified and unmodified copies of the Font
Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components,
in Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
redistributed and/or sold with any software, provided that each copy
contains the above copyright notice and this license. These can be
included either as stand-alone text files, human-readable headers or
in the appropriate machine-readable metadata fields within text or
binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
Name(s) unless explicit written permission is granted by the corresponding
Copyright Holder. This restriction only applies to the primary font name as
presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
Software shall not be used to promote, endorse or advertise any
Modified Version, except to acknowledge the contribution(s) of the
Copyright Holder(s) and the Author(s) or with their explicit written
permission.

5) The Font Software, modified or unmodified, in part or in whole,
must be distributed entirely under this license, and must not be
distributed under any other license. The requirement for fonts to
remain under this license does not apply to any document created
using the Font Software.

TERMINATION
This license becomes null and void if any of the above conditions are
not met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM
OTHER DEALINGS IN THE FONT SOFTWARE.
```

### Python-2.0, text 1

- npm `argparse`: no copyright line at the top of the licence file

```text
A. HISTORY OF THE SOFTWARE
==========================

Python was created in the early 1990s by Guido van Rossum at Stichting
Mathematisch Centrum (CWI, see http://www.cwi.nl) in the Netherlands
as a successor of a language called ABC.  Guido remains Python's
principal author, although it includes many contributions from others.

In 1995, Guido continued his work on Python at the Corporation for
National Research Initiatives (CNRI, see http://www.cnri.reston.va.us)
in Reston, Virginia where he released several versions of the
software.

In May 2000, Guido and the Python core development team moved to
BeOpen.com to form the BeOpen PythonLabs team.  In October of the same
year, the PythonLabs team moved to Digital Creations, which became
Zope Corporation.  In 2001, the Python Software Foundation (PSF, see
https://www.python.org/psf/) was formed, a non-profit organization
created specifically to own Python-related Intellectual Property.
Zope Corporation was a sponsoring member of the PSF.

All Python releases are Open Source (see http://www.opensource.org for
the Open Source Definition).  Historically, most, but not all, Python
releases have also been GPL-compatible; the table below summarizes
the various releases.

    Release         Derived     Year        Owner       GPL-
                    from                                compatible? (1)

    0.9.0 thru 1.2              1991-1995   CWI         yes
    1.3 thru 1.5.2  1.2         1995-1999   CNRI        yes
    1.6             1.5.2       2000        CNRI        no
    2.0             1.6         2000        BeOpen.com  no
    1.6.1           1.6         2001        CNRI        yes (2)
    2.1             2.0+1.6.1   2001        PSF         no
    2.0.1           2.0+1.6.1   2001        PSF         yes
    2.1.1           2.1+2.0.1   2001        PSF         yes
    2.1.2           2.1.1       2002        PSF         yes
    2.1.3           2.1.2       2002        PSF         yes
    2.2 and above   2.1.1       2001-now    PSF         yes

Footnotes:

(1) GPL-compatible doesn't mean that we're distributing Python under
    the GPL.  All Python licenses, unlike the GPL, let you distribute
    a modified version without making your changes open source.  The
    GPL-compatible licenses make it possible to combine Python with
    other software that is released under the GPL; the others don't.

(2) According to Richard Stallman, 1.6.1 is not GPL-compatible,
    because its license has a choice of law clause.  According to
    CNRI, however, Stallman's lawyer has told CNRI's lawyer that 1.6.1
    is "not incompatible" with the GPL.

Thanks to the many outside volunteers who have worked under Guido's
direction to make these releases possible.


B. TERMS AND CONDITIONS FOR ACCESSING OR OTHERWISE USING PYTHON
===============================================================

PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2
--------------------------------------------

1. This LICENSE AGREEMENT is between the Python Software Foundation
("PSF"), and the Individual or Organization ("Licensee") accessing and
otherwise using this software ("Python") in source or binary form and
its associated documentation.

2. Subject to the terms and conditions of this License Agreement, PSF hereby
grants Licensee a nonexclusive, royalty-free, world-wide license to reproduce,
analyze, test, perform and/or display publicly, prepare derivative works,
distribute, and otherwise use Python alone or in any derivative version,
provided, however, that PSF's License Agreement and PSF's notice of copyright,
i.e., "Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020 Python Software Foundation;
All Rights Reserved" are retained in Python alone or in any derivative version
prepared by Licensee.

3. In the event Licensee prepares a derivative work that is based on
or incorporates Python or any part thereof, and wants to make
the derivative work available to others as provided herein, then
Licensee hereby agrees to include in any such work a brief summary of
the changes made to Python.

4. PSF is making Python available to Licensee on an "AS IS"
basis.  PSF MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, PSF MAKES NO AND
DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON WILL NOT
INFRINGE ANY THIRD PARTY RIGHTS.

5. PSF SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON
FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS
A RESULT OF MODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON,
OR ANY DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.

6. This License Agreement will automatically terminate upon a material
breach of its terms and conditions.

7. Nothing in this License Agreement shall be deemed to create any
relationship of agency, partnership, or joint venture between PSF and
Licensee.  This License Agreement does not grant permission to use PSF
trademarks or trade name in a trademark sense to endorse or promote
products or services of Licensee, or any third party.

8. By copying, installing or otherwise using Python, Licensee
agrees to be bound by the terms and conditions of this License
Agreement.


BEOPEN.COM LICENSE AGREEMENT FOR PYTHON 2.0
-------------------------------------------

BEOPEN PYTHON OPEN SOURCE LICENSE AGREEMENT VERSION 1

1. This LICENSE AGREEMENT is between BeOpen.com ("BeOpen"), having an
office at 160 Saratoga Avenue, Santa Clara, CA 95051, and the
Individual or Organization ("Licensee") accessing and otherwise using
this software in source or binary form and its associated
documentation ("the Software").

2. Subject to the terms and conditions of this BeOpen Python License
Agreement, BeOpen hereby grants Licensee a non-exclusive,
royalty-free, world-wide license to reproduce, analyze, test, perform
and/or display publicly, prepare derivative works, distribute, and
otherwise use the Software alone or in any derivative version,
provided, however, that the BeOpen Python License is retained in the
Software, alone or in any derivative version prepared by Licensee.

3. BeOpen is making the Software available to Licensee on an "AS IS"
basis.  BEOPEN MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, BEOPEN MAKES NO AND
DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF THE SOFTWARE WILL NOT
INFRINGE ANY THIRD PARTY RIGHTS.

4. BEOPEN SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF THE
SOFTWARE FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS
AS A RESULT OF USING, MODIFYING OR DISTRIBUTING THE SOFTWARE, OR ANY
DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.

5. This License Agreement will automatically terminate upon a material
breach of its terms and conditions.

6. This License Agreement shall be governed by and interpreted in all
respects by the law of the State of California, excluding conflict of
law provisions.  Nothing in this License Agreement shall be deemed to
create any relationship of agency, partnership, or joint venture
between BeOpen and Licensee.  This License Agreement does not grant
permission to use BeOpen trademarks or trade names in a trademark
sense to endorse or promote products or services of Licensee, or any
third party.  As an exception, the "BeOpen Python" logos available at
http://www.pythonlabs.com/logos.html may be used according to the
permissions granted on that web page.

7. By copying, installing or otherwise using the software, Licensee
agrees to be bound by the terms and conditions of this License
Agreement.


CNRI LICENSE AGREEMENT FOR PYTHON 1.6.1
---------------------------------------

1. This LICENSE AGREEMENT is between the Corporation for National
Research Initiatives, having an office at 1895 Preston White Drive,
Reston, VA 20191 ("CNRI"), and the Individual or Organization
("Licensee") accessing and otherwise using Python 1.6.1 software in
source or binary form and its associated documentation.

2. Subject to the terms and conditions of this License Agreement, CNRI
hereby grants Licensee a nonexclusive, royalty-free, world-wide
license to reproduce, analyze, test, perform and/or display publicly,
prepare derivative works, distribute, and otherwise use Python 1.6.1
alone or in any derivative version, provided, however, that CNRI's
License Agreement and CNRI's notice of copyright, i.e., "Copyright (c)
1995-2001 Corporation for National Research Initiatives; All Rights
Reserved" are retained in Python 1.6.1 alone or in any derivative
version prepared by Licensee.  Alternately, in lieu of CNRI's License
Agreement, Licensee may substitute the following text (omitting the
quotes): "Python 1.6.1 is made available subject to the terms and
conditions in CNRI's License Agreement.  This Agreement together with
Python 1.6.1 may be located on the Internet using the following
unique, persistent identifier (known as a handle): 1895.22/1013.  This
Agreement may also be obtained from a proxy server on the Internet
using the following URL: http://hdl.handle.net/1895.22/1013".

3. In the event Licensee prepares a derivative work that is based on
or incorporates Python 1.6.1 or any part thereof, and wants to make
the derivative work available to others as provided herein, then
Licensee hereby agrees to include in any such work a brief summary of
the changes made to Python 1.6.1.

4. CNRI is making Python 1.6.1 available to Licensee on an "AS IS"
basis.  CNRI MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, CNRI MAKES NO AND
DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON 1.6.1 WILL NOT
INFRINGE ANY THIRD PARTY RIGHTS.

5. CNRI SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON
1.6.1 FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS
A RESULT OF MODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON 1.6.1,
OR ANY DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.

6. This License Agreement will automatically terminate upon a material
breach of its terms and conditions.

7. This License Agreement shall be governed by the federal
intellectual property law of the United States, including without
limitation the federal copyright law, and, to the extent such
U.S. federal law does not apply, by the law of the Commonwealth of
Virginia, excluding Virginia's conflict of law provisions.
Notwithstanding the foregoing, with regard to derivative works based
on Python 1.6.1 that incorporate non-separable material that was
previously distributed under the GNU General Public License (GPL), the
law of the Commonwealth of Virginia shall govern this License
Agreement only as to issues arising under or with respect to
Paragraphs 4, 5, and 7 of this License Agreement.  Nothing in this
License Agreement shall be deemed to create any relationship of
agency, partnership, or joint venture between CNRI and Licensee.  This
License Agreement does not grant permission to use CNRI trademarks or
trade name in a trademark sense to endorse or promote products or
services of Licensee, or any third party.

8. By clicking on the "ACCEPT" button where indicated, or by copying,
installing or otherwise using Python 1.6.1, Licensee agrees to be
bound by the terms and conditions of this License Agreement.

        ACCEPT


CWI LICENSE AGREEMENT FOR PYTHON 0.9.0 THROUGH 1.2
--------------------------------------------------

Copyright (c) 1991 - 1995, Stichting Mathematisch Centrum Amsterdam,
The Netherlands.  All rights reserved.

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Stichting Mathematisch
Centrum or CWI not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

STICHTING MATHEMATISCH CENTRUM DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL STICHTING MATHEMATISCH CENTRUM BE LIABLE
FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

### NOTICE files

npm `dexie`, NOTICE:

```text
Dexie.js

Copyright (c) 2014-2017 David Fahlander

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

npm `echarts`, NOTICE:

```text
Apache ECharts
Copyright 2017-2026 The Apache Software Foundation

This product includes software developed at
The Apache Software Foundation (https://www.apache.org/).
```

### Packages without a licence file

- crate `defmt-parser` (MIT OR Apache-2.0): the package carries no licence file
- crate `encoding-index-japanese` (CC0-1.0): the package carries no licence file
- crate `encoding-index-korean` (CC0-1.0): the package carries no licence file
- crate `encoding-index-simpchinese` (CC0-1.0): the package carries no licence file
- crate `encoding-index-singlebyte` (CC0-1.0): the package carries no licence file
- crate `encoding-index-tradchinese` (CC0-1.0): the package carries no licence file
- crate `encoding_index_tests` (CC0-1.0): the package carries no licence file
- crate `r-efi` (MIT OR Apache-2.0 OR LGPL-2.1-or-later): the package carries no licence file
- crate `utf16-simd` (MIT OR Apache-2.0): the package carries no licence file
<!-- END generated: texts -->
