# Third-party notices

REMN is licensed under the Apache License 2.0 (see `LICENSE`). It ships or pulls in the
following third-party material, each under its own terms. Package licences below are as
declared by the packages at the time of writing; the authoritative text is the one each
package distributes.

## Detection rule packs (`rules/community/`)

Imported verbatim by `tools/import_community_rules.py`; each pack directory carries the
upstream `LICENSE` and a provenance file with the commit it was taken from.

| Pack | Upstream | Licence |
| --- | --- | --- |
| SigmaHQ rules (Windows, emerging threats, threat hunting) | https://github.com/SigmaHQ/sigma | Detection Rule License 1.1 (DRL-1.1) |
| Sublime Security rules | https://github.com/sublime-security/sublime-rules | MIT |

## Fonts

| Font | Source | Licence |
| --- | --- | --- |
| Gulax (wordmark; embedded in printed reports) | `frontend/public/fonts/` | SIL Open Font License 1.1 (see `Gulax-LICENSE.txt` and `Gulax-COPYRIGHT.md` there) |
| Inter Variable | `@fontsource-variable/inter` | SIL Open Font License 1.1 |
| JetBrains Mono Variable | `@fontsource-variable/jetbrains-mono` | SIL Open Font License 1.1 |

## Reference data (downloaded by the operator, not redistributed)

| Data | Source | Terms |
| --- | --- | --- |
| GeoLite2 databases | MaxMind | GeoLite2 End User License Agreement; requires a MaxMind account |
| Offline block lists (URLhaus, ThreatFox, …) | abuse.ch and others | Each list's own terms |
| Public tranco list | https://tranco-list.eu | See the site |

## Public test corpora (`samples/public/`, gitignored, fetched by `tools/validate_public.py`)

| Corpus | Source | Licence |
| --- | --- | --- |
| Nazario phishing corpus | https://monkey.org/~jose/phishing/ | CC BY 4.0 |
| Phishing Pot | https://github.com/rf-peixoto/phishing_pot | As stated in the repository |
| SpamAssassin public corpus | https://spamassassin.apache.org/old/publiccorpus/ | Apache License 2.0 |
| Apache Tika test PST | https://github.com/apache/tika | Apache License 2.0 |
| Microsoft 365 audit log samples | https://github.com/invictus-ir | As stated in the repository |

## Python packages (`backend/requirements*.txt`)

| Package | Licence |
| --- | --- |
| Django | BSD-3-Clause |
| waitress | ZPL-2.1 |
| python-dotenv | BSD-3-Clause |
| PyYAML | MIT |
| evtx | MIT / Apache-2.0 |
| extract-msg | GPL-3.0 |
| oletools | BSD-2-Clause |
| pypdf | BSD-3-Clause |
| puremagic | MIT |
| confusable-homoglyphs | MIT |
| dnspython | ISC |
| tldextract | BSD-3-Clause |
| httpx | BSD-3-Clause |
| ollama | MIT |
| idna | BSD-3-Clause |
| duckdb | MIT |
| pyarrow | Apache-2.0 |
| libpff-python (optional) | LGPL-3.0-or-later |
| yara-python (optional) | BSD-3-Clause |
| pytest, pytest-django, ruff (development) | MIT |

`extract-msg` is GPL-3.0. REMN imports it for `.msg` parsing only; anyone redistributing a
combined build should read that licence first.

## JavaScript packages (`frontend/package.json`)

| Package | Licence |
| --- | --- |
| react, react-dom | MIT |
| zustand | MIT |
| dexie | Apache-2.0 |
| echarts | Apache-2.0 |
| dompurify | Apache-2.0 or MPL-2.0 |
| hash-wasm | MIT |
| js-yaml | MIT |
| @tanstack/react-virtual | MIT |
| vite, vitest, typescript, eslint, prettier and the testing-library packages (development) | MIT / Apache-2.0 |

## Standards and references

MITRE ATT&CK technique identifiers are used under the ATT&CK terms of use
(https://attack.mitre.org/resources/terms-of-use/). Sigma and Sublime rule formats are
implemented from their public specifications.
