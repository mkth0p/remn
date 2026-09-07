# Setup and run

REMN is two programs: a Python API (Django, stateless) and a browser application (Vite,
React, TypeScript). For daily use the API serves the built browser application on one
port, so a single process and a single address are all there is. During development the
two run separately with hot reload. This page covers what to install, the two ways to
run, the Docker alternative, remote access to a machine at home or in a lab, and how
the repository is laid out.

## Requirements

- Python 3.13. The optional PST and YARA packages have wheels for 3.13 and not yet for
  3.14, and the continuous integration and the Docker image use 3.13.
- Node 22 or later, for building the browser application. Continuous integration and
  the Docker image use 22.
- Developed and used on Windows 11; the same code runs on Linux in the Docker image and
  in continuous integration. The commands below are given for both; on Linux and macOS
  the virtual environment's interpreter is `.venv/bin/python` instead of
  `.venv\Scripts\python.exe`, and that is the only difference.
- Optional, for the AI features: [Ollama](https://ollama.com) with a model that supports
  tools (`gemma4`, `qwen3` and `llama3.1` are known to), or a Claude Code sign-in on the
  server machine. See [AI analyst](ai.md).
- Optional Python packages: `libpff-python` for PST and OST mailboxes, `yara-python` for
  YARA scanning of attachments. Everything else works without them.

## Install

Windows:

```bash
# the API, in a virtual environment on Python 3.13
py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install -r backend\requirements.txt

# optional: PST and YARA support
.venv\Scripts\python.exe -m pip install -r backend\requirements-optional.txt

# the browser application
cd frontend && npm ci && npm run build && cd ..
```

Linux and macOS:

```bash
# the API, in a virtual environment on Python 3.13
python3.13 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt

# optional: PST and YARA support (libpff builds from source: apt install build-essential python3.13-dev first)
.venv/bin/python -m pip install -r backend/requirements-optional.txt

# the browser application
cd frontend && npm ci && npm run build && cd ..
```

Where the distribution's Python is older than 3.13 (Ubuntu 24.04 ships 3.12), install it
from the deadsnakes PPA, with `uv python install 3.13`, or with pyenv. Every package in
`requirements.txt` has a Linux wheel and so has `yara-python`; `libpff-python` is the one
that compiles, which is why it needs the compiler and the Python headers.

Configuration is optional and lives in a `.env` file at the project root: copy
`.env.example` and set what you need (reputation provider keys, `OLLAMA_MODEL`, the
remote-access variables below). Every variable is documented in that file.

## Run

One process, one port, the built browser application served by the API:

```bash
.venv\Scripts\python.exe backend\run.py --port 8000
```

```bash
.venv/bin/python backend/run.py --port 8000        # Linux and macOS
```

Then open http://127.0.0.1:8000. `run.py` uses waitress, threaded, with streaming
responses; it prints a warning if `frontend/dist` is missing.

For development, run the API and the browser application separately; the second reloads
on every save and proxies `/api` to the first:

```bash
.venv\Scripts\python.exe backend\manage.py runserver 127.0.0.1:8000
cd frontend && npm run dev        # http://127.0.0.1:5173
```

```bash
.venv/bin/python backend/manage.py runserver 127.0.0.1:8000    # Linux and macOS
cd frontend && npm run dev
```

The two setups differ in one way that matters when something works in one and not the
other: in development Vite serves the script files, in the single-port setup Django does,
with the security headers described on the [security page](security.md).

## Docker

One container serves the API and the built browser application on port 8000:

```
docker compose up --build
```

`docker-compose.yml` publishes the port on 127.0.0.1 only, keeps the server store and
the upload area in named volumes (`remn-data`, `remn-tmp`), and points `OLLAMA_HOST` at an
Ollama on the host machine for the server proxy transport (the browser-direct transport
needs nothing from the container).

If the container starts but the page does not load, check these in order:

- **Port 8000 is already taken**, typically by a REMN development server on the same
  machine. Compose then stops with "ports are not available". Pick another host port:
  `REMN_PORT=8020 docker compose up` (`set REMN_PORT=8020` first in a Windows command
  prompt), then open http://127.0.0.1:8020.
- **The address.** The port is bound to 127.0.0.1, so http://localhost:8000 and
  http://127.0.0.1:8000 work from the same machine and nothing else does. Reaching it by
  the machine's name or address, or from another machine, needs the remote-access setup
  below: publish on `0.0.0.0` in the compose file, add the name or address to
  `FORENSIC_ALLOWED_HOSTS` (Django answers 400 otherwise) and set `FORENSIC_AUTH_TOKEN`.
- **`docker run` without `-p`.** The container listens on 8000 inside; publish it with
  `-p 127.0.0.1:8000:8000`.

The default build is the core: everything in `requirements.txt`, no PST or YARA. The
full build adds the optional packages; they are named at build time because the runtime
image keeps no package manager, and a build stage with a compiler takes care of libpff:

```
docker build --build-arg EXTRA_PIP="yara-python libpff-python" -t remn .
```

or, with compose, `REMN_EXTRA_PIP="yara-python libpff-python" docker compose up --build`
(`set REMN_EXTRA_PIP=yara-python libpff-python` first in a Windows command prompt). The
health endpoint, `/api/health`, reports what the running server has under `optional`.

Still not in the image: GeoLite2 and the offline lists, which are data the operator
downloads under licence (mount your `backend/data` folder at `/app/backend/data`), YARA
rules themselves (drop `.yar` files under that folder's `yara/`), and the Claude Code
connector, which runs the `claude` command line on the host.

The image is built from base images pinned by digest, takes Debian's security updates at
build time, runs as a non-root user with neither a compiler nor pip, and continuous
integration scans every build with Trivy, failing on critical or high findings that have
a fix. Findings without a fix from Debian yet (zlib and tar at the time of writing) stay
visible in a scan but do not fail the build.

## Remote access

By default everything binds to loopback. To host REMN on a home server or a lab machine
and use it from elsewhere, set two environment variables and put a TLS proxy in front:

```
FORENSIC_AUTH_TOKEN=<long-random-string>     # shared access token, required for every /api call
FORENSIC_ALLOWED_HOSTS=remn.example.com      # extra Host header values (comma list)
```

The first time a browser reaches a token-protected server, the app shows a token prompt;
the value is kept in that browser's IndexedDB and sent as the `X-Forensic-Client`
header. A wrong token gets `401 {"code":"auth"}`.

**Recommended: Tailscale Serve.** Keep `run.py` on `127.0.0.1` and run
`tailscale serve --bg 8000`; you get HTTPS (a secure context, which the app needs for
the crypto and clipboard APIs) with no open port, and only devices in your tailnet can
reach it. Set `FORENSIC_ALLOWED_HOSTS` to your tailnet name.

**Alternative: Caddy** (`caddy reverse-proxy --from remn.example.com --to 127.0.0.1:8000`)
gives automatic HTTPS. With nginx, disable response buffering (`proxy_buffering off;`),
or the streaming paths (chunked uploads, NDJSON ingest, server-sent events) stall.

**AI in remote mode.** The default transport is browser-direct: each analyst's page
calls *their own* local Ollama at `http://localhost:11434`, so prompts and evidence
excerpts never reach the server. Because the page origin is then your remote host name,
each analyst allows it once on their machine: `setx OLLAMA_ORIGINS "https://remn.example.com"`,
then restart Ollama. Chrome, Edge and Firefox let an HTTPS page call `http://localhost`;
Safari does not, so that analyst switches to the server-proxy transport in Settings → AI.

**Accepted trade-offs of this first version** (one shared token, keep the deployment
private): no per-user accounts or audit log, no rate limiting, DuckDB case stores are not
encrypted at rest, and anyone with the token can read or delete every case store.
Confidential rows only reach the server when a case uses the server store; browser-store
cases keep evidence in the analyst's browser. See [Storage modes](storage.md).

## Repository layout

```
backend/            Django project (stateless API) and services/ (pure Python: parsers, analysis, reputation, AI)
backend/data/       lists/ (offline block lists), yara/ (rules), geoip/ (GeoLite2 .mmdb); cases/ holds the server stores
frontend/           Vite + React + TypeScript application (Dexie/IndexedDB, web workers, ECharts)
rules/              bundled detection rules (YAML) and the community packs under rules/community/
samples/            synthetic generators (samples/synthetic/) and, gitignored, public corpora and local evidence
tests/backend/      pytest suite; tests/fixtures/ holds the parity and prompt fixtures
tools/              maintenance scripts: rule pack import, public-data validation, calibration, fixtures
docs/               these pages
.github/            continuous integration, release workflow, dependabot, templates
```
