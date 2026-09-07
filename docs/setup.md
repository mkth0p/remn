# Setup and run

_Requirements, installation, the two ways to run, remote access._

## Requirements

* Windows 11 (tested), Python 3.13, Node 24
* [Ollama](https://ollama.com) with a model that supports tools (e.g. `gemma4`, `qwen3`, `llama3.1`)
* Optional: `libpff-python` for PST/OST, `yara-python` for YARA scanning

## Setup

```bash
# backend (venv with Python 3.13)
py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
# optional: PST / YARA
.venv\Scripts\python.exe -m pip install -r backend\requirements-optional.txt

# frontend
cd frontend && npm install && npm run build && cd ..

# configuration (optional): copy .env.example to .env and set API keys / OLLAMA_MODEL
```

## Run

```bash
# single port, production-style (serves frontend/dist)
.venv\Scripts\python.exe backend\run.py --port 8000
# then open http://127.0.0.1:8000
```

Development (hot reload):

```bash
.venv\Scripts\python.exe backend\manage.py runserver 127.0.0.1:8000
cd frontend && npm run dev        # http://127.0.0.1:5173 (proxies /api)
```

## Remote access (home-server mode)

By default everything binds to loopback. To host REMN on a home server and use
it from anywhere, set two environment variables and put a TLS proxy in front:

```
FORENSIC_AUTH_TOKEN=<long-random-string>     # shared access token, required for every /api call
FORENSIC_ALLOWED_HOSTS=remn.example.com      # extra Host header values (comma list)
```

The first time a browser hits a token-protected server, the app shows a token
prompt; the value is kept in that browser's IndexedDB and sent as the
`X-Forensic-Client` header. A wrong token gets `401 {"code":"auth"}`.

**Recommended: Tailscale Serve.** Keep `run.py` on `127.0.0.1` and run
`tailscale serve --bg 8000`; you get HTTPS (a secure context, which the app
needs for crypto/clipboard APIs) with zero open ports, and only devices in your
tailnet can even reach it. Set `FORENSIC_ALLOWED_HOSTS` to your tailnet name.

**Alternative: Caddy** (`caddy reverse-proxy --from remn.example.com --to 127.0.0.1:8000`)
gives automatic HTTPS. With nginx, disable response buffering
(`proxy_buffering off;`) or streaming (chunked uploads, NDJSON ingest, SSE)
stalls.

**AI in remote mode.** The default transport is browser-direct: each analyst's
page calls *their own* local Ollama at `http://localhost:11434`, so prompts and
evidence excerpts never reach the server. Because the page origin is then your
remote hostname, each analyst must allow it once on their machine:
`setx OLLAMA_ORIGINS "https://remn.example.com"` (then restart Ollama).
Chrome, Edge and Firefox allow an HTTPS page to call `http://localhost`
(loopback exemption); Safari does not — switch that analyst to the server-proxy
transport in Settings → AI.

**Accepted v1 trade-offs** (single shared token, keep the deployment private):
no per-user accounts or audit log, no rate limiting, DuckDB case stores are not
encrypted at rest, and anyone with the token can read or delete every case
store. Confidential rows only reach the server when a case uses the *server
store*; browser-store cases keep evidence in the analyst's browser.

## Layout

```
backend/            Django project (stateless API) + services/ (pure Python: parsers, analysis, reputation, AI)
frontend/           Vite + React + TypeScript SPA (Dexie/IndexedDB, web workers, ECharts)
rules/              bundled detection rules (YAML DSL, served by /api/meta)
samples/            local EVTX exports (gitignored) + synthetic/ mail generator for tests
tests/backend/      pytest suite
backend/data/       lists/ (offline block lists), yara/ (rules), geoip/ (GeoLite2 .mmdb)
```

## Docker

One container serves the API and the built frontend on port 8000:

```
docker compose up --build
```

`docker-compose.yml` publishes the port on 127.0.0.1 only, keeps the server store and
the upload area in named volumes (`remn-data`, `remn-tmp`), and points `OLLAMA_HOST` at an
Ollama on the host machine for the server proxy transport (the browser-direct transport
needs nothing from the container). For remote access add the machine's name or address to
`FORENSIC_ALLOWED_HOSTS` and set `FORENSIC_AUTH_TOKEN`, as in the remote access section.

Not in the image: PST support (libpff needs a build), YARA, GeoLite2 and the offline
lists (mount them under `/app/backend/data`), and the Claude Code connector, which runs
the `claude` command line on the host. To add the optional Python packages, build with a
requirements file of your own or run `pip install` in a derived image.
