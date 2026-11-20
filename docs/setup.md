# Setup and run

REMN is two programs: a Python API (Django, stateless) and a browser application (Vite,
React, TypeScript). For daily use the API serves the built browser application on one
port, so a single process and a single address are all there is. During development the
two run separately with hot reload. This page covers what to install, the two ways to
run, the Docker alternative, remote access to a machine at home or in a lab, and how
the repository is laid out.

## Requirements

- Python 3.13. The lock files are resolved for 3.13, and the continuous integration and
  the Docker image use it.
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
  YARA scanning of attachments, `py7zr` for packages delivered as 7z (DFIR-ORC). Everything
  else works without them.

## Install

Windows:

```bash
# the API, in a virtual environment on Python 3.13
py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install -r backend\requirements.txt

# optional: PST, YARA and 7z support
.venv\Scripts\python.exe -m pip install -r backend\requirements-optional.txt

# the browser application
cd frontend && npm ci && npm run build && cd ..
```

Linux and macOS:

```bash
# the API, in a virtual environment on Python 3.13
python3.13 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt

# optional: PST, YARA and 7z support (libpff builds from source: apt install build-essential python3.13-dev first)
.venv/bin/python -m pip install -r backend/requirements-optional.txt

# the browser application
cd frontend && npm ci && npm run build && cd ..
```

`backend/requirements.txt` fixes every package at an exact version with its hashes, so two
installs of one commit are the same install; pip refuses a file whose hash differs.
`backend/requirements-optional.txt` does the same for the optional packages, at versions
that agree with the main set.

Where the distribution's Python is older than 3.13 (Ubuntu 24.04 ships 3.12), install it
from the deadsnakes PPA, with `uv python install 3.13`, or with pyenv. Every package in
`requirements.txt` has a Linux wheel and so has `yara-python`; `libpff-python` is the one
that compiles, which is why it needs the compiler and the Python headers.

Configuration is optional and lives in a `.env` file at the project root: copy
`.env.example` and set what you need (reputation provider keys, `OLLAMA_MODEL`, the
remote-access variables below). Every variable is documented in that file.

Evidence passes through a staging area (`FORENSIC_TMP_DIR`, `backend/tmp` of the checkout)
while it is parsed. By default the staging area may use the free space of its disk less a
tenth of that disk (at most 10 GiB), so the largest file is set by the chunked-upload limit
(`FORENSIC_MAX_CHUNKED_GB`, 64) and by that disk; `FORENSIC_TMP_MAX_GB` sets a fixed total
instead. A file larger than the staging area can hold is refused with a message that says
which of the two decides it. Put the staging area on a disk with room for the largest
mailbox or collection you expect, and the case stores (`FORENSIC_CASES_DIR`) on one with
room for what it becomes.

Each parse runs in a process of its own, started from the same interpreter in isolated mode
(`python -I`), so the packages must be installed where that interpreter finds them without
`PYTHONPATH` or a user site folder, as the virtual environment above does. One parse may use
`FORENSIC_PARSE_MAX_MB` of memory (4096 by default) and `FORENSIC_PARSE_MAX_CPU_S` seconds of
processor time (six hours; not enforced on Windows), and is stopped past either with what it had
read and the reason. A server that runs as root on Linux or macOS can run the parses as another
account with `FORENSIC_PARSE_UID`. What each system enforces, and what
`FORENSIC_PARSE_ISOLATION=0` gives up, is on the [security page](security.md#each-parse-in-a-process-of-its-own).

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
- **The address.** By default the port is bound to 127.0.0.1, so http://localhost:8000
  and http://127.0.0.1:8000 work from the same machine and nothing else does: a browser
  on another computer gets a refused connection. Publishing on the network takes three
  variables: `REMN_BIND=0.0.0.0`, `REMN_HOSTS` with the name or address browsers will use
  (Django answers 400 to any other), and `REMN_TOKEN`, which every analyst pastes once
  when the page asks for it. Without a token or accounts (see
  [Accounts for a team](#accounts-for-a-team)), a server published on anything but a
  loopback address does not start, and its log says why. For example, on a machine
  reached as 192.0.2.10:

  ```
  REMN_BIND=0.0.0.0 REMN_HOSTS=192.0.2.10 REMN_TOKEN=$(openssl rand -hex 24) docker compose up -d --build
  ```

  The traffic is plain HTTP, so this is for a network you trust; the remote-access
  section below covers HTTPS and access from outside.
- **Behind your own protection.** When a reverse proxy, a VPN or a firewall in front
  already decides who gets in, both checks can be switched off: `REMN_HOSTS='*'` accepts
  any host name, and `REMN_NO_TOKEN=1` with an empty `REMN_TOKEN` starts the server on
  the network without a token. The server then prints a warning at start, because anyone
  who reaches the port can read and delete every server-store case; that is the
  trade-off being made, and it has to be stated. `docker-compose.open.yml`
  is that configuration in one file, full build included, on port 8300 of the machine
  itself, with `deploy/apache-remn.conf` as the matching Apache virtual host:

  ```
  sudo docker compose -f docker-compose.open.yml up -d --build
  ```
- **`docker run` without `-p`.** The container listens on 8000 inside; publish it with
  `-p 127.0.0.1:8000:8000 -e FORENSIC_PUBLISHED_ON=127.0.0.1`. The server inside the
  container cannot see where its port is published, so it is told: without a token it
  starts only when `FORENSIC_PUBLISHED_ON` is a loopback address, or when
  `FORENSIC_ALLOW_NO_TOKEN=1` says that running open is intended.

The default build is the core: everything in `requirements.txt`, no PST, YARA or 7z. The
full build adds the optional packages; they are named at build time because the runtime
image keeps no package manager, and a build stage with a compiler takes care of libpff:

```
docker build --build-arg EXTRA_PIP="yara-python libpff-python py7zr" -t remn .
```

or, with compose, `REMN_EXTRA_PIP="yara-python libpff-python" docker compose up --build`
(`set REMN_EXTRA_PIP=yara-python libpff-python` first in a Windows command prompt). The
names are chosen from `backend/requirements-optional.txt` and installed at the versions
and hashes that file fixes; a name it does not list fails the build. The health endpoint,
`/api/health`, reports what the running server has under `optional` to a request that
carries the `X-Forensic-Client` header (the token, when one is set). Without the header it
answers `{"ok": true}` and nothing else; that is what the image's health check
(`tools/healthcheck.py`) asks, so the check needs no token.

The image differs from a virtual-environment install in one more way: it carries
[Hayabusa](https://github.com/Yamato-Security/hayabusa) (AGPL-3.0, run as a separate
program) and runs it over Windows event logs as a third detection engine beside REMN's
two. A virtual-environment install has that engine only when Hayabusa is installed on the
machine (on `PATH`, or where `HAYABUSA_PATH` points), so the same evidence can give more
findings in the container. `--build-arg HAYABUSA=0` builds the image without it.

Still not in the image: GeoLite2 and the offline lists, which are data the operator
downloads under licence (mount your `backend/data` folder at `/app/backend/data`), YARA
rules themselves (drop `.yar` files under that folder's `yara/`), and the Claude Code
connector, which runs the `claude` command line on the host.

The image is built from base images pinned by digest, takes Debian's security updates at
build time, runs as a non-root user with neither a compiler nor pip, and continuous
integration scans every build with Trivy, failing on critical or high findings that have
a fix. Findings without a fix from Debian yet (zlib and tar at the time of writing) stay
visible in a scan but do not fail the build.

## A public instance

To put REMN on the open internet, run it in browser-only mode: the server parses and
returns rows and keeps nothing, every case stays in the visitor's browser, and the paths
that would keep state, spend money or run a model on the server are closed. The
[security page](security.md) lists exactly what is open and what is not.
`docker-compose.public.yml` is that configuration with Caddy in front for HTTPS. On a
small Linux virtual machine with Docker, a name that already points at it, and ports 80
and 443 open:

```
REMN_DOMAIN=remn.example.tech docker compose -f docker-compose.public.yml up -d --build
```

The setup script writes `REMN_DOMAIN` into a `.env` file beside the compose file, so later
commands such as `docker compose -f docker-compose.public.yml logs -f caddy` work without
repeating it. Caddy obtains and renews the certificate itself. The variables `REMN_RATE_LIMIT`
(heavy requests a minute per address, 60), `REMN_MAX_UPLOAD_MB` (512) and `REMN_EXTRA_PIP`
(the full build by default) adjust it. Visitors who want the AI analyst run Ollama on
their own machine and allow the site's origin in it, as described on the [AI page](ai.md);
the server has no model.

### From an empty virtual machine

The machine: two virtual processors, 2 GB of memory and 40 GB of disk are enough, since
nothing is stored between visits; parsing is what uses the processor. Any current Ubuntu
LTS or Debian works. The name needs one DNS record, `A` for the address of the machine
(and `AAAA` if it has an IPv6 one). Let it resolve before starting the stack, or the
certificate request fails and Caddy backs off for a while.

Everything below runs as a normal user with `sudo`; do not work as root.

One script does all of it, from a clone of the repository:

```bash
sudo REMN_DOMAIN=remn.example.tech bash deploy/public-server-setup.sh
```

It stops when the name does not resolve (and warns, then waits ten seconds, when it
resolves to an address other than the machine's), installs Docker and the
firewall, opens 22, 80 and 443 and nothing else, turns on unattended security updates,
closes SSH password logins only once it has found a key to log in with (never before, so
it cannot lock you out), starts the stack and waits for the certificate. Running it again
is safe.

Two things the script cannot do for you, because they live in the provider's console. The
cloud firewall in front of the machine has to allow 80 and 443, whatever the machine's own
firewall says; on most providers that is a security list or a network security group. And
some images, Oracle's Ubuntu among them, ship a saved iptables ruleset that rejects those
ports in front of ufw, which is the usual reason a certificate request fails on a machine
that looks correctly configured; the script detects that ruleset, keeps a copy and hands
the firewall to ufw.

The same steps by hand, if you would rather see each one:

```bash
sudo apt update && sudo apt -y upgrade && sudo apt -y install docker.io docker-compose-v2 ufw unattended-upgrades fail2ban git
```

```bash
sudo ufw default deny incoming && sudo ufw allow OpenSSH && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw --force enable
```

Only three ports are open, and the application container publishes none of its own: Caddy
reaches it over the compose network, so the only way in is through TLS. Then disable
password logins over SSH, which is what removes the class of attack that actually happens
to a machine with a public address (edit `/etc/ssh/sshd_config`, or a file under
`/etc/ssh/sshd_config.d/`):

```
PasswordAuthentication no
PermitRootLogin no
```

```bash
sudo systemctl restart ssh
```

Keep a working key-based session open while you test a second one. Then enable the
automatic security updates that the package above only installs:

```bash
sudo dpkg-reconfigure -plow unattended-upgrades
```

Finally the stack itself, from a clone of the repository:

```bash
git clone https://github.com/mkth0p/remn.git && cd remn
```

```bash
REMN_DOMAIN=remn.example.tech sudo -E docker compose -f docker-compose.public.yml up -d --build
```

### Upkeep

There is no case data on the machine to back up: browser-only mode keeps nothing, staging
is a RAM-backed tmpfs in a read-only container, and the only volumes hold Caddy's
certificates and configuration. What needs attention is the code and the base images, since
a public address means the vulnerabilities in them are reachable:

```bash
REMN_DOMAIN=remn.example.tech sudo -E bash deploy/update.sh
```

`deploy/update.sh` pulls the clone, rebuilds the images stamped with the commit (which the
page shows visitors, with a link to that source; a plain `docker compose up --build` shows
the build as unknown), checks the new proxy image and Caddyfile before it replaces anything,
and restarts the stack. `REMN_DOMAIN` can stay out of the command when the `.env` beside the
compose file holds it, as the setup script leaves it. Run it when a release is tagged. Continuous integration scans every image build with
Trivy and fails on critical or high findings that have a fix, so a green build is the
signal that the image is worth deploying. `docker logs` on the two containers shows what
happened; `sudo docker system prune -f` reclaims the space of the images replaced.

### What is still true of a public instance

Anyone who reaches it can use it, and the request budget only bounds how fast. The server
parses whatever it is given, so treat it as a machine that runs untrusted input through
the parsers all day: that is why it holds no case data, no keys and no model account, and
why it lives on a machine of its own rather than next to anything that matters. Visitors
upload evidence to it; the rows come back to their browser and the temporary copy is
discarded, but during the parse the file is held on that machine, in its RAM-backed staging
area, so the instance is a place to
try REMN and not a place for anyone's real evidence. Say so on the page that links to it.

## Remote access

By default everything binds to loopback. To host REMN on a home server or a lab machine
and use it from elsewhere, set two environment variables and put a TLS proxy in front:

```
FORENSIC_AUTH_TOKEN=<long-random-string>     # shared access token, required for every /api call
FORENSIC_ALLOWED_HOSTS=remn.example.com      # extra Host header values (comma list)
```

`backend/run.py` does not start on an address other machines can reach (`--host 0.0.0.0`,
or a container published beyond loopback) without `FORENSIC_AUTH_TOKEN` or accounts: it exits
with code 2 and a message naming the choices. `FORENSIC_ALLOW_NO_TOKEN=1` overrides that, for a
server whose own proxy, VPN or firewall decides who gets in, and for a browser-only
instance that is open by design.

The first time a browser reaches a token-protected server, the app shows a token prompt;
the value is kept in that browser's IndexedDB and sent as the `X-Forensic-Client`
header. A wrong token gets `401 {"code":"auth"}`. Ten wrong tokens in a minute from one
address (`FORENSIC_AUTH_FAILURES_PER_MIN`, 0 for no limit) get that address `429` with a
Retry-After for every request that carries a token, the right one included, until the
allowance refills; behind a proxy, set `FORENSIC_TRUST_PROXY=1` so that each client is counted
on its own address rather than all of them on the proxy's.

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

**Accepted trade-offs.** The shared token is the single-user mode: whoever holds it can read
or delete every case store, and nothing records who did what; keep such a deployment private,
or use accounts. In either mode there is no request budget unless `FORENSIC_RATE_LIMIT_PER_MIN`
is set (wrong tokens are limited, as above) and DuckDB case stores are not encrypted at rest.
Confidential rows only reach the server when a case uses the server store; browser-store
cases keep evidence in the analyst's browser. See [Storage modes](storage.md).

### Accounts for a team

A team that shares one server gives each person an account. The first account turns accounts
on: from the next request every API call needs a personal token, the shared
`FORENSIC_AUTH_TOKEN` is no longer accepted (leave it empty), the server starts beyond loopback
without it, and requests are recorded in an audit log. What each role may do, and what the
audit log records and proves, is on the [security page](security.md#accounts-roles-and-the-audit-log).

```bash
.venv/bin/python backend/manage.py accounts create lead --role admin         # prints the token once
.venv/bin/python backend/manage.py accounts create analyst-a --role analyst
.venv/bin/python backend/manage.py accounts create reviewer --role viewer
```

With Docker, run it in the running container, which runs as the server's account:
`docker compose exec remn python backend/manage.py accounts create lead --role admin`. Outside
Docker, run it as the account the server runs as; run with sudo, the files it writes are given
to the owner of the data directory. Each token is printed once and kept on the server only as a
digest: hand it to its owner over a channel you trust. They paste it once when the page asks
for it.

| Command | Does |
|---|---|
| `accounts list` | the accounts, their roles, and the ids of their tokens |
| `accounts rotate <name>` | revokes every token of the account and prints a new one |
| `accounts revoke <name> [--token <id>]` | revokes one token, or all of them |
| `accounts disable <name>`, `accounts enable <name>` | refuses the account's tokens, or accepts them again |
| `accounts role <name> admin\|analyst\|viewer` | gives the account another role |
| `accounts cases` | the case records, and the stores no record covers |
| `accounts case <key> --owner <name> --members <a,b>` | gives a case an owner, or sets its members |

A change takes effect at the next request, without a restart. The accounts are in
`accounts.json` in the data directory (`FORENSIC_DATA_DIR`, the `remn-data` volume with Docker).

The analyst who creates a server-store case, by its first upload or import, owns it. The owner
sets its members by account name (`POST /api/store/<key>/access` with `{"members": [...]}`). A
store created before accounts were turned on has no owner and only an admin opens it: list such
stores with `accounts cases` and give each one an owner with `accounts case <key> --owner <name>`.

The audit log is `audit.log` beside the accounts file. An admin reads it with
`manage.py audit show [--case <key>] [--account <name>]` or `GET /api/audit`, and checks it with
`manage.py audit verify` or `GET /api/audit/verify`. `verify` ends with the code of the newest
entry: note it somewhere the server cannot write, and give it back next time with
`--head <code>`, which is what finds entries cut off the end. The key that chains the log is
`FORENSIC_AUDIT_KEY`, or a random key written to `audit.key` beside the log when that is empty;
set the variable to keep the key out of the data directory and its backups. Changing the key
makes the entries written under the old one fail verification.

Removing `accounts.json` turns accounts off at the next request: every case is then open to
whoever reaches the server, as in the single-user mode, until the server is restarted, when the
rule above about a token beyond loopback applies again.

**Upgrading from a version that only warned.** Before this change the server printed a
warning and listened when it was reachable beyond loopback without a token. It now
refuses, so these setups have to change:

- `docker run -p 8000:8000` without a token: publish on loopback and say so
  (`-p 127.0.0.1:8000:8000 -e FORENSIC_PUBLISHED_ON=127.0.0.1`), or set
  `FORENSIC_AUTH_TOKEN`, or `FORENSIC_ALLOW_NO_TOKEN=1`.
- `docker compose` with `REMN_BIND` off loopback and no `REMN_TOKEN`: set `REMN_TOKEN`, or
  `REMN_NO_TOKEN=1` for a setup behind its own proxy, VPN or firewall. The default
  (`REMN_BIND` unset, loopback) needs nothing.
- `run.py --host` with an address other machines reach, without a token: set
  `FORENSIC_AUTH_TOKEN` or `FORENSIC_ALLOW_NO_TOKEN=1`.
- A browser-only instance started outside `docker-compose.public.yml`:
  `FORENSIC_ALLOW_NO_TOKEN=1`.
- `docker-compose.open.yml`, `docker-compose.public.yml`, `deploy/update.sh`,
  `deploy/public-server-setup.sh` and a server on `127.0.0.1` need nothing: the compose
  files set what they need.

A container that refuses to start under `restart: unless-stopped` restarts in a loop, with
the reason in `docker logs`.

## Backup and upgrade

This section is for a server that keeps cases in the server store. A browser-store case lives
in the analyst's browser and is kept with a case bundle (see
[Storage modes](storage.md#portable-case-backups)); a public instance keeps no case at all.
The case bundles are still worth exporting from a server-store case: the findings, notes and
decisions of every case live in the browser, not in its store.

### Backing up the case stores

`tools/store_backup.py` copies each case store into a backup folder, byte for byte, with a
`manifest.json` per case that lists each file's size and SHA-256, the store's schema version
and the row count of every table. It checks each copy by opening it before it reports the
case as backed up, and it never writes over an earlier backup, so give it a new folder each
time. `verify` checks a backup folder again later, for instance after it has been copied to
other media.

```bash
.venv/bin/python tools/store_backup.py backup /srv/remn-backups/2026-11-19
.venv/bin/python tools/store_backup.py verify /srv/remn-backups/2026-11-19
```

On Windows the interpreter is `.venv\Scripts\python.exe` and the folder a Windows path. The
tool reads the cases folder from the same `.env` as the server; `--cases-dir` names another.

The server holds a store open while it is used, and for `FORENSIC_STORE_IDLE_S` seconds (600)
after its last use. A backup taken while the server runs copies every case nobody is working
on, skips the others with a line naming each one and why, and ends with exit code 1; run it
again later for those, or stop the server first to back up every case in one run. While the
tool copies a case, the server answers requests for that case with 503 and asks to try again.

With Docker, the stores are in the `remn-data` volume and the tool is in the image. Stop the
service, run the tool in a one-off container with a host folder for the backups, and start
the service again. The container runs as uid 1000, which needs to be able to write the folder:

```bash
mkdir -p remn-backups && sudo chown 1000 remn-backups
docker compose stop remn
docker compose run --rm -v "$PWD/remn-backups:/backups" remn python tools/store_backup.py backup /backups/2026-11-19
docker compose start remn
```

A backup holds the evidence rows of every case it covers: keep it on an encrypted volume, as
the stores themselves (see [Security model](security.md#where-evidence-lives)). The tool copies
the case stores only. On a server with accounts, copy `accounts.json`, `audit.log` and
`audit.key` from the data directory with them (or keep `FORENSIC_AUDIT_KEY`): without the
accounts file a restored case has no owner, and without the key the log cannot be verified.

### Restoring a case

```bash
.venv/bin/python tools/store_backup.py restore /srv/remn-backups/2026-11-19            # every case in the backup
.venv/bin/python tools/store_backup.py restore /srv/remn-backups/2026-11-19 <case key>  # one case
```

A restore first checks the backup against its manifest (digests, row counts, schema version)
and changes nothing if they differ. It does not write over a case that is already in the cases
folder: such a case is skipped, with a line saying so. `--replace` restores over it and keeps
the case it replaces beside the others as `<key>.before-restore-<time>`, which the server does
not list; remove that folder once the restored case has been checked. Restore with the server
stopped, or only cases nobody is using: a case the server holds open is refused. A backup
written by a newer version of REMN is not restored by an older one.

### Upgrading

1. Note the version that runs now: `git rev-parse HEAD` in the clone (the build is also in
   `/api/health`).
2. Stop the server, back up every case into a new folder as above, and check that the last
   line counts every store as backed up. Keep this backup until the new version has been
   running for as long as a rollback could still be wanted.
3. Update the code: `git pull --ff-only` (or check out the release), install the
   requirements again (`pip install -r backend/requirements.txt`, and the optional file if
   you use it) and rebuild the browser application (`cd frontend && npm ci && npm run build`).
   With Docker, `git pull --ff-only` and `docker compose up -d --build`.
4. Start the server. A store written by an older version is upgraded the first time it is
   opened, in one transaction, and the server log says so (`case store <key> upgraded from
   schema 1 to 2`); see [Storage modes](storage.md#server-store). Open the cases you need
   and check their counts on the Dashboard.

### Rolling back

1. Stop the server and go back to the version noted in step 1 of the upgrade:
   `git checkout <commit>`, then the requirements and the browser application as in step 3
   (with Docker, `docker compose up -d --build` after the checkout).
2. Start it and open the cases. A store the older version reads opens as it is. A store the
   newer version upgraded to a schema the older one does not read is refused, with nothing in
   it changed: the case answers 409 (`storeVersion`) with a message that names both versions.
3. For each refused case, stop the server, restore the case from the backup taken before the
   upgrade, and start the server again:
   `tools/store_backup.py restore --replace <backup folder> <case key>` (with Docker, run it
   as the backup was run). What was added to that case after the upgrade is not in the
   restored store; it stays in the store kept aside as `<key>.before-restore-<time>` until that
   folder is removed.

## Repository layout

```
backend/            Django project (stateless API) and services/ (pure Python: parsers, analysis, reputation, AI)
backend/data/       lists/ (offline block lists), yara/ (rules), geoip/ (GeoLite2 .mmdb); cases/ holds the server stores
frontend/           Vite + React + TypeScript application (Dexie/IndexedDB, web workers, ECharts)
rules/              bundled detection rules (YAML), the community packs under rules/community/, and their measures
samples/            synthetic generators (samples/synthetic/) and, gitignored, public corpora and local evidence
tests/backend/      pytest suite; tests/fixtures/ holds the parity, prompt, golden-corpus and attack-sample fixtures
tools/              maintenance scripts: rule pack import, rule measurement and the head-to-head, public-data validation, calibration, fixtures
docs/               these pages, and docs/reviews/ for the dated reviews and measurements
.github/            continuous integration, the weekly rule measurement, release workflow, dependabot, templates
```
