# Records Continuity Service

Implemented optional honeypot for the public browser-only deployment. It is a
separate synthetic archive: two passive discovery artifacts, signed reference
handles, a finite administrative mystery, private telemetry/replay, and a
separately consented investigation exercise. No live remn.tech deployment is
performed by adding these files.

## Start on the Oracle host

Keep the public application's existing domain. Add an A record for a **different**
archive hostname, pointing to this server; add AAAA only if IPv6 is configured.
The example below assumes the existing public Compose deployment in this checkout.
Use its existing Compose project name if you previously set one with `-p`.

```sh
export REMN_DOMAIN=remn.tech
export REMN_ARCHIVE_DOMAIN=vault.remn.tech
docker compose -f docker-compose.public.yml -f docker-compose.honeypot.yml config --quiet
docker compose -f docker-compose.public.yml -f docker-compose.honeypot.yml build archive
docker compose -f docker-compose.public.yml -f docker-compose.honeypot.yml up -d
docker compose -f docker-compose.public.yml -f docker-compose.honeypot.yml exec -T archive python -m honeypot.verify boundary
```

Keep these domain settings in the deployment environment or its existing `.env`.
Caddy obtains HTTPS certificates. Use the overlay on subsequent Compose commands.
The main REMN image also needs the current code/build to import `Deception`
observations. The archive image has no REMN dependencies; its build context is
only `honeypot/` and its runtime uses Python's standard library.

To remove the lures without deleting telemetry, return Caddy to the original
profile, then stop the archive:

```sh
docker compose -f docker-compose.public.yml up -d --no-deps caddy
docker compose -f docker-compose.public.yml -f docker-compose.honeypot.yml stop archive
```

## Discovery and the fiction

The real application's `/.env.bak` and `/_retained/release.json` are synthetic
read-only artifacts. They point to a compatibility manifest at the separate
origin. Neither is an actual configuration file or source map. The application
UI never requests them. Real API routes retain the browser-only behavior.

The replacement index withdraws RC-0041; its retained reference returns the same
payload checksum under a different receiving-office assignment. Schema exceptions,
transfer schedules, a facilities notice and a surviving delegation explain how
Annex C became a logical queue. Retrieving the copy issues a receipt at the actual
request time. Historical dates remain fixed; there is no claim of personal access.

The technical and administrative branches can be read in different orders.
References are bound to their episode, parent exhibit, target route, mode and
24-hour expiry. There are at most eight hops along a reference chain. Branching
and replay remain possible; they do not create an infinite sequence of new
documents. Shared links establish information lineage, never visitor identity.

`https://vault.remn.tech/exercise` is an explicit training entry. Its consent POST
creates a new signed challenge episode. It cannot relabel previous archive
activity. The resolution distinguishes a temporary reference receipt from the
historical transfer; completion downloads a small REMN-compatible ZIP containing
only that exercise's copy and disposition observations.

## Private operator workflow

There is no operator HTTP endpoint. On the host, list retained episodes:

```sh
docker compose -f docker-compose.public.yml -f docker-compose.honeypot.yml exec -T archive python -m honeypot.operator list
```

Choose an episode ID and export it locally on the Linux host:

```sh
docker compose -f docker-compose.public.yml -f docker-compose.honeypot.yml exec -T archive python -m honeypot.operator export --episode EPISODE_ID > archive-episode.zip
```

Open `operator-replay.html` from that ZIP for an offline, scrub-able observation
replay. Import the ZIP as an investigation package into REMN to explore the
episode/exhibit/reference graph and cite source rows. The HTML file is inventoried
as unsupported evidence; the `Deception/observations.ndjson` member is parsed.
Challenge and archive scopes are visibly separate. No automated ban or outbound
notification is configured.

The replay shows measured actions and response digests. It deliberately does not
store full responses or live tokens and cannot recreate their exact bytes.
Exports contain at most the latest 96 retained observations and 128 KiB compressed;
the manifest reports truncation and coverage limits. Missing parents can result
from sampling, rotation or export limits. Episode listing is capped at 4,096.

## Enforced boundaries and limits

- The archive runs with `network_mode: none`, an unprivileged UID, all capabilities
  dropped, no privilege escalation, and a read-only root filesystem. Caddy reaches
  it through its own Unix socket. No application volume, host socket, credentials,
  Docker socket or operator telemetry is mounted into Caddy from the archive.
- A 1 MiB temporary shared volume carries only that socket; a separate archive
  state volume contains its signing key and bounded journals. Caddy mounts the
  socket volume read-only. No archive TCP listener is enabled in deployment.
- Container ceilings: 128 MiB RAM, 0.25 CPU, 32 processes/threads, 128 descriptors.
  Request ceilings: 16 handlers, backlog 8, five-second absolute lifetime,
  8 KiB headers/body, 2 KiB URL, 32 KiB response. Discovery and signed reads use
  separate global budgets, respectively 2/s and 12/s with bursts of 8 and 32.
- Journal lanes reserve 48 MiB for novel signed transitions and 16 MiB for
  discovery/repeated activity. Noise is sampled. Expired segments are removed
  on startup and approximately every 30 seconds while running; exports exclude
  segments older than seven days. A stopped container cannot erase its volume.
  Suppressed-event and journal-error counters accompany retained observations.
- Caddy access logging is disabled; its diagnostic/error log formatter removes
  request objects and response headers, including on upstream failures. Caddy's
  container logs are separately capped at 2 MiB.
- No raw IPs, credentials, cookies, authorization headers, arbitrary request URLs
  or bodies are journaled. The proxy strips credentials before forwarding.
  Responses set no cookies, allow no CORS, and load no scripts or external assets.
  HTML uses same-origin referrers so browser form POSTs retain a verifiable Origin;
  passive documents use no-referrer. The proxy strips incoming referrers.
  Discovery responses additionally receive a sandboxed CSP at the real origin.

The state volume has an application-enforced journal budget, not a filesystem
quota. Normal Docker container logs are separately capped at 2 MiB. This is
shared-host isolation, not a VM boundary or protection against a kernel exploit.
It also does not prevent link sharing, scanners consuming global budgets, or
traffic exhausting the host/Caddy before reaching the service.

The archive subdomain is a separate origin but shares its registrable site with
REMN. Do not introduce parent-domain cookies; use a separate registrable domain
if the real app later adds sensitive same-site session behavior.

## Verification and local preview

```sh
python -m unittest honeypot.test_archive -q
pytest tests/backend/test_deception.py tests/backend/test_packages.py -q
docker build -t remn-archive honeypot
python tools/validate_honeypot.py
```

The Docker integration check uses an existing `remn:latest` image, a disposable
project, loopback HTTP, and no ACME requests. It checks actual network/privilege
boundaries, Caddy's read-only socket connection, real API denial, the complete
reference trail and private export, then removes only its temporary project.
CI repeats it against the current application image. The export remains under
`backend/tmp/archive-smoke-export.zip` for inspection.

For a local preview (Windows or Linux), using a disposable state directory:

```sh
python -m honeypot.archive --dev-port 8369 --state backend/tmp/archive-preview
```

Open `http://127.0.0.1:8369/discovery/env` for the discovery trail or `/exercise`
for the consented version. This explicit preview mode binds only loopback and
uses local HTTP references; it is not the production transport.

Locally verified on Docker Desktop/Linux amd64: isolated service and end-to-end
Caddy routing pass; roughly 17 MiB idle memory in the test. Oracle/ARM64 load
behavior remains to be measured on the deployment host. The pinned Python image
supports the architecture through Docker's image platform selection.

Implementation uses [Caddy's Unix-socket upstream support](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#upstream-addresses)
and [Docker's none network driver](https://docs.docker.com/engine/network/drivers/none/).
The earlier [design proposal](honeypot-design.md) and [narrative](ghost-archive-narrative.md)
remain the rationale; this document describes the shipped behavior.
