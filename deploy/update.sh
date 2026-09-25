#!/usr/bin/env bash
# Bring a public REMN instance up to date with its clone, and rebuild it stamped with the commit.
#
#   bash deploy/update.sh            # from the repository clone, as a user who can run docker
#
# The commit is what the app shows visitors, with a link to that exact source, so the image is
# built with it rather than with whatever an earlier build left in the environment.
set -euo pipefail
[ -f docker-compose.public.yml ] || { echo "run this from the repository clone" >&2; exit 1; }
git pull --ff-only
export REMN_BUILD_ID=$(git rev-parse HEAD)
compose=(docker compose -f docker-compose.public.yml)
"${compose[@]}" build
# The running site is replaced only by a proxy that can start: the Caddyfile is checked, and the
# app is in the image, by the new image itself before anything is recreated.
"${compose[@]}" run --rm --no-deps --entrypoint sh caddy -c \
    'test -f /srv/remn/index.html && caddy validate --config /etc/caddy/site/Caddyfile --adapter caddyfile' \
    || { echo "the new proxy image or deploy/Caddyfile is not valid; the running site is unchanged" >&2; exit 1; }
"${compose[@]}" up -d
"${compose[@]}" exec -T remn python -c "import sys; sys.path.insert(0, 'backend'); from forensic.build import build_id; print('running', build_id())" 2>/dev/null || true
