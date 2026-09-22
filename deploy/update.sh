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
REMN_BUILD_ID=$(git rev-parse HEAD) docker compose -f docker-compose.public.yml up -d --build
docker compose -f docker-compose.public.yml exec -T remn python -c "import sys; sys.path.insert(0, 'backend'); from forensic.build import build_id; print('running', build_id())" 2>/dev/null || true
