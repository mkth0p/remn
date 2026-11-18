#!/bin/sh
# Resolve backend/requirements.ranges and backend/requirements-dev.ranges into the two files an
# install reads: exact versions, every transitive package, a hash for every file of every platform.
# Needs uv (https://docs.astral.sh/uv/). Run from the repository root after changing a range, or
# with --upgrade to take the newest versions the ranges allow.
set -eu
cd "$(dirname "$0")/.."
common="--universal --python-version 3.13 --generate-hashes --no-header --quiet"
# shellcheck disable=SC2086
uv pip compile $common "$@" backend/requirements.ranges -o backend/requirements.txt
# shellcheck disable=SC2086
uv pip compile $common "$@" backend/requirements-dev.ranges -o backend/requirements-dev.txt
for f in backend/requirements.txt backend/requirements-dev.txt; do
    { printf '# Written by tools/lock_requirements.sh from %s. Do not edit by hand.\n' "${f%.txt}.ranges"; cat "$f"; } > "$f.tmp"
    mv "$f.tmp" "$f"
done
