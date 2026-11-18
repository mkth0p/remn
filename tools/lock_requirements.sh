#!/bin/sh
# Resolve the three .ranges files under backend/ into the files an install reads: exact versions,
# every transitive package, a hash for every file of every platform. requirements.txt is resolved
# first; the development and optional sets are resolved against it, so the three never disagree.
# Needs uv (https://docs.astral.sh/uv/). Run from the repository root after changing a range, or
# with --upgrade to take the newest versions the ranges allow.
set -eu
cd "$(dirname "$0")/.."
common="--universal --python-version 3.13 --generate-hashes --no-header --quiet"
for name in requirements requirements-dev requirements-optional; do
    # shellcheck disable=SC2086
    uv pip compile $common "$@" "backend/$name.ranges" -o "backend/$name.txt"
    { printf '# Written by tools/lock_requirements.sh from backend/%s.ranges. Do not edit by hand.\n' "$name"; cat "backend/$name.txt"; } > "backend/$name.txt.tmp"
    mv "backend/$name.txt.tmp" "backend/$name.txt"
done
