#!/bin/sh
# Pack a release into a directory (default: out/): the tree of the current commit exactly as git
# holds it, plus the built frontend, as one archive that runs without Node; a bill of materials;
# and SHA-256 sums of both. Run from a clean checkout of the tag, after `npm ci && npm run build`
# in frontend/. The release workflow runs this; run by hand, it gives the same three files.
set -eu
cd "$(dirname "$0")/.."
out=${1:-out}
version=$(python3 tools/check_version.py)
name="remn-$version"
test -f frontend/dist/index.html || { echo "frontend/dist is missing: run 'npm ci && npm run build' in frontend/ first" >&2; exit 1; }
rm -rf "$out"
mkdir -p "$out"
git archive --format=tar --prefix="$name/" HEAD | tar -x -C "$out"
cp -R frontend/dist "$out/$name/frontend/dist"
# no .git in an archive: the server reads the commit it reports from this file (backend/forensic/build.py)
git rev-parse HEAD > "$out/$name/BUILD_ID"
cat > "$out/$name/INSTALL.md" <<INSTALL
# REMN $version, from the release archive

This archive is the source of REMN $version at commit $(git rev-parse HEAD), with the browser
application already built in \`frontend/dist\`. Python 3.13 is the only thing to install; Node is
needed only to rebuild the browser application after changing it.

Windows (PowerShell or Command Prompt):

    py -3.13 -m venv .venv
    .venv\\Scripts\\python.exe -m pip install --require-hashes -r backend\\requirements.txt
    .venv\\Scripts\\python.exe backend\\run.py

Linux and macOS:

    python3.13 -m venv .venv
    .venv/bin/python -m pip install --require-hashes -r backend/requirements.txt
    .venv/bin/python backend/run.py

Then open http://127.0.0.1:8000. \`docs/setup.md\` covers the optional parsers, Docker, the
configuration and access from another machine; \`docs/releasing.md\` says how to check this
archive against its published checksum and build provenance.
INSTALL
(cd "$out" && zip -q -r -X "$name.zip" "$name" && rm -rf "$name")
python3 tools/sbom.py --version "$version" --out "$out/$name.cdx.json"
# sha256sum on Linux and in Git for Windows, shasum on macOS: the same output format
if command -v sha256sum > /dev/null; then sum="sha256sum"; else sum="shasum -a 256"; fi
(cd "$out" && $sum "$name.zip" "$name.cdx.json" > SHA256SUMS && cat SHA256SUMS)
