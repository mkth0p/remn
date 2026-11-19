# Releasing

A release is a tag. Pushing `vX.Y.Z` runs `.github/workflows/release.yml`, which publishes
three things and nothing else:

- a GitHub release with `remn-X.Y.Z.zip` (the source at that commit with the browser
  application already built, and an `INSTALL.md` whose commands work as written),
  `remn-X.Y.Z.cdx.json` (the bill of materials, CycloneDX 1.5) and `SHA256SUMS`;
- the Docker image `ghcr.io/<owner>/remn:X.Y.Z` on GitHub Container Registry, the default
  build of the `Dockerfile` for linux/amd64;
- for the archive, the bill of materials and the image, a signed build provenance statement
  that names the repository, the commit and the workflow run that built them.

Nothing is published from a branch, a pull request or a manual run.

## Cutting a release

1. On `main`, with CI green, set the version in three files: `VERSION` in
   `backend/forensic/build.py`, and `version` in `frontend/package.json` and
   `frontend/package-lock.json` (`npm version X.Y.Z --no-git-tag-version` in `frontend/`
   writes both).
2. In `CHANGELOG.md`, rename `## Unreleased` to `## X.Y.Z (YYYY-MM-DD)` and add an empty
   `## Unreleased` above it. The text under the version heading becomes the release notes.
3. Check, commit, merge:

   ```
   python tools/check_version.py
   ```

   It prints the version when the three files and the changelog agree and names what
   differs when they do not. The test suite runs the same check on every pull request.
4. Tag the merged commit and push the tag:

   ```
   git tag -a vX.Y.Z -m "REMN X.Y.Z"
   git push origin vX.Y.Z
   ```

The workflow first compares the tag with the code (`tools/check_version.py --tag vX.Y.Z`)
and stops there when they differ, then runs the whole of CI on the tagged commit, then
builds and publishes. A failed run publishes nothing; delete the tag, fix, and tag again.
Whether the image can be pulled without signing in is the package's visibility, which is
set in the package's settings on GitHub: check it after the first release.

`tools/release_pack.sh` is what the workflow runs to build the archive, the bill of
materials and the sums; run from a checkout after `npm ci && npm run build` in `frontend/`,
it writes the same three files to `out/`.

## Checking a release

The sums:

```
sha256sum -c SHA256SUMS
```

On Windows, `Get-FileHash remn-X.Y.Z.zip -Algorithm SHA256` prints the value to compare
with the line in `SHA256SUMS`.

The provenance, with the [GitHub CLI](https://cli.github.com), for the archive and for the
image:

```
gh attestation verify remn-X.Y.Z.zip --repo <owner>/remn
gh attestation verify oci://ghcr.io/<owner>/remn:X.Y.Z --repo <owner>/remn
```

A sum says the file is the one that was published. The provenance says more: that the file
was built by this repository's release workflow from the tagged commit, on a GitHub-hosted
runner, and not uploaded by hand.

The commit a running server was built from is on its health route (`build`), shown in the
app, and written in `BUILD_ID` at the root of the archive.

## What the bill of materials covers

`tools/sbom.py` writes it from the lock files, so it lists what an install or a build
really takes: the Python packages of `backend/requirements.txt`, the optional parsers of
`backend/requirements-optional.txt`, the npm packages the built browser application is
made from (development tools left out), the Rust crates compiled into the EVTX decoder,
and Hayabusa at the version the `Dockerfile` pins. It does not list the operating-system
packages of the Docker base image; the image scan in CI reads those.

## Keeping the dependencies current

- Dependabot opens grouped pull requests: Python and npm weekly, the Docker base images
  weekly, the GitHub Actions monthly. Actions are pinned to a commit with the version in a
  comment, and Dependabot raises both.
- The Python locks are written by `tools/lock_requirements.sh` (see `CONTRIBUTING.md`).
  When a Dependabot bump of a single pin fails its checks, run the script with `--upgrade`
  instead of editing the lock.
- A nightly CI run installs the newest versions the ranges allow, and a weekly run measures
  every rule. When a scheduled run fails, `.github/workflows/scheduled-report.yml` opens an
  issue titled "Scheduled run failing: <workflow>" with the run's address, adds to it while
  the failure lasts, and closes it on the first scheduled run that passes.
