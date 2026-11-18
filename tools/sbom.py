"""A software bill of materials for a release, in CycloneDX 1.5 JSON, from the lock files alone.

    python tools/sbom.py --version 0.2.0 --out remn-0.2.0.cdx.json

Three sets, each read from the file an install or a build really uses, so the list cannot drift
from what is shipped: the Python packages of backend/requirements.txt and the optional parsers of
backend/requirements-optional.txt (exact versions, tools/lock_requirements.sh); the npm packages
the built frontend is made from (frontend/package-lock.json, development-only packages left out);
the Rust crates compiled into the EVTX decoder (frontend/wasm/evtx/Cargo.lock). The Docker image
adds Hayabusa at the version its Dockerfile pins, listed here for that reason.

No tool is installed to write it: the format is a list, and a generator that is itself a
dependency would have to be listed and trusted too.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import tomllib
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")


def _python(lock: Path, group: str) -> list[dict]:
    out = []
    for line in lock.read_text(encoding="utf-8").splitlines():
        m = PIN.match(line)
        if m:
            name = re.sub(r"[-_.]+", "-", m.group(1)).lower()
            out.append(
                {
                    "type": "library",
                    "group": group,
                    "name": name,
                    "version": m.group(2),
                    "purl": f"pkg:pypi/{name}@{m.group(2)}",
                    "bom-ref": f"pkg:pypi/{name}@{m.group(2)}",
                }
            )
    return out


def _npm(lock: Path) -> list[dict]:
    out = []
    packages = json.loads(lock.read_text(encoding="utf-8")).get("packages", {})
    for path, meta in sorted(packages.items()):
        if not path or meta.get("dev") or meta.get("link") or "version" not in meta:
            continue
        name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
        purl = f"pkg:npm/{quote(name, safe='/')}@{meta['version']}"
        component = {"type": "library", "group": "frontend", "name": name, "version": meta["version"], "purl": purl, "bom-ref": f"{purl}#{path}"}
        integrity = meta.get("integrity", "")
        if integrity.startswith("sha512-"):
            component["hashes"] = [{"alg": "SHA-512", "content": base64.b64decode(integrity[7:]).hex()}]
        out.append(component)
    return out


def _cargo(lock: Path) -> list[dict]:
    out = []
    for package in tomllib.loads(lock.read_text(encoding="utf-8")).get("package", []):
        if "source" not in package:
            # the decoder crate itself, not a dependency
            continue
        purl = f"pkg:cargo/{package['name']}@{package['version']}"
        component = {"type": "library", "group": "evtx-decoder", "name": package["name"], "version": package["version"], "purl": purl, "bom-ref": purl}
        if package.get("checksum"):
            component["hashes"] = [{"alg": "SHA-256", "content": package["checksum"]}]
        out.append(component)
    return out


def _hayabusa(dockerfile: Path) -> list[dict]:
    m = re.search(r"^ARG HAYABUSA_VERSION=(\S+)", dockerfile.read_text(encoding="utf-8"), re.MULTILINE)
    if not m:
        return []
    purl = f"pkg:github/Yamato-Security/hayabusa@v{m.group(1)}"
    return [{"type": "application", "group": "image", "name": "hayabusa", "version": m.group(1), "purl": purl, "bom-ref": purl}]


def build(version: str, root: Path = ROOT) -> dict:
    components = (
        _python(root / "backend" / "requirements.txt", "backend")
        + _python(root / "backend" / "requirements-optional.txt", "backend-optional")
        + _npm(root / "frontend" / "package-lock.json")
        + _cargo(root / "frontend" / "wasm" / "evtx" / "Cargo.lock")
        + _hayabusa(root / "Dockerfile")
    )
    # a package of the optional set that the main set already pins is one component, not two
    seen: set[str] = set()
    unique = []
    for component in components:
        if component["bom-ref"] not in seen:
            seen.add(component["bom-ref"])
            unique.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "remn", "version": version, "bom-ref": f"remn@{version}"}},
        "components": unique,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--version", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    bom = build(args.version)
    args.out.write_text(json.dumps(bom, indent=1) + "\n", encoding="utf-8")
    print(f"{args.out}: {len(bom['components'])} components")


if __name__ == "__main__":
    main()
